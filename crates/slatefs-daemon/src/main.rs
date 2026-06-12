//! slatefsd — serves SlateFS volumes over NFSv3 (9P arrives in Phase 4).
//!
//! Startup: read config → open control plane just long enough to resolve
//! exports, DEKs, and the fh-HMAC key → close it (so the CLI can use the
//! control DB while the daemon runs) → open volumes → one NFS listener per
//! export (DD-10).

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use slatefs_core::config::Config;
use slatefs_core::control::ControlPlane;
use slatefs_core::crypto::kms;
use slatefs_core::store;
use slatefs_core::volume::Volume;
use slatefs_nfs::{NFSTcp, SquashPolicy};

#[derive(Parser)]
#[command(name = "slatefsd", version, about = "SlateFS file server daemon")]
struct Args {
    /// Path to the slatefs TOML config file.
    #[arg(long, short, default_value = "/etc/slatefs/slatefs.toml")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let config = Config::load(&args.config)
        .with_context(|| format!("loading config from {}", args.config.display()))?;
    if config.exports.is_empty() {
        anyhow::bail!(
            "no [[exports]] configured in {}; nothing to serve",
            args.config.display()
        );
    }

    let object_store = store::resolve_root(&config.object_store.url)
        .with_context(|| format!("resolving object store {}", config.object_store.url))?;
    let kms = kms::from_config(&config.kms)?;

    // Resolve everything we need from the control plane, then release it.
    let control = ControlPlane::open(Arc::clone(&object_store), kms)
        .await
        .context("opening control-plane DB")?;
    let fh_key = control.server_fh_key().await?;
    let mut planned = Vec::new();
    for export in &config.exports {
        let record = control.get_volume(&export.tenant, &export.volume).await?;
        let dek = control.unwrap_volume_dek(&record).await?;
        planned.push((export.clone(), record, dek));
    }
    control.close().await.context("closing control-plane DB")?;

    let mut volumes = Vec::new();
    let mut servers = tokio::task::JoinSet::new();
    for (export, record, dek) in planned {
        let volume = Volume::open(&record, dek, Arc::clone(&object_store))
            .await
            .with_context(|| format!("opening volume {}/{}", export.tenant, export.volume))?;
        volumes.push(Arc::clone(&volume));

        let policy = SquashPolicy {
            mode: export.squash,
            anon_uid: export.anon_uid,
            anon_gid: export.anon_gid,
        };
        let listener = slatefs_nfs::bind_export(volume, fh_key.clone(), policy, &export.listen)
            .await
            .with_context(|| format!("binding {}", export.listen))?;
        tracing::info!(
            tenant = export.tenant,
            volume = export.volume,
            listen = export.listen,
            port = listener.get_listen_port(),
            "export ready; mount with: mount -t nfs -o vers=3,nolock,tcp,port={p},mountport={p} <host>:/ <dir>",
            p = listener.get_listen_port(),
        );
        servers.spawn(async move { listener.handle_forever().await });
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down on SIGINT");
        }
        Some(res) = servers.join_next() => {
            tracing::error!("an export listener exited unexpectedly: {res:?}");
        }
    }

    servers.abort_all();
    for volume in &volumes {
        if let Err(e) = volume.shutdown().await {
            tracing::error!("volume shutdown: {e}");
        }
    }
    Ok(())
}
