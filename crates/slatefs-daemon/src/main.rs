//! slatefsd — serves SlateFS volumes over NFSv3 (9P arrives in Phase 4).
//!
//! Startup: read config → open control plane just long enough to resolve
//! exports, DEKs, and the fh-HMAC key → close it (so the CLI can use the
//! control DB while the daemon runs) → open volumes → one NFS listener per
//! export (DD-10).

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use slatefs_core::config::{Config, ExportProtocol};
use slatefs_core::control::ControlPlane;
use slatefs_core::crypto::kms;
use slatefs_core::rate::{RateLimiter, RateLimits};
use slatefs_core::store;
use slatefs_core::volume::{Volume, VolumeCaches};
use slatefs_nfs::{NFSTcp, SquashPolicy};

#[derive(Parser)]
#[command(name = "slatefsd", version, about = "SlateFS file server daemon")]
struct Args {
    /// Path to the slatefs TOML config file.
    #[arg(long, short, default_value = "/etc/slatefs/slatefs.toml")]
    config: std::path::PathBuf,
}

fn tenant_rate_limiter(
    limiters: &mut std::collections::HashMap<String, Arc<RateLimiter>>,
    tenant: String,
    limits: RateLimits,
) -> Option<Arc<RateLimiter>> {
    if limits.is_unlimited() {
        return None;
    }
    Some(
        limiters
            .entry(tenant)
            .or_insert_with(|| Arc::new(RateLimiter::new(limits)))
            .clone(),
    )
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
        let record = control
            .get_mountable_volume(&export.tenant, &export.volume)
            .await?;
        let tenant = control.get_tenant(&export.tenant).await?;
        let dek = control.unwrap_volume_dek(&record).await?;
        planned.push((export.clone(), record, dek, tenant.rate_limits));
    }
    control.close().await.context("closing control-plane DB")?;

    let mut volumes = Vec::new();
    let mut servers = tokio::task::JoinSet::new();
    // One Volume per (tenant, volume) — a SlateDB has exactly one writer
    // (DD-5), and several exports (e.g. NFS + 9P, plan §9.4) share it.
    let mut open_volumes: std::collections::HashMap<(String, String), Arc<Volume>> =
        std::collections::HashMap::new();
    let mut rate_limiters: std::collections::HashMap<String, Arc<RateLimiter>> =
        std::collections::HashMap::new();
    let distinct: std::collections::HashSet<(String, String)> = config
        .exports
        .iter()
        .map(|e| (e.tenant.clone(), e.volume.clone()))
        .collect();
    let share_count = distinct.len();
    for (export, record, dek, rate_limits) in planned {
        let key = (export.tenant.clone(), export.volume.clone());
        let rate_limiter =
            tenant_rate_limiter(&mut rate_limiters, export.tenant.clone(), rate_limits);
        let volume = match open_volumes.get(&key) {
            Some(v) => Arc::clone(v),
            None => {
                let mut caches = VolumeCaches::from_config(
                    &config.cache,
                    &export.tenant,
                    &export.volume,
                    share_count,
                );
                let recorder = Arc::new(slatefs_core::metrics::AggregatingRecorder::default());
                caches.recorder = Some(Arc::clone(&recorder));
                let volume =
                    Volume::open_with_caches(&record, dek, Arc::clone(&object_store), &caches)
                        .await
                        .with_context(|| {
                            format!("opening volume {}/{}", export.tenant, export.volume)
                        })?;

                // Cache hit-rate visibility (plan §13 / Phase 3 AC): log the
                // cache-related engine metrics periodically per volume.
                let (tenant, volume_name) = (export.tenant.clone(), export.volume.clone());
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
                    tick.tick().await; // skip the immediate tick
                    loop {
                        tick.tick().await;
                        let stats: Vec<String> = recorder
                            .snapshot()
                            .into_iter()
                            .filter(|(name, value)| name.contains("cache") && *value != 0.0)
                            .map(|(name, value)| format!("{name}={value}"))
                            .collect();
                        if !stats.is_empty() {
                            tracing::info!(
                                tenant,
                                volume = volume_name,
                                "cache metrics: {}",
                                stats.join(" ")
                            );
                        }
                    }
                });
                volumes.push(Arc::clone(&volume));
                open_volumes.insert(key, Arc::clone(&volume));
                volume
            }
        };

        match export.protocol {
            ExportProtocol::Nfs => {
                let policy = SquashPolicy {
                    mode: export.squash,
                    anon_uid: export.anon_uid,
                    anon_gid: export.anon_gid,
                };
                let listener = slatefs_nfs::bind_export_with_allowlist_and_rate_limit(
                    volume,
                    fh_key.clone(),
                    policy,
                    export.allowed_clients.clone(),
                    rate_limiter.clone(),
                    &export.listen,
                )
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
            ExportProtocol::P9 => {
                let export_name = format!("/{}/{}", export.tenant, export.volume);
                let listen = export.listen.clone();
                let token = export.p9_token.clone();
                let allowed_clients = export.allowed_clients.clone();
                tracing::info!(
                    tenant = export.tenant,
                    volume = export.volume,
                    listen = export.listen,
                    "export ready; mount with: mount -t 9p -o trans=tcp,version=9p2000.L,port=<port>{} <host> <dir>",
                    if token.is_some() {
                        ",uname=<token>"
                    } else {
                        ""
                    },
                );
                servers.spawn(async move {
                    slatefs_9p::serve_export_with_allowlist_and_rate_limit(
                        volume,
                        export_name,
                        token,
                        allowed_clients,
                        rate_limiter,
                        &listen,
                    )
                    .await
                });
            }
        }
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
