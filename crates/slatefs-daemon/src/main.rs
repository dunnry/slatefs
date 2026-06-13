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
use slatefs_core::metrics::{AggregatingRecorder, PrometheusSample, render_prometheus};
use slatefs_core::rate::{RateLimiter, RateLimits};
use slatefs_core::snapshot::SnapshotVolume;
use slatefs_core::store;
use slatefs_core::vfs::Vfs;
use slatefs_core::volume::{Volume, VolumeCaches};
use slatefs_nfs::{NFSTcp, SquashPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser)]
#[command(name = "slatefsd", version, about = "SlateFS file server daemon")]
struct Args {
    /// Path to the slatefs TOML config file.
    #[arg(long, short, default_value = "/etc/slatefs/slatefs.toml")]
    config: std::path::PathBuf,
}

#[derive(Clone)]
struct MetricsTarget {
    tenant: String,
    volume_name: String,
    recorder: Arc<AggregatingRecorder>,
    volume: Arc<Volume>,
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

fn render_daemon_metrics(targets: &[MetricsTarget]) -> String {
    let mut samples = Vec::new();
    for target in targets {
        let labels = [
            ("tenant", target.tenant.as_str()),
            ("volume", target.volume_name.as_str()),
        ];
        samples.push(PrometheusSample::new(
            "slatefs_volume_dead",
            labels,
            if target.volume.is_dead() { 1.0 } else { 0.0 },
        ));
        samples.extend(target.recorder.prometheus_samples(&labels));
    }
    render_prometheus(&samples)
}

async fn handle_metrics_connection(
    mut stream: TcpStream,
    targets: Vec<MetricsTarget>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await;
    let n = match read {
        Ok(result) => result?,
        Err(_) => return Ok(()),
    };
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let mut request_line = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = request_line.next();
    let path = request_line.next();
    let (status, content_type, body) = if method == Some("GET") && path == Some("/metrics") {
        (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render_daemon_metrics(&targets),
        )
    } else {
        (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        )
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

async fn serve_metrics(listen: String, targets: Vec<MetricsTarget>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&listen).await?;
    tracing::info!(listen, "metrics endpoint ready at /metrics");
    loop {
        let (stream, peer) = listener.accept().await?;
        let targets = targets.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_metrics_connection(stream, targets).await {
                tracing::debug!(%peer, "metrics scrape failed: {error}");
            }
        });
    }
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

    let mut writable_volumes = Vec::new();
    let mut snapshot_volumes = Vec::new();
    let mut metrics_targets = Vec::new();
    let mut servers = tokio::task::JoinSet::new();
    // One writable Volume per live (tenant, volume) — a SlateDB has exactly
    // one writer (DD-5). Snapshot exports are read-only DbReader backends
    // keyed by checkpoint id.
    let mut open_backends: std::collections::HashMap<
        (String, String, Option<String>),
        Arc<dyn Vfs>,
    > = std::collections::HashMap::new();
    let mut open_writers: std::collections::HashMap<(String, String), Arc<Volume>> =
        std::collections::HashMap::new();
    let mut rate_limiters: std::collections::HashMap<String, Arc<RateLimiter>> =
        std::collections::HashMap::new();
    let distinct: std::collections::HashSet<(String, String)> = config
        .exports
        .iter()
        .filter(|e| e.snapshot.is_none())
        .map(|e| (e.tenant.clone(), e.volume.clone()))
        .collect();
    let share_count = distinct.len();
    for (export, record, dek, rate_limits) in planned {
        let key = (
            export.tenant.clone(),
            export.volume.clone(),
            export.snapshot.clone(),
        );
        let rate_limiter =
            tenant_rate_limiter(&mut rate_limiters, export.tenant.clone(), rate_limits);
        let volume = match open_backends.get(&key) {
            Some(v) => Arc::clone(v),
            None => {
                let backend: Arc<dyn Vfs> = if let Some(snapshot) = &export.snapshot {
                    let snapshot_volume =
                        SnapshotVolume::open(&record, dek, Arc::clone(&object_store), snapshot)
                            .await
                            .with_context(|| {
                                format!(
                                    "opening snapshot {snapshot} for {}/{}",
                                    export.tenant, export.volume
                                )
                            })?;
                    snapshot_volumes.push(Arc::clone(&snapshot_volume));
                    snapshot_volume
                } else {
                    let writer_key = (export.tenant.clone(), export.volume.clone());
                    match open_writers.get(&writer_key) {
                        Some(volume) => Arc::<Volume>::clone(volume),
                        None => {
                            let mut caches = VolumeCaches::from_config(
                                &config.cache,
                                &export.tenant,
                                &export.volume,
                                share_count,
                            );
                            let recorder =
                                Arc::new(slatefs_core::metrics::AggregatingRecorder::default());
                            caches.recorder = Some(Arc::clone(&recorder));
                            let volume = Volume::open_with_caches(
                                &record,
                                dek,
                                Arc::clone(&object_store),
                                &caches,
                            )
                            .await
                            .with_context(|| {
                                format!("opening volume {}/{}", export.tenant, export.volume)
                            })?;
                            let watched = Arc::clone(&volume);
                            let watched_tenant = export.tenant.clone();
                            let watched_volume = export.volume.clone();
                            servers.spawn(async move {
                                watched.wait_dead().await;
                                tracing::error!(
                                    tenant = watched_tenant,
                                    volume = watched_volume,
                                    "volume fenced; dropping daemon exports"
                                );
                                Err(std::io::Error::other("volume fenced by newer writer"))
                            });

                            // Cache hit-rate visibility (plan §13 / Phase 3 AC): log the
                            // cache-related engine metrics periodically per volume.
                            let (tenant, volume_name) =
                                (export.tenant.clone(), export.volume.clone());
                            metrics_targets.push(MetricsTarget {
                                tenant: tenant.clone(),
                                volume_name: volume_name.clone(),
                                recorder: Arc::clone(&recorder),
                                volume: Arc::clone(&volume),
                            });
                            tokio::spawn(async move {
                                let mut tick =
                                    tokio::time::interval(std::time::Duration::from_secs(60));
                                tick.tick().await; // skip the immediate tick
                                loop {
                                    tick.tick().await;
                                    let stats: Vec<String> = recorder
                                        .snapshot()
                                        .into_iter()
                                        .filter(|(name, value)| {
                                            name.contains("cache") && *value != 0.0
                                        })
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
                            writable_volumes.push(Arc::clone(&volume));
                            open_writers.insert(writer_key, Arc::clone(&volume));
                            volume
                        }
                    }
                };
                open_backends.insert(key, Arc::clone(&backend));
                backend
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
                    snapshot = export.snapshot.as_deref().unwrap_or("-"),
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
                    snapshot = export.snapshot.as_deref().unwrap_or("-"),
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

    if let Some(listen) = config.metrics.listen.clone() {
        servers.spawn(async move { serve_metrics(listen, metrics_targets).await });
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
    for volume in &writable_volumes {
        if let Err(e) = volume.shutdown().await {
            tracing::error!("volume shutdown: {e}");
        }
    }
    for snapshot in &snapshot_volumes {
        if let Err(e) = snapshot.shutdown().await {
            tracing::error!("snapshot shutdown: {e}");
        }
    }
    Ok(())
}
