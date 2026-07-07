//! slatefsd — serves SlateFS volumes over NFSv3 and 9P2000.L.
//!
//! Startup: read config → open control plane just long enough to resolve
//! exports, DEKs, and the fh-HMAC key → close it (so the CLI can use the
//! control DB while the daemon runs) → open volumes → one listener per export
//! (DD-10).

use std::collections::HashMap;
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
use slatefs_core::volume::{self, Volume, VolumeCaches};
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
enum MetricsTarget {
    Writable {
        tenant: String,
        volume_name: String,
        recorder: Arc<AggregatingRecorder>,
        volume: Arc<Volume>,
    },
    TenantRateLimiter {
        tenant: String,
        limiter: Arc<RateLimiter>,
    },
    Snapshot {
        tenant: String,
        volume_name: String,
        snapshot_id: String,
        volume: Arc<SnapshotVolume>,
    },
}

type AdminTargets = Arc<HashMap<(String, String), Arc<Volume>>>;

const CACHE_TIER_ACCESS_TOTAL: &str = "slatefs_cache_tier_access_total";
const SLATEDB_DB_CACHE_ACCESS_COUNT: &str = "slatefs_slatedb.db_cache.access_count";
const SLATEDB_OBJECT_STORE_CACHE_PART_ACCESS_COUNT: &str =
    "slatefs_slatedb.object_store_cache.part_access_count";
const SLATEDB_OBJECT_STORE_CACHE_PART_HIT_COUNT: &str =
    "slatefs_slatedb.object_store_cache.part_hit_count";

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

fn hard_limit_value(limit: Option<u64>) -> f64 {
    limit.map(|value| value as f64).unwrap_or(f64::INFINITY)
}

fn sample_label<'a>(sample: &'a PrometheusSample, name: &str) -> Option<&'a str> {
    sample
        .labels
        .iter()
        .find_map(|(label_name, value)| (label_name == name).then_some(value.as_str()))
}

fn cache_tier_sample(
    tenant: &str,
    volume: &str,
    tier: &str,
    result: &str,
    value: f64,
) -> PrometheusSample {
    PrometheusSample::new(
        CACHE_TIER_ACCESS_TOTAL,
        [
            ("tenant", tenant),
            ("volume", volume),
            ("tier", tier),
            ("result", result),
        ],
        value,
    )
}

fn cache_tier_samples(
    tenant: &str,
    volume: &str,
    engine_samples: &[PrometheusSample],
) -> Vec<PrometheusSample> {
    let mut saw_ram = false;
    let mut ram_hits = 0.0;
    let mut ram_misses = 0.0;
    let mut saw_disk_access = false;
    let mut disk_access = 0.0;
    let mut disk_hits = 0.0;

    for sample in engine_samples {
        match sample.name.as_str() {
            SLATEDB_DB_CACHE_ACCESS_COUNT => {
                saw_ram = true;
                match sample_label(sample, "result") {
                    Some("hit") => ram_hits += sample.value,
                    Some("miss") => ram_misses += sample.value,
                    _ => {}
                }
            }
            SLATEDB_OBJECT_STORE_CACHE_PART_ACCESS_COUNT => {
                saw_disk_access = true;
                disk_access += sample.value;
            }
            SLATEDB_OBJECT_STORE_CACHE_PART_HIT_COUNT => {
                disk_hits += sample.value;
            }
            _ => {}
        }
    }

    let mut samples = Vec::new();
    if saw_ram {
        samples.push(cache_tier_sample(tenant, volume, "ram", "hit", ram_hits));
        samples.push(cache_tier_sample(tenant, volume, "ram", "miss", ram_misses));
    }
    if saw_disk_access {
        samples.push(cache_tier_sample(tenant, volume, "disk", "hit", disk_hits));
        samples.push(cache_tier_sample(
            tenant,
            volume,
            "disk",
            "miss",
            (disk_access - disk_hits).max(0.0),
        ));
    }
    samples
}

fn render_daemon_metrics(targets: &[MetricsTarget]) -> String {
    let mut samples = Vec::new();
    for target in targets {
        match target {
            MetricsTarget::Writable {
                tenant,
                volume_name,
                recorder,
                volume,
            } => {
                let labels = [
                    ("tenant", tenant.as_str()),
                    ("volume", volume_name.as_str()),
                ];
                samples.push(PrometheusSample::new(
                    "slatefs_volume_dead",
                    labels,
                    if volume.is_dead() { 1.0 } else { 0.0 },
                ));
                samples.push(PrometheusSample::new(
                    "slatefs_volume_degraded",
                    labels,
                    if volume.is_degraded() { 1.0 } else { 0.0 },
                ));
                samples.push(PrometheusSample::new(
                    "slatefs_writer_fencing_events_total",
                    labels,
                    volume.writer_fencing_events() as f64,
                ));
                samples.push(PrometheusSample::new(
                    "slatefs_storage_errors_total",
                    labels,
                    volume.storage_errors() as f64,
                ));
                let (bytes_used, inodes_used) = volume.quota_usage();
                let (bytes_limit, inodes_limit) = volume.quota_hard_limits();
                samples.push(PrometheusSample::new(
                    "slatefs_quota_bytes_used",
                    labels,
                    bytes_used as f64,
                ));
                samples.push(PrometheusSample::new(
                    "slatefs_quota_bytes_hard_limit",
                    labels,
                    hard_limit_value(bytes_limit),
                ));
                samples.push(PrometheusSample::new(
                    "slatefs_quota_inodes_used",
                    labels,
                    inodes_used as f64,
                ));
                samples.push(PrometheusSample::new(
                    "slatefs_quota_inodes_hard_limit",
                    labels,
                    hard_limit_value(inodes_limit),
                ));
                samples.push(PrometheusSample::new(
                    "slatefs_quota_rejections_total",
                    labels,
                    volume.quota_rejections() as f64,
                ));
                let block_labels = [
                    ("tenant", tenant.as_str()),
                    ("volume", volume_name.as_str()),
                    ("snapshot", "-"),
                ];
                samples.push(PrometheusSample::new(
                    "slatefs_block_decode_failures_total",
                    block_labels,
                    volume.block_decode_failures() as f64,
                ));
                let engine_samples = recorder.prometheus_samples(&labels);
                samples.extend(cache_tier_samples(tenant, volume_name, &engine_samples));
                samples.extend(engine_samples);
            }
            MetricsTarget::TenantRateLimiter { tenant, limiter } => {
                samples.push(PrometheusSample::new(
                    "slatefs_rate_limit_rejections_total",
                    [("tenant", tenant.as_str())],
                    limiter.rejections() as f64,
                ));
            }
            MetricsTarget::Snapshot {
                tenant,
                volume_name,
                snapshot_id,
                volume,
            } => {
                let labels = [
                    ("tenant", tenant.as_str()),
                    ("volume", volume_name.as_str()),
                    ("snapshot", snapshot_id.as_str()),
                ];
                samples.push(PrometheusSample::new(
                    "slatefs_block_decode_failures_total",
                    labels,
                    volume.block_decode_failures() as f64,
                ));
            }
        }
    }
    render_prometheus(&samples)
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: String,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
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

    write_http_response(&mut stream, status, content_type, body).await
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

fn parse_admin_snapshot_path(path: &str) -> Result<(String, String, Option<String>), &'static str> {
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    let mut segments = route.trim_start_matches('/').split('/');
    if segments.next() != Some("snapshot") {
        return Err("expected /snapshot/<tenant>/<volume>");
    }
    let tenant = segments.next().ok_or("missing tenant")?;
    let volume = segments.next().ok_or("missing volume")?;
    if tenant.is_empty() || volume.is_empty() || segments.next().is_some() {
        return Err("expected /snapshot/<tenant>/<volume>");
    }
    let mut name = None;
    for part in query.split('&') {
        let Some(raw) = part.strip_prefix("name=") else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        name = Some(percent_decode(raw)?);
        break;
    }
    Ok((tenant.to_string(), volume.to_string(), name))
}

fn percent_decode(raw: &str) -> Result<String, &'static str> {
    let mut out = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("invalid percent encoding");
            }
            let hi = hex_value(bytes[i + 1]).ok_or("invalid percent encoding")?;
            let lo = hex_value(bytes[i + 2]).ok_or("invalid percent encoding")?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "invalid utf-8 in percent encoding")
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

async fn handle_admin_connection(
    mut stream: TcpStream,
    targets: AdminTargets,
) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
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
    let (status, body) = match (method, path) {
        (Some("POST"), Some(path)) => match parse_admin_snapshot_path(path) {
            Ok((tenant, volume, name)) => match targets.get(&(tenant.clone(), volume.clone())) {
                Some(target) => match target.create_live_snapshot(name).await {
                    Ok(snapshot) => (
                        "200 OK",
                        format!(
                            "id={}\nmanifest={}\nname={}\n",
                            snapshot.id,
                            snapshot.manifest_id,
                            snapshot.name.as_deref().unwrap_or("-")
                        ),
                    ),
                    Err(error) => (
                        "500 Internal Server Error",
                        format!("snapshot create failed: {error}\n"),
                    ),
                },
                None => (
                    "404 Not Found",
                    format!("no live writable volume {tenant}/{volume}\n"),
                ),
            },
            Err(error) => ("400 Bad Request", format!("{error}\n")),
        },
        _ => ("404 Not Found", "not found\n".to_string()),
    };
    write_http_response(&mut stream, status, "text/plain; charset=utf-8", body).await
}

async fn serve_admin(listen: String, targets: AdminTargets) -> std::io::Result<()> {
    let listener = TcpListener::bind(&listen).await?;
    tracing::info!(listen, "admin endpoint ready");
    loop {
        let (stream, peer) = listener.accept().await?;
        let targets = Arc::clone(&targets);
        tokio::spawn(async move {
            if let Err(error) = handle_admin_connection(stream, targets).await {
                tracing::debug!(%peer, "admin request failed: {error}");
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
        let clone_parent_prefixes = volume::clone_parent_prefixes(&control, &record).await?;
        planned.push((
            export.clone(),
            record,
            dek,
            tenant.rate_limits,
            clone_parent_prefixes,
        ));
    }
    control.close().await.context("closing control-plane DB")?;

    let mut writable_volumes = Vec::new();
    let mut snapshot_volumes = Vec::new();
    let mut metrics_targets = Vec::new();
    let mut servers = tokio::task::JoinSet::new();
    // One writable Volume per live (tenant, volume) — a SlateDB has exactly
    // one writer (DD-5). Snapshot exports are read-only DbReader backends
    // keyed by checkpoint id.
    let mut open_backends: HashMap<(String, String, Option<String>), Arc<dyn Vfs>> = HashMap::new();
    let mut open_writers: HashMap<(String, String), Arc<Volume>> = HashMap::new();
    let mut rate_limiters: HashMap<String, Arc<RateLimiter>> = HashMap::new();
    let distinct: std::collections::HashSet<(String, String)> = config
        .exports
        .iter()
        .filter(|e| e.snapshot.is_none())
        .map(|e| (e.tenant.clone(), e.volume.clone()))
        .collect();
    let share_count = distinct.len();
    for (export, record, dek, rate_limits, clone_parent_prefixes) in planned {
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
                    let snapshot_volume = SnapshotVolume::open(
                        &record,
                        dek,
                        Arc::clone(&object_store),
                        snapshot,
                        clone_parent_prefixes,
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "opening snapshot {snapshot} for {}/{}",
                            export.tenant, export.volume
                        )
                    })?;
                    metrics_targets.push(MetricsTarget::Snapshot {
                        tenant: export.tenant.clone(),
                        volume_name: export.volume.clone(),
                        snapshot_id: snapshot.clone(),
                        volume: Arc::clone(&snapshot_volume),
                    });
                    snapshot_volumes.push(Arc::clone(&snapshot_volume));
                    snapshot_volume
                } else {
                    let writer_key = (export.tenant.clone(), export.volume.clone());
                    match open_writers.get(&writer_key) {
                        Some(volume) => Arc::<Volume>::clone(volume),
                        None => {
                            let mut caches = VolumeCaches::from_config(
                                &config.cache,
                                &config.slatedb,
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
                            metrics_targets.push(MetricsTarget::Writable {
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
                let tls = match (&export.p9_tls_cert, &export.p9_tls_key) {
                    (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
                    (None, None) => None,
                    _ => anyhow::bail!(
                        "9P export {}/{} must set both p9_tls_cert and p9_tls_key, or neither",
                        export.tenant,
                        export.volume
                    ),
                };
                if tls.is_some() {
                    tracing::info!(
                        tenant = export.tenant,
                        volume = export.volume,
                        snapshot = export.snapshot.as_deref().unwrap_or("-"),
                        listen = export.listen,
                        token_required = token.is_some(),
                        "TLS-wrapped 9P export ready; connect with a TLS-capable 9P client or tunnel"
                    );
                } else {
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
                }
                servers.spawn(async move {
                    match tls {
                        Some((cert, key)) => {
                            slatefs_9p::serve_export_tls_with_allowlist_and_rate_limit(
                                volume,
                                export_name,
                                token,
                                allowed_clients,
                                rate_limiter,
                                &listen,
                                slatefs_9p::TlsIdentity {
                                    cert_path: cert,
                                    key_path: key,
                                },
                            )
                            .await
                        }
                        None => {
                            slatefs_9p::serve_export_with_allowlist_and_rate_limit(
                                volume,
                                export_name,
                                token,
                                allowed_clients,
                                rate_limiter,
                                &listen,
                            )
                            .await
                        }
                    }
                });
            }
        }
    }

    for (tenant, limiter) in &rate_limiters {
        metrics_targets.push(MetricsTarget::TenantRateLimiter {
            tenant: tenant.clone(),
            limiter: Arc::clone(limiter),
        });
    }

    if let Some(listen) = config.admin.listen.clone() {
        let targets = Arc::new(
            open_writers
                .iter()
                .map(|(key, volume)| (key.clone(), Arc::clone(volume)))
                .collect(),
        );
        servers.spawn(async move { serve_admin(listen, targets).await });
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

#[cfg(test)]
mod tests {
    use super::*;

    use slatefs_core::config::Compression;
    use slatefs_core::control::{ControlPlane, QuotaLimits};
    use slatefs_core::crypto::kms::StaticKms;
    use slatefs_core::crypto::{Cipher, Secret32};
    use slatefs_core::meta::inode::ROOT_INO;
    use slatefs_core::snapshot::SnapshotVolume;
    use slatefs_core::vfs::{Credentials, Vfs};

    fn create_opts() -> slatefs_core::volume::CreateVolumeOptions {
        slatefs_core::volume::CreateVolumeOptions {
            cipher: Cipher::Aes256Gcm,
            chunk_size: 4096,
            compression: Compression::Lz4,
            quota: QuotaLimits::default(),
            note: None,
        }
    }

    #[test]
    fn parses_admin_snapshot_path() {
        assert_eq!(
            parse_admin_snapshot_path("/snapshot/t/v?name=baseline%20one").unwrap(),
            (
                "t".to_string(),
                "v".to_string(),
                Some("baseline one".to_string())
            )
        );
        assert!(parse_admin_snapshot_path("/metrics").is_err());
        assert!(parse_admin_snapshot_path("/snapshot/t").is_err());
        assert!(parse_admin_snapshot_path("/snapshot/t/v?name=%zz").is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_snapshot_endpoint_creates_live_checkpoint() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms = Arc::new(StaticKms::new(Secret32::from_bytes([5; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), kms)
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        let record = slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        let dek = control.unwrap_volume_dek(&record).await.unwrap();
        let volume = Volume::open(&record, dek, Arc::clone(&object_store))
            .await
            .unwrap();
        let creds = Credentials::root();
        let file = volume
            .create(&creds, ROOT_INO, b"file", 0o644, true)
            .await
            .unwrap();
        volume
            .write(&creds, file.ino, 0, b"baseline")
            .await
            .unwrap();
        let writable_metrics = render_daemon_metrics(&[MetricsTarget::Writable {
            tenant: "t".to_string(),
            volume_name: "v".to_string(),
            recorder: Arc::new(AggregatingRecorder::default()),
            volume: Arc::clone(&volume),
        }]);
        assert!(
            writable_metrics.contains("slatefs_volume_degraded{tenant=\"t\",volume=\"v\"} 0"),
            "{writable_metrics}"
        );
        assert!(
            writable_metrics
                .contains("slatefs_writer_fencing_events_total{tenant=\"t\",volume=\"v\"} 0"),
            "{writable_metrics}"
        );
        assert!(
            writable_metrics.contains("slatefs_storage_errors_total{tenant=\"t\",volume=\"v\"} 0"),
            "{writable_metrics}"
        );
        assert!(
            writable_metrics.contains("slatefs_quota_bytes_used{tenant=\"t\",volume=\"v\"}"),
            "{writable_metrics}"
        );
        assert!(
            writable_metrics
                .contains("slatefs_quota_bytes_hard_limit{tenant=\"t\",volume=\"v\"} +Inf"),
            "{writable_metrics}"
        );
        assert!(
            writable_metrics
                .contains("slatefs_quota_inodes_hard_limit{tenant=\"t\",volume=\"v\"} +Inf"),
            "{writable_metrics}"
        );
        assert!(
            writable_metrics
                .contains("slatefs_quota_rejections_total{tenant=\"t\",volume=\"v\"} 0"),
            "{writable_metrics}"
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut targets = HashMap::new();
        targets.insert(("t".to_string(), "v".to_string()), Arc::clone(&volume));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_admin_connection(stream, Arc::new(targets))
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"POST /snapshot/t/v?name=admin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        server.await.unwrap();

        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        let snapshot_id = response
            .lines()
            .find_map(|line| line.strip_prefix("id="))
            .expect("snapshot id")
            .to_string();

        volume
            .write(&creds, file.ino, 0, b"latest!!")
            .await
            .unwrap();
        volume.flush().await.unwrap();

        let snapshot_dek = control.unwrap_volume_dek(&record).await.unwrap();
        let snapshot = SnapshotVolume::open(
            &record,
            snapshot_dek,
            Arc::clone(&object_store),
            &snapshot_id,
            Vec::new(),
        )
        .await
        .unwrap();
        let attr = snapshot.lookup(&creds, ROOT_INO, b"file").await.unwrap();
        let bytes = snapshot
            .read(&creds, attr.ino, 0, attr.size as u32)
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), b"baseline");
        let metrics = render_daemon_metrics(&[MetricsTarget::Snapshot {
            tenant: "t".to_string(),
            volume_name: "v".to_string(),
            snapshot_id: snapshot_id.clone(),
            volume: Arc::clone(&snapshot),
        }]);
        assert!(
            metrics.contains(&format!(
                "slatefs_block_decode_failures_total{{tenant=\"t\",volume=\"v\",snapshot=\"{snapshot_id}\"}} 0"
            )),
            "{metrics}"
        );
        snapshot.shutdown().await.unwrap();
        volume.shutdown().await.unwrap();
        control.close().await.unwrap();
    }

    #[test]
    fn renders_tenant_rate_limit_rejections() {
        let limiter = Arc::new(RateLimiter::new(RateLimits {
            ops_per_second: Some(0),
            bytes_per_second: None,
        }));
        assert!(limiter.check(0).is_err());

        let metrics = render_daemon_metrics(&[MetricsTarget::TenantRateLimiter {
            tenant: "t".to_string(),
            limiter,
        }]);

        assert!(
            metrics.contains("slatefs_rate_limit_rejections_total{tenant=\"t\"} 1"),
            "{metrics}"
        );
    }

    #[test]
    fn derives_cache_tier_hit_miss_counters() {
        let engine_samples = vec![
            PrometheusSample::new(
                SLATEDB_DB_CACHE_ACCESS_COUNT,
                [
                    ("tenant", "t"),
                    ("volume", "v"),
                    ("entry_kind", "data_block"),
                    ("result", "hit"),
                ],
                3.0,
            ),
            PrometheusSample::new(
                SLATEDB_DB_CACHE_ACCESS_COUNT,
                [
                    ("tenant", "t"),
                    ("volume", "v"),
                    ("entry_kind", "index"),
                    ("result", "miss"),
                ],
                2.0,
            ),
            PrometheusSample::new(
                SLATEDB_OBJECT_STORE_CACHE_PART_ACCESS_COUNT,
                [("tenant", "t"), ("volume", "v")],
                5.0,
            ),
            PrometheusSample::new(
                SLATEDB_OBJECT_STORE_CACHE_PART_HIT_COUNT,
                [("tenant", "t"), ("volume", "v")],
                2.0,
            ),
        ];

        let metrics = render_prometheus(&cache_tier_samples("t", "v", &engine_samples));

        assert!(
            metrics.contains(
                "slatefs_cache_tier_access_total{tenant=\"t\",volume=\"v\",tier=\"ram\",result=\"hit\"} 3"
            ),
            "{metrics}"
        );
        assert!(
            metrics.contains(
                "slatefs_cache_tier_access_total{tenant=\"t\",volume=\"v\",tier=\"ram\",result=\"miss\"} 2"
            ),
            "{metrics}"
        );
        assert!(
            metrics.contains(
                "slatefs_cache_tier_access_total{tenant=\"t\",volume=\"v\",tier=\"disk\",result=\"hit\"} 2"
            ),
            "{metrics}"
        );
        assert!(
            metrics.contains(
                "slatefs_cache_tier_access_total{tenant=\"t\",volume=\"v\",tier=\"disk\",result=\"miss\"} 3"
            ),
            "{metrics}"
        );
    }
}
