//! slatefsd — serves SlateFS volumes over NFSv3 and 9P2000.L.
//!
//! Startup: read config → open control plane just long enough to resolve
//! exports, DEKs, and the fh-HMAC key → close it (so the CLI can use the
//! control DB while the daemon runs) → open volumes → one listener per export
//! (DD-10).

use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use slatedb::admin::AdminBuilder;
use slatedb::object_store::ObjectStore;
use slatefs_core::block::{
    BlockDev, BlockVolume, ReadOnlyBlockDev, SnapshotBlockVolume, StrictSyncBlockDev,
};
use slatefs_core::config::{
    AdminConfig, AtimeMode, ClientAddrRule, Config, ExportConfig, ExportProtocol, NbdSyncMode,
    SquashMode, validate_export_volume_kind,
};
use slatefs_core::control::{
    AuditAction, AuditActor, AuditDetailValue, AuditOutcome, AuditPlane, AuditQuery, AuditRecord,
    AuditScope, ControlPlane, ControlReader, ExportRecord, QuotaLimits, SnapshotRetentionPolicy,
    TenantRecord, VolumePlacementRecord, VolumeRecord,
};
use slatefs_core::crypto::kms;
use slatefs_core::meta::superblock::VolumeKind;
use slatefs_core::metrics::{AggregatingRecorder, PrometheusSample, render_prometheus};
use slatefs_core::rate::{RateLimiter, RateLimits};
use slatefs_core::snapshot::SnapshotVolume;
use slatefs_core::store;
use slatefs_core::vfs::Vfs;
use slatefs_core::volume::{self, Volume, VolumeCaches};
use slatefs_nbd::NbdShutdownHandle;
use slatefs_nfs::{NFSTcp, NfsExportRuntime, QuotaRejectionAudit, SquashPolicy};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tracing::Instrument;
use x509_parser::{extensions::GeneralName, parse_x509_certificate, x509::X509Name};

type SharedServerConfig = Arc<RwLock<Arc<ServerConfig>>>;

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
    BlockWritable {
        tenant: String,
        volume_name: String,
        volume: Arc<BlockVolume>,
    },
    BlockSnapshot {
        tenant: String,
        volume_name: String,
        snapshot_id: String,
    },
}

type AdminTargets = Arc<Mutex<HashMap<(String, String), Arc<Volume>>>>;
type AdminBlockTargets = Arc<Mutex<HashMap<(String, String), Arc<BlockVolume>>>>;

#[derive(Clone)]
struct ExportManagerTargets {
    metrics: Arc<Mutex<Vec<MetricsTarget>>>,
    admin: AdminTargets,
    admin_blocks: AdminBlockTargets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ExportSource {
    Config,
    Control,
}

impl ExportSource {
    fn as_str(self) -> &'static str {
        match self {
            ExportSource::Config => "config",
            ExportSource::Control => "control",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExportKey {
    source: ExportSource,
    id: String,
}

#[derive(Clone, PartialEq, Eq)]
struct DesiredExport {
    key: ExportKey,
    config: ExportConfig,
}

#[derive(Clone, Default)]
struct ExportMetrics {
    active: Arc<Mutex<HashMap<(ExportProtocol, ExportSource), usize>>>,
    reconcile_failures: Arc<AtomicU64>,
    snapshot_retention_deleted: Arc<Mutex<HashMap<(String, String), u64>>>,
    tls_reloads: Arc<Mutex<HashMap<String, u64>>>,
    tls_reload_failures: Arc<Mutex<HashMap<String, u64>>>,
    tls_expiry: Arc<Mutex<HashMap<String, i64>>>,
}

impl ExportMetrics {
    fn started(&self, protocol: ExportProtocol, source: ExportSource) {
        let mut active = self.active.lock().expect("export metrics poisoned");
        *active.entry((protocol, source)).or_insert(0) += 1;
    }

    fn stopped(&self, protocol: ExportProtocol, source: ExportSource) {
        let mut active = self.active.lock().expect("export metrics poisoned");
        let count = active.entry((protocol, source)).or_insert(0);
        *count = count.saturating_sub(1);
    }

    fn failure(&self) {
        self.reconcile_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot_retention_deleted(&self, tenant: &str, volume: &str, count: u64) {
        if count == 0 {
            return;
        }
        let mut deleted = self
            .snapshot_retention_deleted
            .lock()
            .expect("snapshot retention metrics poisoned");
        *deleted
            .entry((tenant.to_string(), volume.to_string()))
            .or_insert(0) += count;
    }

    fn register_tls_surface(&self, surface: &str, expiry_timestamp_seconds: i64) {
        self.tls_reloads
            .lock()
            .expect("TLS reload metrics poisoned")
            .entry(surface.to_string())
            .or_insert(0);
        self.tls_reload_failures
            .lock()
            .expect("TLS reload metrics poisoned")
            .entry(surface.to_string())
            .or_insert(0);
        self.tls_expiry
            .lock()
            .expect("TLS reload metrics poisoned")
            .insert(surface.to_string(), expiry_timestamp_seconds);
    }

    fn unregister_tls_surface(&self, surface: &str) {
        self.tls_reloads
            .lock()
            .expect("TLS reload metrics poisoned")
            .remove(surface);
        self.tls_reload_failures
            .lock()
            .expect("TLS reload metrics poisoned")
            .remove(surface);
        self.tls_expiry
            .lock()
            .expect("TLS reload metrics poisoned")
            .remove(surface);
    }

    fn tls_reload_success(&self, surface: &str, expiry_timestamp_seconds: i64) {
        *self
            .tls_reloads
            .lock()
            .expect("TLS reload metrics poisoned")
            .entry(surface.to_string())
            .or_insert(0) += 1;
        self.tls_expiry
            .lock()
            .expect("TLS reload metrics poisoned")
            .insert(surface.to_string(), expiry_timestamp_seconds);
    }

    fn tls_reload_failure(&self, surface: &str) {
        *self
            .tls_reload_failures
            .lock()
            .expect("TLS reload metrics poisoned")
            .entry(surface.to_string())
            .or_insert(0) += 1;
    }

    fn active_total(&self) -> usize {
        self.active
            .lock()
            .expect("export metrics poisoned")
            .values()
            .sum()
    }

    fn samples(&self) -> Vec<PrometheusSample> {
        let active = self.active.lock().expect("export metrics poisoned");
        let mut samples = Vec::new();
        for protocol in [ExportProtocol::Nfs, ExportProtocol::P9, ExportProtocol::Nbd] {
            for source in [ExportSource::Config, ExportSource::Control] {
                let value = active.get(&(protocol, source)).copied().unwrap_or(0);
                samples.push(PrometheusSample::new(
                    "slatefs_exports_active",
                    [
                        ("protocol", protocol_label(protocol)),
                        ("source", source.as_str()),
                    ],
                    value as f64,
                ));
            }
        }
        samples.push(PrometheusSample::new(
            "slatefs_export_reconcile_failures_total",
            std::iter::empty::<(&str, &str)>(),
            self.reconcile_failures.load(Ordering::Relaxed) as f64,
        ));
        let deleted = self
            .snapshot_retention_deleted
            .lock()
            .expect("snapshot retention metrics poisoned");
        for ((tenant, volume), value) in deleted.iter() {
            samples.push(PrometheusSample::new(
                "slatefs_snapshots_retention_deleted_total",
                [("tenant", tenant.as_str()), ("volume", volume.as_str())],
                *value as f64,
            ));
        }
        for (surface, value) in self
            .tls_reloads
            .lock()
            .expect("TLS reload metrics poisoned")
            .iter()
        {
            samples.push(PrometheusSample::new(
                "slatefs_tls_reloads_total",
                [("surface", surface.as_str())],
                *value as f64,
            ));
        }
        for (surface, value) in self
            .tls_reload_failures
            .lock()
            .expect("TLS reload metrics poisoned")
            .iter()
        {
            samples.push(PrometheusSample::new(
                "slatefs_tls_reload_failures_total",
                [("surface", surface.as_str())],
                *value as f64,
            ));
        }
        for (surface, value) in self
            .tls_expiry
            .lock()
            .expect("TLS reload metrics poisoned")
            .iter()
        {
            samples.push(PrometheusSample::new(
                "slatefs_tls_cert_expiry_timestamp_seconds",
                [("surface", surface.as_str())],
                *value as f64,
            ));
        }
        samples
    }
}

struct RunningExport {
    desired: DesiredExport,
    backend_key: (String, String, Option<String>),
    nbd_shutdown: Option<NbdShutdownHandle>,
    tls_reload: Option<Arc<TlsReloadTarget>>,
    task: tokio::task::JoinHandle<()>,
}

struct OpenBackend {
    vfs: Option<Arc<dyn Vfs>>,
    block: Option<Arc<dyn BlockDev>>,
    writable: Option<Arc<Volume>>,
    snapshot: Option<Arc<SnapshotVolume>>,
    block_writable: Option<Arc<BlockVolume>>,
    block_snapshot: Option<Arc<SnapshotBlockVolume>>,
    nbd_shutdowns: Arc<Mutex<Vec<NbdShutdownHandle>>>,
    ref_count: usize,
}

enum BackendExport {
    Fs(Arc<dyn Vfs>),
    Block {
        device: Arc<dyn BlockDev>,
        shutdowns: Arc<Mutex<Vec<NbdShutdownHandle>>>,
    },
}

struct ExportManager {
    object_store: Arc<dyn ObjectStore>,
    kms: Arc<dyn kms::Kms>,
    fh_key: slatefs_core::crypto::Secret32,
    cache: slatefs_core::config::CacheConfig,
    slatedb: slatefs_core::config::SlateDbConfig,
    config_exports: Arc<Vec<ConfigExportRecord>>,
    metrics: ExportMetrics,
    metrics_targets: Arc<Mutex<Vec<MetricsTarget>>>,
    admin_targets: AdminTargets,
    admin_block_targets: AdminBlockTargets,
    running: HashMap<ExportKey, RunningExport>,
    open_backends: HashMap<(String, String, Option<String>), OpenBackend>,
    rate_limiters: HashMap<String, Arc<RateLimiter>>,
    live_share_count: usize,
}

const CACHE_TIER_ACCESS_TOTAL: &str = "slatefs_cache_tier_access_total";
const SLATEDB_DB_CACHE_ACCESS_COUNT: &str = "slatefs_slatedb.db_cache.access_count";
const SLATEDB_OBJECT_STORE_CACHE_PART_ACCESS_COUNT: &str =
    "slatefs_slatedb.object_store_cache.part_access_count";
const SLATEDB_OBJECT_STORE_CACHE_PART_HIT_COUNT: &str =
    "slatefs_slatedb.object_store_cache.part_hit_count";

fn protocol_label(protocol: ExportProtocol) -> &'static str {
    match protocol {
        ExportProtocol::Nfs => "nfs",
        ExportProtocol::P9 => "p9",
        ExportProtocol::Nbd => "nbd",
    }
}

fn tls_surface_for_export(key: &ExportKey) -> String {
    format!("p9:{}:{}", key.source.as_str(), key.id)
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

#[cfg(test)]
fn render_daemon_metrics(targets: &[MetricsTarget]) -> String {
    render_daemon_metrics_with_exports(targets, &ExportMetrics::default())
}

fn render_daemon_metrics_with_exports(
    targets: &[MetricsTarget],
    export_metrics: &ExportMetrics,
) -> String {
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
            MetricsTarget::BlockWritable {
                tenant,
                volume_name,
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
                samples.push(PrometheusSample::new(
                    "slatefs_quota_bytes_used",
                    labels,
                    volume.quota_usage().0 as f64,
                ));
                samples.push(PrometheusSample::new(
                    "slatefs_quota_bytes_hard_limit",
                    labels,
                    hard_limit_value(volume.quota_hard_limits().0),
                ));
            }
            MetricsTarget::BlockSnapshot {
                tenant,
                volume_name,
                snapshot_id,
            } => {
                samples.push(PrometheusSample::new(
                    "slatefs_block_snapshot_exports_active",
                    [
                        ("tenant", tenant.as_str()),
                        ("volume", volume_name.as_str()),
                        ("snapshot", snapshot_id.as_str()),
                    ],
                    1.0,
                ));
            }
        }
    }
    samples.extend(slatefs_nbd::prometheus_samples());
    samples.extend(export_metrics.samples());
    render_prometheus(&samples)
}

async fn write_http_response<W>(
    stream: &mut W,
    status: &str,
    content_type: &str,
    body: String,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_http_response_with_headers(stream, status, content_type, &[], body).await
}

async fn write_http_response_with_headers<W>(
    stream: &mut W,
    status: &str,
    content_type: &str,
    headers: &[(&str, String)],
    body: String,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    for (name, value) in headers {
        stream
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .await?;
    }
    stream.write_all(format!("\r\n{body}").as_bytes()).await?;
    stream.shutdown().await
}

async fn handle_metrics_connection(
    mut stream: TcpStream,
    targets: Arc<Mutex<Vec<MetricsTarget>>>,
    export_metrics: ExportMetrics,
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
        ("200 OK", "text/plain; version=0.0.4; charset=utf-8", {
            let targets = targets.lock().expect("metrics targets poisoned").clone();
            render_daemon_metrics_with_exports(&targets, &export_metrics)
        })
    } else {
        (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        )
    };

    write_http_response(&mut stream, status, content_type, body).await
}

async fn serve_metrics(
    listen: String,
    targets: Arc<Mutex<Vec<MetricsTarget>>>,
    export_metrics: ExportMetrics,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&listen).await?;
    tracing::info!(listen, "metrics endpoint ready at /metrics");
    loop {
        let (stream, peer) = listener.accept().await?;
        let targets = Arc::clone(&targets);
        let export_metrics = export_metrics.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_metrics_connection(stream, targets, export_metrics).await {
                tracing::debug!(%peer, "metrics scrape failed: {error}");
            }
        });
    }
}

const REQUEST_ID_HEADER: &str = "X-Request-Id";
const ADMIN_API_PREFIX: &str = "/admin/v1";
const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 1_000;
const SLATEDB_VERSION: &str = "0.14.1";
static RUSTLS_PROVIDER: Once = Once::new();

#[derive(Clone)]
enum AdminControl {
    Available(Arc<ControlReader>),
    Unavailable(String),
}

#[derive(Clone)]
struct AdminState {
    targets: AdminTargets,
    block_targets: AdminBlockTargets,
    control: AdminControl,
    object_store: Arc<dyn ObjectStore>,
    kms: Arc<dyn kms::Kms>,
    config_exports: Arc<Vec<ConfigExportRecord>>,
    export_metrics: ExportMetrics,
    started_at: Instant,
    export_count: usize,
    snapshot_export_count: usize,
    auth_token: Option<String>,
    allow_cert_auth: bool,
    node_id: Option<String>,
}

struct AdminHttpRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    request_id: String,
    peer: Option<SocketAddr>,
    cert_principal: Option<String>,
    authenticated_principal: Option<String>,
    body: String,
}

struct AdminHttpResponse {
    status: u16,
    content_type: &'static str,
    body: String,
    headers: Vec<(&'static str, String)>,
}

#[derive(Debug)]
struct AdminError {
    status: u16,
    message: String,
}

#[derive(Clone)]
struct ConfigExportRecord {
    id: String,
    export: ExportConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportCreateRequest {
    tenant: String,
    volume: String,
    #[serde(default)]
    snapshot: Option<String>,
    listen: String,
    #[serde(default)]
    allowed_clients: Vec<ClientAddrRule>,
    #[serde(default)]
    protocol: ExportProtocol,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    sync: NbdSyncMode,
    #[serde(default)]
    nbd_tls_cert: Option<std::path::PathBuf>,
    #[serde(default)]
    nbd_tls_key: Option<std::path::PathBuf>,
    #[serde(default)]
    nbd_tls_client_ca: Option<std::path::PathBuf>,
    #[serde(default)]
    p9_token: Option<String>,
    #[serde(default)]
    p9_tls_cert: Option<std::path::PathBuf>,
    #[serde(default)]
    p9_tls_key: Option<std::path::PathBuf>,
    #[serde(default)]
    squash: SquashMode,
    #[serde(default)]
    atime: AtimeMode,
    #[serde(default = "default_anon_id_json")]
    anon_uid: u32,
    #[serde(default = "default_anon_id_json")]
    anon_gid: u32,
    #[serde(default = "default_enabled_json")]
    enabled: bool,
}

impl ExportCreateRequest {
    fn into_record(self, id: String) -> ExportRecord {
        ExportRecord::from_config(
            id,
            ExportConfig {
                tenant: self.tenant,
                volume: self.volume,
                snapshot: self.snapshot,
                listen: self.listen,
                allowed_clients: self.allowed_clients,
                protocol: self.protocol,
                read_only: self.read_only,
                sync: self.sync,
                nbd_tls_cert: self.nbd_tls_cert,
                nbd_tls_key: self.nbd_tls_key,
                nbd_tls_client_ca: self.nbd_tls_client_ca,
                p9_token: self.p9_token,
                p9_tls_cert: self.p9_tls_cert,
                p9_tls_key: self.p9_tls_key,
                squash: self.squash,
                atime: self.atime,
                anon_uid: self.anon_uid,
                anon_gid: self.anon_gid,
            },
            self.enabled,
        )
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportPatchRequest {
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    volume: Option<String>,
    #[serde(default)]
    snapshot: Option<Option<String>>,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    allowed_clients: Option<Vec<ClientAddrRule>>,
    #[serde(default)]
    protocol: Option<ExportProtocol>,
    #[serde(default)]
    read_only: Option<bool>,
    #[serde(default)]
    sync: Option<NbdSyncMode>,
    #[serde(default)]
    nbd_tls_cert: Option<Option<std::path::PathBuf>>,
    #[serde(default)]
    nbd_tls_key: Option<Option<std::path::PathBuf>>,
    #[serde(default)]
    nbd_tls_client_ca: Option<Option<std::path::PathBuf>>,
    #[serde(default)]
    p9_token: Option<Option<String>>,
    #[serde(default)]
    p9_tls_cert: Option<Option<std::path::PathBuf>>,
    #[serde(default)]
    p9_tls_key: Option<Option<std::path::PathBuf>>,
    #[serde(default)]
    squash: Option<SquashMode>,
    #[serde(default)]
    atime: Option<AtimeMode>,
    #[serde(default)]
    anon_uid: Option<u32>,
    #[serde(default)]
    anon_gid: Option<u32>,
    #[serde(default)]
    enabled: Option<bool>,
}

impl ExportPatchRequest {
    fn apply_to(self, record: &mut ExportRecord) {
        if let Some(tenant) = self.tenant {
            record.tenant = tenant;
        }
        if let Some(volume) = self.volume {
            record.volume = volume;
        }
        if let Some(snapshot) = self.snapshot {
            record.snapshot = snapshot;
        }
        if let Some(listen) = self.listen {
            record.listen = listen;
        }
        if let Some(allowed_clients) = self.allowed_clients {
            record.allowed_clients = allowed_clients;
        }
        if let Some(protocol) = self.protocol {
            record.protocol = protocol;
        }
        if let Some(read_only) = self.read_only {
            record.read_only = read_only;
        }
        if let Some(sync) = self.sync {
            record.sync = sync;
        }
        if let Some(nbd_tls_cert) = self.nbd_tls_cert {
            record.nbd_tls_cert = nbd_tls_cert;
        }
        if let Some(nbd_tls_key) = self.nbd_tls_key {
            record.nbd_tls_key = nbd_tls_key;
        }
        if let Some(nbd_tls_client_ca) = self.nbd_tls_client_ca {
            record.nbd_tls_client_ca = nbd_tls_client_ca;
        }
        if let Some(p9_token) = self.p9_token {
            record.p9_token = p9_token;
        }
        if let Some(p9_tls_cert) = self.p9_tls_cert {
            record.p9_tls_cert = p9_tls_cert;
        }
        if let Some(p9_tls_key) = self.p9_tls_key {
            record.p9_tls_key = p9_tls_key;
        }
        if let Some(squash) = self.squash {
            record.squash = squash;
        }
        if let Some(atime) = self.atime {
            record.atime = atime;
        }
        if let Some(anon_uid) = self.anon_uid {
            record.anon_uid = anon_uid;
        }
        if let Some(anon_gid) = self.anon_gid {
            record.anon_gid = anon_gid;
        }
        if let Some(enabled) = self.enabled {
            record.enabled = enabled;
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRetentionPatchRequest {
    #[serde(default)]
    keep_last: Option<Option<u32>>,
    #[serde(default)]
    max_age_secs: Option<Option<u64>>,
    #[serde(default)]
    clear: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuotaPatchRequest {
    #[serde(default)]
    bytes_soft: Option<Option<u64>>,
    #[serde(default)]
    bytes_hard: Option<Option<u64>>,
    #[serde(default, alias = "bytes_grace_until")]
    bytes_grace: Option<Option<u64>>,
    #[serde(default)]
    inodes_soft: Option<Option<u64>>,
    #[serde(default)]
    inodes_hard: Option<Option<u64>>,
    #[serde(default, alias = "inodes_grace_until")]
    inodes_grace: Option<Option<u64>>,
}

impl QuotaPatchRequest {
    fn is_empty(&self) -> bool {
        self.bytes_soft.is_none()
            && self.bytes_hard.is_none()
            && self.bytes_grace.is_none()
            && self.inodes_soft.is_none()
            && self.inodes_hard.is_none()
            && self.inodes_grace.is_none()
    }

    fn apply_to(self, quota: &mut QuotaLimits) {
        if let Some(value) = self.bytes_soft {
            quota.bytes.soft = value;
        }
        if let Some(value) = self.bytes_hard {
            quota.bytes.hard = value;
        }
        if let Some(value) = self.bytes_grace {
            quota.bytes.grace_until = value;
        }
        if let Some(value) = self.inodes_soft {
            quota.inodes.soft = value;
        }
        if let Some(value) = self.inodes_hard {
            quota.inodes.hard = value;
        }
        if let Some(value) = self.inodes_grace {
            quota.inodes.grace_until = value;
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRatePatchRequest {
    #[serde(default)]
    ops_per_second: Option<Option<u64>>,
    #[serde(default)]
    bytes_per_second: Option<Option<u64>>,
}

impl TenantRatePatchRequest {
    fn is_empty(&self) -> bool {
        self.ops_per_second.is_none() && self.bytes_per_second.is_none()
    }

    fn apply_to(self, limits: &mut RateLimits) {
        if let Some(value) = self.ops_per_second {
            limits.ops_per_second = value;
        }
        if let Some(value) = self.bytes_per_second {
            limits.bytes_per_second = value;
        }
    }
}

fn default_enabled_json() -> bool {
    true
}

fn default_anon_id_json() -> u32 {
    65534
}

impl AdminState {
    fn control_reader(&self) -> Result<Arc<ControlReader>, AdminError> {
        match &self.control {
            AdminControl::Available(reader) => Ok(Arc::clone(reader)),
            AdminControl::Unavailable(error) => Err(AdminError {
                status: 503,
                message: format!("control plane unavailable: {error}"),
            }),
        }
    }

    async fn control_writer(&self) -> Result<ControlPlane, AdminError> {
        ControlPlane::open(Arc::clone(&self.object_store), Arc::clone(&self.kms))
            .await
            .map_err(core_error)
    }
}

impl AdminHttpResponse {
    fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into(),
            headers: Vec::new(),
        }
    }

    fn json(status: u16, body: Value) -> Self {
        let body = serde_json::to_string(&body).unwrap_or_else(|error| {
            format!(
                r#"{{"error":{{"code":"serialization_error","message":"{error}","request_id":""}}}}"#
            )
        });
        Self {
            status,
            content_type: "application/json",
            body,
            headers: Vec::new(),
        }
    }

    fn json_pretty(status: u16, body: Value) -> Self {
        let body = serde_json::to_string_pretty(&body).unwrap_or_else(|error| {
            format!(
                r#"{{"error":{{"code":"serialization_error","message":"{error}","request_id":""}}}}"#
            )
        });
        Self {
            status,
            content_type: "application/json",
            body,
            headers: Vec::new(),
        }
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
    let query = parse_query_string(query).map_err(|_| "invalid query string")?;
    Ok((
        percent_decode(tenant)?.to_string(),
        percent_decode(volume)?.to_string(),
        query.get("name").filter(|name| !name.is_empty()).cloned(),
    ))
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

fn parse_query_string(raw: &str) -> Result<HashMap<String, String>, &'static str> {
    let mut query = HashMap::new();
    for part in raw.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        query.insert(percent_decode(key)?, percent_decode(value)?);
    }
    Ok(query)
}

fn request_id_from_headers(headers: &HashMap<String, String>) -> Option<String> {
    let value = headers.get("x-request-id")?.trim();
    (!value.is_empty() && value.len() <= 128 && value.is_ascii()).then(|| value.to_string())
}

fn generated_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn status_line(status: u16) -> &'static str {
    match status {
        200 => "200 OK",
        201 => "201 Created",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        404 => "404 Not Found",
        405 => "405 Method Not Allowed",
        409 => "409 Conflict",
        500 => "500 Internal Server Error",
        503 => "503 Service Unavailable",
        _ => "500 Internal Server Error",
    }
}

fn admin_error_code(status: u16) -> &'static str {
    match status {
        400 => "bad_request",
        401 => "unauthorized",
        404 => "not_found",
        405 => "method_not_allowed",
        409 => "conflict",
        503 => "service_unavailable",
        500 => "server_error",
        _ if (400..500).contains(&status) => "client_error",
        _ if status >= 500 => "server_error",
        _ => "error",
    }
}

fn json_error_response(
    status: u16,
    message: impl Into<String>,
    request_id: &str,
) -> AdminHttpResponse {
    AdminHttpResponse::json(
        status,
        json!({
            "error": {
                "code": admin_error_code(status),
                "message": message.into(),
                "request_id": request_id,
            }
        }),
    )
}

fn core_error(error: slatefs_core::error::Error) -> AdminError {
    let status = match &error {
        slatefs_core::error::Error::NotFound { .. } => 404,
        slatefs_core::error::Error::AlreadyExists { .. } => 409,
        slatefs_core::error::Error::Invalid { .. } | slatefs_core::error::Error::Config(_) => 400,
        _ => 500,
    };
    AdminError {
        status,
        message: error.to_string(),
    }
}

fn bad_request(message: impl Into<String>) -> AdminError {
    AdminError {
        status: 400,
        message: message.into(),
    }
}

fn not_found(message: impl Into<String>) -> AdminError {
    AdminError {
        status: 404,
        message: message.into(),
    }
}

fn internal_error(message: impl Into<String>) -> AdminError {
    AdminError {
        status: 500,
        message: message.into(),
    }
}

fn page_limit(query: &HashMap<String, String>) -> Result<usize, AdminError> {
    let Some(raw) = query.get("limit") else {
        return Ok(DEFAULT_PAGE_LIMIT);
    };
    let parsed = raw
        .parse::<usize>()
        .map_err(|error| bad_request(format!("invalid limit: {error}")))?;
    Ok(if parsed == 0 {
        DEFAULT_PAGE_LIMIT
    } else {
        parsed.min(MAX_PAGE_LIMIT)
    })
}

fn query_bool(query: &HashMap<String, String>, key: &str, default: bool) -> bool {
    query
        .get(key)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn paginate_by<T, F>(
    items: Vec<T>,
    page_token: Option<&str>,
    limit: usize,
    id: F,
) -> (Vec<T>, Option<String>)
where
    F: Fn(&T) -> String,
{
    let mut started = page_token.is_none();
    let mut page = Vec::new();
    let mut next = None;
    for item in items {
        let item_id = id(&item);
        if !started {
            if page_token == Some(item_id.as_str()) {
                started = true;
            }
            continue;
        }
        if page.len() == limit {
            next = page.last().map(&id);
            break;
        }
        page.push(item);
    }
    (page, next)
}

fn token_matches(expected: &str, presented: &str) -> bool {
    let expected = expected.as_bytes();
    let presented = presented.as_bytes();
    let max_len = expected.len().max(presented.len());
    let mut diff = expected.len() ^ presented.len();
    for i in 0..max_len {
        let left = expected.get(i).copied().unwrap_or(0);
        let right = presented.get(i).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }
    diff == 0
}

fn bearer_token_from_headers(headers: &HashMap<String, String>) -> Option<&str> {
    let header = headers.get("authorization")?;
    let (scheme, token) = header.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token)
}

fn admin_principal_from_headers(headers: &HashMap<String, String>) -> Option<String> {
    let value = headers.get("x-admin-principal")?.trim();
    (!value.is_empty() && value.len() <= 256).then(|| value.to_string())
}

fn cert_auth_principal(request: &AdminHttpRequest) -> Option<String> {
    request
        .cert_principal
        .as_ref()
        .map(|principal| format!("cert:{principal}"))
}

fn authenticate_admin_request(
    state: &AdminState,
    request: &AdminHttpRequest,
) -> Result<Option<String>, AdminError> {
    if let Some(expected) = state.auth_token.as_deref() {
        let Some(presented) = bearer_token_from_headers(&request.headers) else {
            if state.allow_cert_auth
                && let Some(principal) = cert_auth_principal(request)
            {
                return Ok(Some(principal));
            }
            return Err(AdminError {
                status: 401,
                message: "missing bearer token".to_string(),
            });
        };
        if token_matches(expected, presented) {
            return Ok(admin_principal_from_headers(&request.headers));
        }
        if state.allow_cert_auth
            && let Some(principal) = cert_auth_principal(request)
        {
            return Ok(Some(principal));
        }
        return Err(AdminError {
            status: 401,
            message: "invalid bearer token".to_string(),
        });
    }

    if state.allow_cert_auth {
        return cert_auth_principal(request)
            .map(Some)
            .ok_or_else(|| AdminError {
                status: 401,
                message: "missing client certificate".to_string(),
            });
    }

    Ok(None)
}

async fn read_admin_request<R>(
    stream: &mut R,
    peer: Option<SocketAddr>,
) -> Result<Option<AdminHttpRequest>, AdminError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    let n = match read {
        Ok(result) => result.map_err(|error| AdminError {
            status: 400,
            message: format!("read failed: {error}"),
        })?,
        Err(_) => return Ok(None),
    };
    if n == 0 {
        return Ok(None);
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let (head, body) = request.split_once("\r\n\r\n").unwrap_or((&request, ""));
    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| bad_request("missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| bad_request("missing method"))?
        .to_string();
    let target = request_parts
        .next()
        .ok_or_else(|| bad_request("missing request target"))?
        .to_string();
    let mut headers = HashMap::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let (path, raw_query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    let request_id = request_id_from_headers(&headers).unwrap_or_else(generated_request_id);
    let query = parse_query_string(raw_query).map_err(bad_request)?;
    Ok(Some(AdminHttpRequest {
        method,
        path: path.to_string(),
        query,
        headers,
        request_id,
        peer,
        cert_principal: None,
        authenticated_principal: None,
        body: body.to_string(),
    }))
}

fn route_segments(path: &str) -> Result<Vec<String>, AdminError> {
    path.trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| percent_decode(segment).map_err(bad_request))
        .collect()
}

async fn create_live_snapshot_response(
    state: &AdminState,
    tenant: String,
    volume: String,
    name: Option<String>,
    json_body: bool,
) -> Result<AdminHttpResponse, AdminError> {
    let target = state
        .targets
        .lock()
        .expect("admin targets poisoned")
        .get(&(tenant.clone(), volume.clone()))
        .cloned()
        .ok_or_else(|| not_found(format!("no live writable volume {tenant}/{volume}")))?;
    let snapshot = target
        .create_live_snapshot(name)
        .await
        .map_err(core_error)?;
    if json_body {
        Ok(AdminHttpResponse::json(
            200,
            json!({
                "snapshot": {
                    "id": snapshot.id,
                    "manifest_id": snapshot.manifest_id,
                    "name": snapshot.name,
                }
            }),
        ))
    } else {
        Ok(AdminHttpResponse::text(
            200,
            format!(
                "id={}\nmanifest={}\nname={}\n",
                snapshot.id,
                snapshot.manifest_id,
                snapshot.name.as_deref().unwrap_or("-")
            ),
        ))
    }
}

fn rate_limits_json(record: &TenantRecord) -> Value {
    json!({
        "ops_per_second": record.rate_limits.ops_per_second,
        "bytes_per_second": record.rate_limits.bytes_per_second,
    })
}

fn quota_limits_json(record: &VolumeRecord) -> Value {
    json!({
        "bytes": {
            "soft": record.quota.bytes.soft,
            "hard": record.quota.bytes.hard,
            "grace_until": record.quota.bytes.grace_until,
        },
        "inodes": {
            "soft": record.quota.inodes.soft,
            "hard": record.quota.inodes.hard,
            "grace_until": record.quota.inodes.grace_until,
        },
    })
}

fn quota_json(record: &VolumeRecord, targets: &AdminTargets) -> Value {
    let quota_usage = targets
        .lock()
        .expect("admin targets poisoned")
        .get(&(record.tenant.clone(), record.name.clone()))
        .map(|volume| {
            let (bytes, inodes) = volume.quota_usage();
            json!({ "bytes": bytes, "inodes": inodes })
        })
        .unwrap_or(Value::Null);
    json!({
        "limits": quota_limits_json(record),
        "usage": quota_usage,
    })
}

fn snapshot_retention_json(policy: Option<&SnapshotRetentionPolicy>) -> Value {
    policy
        .map(|policy| {
            json!({
                "tenant": policy.tenant,
                "volume": policy.volume,
                "keep_last": policy.keep_last,
                "max_age_secs": policy.max_age_secs,
                "updated_at": policy.updated_at,
                "named_snapshots_exempt": false,
                "active_clone_parent_behavior": "skip_pinned_checkpoints_or_legacy_volume",
            })
        })
        .unwrap_or(Value::Null)
}

fn placement_json(placement: Option<VolumePlacementRecord>) -> Result<Value, AdminError> {
    placement
        .map(|placement| {
            serde_json::to_value(placement).map_err(|error| internal_error(error.to_string()))
        })
        .transpose()
        .map(|value| value.unwrap_or(Value::Null))
}

fn volume_json(
    record: VolumeRecord,
    placement: Option<VolumePlacementRecord>,
    targets: &AdminTargets,
    block_targets: &AdminBlockTargets,
) -> Result<Value, AdminError> {
    let quota = quota_json(&record, targets);
    let (kind, size_bytes, allocated_bytes) = match record.kind {
        VolumeKind::Filesystem => ("filesystem", Value::Null, Value::Null),
        VolumeKind::Block { size_bytes } => {
            let allocated = block_targets
                .lock()
                .expect("admin block targets poisoned")
                .get(&(record.tenant.clone(), record.name.clone()))
                .map(|volume| json!(volume.quota_usage().0))
                .unwrap_or(Value::Null);
            ("block", json!(size_bytes), allocated)
        }
    };
    Ok(json!({
        "tenant": record.tenant,
        "name": record.name,
        "state": format!("{:?}", record.state),
        "kind": kind,
        "size_bytes": size_bytes,
        "allocated_bytes": allocated_bytes,
        "fsid": format!("{:016x}", record.fsid),
        "cipher": record.cipher.to_string(),
        "chunk_size": record.chunk_size,
        "compression": format!("{:?}", record.compression),
        "quota": quota,
        "clone_parent": record.clone_parent,
        "placement": placement_json(placement)?,
        "created_at": record.created_at,
    }))
}

fn export_config_json(id: &str, source: &str, export: &ExportConfig, enabled: bool) -> Value {
    json!({
        "id": id,
        "source": source,
        "tenant": export.tenant,
        "volume": export.volume,
        "snapshot": export.snapshot,
        "protocol": export.protocol,
        "listen": export.listen,
        "allowed_clients": export
            .allowed_clients
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "squash": export.squash,
        "atime": export.atime,
        "anon_uid": export.anon_uid,
        "anon_gid": export.anon_gid,
        "p9_token_set": export.p9_token.is_some(),
        "p9_tls_cert": export.p9_tls_cert.as_deref().map(|path| path.display().to_string()),
        "p9_tls_key": export.p9_tls_key.as_deref().map(|path| path.display().to_string()),
        "nbd_tls_cert": export.nbd_tls_cert.as_deref().map(|path| path.display().to_string()),
        "nbd_tls_key": export.nbd_tls_key.as_deref().map(|path| path.display().to_string()),
        "nbd_tls_client_ca": export.nbd_tls_client_ca.as_deref().map(|path| path.display().to_string()),
        "enabled": enabled,
        "read_only": export.effective_read_only(),
        "sync": export.sync,
    })
}

fn export_record_json(record: &ExportRecord) -> Value {
    let mut value = export_config_json(&record.id, "control", &record.to_config(), record.enabled);
    value["created_at"] = json!(record.created_at);
    value["updated_at"] = json!(record.updated_at);
    value
}

fn parse_json_body<T: for<'de> Deserialize<'de>>(
    request: &AdminHttpRequest,
) -> Result<T, AdminError> {
    if request.body.trim().is_empty() {
        return Err(bad_request("request body must be JSON"));
    }
    serde_json::from_str(&request.body)
        .map_err(|error| bad_request(format!("invalid JSON: {error}")))
}

fn admin_actor(request: &AdminHttpRequest) -> AuditActor {
    AuditActor {
        plane: AuditPlane::Admin,
        principal: request.authenticated_principal.clone(),
        source_ip: request.peer.map(|addr| addr.ip().to_string()),
        client_agent: request.headers.get("user-agent").cloned(),
    }
}

async fn append_export_audit(
    control: &ControlPlane,
    request: &AdminHttpRequest,
    action: AuditAction,
    record: &ExportRecord,
) -> Result<(), AdminError> {
    let mut audit = AuditRecord::new(
        admin_actor(request),
        action,
        AuditScope {
            tenant: Some(record.tenant.clone()),
            volume: Some(record.volume.clone()),
            node: None,
        },
        request.request_id.clone(),
        AuditOutcome::Success,
    );
    audit.details.insert(
        "export_id".to_string(),
        slatefs_core::control::AuditDetailValue::String(record.id.clone()),
    );
    audit.details.insert(
        "listen".to_string(),
        slatefs_core::control::AuditDetailValue::String(record.listen.clone()),
    );
    audit.details.insert(
        "enabled".to_string(),
        slatefs_core::control::AuditDetailValue::Bool(record.enabled),
    );
    control
        .append_audit_record(audit)
        .await
        .map_err(core_error)?;
    Ok(())
}

async fn append_quota_audit(
    control: &ControlPlane,
    request: &AdminHttpRequest,
    record: &VolumeRecord,
) -> Result<(), AdminError> {
    let mut audit = AuditRecord::new(
        admin_actor(request),
        AuditAction::QuotaSet,
        AuditScope {
            tenant: Some(record.tenant.clone()),
            volume: Some(record.name.clone()),
            node: None,
        },
        request.request_id.clone(),
        AuditOutcome::Success,
    );
    audit.details.insert(
        "quota_limits".to_string(),
        AuditDetailValue::from(quota_limits_json(record)),
    );
    control
        .append_audit_record(audit)
        .await
        .map_err(core_error)?;
    Ok(())
}

async fn append_tenant_rate_audit(
    control: &ControlPlane,
    request: &AdminHttpRequest,
    record: &TenantRecord,
) -> Result<(), AdminError> {
    let mut audit = AuditRecord::new(
        admin_actor(request),
        AuditAction::TenantRateSet,
        AuditScope {
            tenant: Some(record.name.clone()),
            volume: None,
            node: None,
        },
        request.request_id.clone(),
        AuditOutcome::Success,
    );
    audit.details.insert(
        "rate_limits".to_string(),
        AuditDetailValue::from(rate_limits_json(record)),
    );
    control
        .append_audit_record(audit)
        .await
        .map_err(core_error)?;
    Ok(())
}

async fn list_tenants_response(
    state: &AdminState,
    request: &AdminHttpRequest,
) -> Result<AdminHttpResponse, AdminError> {
    let reader = state.control_reader()?;
    let tenants = reader.list_tenants().await.map_err(core_error)?;
    let limit = page_limit(&request.query)?;
    let (page, next) = paginate_by(
        tenants,
        request.query.get("page_token").map(String::as_str),
        limit,
        |tenant| tenant.name.clone(),
    );
    let mut out = Vec::with_capacity(page.len());
    for tenant in page {
        let volume_count = reader
            .list_volumes(&tenant.name)
            .await
            .map_err(core_error)?
            .len();
        out.push(json!({
            "name": tenant.name,
            "display_name": tenant.display_name,
            "state": format!("{:?}", tenant.state),
            "rate_limits": rate_limits_json(&tenant),
            "volume_count": volume_count,
            "created_at": tenant.created_at,
        }));
    }
    Ok(AdminHttpResponse::json(
        200,
        json!({ "tenants": out, "next_page_token": next }),
    ))
}

async fn list_volumes_response(
    state: &AdminState,
    request: &AdminHttpRequest,
    tenant: &str,
) -> Result<AdminHttpResponse, AdminError> {
    let reader = state.control_reader()?;
    reader.get_tenant(tenant).await.map_err(core_error)?;
    let volumes = reader.list_volumes(tenant).await.map_err(core_error)?;
    let limit = page_limit(&request.query)?;
    let (page, next) = paginate_by(
        volumes,
        request.query.get("page_token").map(String::as_str),
        limit,
        |volume| volume.name.clone(),
    );
    let mut out = Vec::with_capacity(page.len());
    for volume in page {
        let placement = reader
            .try_get_volume_placement(&volume.tenant, &volume.name)
            .await
            .map_err(core_error)?;
        out.push(volume_json(
            volume,
            placement,
            &state.targets,
            &state.block_targets,
        )?);
    }
    Ok(AdminHttpResponse::json(
        200,
        json!({ "volumes": out, "next_page_token": next }),
    ))
}

async fn get_volume_response(
    state: &AdminState,
    tenant: &str,
    volume: &str,
) -> Result<AdminHttpResponse, AdminError> {
    let reader = state.control_reader()?;
    let record = reader
        .get_volume(tenant, volume)
        .await
        .map_err(core_error)?;
    let placement = reader
        .try_get_volume_placement(tenant, volume)
        .await
        .map_err(core_error)?;
    Ok(AdminHttpResponse::json(
        200,
        json!({ "volume": volume_json(record, placement, &state.targets, &state.block_targets)? }),
    ))
}

async fn patch_volume_quota_response(
    state: &AdminState,
    request: &AdminHttpRequest,
    tenant: &str,
    volume: &str,
) -> Result<AdminHttpResponse, AdminError> {
    let body: QuotaPatchRequest = parse_json_body(request)?;
    if body.is_empty() {
        return Err(bad_request("provide at least one quota field"));
    }

    let control = state.control_writer().await?;
    let mut quota = control
        .get_volume(tenant, volume)
        .await
        .map_err(core_error)?
        .quota;
    body.apply_to(&mut quota);
    let record = control
        .set_volume_quota(tenant, volume, quota)
        .await
        .map_err(core_error)?;
    append_quota_audit(&control, request, &record).await?;
    control.close().await.map_err(core_error)?;
    Ok(AdminHttpResponse::json(
        200,
        json!({ "quota": quota_json(&record, &state.targets) }),
    ))
}

async fn patch_tenant_rate_response(
    state: &AdminState,
    request: &AdminHttpRequest,
    tenant: &str,
) -> Result<AdminHttpResponse, AdminError> {
    let body: TenantRatePatchRequest = parse_json_body(request)?;
    if body.is_empty() {
        return Err(bad_request("provide ops_per_second or bytes_per_second"));
    }

    let control = state.control_writer().await?;
    let mut limits = control
        .get_tenant(tenant)
        .await
        .map_err(core_error)?
        .rate_limits;
    body.apply_to(&mut limits);
    let record = control
        .set_tenant_rate_limits(tenant, limits)
        .await
        .map_err(core_error)?;
    append_tenant_rate_audit(&control, request, &record).await?;
    control.close().await.map_err(core_error)?;
    Ok(AdminHttpResponse::json(
        200,
        json!({ "rate_limits": rate_limits_json(&record) }),
    ))
}

async fn list_nodes_response(
    state: &AdminState,
    request: &AdminHttpRequest,
) -> Result<AdminHttpResponse, AdminError> {
    let reader = state.control_reader()?;
    let nodes = reader.list_daemon_nodes().await.map_err(core_error)?;
    let limit = page_limit(&request.query)?;
    let (page, next) = paginate_by(
        nodes,
        request.query.get("page_token").map(String::as_str),
        limit,
        |node| node.id.clone(),
    );
    let nodes = page
        .into_iter()
        .map(|node| serde_json::to_value(node).map_err(|error| internal_error(error.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AdminHttpResponse::json(
        200,
        json!({ "nodes": nodes, "next_page_token": next }),
    ))
}

async fn list_snapshots_response(
    state: &AdminState,
    request: &AdminHttpRequest,
    tenant: &str,
    volume_name: &str,
) -> Result<AdminHttpResponse, AdminError> {
    let reader = state.control_reader()?;
    let record = reader
        .get_volume(tenant, volume_name)
        .await
        .map_err(core_error)?;
    let snapshots = volume::list_snapshots_for_record(
        &record,
        Arc::clone(&state.object_store),
        request.query.get("name").map(String::as_str),
    )
    .await
    .map_err(core_error)?;
    let limit = page_limit(&request.query)?;
    let (page, next) = paginate_by(
        snapshots,
        request.query.get("page_token").map(String::as_str),
        limit,
        |snapshot| snapshot.id.clone(),
    );
    let snapshots = page
        .into_iter()
        .map(|snapshot| {
            json!({
                "id": snapshot.id,
                "manifest_id": snapshot.manifest_id,
                "time": snapshot.create_time,
                "expire_time": snapshot.expire_time,
                "name": snapshot.name,
            })
        })
        .collect::<Vec<_>>();
    Ok(AdminHttpResponse::json(
        200,
        json!({ "snapshots": snapshots, "next_page_token": next }),
    ))
}

async fn get_snapshot_retention_response(
    state: &AdminState,
    tenant: &str,
    volume: &str,
) -> Result<AdminHttpResponse, AdminError> {
    let reader = state.control_reader()?;
    reader
        .get_volume(tenant, volume)
        .await
        .map_err(core_error)?;
    let policy = reader
        .try_get_snapshot_retention_policy(tenant, volume)
        .await
        .map_err(core_error)?;
    Ok(AdminHttpResponse::json(
        200,
        json!({ "retention": snapshot_retention_json(policy.as_ref()) }),
    ))
}

async fn patch_snapshot_retention_response(
    state: &AdminState,
    request: &AdminHttpRequest,
    tenant: &str,
    volume: &str,
) -> Result<AdminHttpResponse, AdminError> {
    let body: SnapshotRetentionPatchRequest = parse_json_body(request)?;
    if body.clear && (body.keep_last.is_some() || body.max_age_secs.is_some()) {
        return Err(bad_request(
            "clear cannot be combined with keep_last or max_age_secs",
        ));
    }
    if !body.clear && body.keep_last.is_none() && body.max_age_secs.is_none() {
        return Err(bad_request(
            "provide keep_last, max_age_secs, or clear=true",
        ));
    }

    let control = state.control_writer().await?;
    let policy = if body.clear {
        control
            .clear_snapshot_retention_policy(tenant, volume)
            .await
            .map_err(core_error)?;
        None
    } else {
        let current = control
            .try_get_snapshot_retention_policy(tenant, volume)
            .await
            .map_err(core_error)?;
        let keep_last = body
            .keep_last
            .unwrap_or_else(|| current.as_ref().and_then(|policy| policy.keep_last));
        let max_age_secs = body
            .max_age_secs
            .unwrap_or_else(|| current.as_ref().and_then(|policy| policy.max_age_secs));
        Some(
            control
                .set_snapshot_retention_policy(tenant, volume, keep_last, max_age_secs)
                .await
                .map_err(core_error)?,
        )
    };
    control.close().await.map_err(core_error)?;
    Ok(AdminHttpResponse::json(
        200,
        json!({ "retention": snapshot_retention_json(policy.as_ref()) }),
    ))
}

async fn list_exports_response(
    state: &AdminState,
    request: &AdminHttpRequest,
) -> Result<AdminHttpResponse, AdminError> {
    let reader = state.control_reader()?;
    let mut exports = state
        .config_exports
        .iter()
        .map(|record| export_config_json(&record.id, "config", &record.export, true))
        .collect::<Vec<_>>();
    exports.extend(
        reader
            .list_exports()
            .await
            .map_err(core_error)?
            .into_iter()
            .map(|record| export_record_json(&record)),
    );
    exports.sort_by(|a, b| {
        a["id"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["id"].as_str().unwrap_or_default())
    });
    let limit = page_limit(&request.query)?;
    let (page, next) = paginate_by(
        exports,
        request.query.get("page_token").map(String::as_str),
        limit,
        |export| export["id"].as_str().unwrap_or_default().to_string(),
    );
    Ok(AdminHttpResponse::json(
        200,
        json!({ "exports": page, "next_page_token": next }),
    ))
}

async fn get_export_response(
    state: &AdminState,
    id: &str,
) -> Result<AdminHttpResponse, AdminError> {
    if let Some(record) = state.config_exports.iter().find(|record| record.id == id) {
        return Ok(AdminHttpResponse::json(
            200,
            json!({ "export": export_config_json(&record.id, "config", &record.export, true) }),
        ));
    }
    let reader = state.control_reader()?;
    let record = reader.get_export(id).await.map_err(core_error)?;
    Ok(AdminHttpResponse::json(
        200,
        json!({ "export": export_record_json(&record) }),
    ))
}

async fn create_export_response(
    state: &AdminState,
    request: &AdminHttpRequest,
    id: &str,
) -> Result<AdminHttpResponse, AdminError> {
    if state.config_exports.iter().any(|record| record.id == id) {
        return Err(AdminError {
            status: 409,
            message: format!("export {id:?} is sourced from config and is read-only"),
        });
    }
    let body: ExportCreateRequest = parse_json_body(request)?;
    let control = state.control_writer().await?;
    let record = control
        .create_export(body.into_record(id.to_string()))
        .await
        .map_err(core_error)?;
    append_export_audit(&control, request, AuditAction::ExportCreate, &record).await?;
    control.close().await.map_err(core_error)?;
    Ok(AdminHttpResponse::json(
        201,
        json!({ "export": export_record_json(&record) }),
    ))
}

async fn patch_export_response(
    state: &AdminState,
    request: &AdminHttpRequest,
    id: &str,
) -> Result<AdminHttpResponse, AdminError> {
    if state.config_exports.iter().any(|record| record.id == id) {
        return Err(AdminError {
            status: 409,
            message: format!("export {id:?} is sourced from config and is read-only"),
        });
    }
    let body: ExportPatchRequest = parse_json_body(request)?;
    let control = state.control_writer().await?;
    let mut record = control.get_export(id).await.map_err(core_error)?;
    body.apply_to(&mut record);
    let record = control.update_export(record).await.map_err(core_error)?;
    append_export_audit(&control, request, AuditAction::ExportUpdate, &record).await?;
    control.close().await.map_err(core_error)?;
    Ok(AdminHttpResponse::json(
        200,
        json!({ "export": export_record_json(&record) }),
    ))
}

async fn delete_export_response(
    state: &AdminState,
    request: &AdminHttpRequest,
    id: &str,
) -> Result<AdminHttpResponse, AdminError> {
    if state.config_exports.iter().any(|record| record.id == id) {
        return Err(AdminError {
            status: 409,
            message: format!("export {id:?} is sourced from config and is read-only"),
        });
    }
    let control = state.control_writer().await?;
    let record = control.remove_export(id).await.map_err(core_error)?;
    append_export_audit(&control, request, AuditAction::ExportDelete, &record).await?;
    control.close().await.map_err(core_error)?;
    Ok(AdminHttpResponse::json(
        200,
        json!({ "export": export_record_json(&record), "deleted": true }),
    ))
}

async fn audit_response(
    state: &AdminState,
    request: &AdminHttpRequest,
) -> Result<AdminHttpResponse, AdminError> {
    let action = request
        .query
        .get("action")
        .map(|value| {
            AuditAction::parse(value)
                .ok_or_else(|| bad_request(format!("unsupported audit action `{value}`")))
        })
        .transpose()?;
    let parse_u64 = |key: &str| -> Result<Option<u64>, AdminError> {
        request
            .query
            .get(key)
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|error| bad_request(format!("invalid {key}: {error}")))
            })
            .transpose()
    };
    let reader = state.control_reader()?;
    let (records, next) = reader
        .list_audit(AuditQuery {
            since: parse_u64("since")?,
            until: parse_u64("until")?,
            tenant: request.query.get("tenant").map(String::as_str),
            volume: request.query.get("volume").map(String::as_str),
            node: None,
            action,
            limit: page_limit(&request.query)?,
            page_token: request.query.get("page_token").map(String::as_str),
            newest_first: query_bool(&request.query, "newest_first", true),
        })
        .await
        .map_err(core_error)?;
    Ok(AdminHttpResponse::json(
        200,
        json!({ "records": records, "next_page_token": next }),
    ))
}

fn legacy_status_response(state: &AdminState) -> AdminHttpResponse {
    let export_count = state.export_metrics.active_total().max(state.export_count);
    let writable_volumes = state.targets.lock().expect("admin targets poisoned").len();
    AdminHttpResponse::text(
        200,
        format!(
            "status=ok\nexports={}\nwritable_volumes={}\nsnapshot_exports={}\n",
            export_count, writable_volumes, state.snapshot_export_count
        ),
    )
}

async fn health_response(state: &AdminState, ready: bool, verbose: bool) -> AdminHttpResponse {
    let mut checks = vec![json!({
        "name": "process",
        "ok": true,
        "detail": "serving",
    })];
    if ready {
        let control_check = match state.control_reader() {
            Ok(reader) => {
                match tokio::time::timeout(Duration::from_millis(100), reader.list_tenants()).await
                {
                    Ok(Ok(_)) => json!({
                        "name": "control_plane",
                        "ok": true,
                        "detail": "control plane reachable",
                    }),
                    Ok(Err(_)) => json!({
                        "name": "control_plane",
                        "ok": false,
                        "detail": "control plane unavailable",
                    }),
                    Err(_) => json!({
                        "name": "control_plane",
                        "ok": false,
                        "detail": "control plane timed out",
                    }),
                }
            }
            Err(_) => json!({
                "name": "control_plane",
                "ok": false,
                "detail": "control plane unavailable",
            }),
        };
        checks.push(control_check);
        let targets = state.targets.lock().expect("admin targets poisoned");
        let writable_volumes = targets.len();
        let dead_writers = targets.values().filter(|volume| volume.is_dead()).count();
        drop(targets);
        let export_count = state.export_metrics.active_total().max(state.export_count);
        let exports_ok = export_count > 0 && dead_writers == 0;
        checks.push(json!({
            "name": "exports_serving",
            "ok": exports_ok,
            "detail": if exports_ok {
                format!(
                    "exports serving; exports={} writable_volumes={} snapshot_exports={}",
                    export_count,
                    writable_volumes,
                    state.snapshot_export_count
                )
            } else {
                format!("exports unavailable; dead_writable_volumes={dead_writers}")
            },
        }));
    }
    let ok = checks
        .iter()
        .all(|check| check.get("ok").and_then(Value::as_bool).unwrap_or(false));
    let mut body = json!({
        "status": if ok { "ok" } else { "degraded" },
        "checks": checks,
    });
    if ready && verbose {
        let writable_volumes = state.targets.lock().expect("admin targets poisoned").len();
        let mut identity = json!({
            "server_version": env!("CARGO_PKG_VERSION"),
            "slatedb_version": SLATEDB_VERSION,
            "control_role": "standalone",
            "uptime_seconds": state.started_at.elapsed().as_secs(),
            "open_repos": writable_volumes,
            "open_volumes": writable_volumes,
            "snapshot_exports": state.snapshot_export_count,
            "exports": state.export_metrics.active_total().max(state.export_count),
        });
        if let Some(node_id) = &state.node_id {
            identity["node_id"] = json!(node_id);
        }
        body["identity"] = identity;
    }
    if verbose {
        AdminHttpResponse::json_pretty(if ok { 200 } else { 503 }, body)
    } else {
        AdminHttpResponse::json(if ok { 200 } else { 503 }, body)
    }
}

async fn route_admin_request(
    state: &AdminState,
    request: &mut AdminHttpRequest,
) -> Result<AdminHttpResponse, AdminError> {
    if request.path.starts_with(ADMIN_API_PREFIX) {
        request.authenticated_principal = authenticate_admin_request(state, request)?;
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/livez") => {
            return Ok(
                health_response(state, false, query_bool(&request.query, "verbose", false)).await,
            );
        }
        ("GET", "/readyz") => {
            return Ok(
                health_response(state, true, query_bool(&request.query, "verbose", false)).await,
            );
        }
        ("GET", "/status") => return Ok(legacy_status_response(state)),
        _ => {}
    }

    if request.method == "POST" && request.path.starts_with("/snapshot/") {
        let mut target = request.path.clone();
        if !request.query.is_empty() {
            let query = request
                .query
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("&");
            target.push('?');
            target.push_str(&query);
        }
        let (tenant, volume, name) = parse_admin_snapshot_path(&target).map_err(bad_request)?;
        return create_live_snapshot_response(state, tenant, volume, name, false).await;
    }

    let segments = route_segments(&request.path)?;
    let parts = segments.iter().map(String::as_str).collect::<Vec<_>>();
    match (request.method.as_str(), parts.as_slice()) {
        ("GET", ["admin", "v1", "audit"]) => audit_response(state, request).await,
        ("GET", ["admin", "v1", "exports"]) => list_exports_response(state, request).await,
        ("GET", ["admin", "v1", "exports", id]) => get_export_response(state, id).await,
        ("POST", ["admin", "v1", "exports", id]) => {
            create_export_response(state, request, id).await
        }
        ("PATCH", ["admin", "v1", "exports", id]) => {
            patch_export_response(state, request, id).await
        }
        ("DELETE", ["admin", "v1", "exports", id]) => {
            delete_export_response(state, request, id).await
        }
        ("GET", ["admin", "v1", "tenants"]) => list_tenants_response(state, request).await,
        ("PATCH", ["admin", "v1", "tenants", tenant, "rate"]) => {
            patch_tenant_rate_response(state, request, tenant).await
        }
        ("GET", ["admin", "v1", "tenants", tenant, "volumes"]) => {
            list_volumes_response(state, request, tenant).await
        }
        ("GET", ["admin", "v1", "tenants", tenant, "volumes", volume]) => {
            get_volume_response(state, tenant, volume).await
        }
        ("PATCH", ["admin", "v1", "tenants", tenant, "volumes", volume, "quota"]) => {
            patch_volume_quota_response(state, request, tenant, volume).await
        }
        ("GET", ["admin", "v1", "nodes"]) => list_nodes_response(state, request).await,
        (
            "GET",
            [
                "admin",
                "v1",
                "tenants",
                tenant,
                "volumes",
                volume,
                "snapshots",
            ],
        ) => list_snapshots_response(state, request, tenant, volume).await,
        (
            "GET",
            [
                "admin",
                "v1",
                "tenants",
                tenant,
                "volumes",
                volume,
                "snapshot-retention",
            ],
        ) => get_snapshot_retention_response(state, tenant, volume).await,
        (
            "PATCH",
            [
                "admin",
                "v1",
                "tenants",
                tenant,
                "volumes",
                volume,
                "snapshot-retention",
            ],
        ) => patch_snapshot_retention_response(state, request, tenant, volume).await,
        (
            "POST",
            [
                "admin",
                "v1",
                "tenants",
                tenant,
                "volumes",
                volume,
                "snapshot",
            ],
        ) => {
            create_live_snapshot_response(
                state,
                (*tenant).to_string(),
                (*volume).to_string(),
                request.query.get("name").cloned(),
                true,
            )
            .await
        }
        _ if request.path.starts_with(ADMIN_API_PREFIX) => Err(not_found("admin route not found")),
        _ => Ok(AdminHttpResponse::text(404, "not found\n")),
    }
}

async fn handle_admin_connection<S>(
    stream: S,
    state: Arc<AdminState>,
    peer: Option<SocketAddr>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_admin_connection_with_cert(stream, state, peer, None).await
}

async fn handle_admin_connection_with_cert<S>(
    mut stream: S,
    state: Arc<AdminState>,
    peer: Option<SocketAddr>,
    cert_principal: Option<String>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = match read_admin_request(&mut stream, peer).await {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(error) => {
            let request_id = generated_request_id();
            let mut response = json_error_response(error.status, error.message, &request_id);
            response
                .headers
                .push((REQUEST_ID_HEADER, request_id.to_string()));
            return write_http_response_with_headers(
                &mut stream,
                status_line(response.status),
                response.content_type,
                &response.headers,
                response.body,
            )
            .await;
        }
    };
    request.cert_principal = cert_principal;

    let span = tracing::info_span!(
        "admin_request",
        method = %request.method,
        path = %request.path,
        request_id = %request.request_id,
        peer = request.peer.map(|addr| addr.to_string()).unwrap_or_default(),
    );
    let mut response = async {
        match route_admin_request(&state, &mut request).await {
            Ok(response) => response,
            Err(error) if request.path.starts_with(ADMIN_API_PREFIX) => {
                json_error_response(error.status, error.message, &request.request_id)
            }
            Err(error) => AdminHttpResponse::text(error.status, format!("{}\n", error.message)),
        }
    }
    .instrument(span.clone())
    .await;
    response
        .headers
        .push((REQUEST_ID_HEADER, request.request_id.clone()));
    {
        let _entered = span.enter();
        tracing::info!(status = response.status, "admin request completed");
    }
    write_http_response_with_headers(
        &mut stream,
        status_line(response.status),
        response.content_type,
        &response.headers,
        response.body,
    )
    .await
}

fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[derive(Clone, PartialEq, Eq)]
struct TlsFileFingerprint {
    len: u64,
    modified: Option<SystemTime>,
    sha256: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
struct TlsInputFingerprint {
    cert: TlsFileFingerprint,
    key: TlsFileFingerprint,
    client_ca: Option<TlsFileFingerprint>,
}

struct FingerprintedFile {
    path: PathBuf,
    bytes: Vec<u8>,
    fingerprint: TlsFileFingerprint,
}

struct TlsInputSnapshot {
    cert: FingerprintedFile,
    key: FingerprintedFile,
    client_ca: Option<FingerprintedFile>,
}

impl TlsInputSnapshot {
    fn load(
        cert_path: &Path,
        key_path: &Path,
        client_ca_path: Option<&Path>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            cert: read_fingerprinted_file(cert_path, "TLS certificate")?,
            key: read_fingerprinted_file(key_path, "TLS private key")?,
            client_ca: client_ca_path
                .map(|path| read_fingerprinted_file(path, "TLS client CA bundle"))
                .transpose()?,
        })
    }

    fn fingerprint(&self) -> TlsInputFingerprint {
        TlsInputFingerprint {
            cert: self.cert.fingerprint.clone(),
            key: self.key.fingerprint.clone(),
            client_ca: self.client_ca.as_ref().map(|file| file.fingerprint.clone()),
        }
    }
}

struct LoadedTlsConfig {
    config: Arc<ServerConfig>,
    fingerprint: TlsInputFingerprint,
    expiry_timestamp_seconds: i64,
}

#[derive(Clone)]
enum TlsReloadKind {
    Admin {
        cert_path: PathBuf,
        key_path: PathBuf,
        client_ca_path: Option<PathBuf>,
    },
    P9 {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

impl TlsReloadKind {
    fn load_snapshot(&self) -> anyhow::Result<TlsInputSnapshot> {
        match self {
            Self::Admin {
                cert_path,
                key_path,
                client_ca_path,
            } => TlsInputSnapshot::load(cert_path, key_path, client_ca_path.as_deref()),
            Self::P9 {
                cert_path,
                key_path,
            } => TlsInputSnapshot::load(cert_path, key_path, None),
        }
    }

    fn build_config(&self, snapshot: &TlsInputSnapshot) -> anyhow::Result<LoadedTlsConfig> {
        let (config, expiry_timestamp_seconds) = match self {
            Self::Admin { .. } => build_admin_server_config(snapshot)?,
            Self::P9 { .. } => build_p9_server_config(snapshot)?,
        };
        Ok(LoadedTlsConfig {
            config,
            fingerprint: snapshot.fingerprint(),
            expiry_timestamp_seconds,
        })
    }
}

struct TlsReloadTarget {
    surface: String,
    kind: TlsReloadKind,
    config: SharedServerConfig,
    metrics: ExportMetrics,
    fingerprint: Mutex<TlsInputFingerprint>,
}

impl TlsReloadTarget {
    fn new(
        surface: String,
        kind: TlsReloadKind,
        config: SharedServerConfig,
        metrics: ExportMetrics,
        loaded: &LoadedTlsConfig,
    ) -> Self {
        metrics.register_tls_surface(&surface, loaded.expiry_timestamp_seconds);
        Self {
            surface,
            kind,
            config,
            metrics,
            fingerprint: Mutex::new(loaded.fingerprint.clone()),
        }
    }

    fn reload_if_changed(&self, force: bool) {
        let snapshot = match self.kind.load_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.metrics.tls_reload_failure(&self.surface);
                tracing::error!(
                    surface = self.surface,
                    "TLS certificate reload failed: {error:#}"
                );
                return;
            }
        };
        let fingerprint = snapshot.fingerprint();
        {
            let current = self.fingerprint.lock().expect("TLS reload target poisoned");
            if !force && *current == fingerprint {
                return;
            }
        }

        match self.kind.build_config(&snapshot) {
            Ok(loaded) => {
                *self.config.write().expect("TLS config poisoned") = Arc::clone(&loaded.config);
                *self.fingerprint.lock().expect("TLS reload target poisoned") = loaded.fingerprint;
                self.metrics
                    .tls_reload_success(&self.surface, loaded.expiry_timestamp_seconds);
                tracing::info!(
                    surface = self.surface,
                    expiry_timestamp_seconds = loaded.expiry_timestamp_seconds,
                    "TLS certificate reloaded"
                );
            }
            Err(error) => {
                *self.fingerprint.lock().expect("TLS reload target poisoned") = fingerprint;
                self.metrics.tls_reload_failure(&self.surface);
                tracing::error!(
                    surface = self.surface,
                    "TLS certificate reload failed: {error:#}"
                );
            }
        }
    }

    fn unregister(&self) {
        self.metrics.unregister_tls_surface(&self.surface);
    }
}

fn shared_server_config(config: Arc<ServerConfig>) -> SharedServerConfig {
    Arc::new(RwLock::new(config))
}

fn tls_acceptor(config: &SharedServerConfig) -> TlsAcceptor {
    TlsAcceptor::from(config.read().expect("TLS config poisoned").clone())
}

fn read_fingerprinted_file(path: &Path, purpose: &str) -> anyhow::Result<FingerprintedFile> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading {purpose} {}", path.display()))?;
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("statting {purpose} {}", path.display()))?;
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    Ok(FingerprintedFile {
        path: path.to_path_buf(),
        bytes,
        fingerprint: TlsFileFingerprint {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            sha256,
        },
    })
}

fn parse_tls_cert_chain(
    bytes: &[u8],
    path: &Path,
    purpose: &str,
) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(Cursor::new(bytes));
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("reading {purpose} {}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!(
            "{purpose} file {} contained no certificates",
            path.display()
        );
    }
    Ok(certs)
}

fn parse_tls_private_key(
    bytes: &[u8],
    path: &Path,
    purpose: &str,
) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(Cursor::new(bytes));
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("reading {purpose} {}", path.display()))?
        .ok_or_else(|| {
            anyhow::anyhow!("{purpose} file {} contained no private key", path.display())
        })
}

fn leaf_expiry_timestamp_seconds(certs: &[CertificateDer<'static>]) -> anyhow::Result<i64> {
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("TLS certificate chain contained no leaf certificate"))?;
    let (_, cert) = parse_x509_certificate(leaf.as_ref())
        .map_err(|error| anyhow::anyhow!("parsing TLS leaf certificate: {error}"))?;
    Ok(cert.validity().not_after.timestamp())
}

fn root_cert_store_from_snapshot(file: &FingerprintedFile) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in parse_tls_cert_chain(&file.bytes, &file.path, "admin TLS client CA bundle")? {
        roots.add(cert).with_context(|| {
            format!(
                "invalid admin TLS client CA certificate in {}",
                file.path.display()
            )
        })?;
    }
    Ok(roots)
}

fn build_admin_server_config(
    snapshot: &TlsInputSnapshot,
) -> anyhow::Result<(Arc<ServerConfig>, i64)> {
    install_rustls_provider();
    let certs = parse_tls_cert_chain(
        &snapshot.cert.bytes,
        &snapshot.cert.path,
        "admin TLS certificate",
    )?;
    let expiry = leaf_expiry_timestamp_seconds(&certs)?;
    let key = parse_tls_private_key(
        &snapshot.key.bytes,
        &snapshot.key.path,
        "admin TLS private key",
    )?;
    let builder = ServerConfig::builder();
    let builder = match &snapshot.client_ca {
        Some(file) => {
            let verifier =
                WebPkiClientVerifier::builder(Arc::new(root_cert_store_from_snapshot(file)?))
                    .build()
                    .with_context(|| {
                        format!("invalid admin TLS client CA bundle {}", file.path.display())
                    })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let mut tls = builder
        .with_single_cert(certs, key)
        .context("invalid admin TLS certificate/key pair")?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((Arc::new(tls), expiry))
}

fn build_p9_server_config(snapshot: &TlsInputSnapshot) -> anyhow::Result<(Arc<ServerConfig>, i64)> {
    install_rustls_provider();
    let certs = parse_tls_cert_chain(
        &snapshot.cert.bytes,
        &snapshot.cert.path,
        "9P TLS certificate",
    )?;
    let expiry = leaf_expiry_timestamp_seconds(&certs)?;
    let key = parse_tls_private_key(
        &snapshot.key.bytes,
        &snapshot.key.path,
        "9P TLS private key",
    )?;
    let tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid 9P TLS certificate/key pair")?;
    Ok((Arc::new(tls), expiry))
}

fn load_tls_config(kind: &TlsReloadKind) -> anyhow::Result<LoadedTlsConfig> {
    let snapshot = kind.load_snapshot()?;
    kind.build_config(&snapshot)
}

fn load_admin_tls_config(config: &AdminConfig) -> anyhow::Result<Option<LoadedTlsConfig>> {
    let (Some(cert_path), Some(key_path)) = (&config.tls_cert, &config.tls_key) else {
        return Ok(None);
    };
    load_tls_config(&TlsReloadKind::Admin {
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        client_ca_path: config.tls_client_ca.clone(),
    })
    .map(Some)
}

#[cfg(test)]
fn load_admin_cert_chain(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = read_fingerprinted_file(path, "admin TLS certificate")?;
    parse_tls_cert_chain(&file.bytes, &file.path, "admin TLS certificate")
}

#[cfg(test)]
fn load_admin_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = read_fingerprinted_file(path, "admin TLS private key")?;
    parse_tls_private_key(&file.bytes, &file.path, "admin TLS private key")
}

#[cfg(test)]
fn load_admin_root_cert_store(path: &Path) -> anyhow::Result<RootCertStore> {
    let file = read_fingerprinted_file(path, "admin TLS client CA bundle")?;
    root_cert_store_from_snapshot(&file)
}

fn verified_client_principal<IO>(stream: &tokio_rustls::server::TlsStream<IO>) -> Option<String> {
    let (_, connection) = stream.get_ref();
    connection
        .peer_certificates()?
        .first()
        .and_then(|cert| cert_principal_from_der(cert.as_ref()))
}

fn cert_principal_from_der(der: &[u8]) -> Option<String> {
    let (_, cert) = parse_x509_certificate(der).ok()?;
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let Some(value) = principal_from_general_name(name) {
                return Some(value);
            }
        }
    }
    cert_common_name(cert.subject())
}

fn principal_from_general_name(name: &GeneralName<'_>) -> Option<String> {
    match name {
        GeneralName::DNSName(value) | GeneralName::RFC822Name(value) | GeneralName::URI(value) => {
            sanitize_cert_principal(value)
        }
        GeneralName::IPAddress(bytes) => cert_ip_principal(bytes).map(|ip| ip.to_string()),
        _ => None,
    }
}

fn cert_ip_principal(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn cert_common_name(name: &X509Name<'_>) -> Option<String> {
    name.iter_common_name()
        .find_map(|cn| cn.as_str().ok())
        .and_then(sanitize_cert_principal)
}

fn sanitize_cert_principal(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 256).then(|| value.to_owned())
}

async fn serve_admin(
    listen: String,
    state: Arc<AdminState>,
    tls: Option<SharedServerConfig>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&listen).await?;
    tracing::info!(listen, tls = tls.is_some(), "admin endpoint ready");
    serve_admin_listener(listener, state, tls).await
}

async fn serve_admin_listener(
    listener: TcpListener,
    state: Arc<AdminState>,
    tls: Option<SharedServerConfig>,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        match tls.clone() {
            Some(config) => {
                tokio::spawn(async move {
                    let acceptor = tls_acceptor(&config);
                    let stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            tracing::debug!(%peer, "admin TLS handshake failed: {error}");
                            return;
                        }
                    };
                    let cert_principal = verified_client_principal(&stream);
                    if let Err(error) =
                        handle_admin_connection_with_cert(stream, state, Some(peer), cert_principal)
                            .await
                    {
                        tracing::debug!(%peer, "admin request failed: {error}");
                    }
                });
            }
            None => {
                tokio::spawn(async move {
                    if let Err(error) = handle_admin_connection(stream, state, Some(peer)).await {
                        tracing::debug!(%peer, "admin request failed: {error}");
                    }
                });
            }
        }
    }
}

fn load_admin_token(config: &AdminConfig) -> anyhow::Result<Option<String>> {
    match (&config.token, &config.token_file) {
        (Some(token), None) => Ok(Some(token.clone())),
        (None, Some(path)) => {
            let token = std::fs::read_to_string(path)
                .with_context(|| format!("reading admin token file {}", path.display()))?;
            let token = token
                .trim_matches(|ch| ch == '\r' || ch == '\n')
                .to_string();
            if token.is_empty() {
                anyhow::bail!("admin.token_file {} is empty", path.display());
            }
            Ok(Some(token))
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => {
            anyhow::bail!("admin.token and admin.token_file are mutually exclusive")
        }
    }
}

fn config_export_records(exports: &[ExportConfig]) -> Arc<Vec<ConfigExportRecord>> {
    Arc::new(
        exports
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, export)| ConfigExportRecord {
                id: format!("config-{idx}"),
                export,
            })
            .collect(),
    )
}

async fn clone_parent_prefixes_from_reader(
    reader: &ControlReader,
    record: &VolumeRecord,
) -> slatefs_core::Result<Vec<String>> {
    let mut prefixes = Vec::new();
    let mut next = record.clone_parent.clone();
    for _ in 0..32 {
        let Some(parent) = next else {
            return Ok(prefixes);
        };
        prefixes.push(store::volume_db_path(&parent.tenant, &parent.volume));
        let parent_record = reader.get_volume(&parent.tenant, &parent.volume).await?;
        next = parent_record.clone_parent;
    }
    Err(slatefs_core::error::Error::invalid(
        "clone ancestry",
        format!(
            "{}/{} has a cycle or too many ancestors",
            record.tenant, record.name
        ),
    ))
}

fn block_export_device(device: Arc<dyn BlockDev>, export: &ExportConfig) -> Arc<dyn BlockDev> {
    let mut device = device;
    if export.effective_read_only() {
        device = ReadOnlyBlockDev::new(device);
    }
    if export.sync == NbdSyncMode::Strict {
        device = StrictSyncBlockDev::new(device);
    }
    device
}

#[derive(Debug)]
struct RetentionDeletedSnapshot {
    id: String,
    manifest_id: u64,
    name: Option<String>,
    reasons: Vec<&'static str>,
}

fn checkpoint_age_secs(checkpoint: &slatedb::Checkpoint, now: u64) -> Option<u64> {
    let created = checkpoint.create_time.timestamp();
    (created >= 0).then(|| now.saturating_sub(created as u64))
}

#[derive(Default)]
struct CloneParentCheckpointPins {
    pinned: HashMap<(String, String), HashSet<String>>,
    conservative: HashSet<(String, String)>,
}

impl CloneParentCheckpointPins {
    fn pinned_for(&self, tenant: &str, volume: &str) -> HashSet<String> {
        self.pinned
            .get(&(tenant.to_string(), volume.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    fn requires_conservative_skip(&self, tenant: &str, volume: &str) -> bool {
        self.conservative
            .contains(&(tenant.to_string(), volume.to_string()))
    }
}

async fn active_clone_parent_checkpoint_pins(
    reader: &ControlReader,
) -> anyhow::Result<CloneParentCheckpointPins> {
    let mut pins = CloneParentCheckpointPins::default();
    for tenant in reader.list_tenants().await? {
        for volume in reader.list_volumes(&tenant.name).await? {
            let Some(parent) = volume.clone_parent.as_ref() else {
                continue;
            };
            if matches!(volume.state, slatefs_core::control::VolumeState::Deleting) {
                continue;
            }
            let parent_key = (parent.tenant.clone(), parent.volume.clone());
            if !matches!(volume.state, slatefs_core::control::VolumeState::Active) {
                pins.conservative.insert(parent_key);
                continue;
            }
            match volume.clone_parent_checkpoint_ids {
                Some(ids) if !ids.is_empty() => {
                    pins.pinned.entry(parent_key).or_default().extend(ids);
                }
                _ => {
                    pins.conservative.insert(parent_key);
                }
            }
        }
    }
    Ok(pins)
}

async fn enforce_retention_for_policy(
    object_store: Arc<dyn ObjectStore>,
    record: &VolumeRecord,
    policy: &SnapshotRetentionPolicy,
    pinned_checkpoints: &HashSet<String>,
) -> anyhow::Result<Vec<RetentionDeletedSnapshot>> {
    let path = store::volume_db_path(&record.tenant, &record.name);
    let admin = AdminBuilder::new(path, object_store).build();
    let mut checkpoints = admin.list_checkpoints(None).await?;
    checkpoints.sort_by(|a, b| {
        b.create_time
            .cmp(&a.create_time)
            .then_with(|| b.manifest_id.cmp(&a.manifest_id))
            .then_with(|| b.id.cmp(&a.id))
    });

    let now = slatefs_core::control::now_unix();
    let mut deleted = Vec::new();
    for (idx, checkpoint) in checkpoints.into_iter().enumerate() {
        let mut reasons = Vec::new();
        if policy
            .keep_last
            .is_some_and(|keep_last| idx >= keep_last as usize)
        {
            reasons.push("keep_last");
        }
        if policy.max_age_secs.is_some_and(|max_age| {
            checkpoint_age_secs(&checkpoint, now).is_some_and(|age| age > max_age)
        }) {
            reasons.push("max_age");
        }
        if reasons.is_empty() {
            continue;
        }
        if pinned_checkpoints.contains(&checkpoint.id.to_string()) {
            continue;
        }
        admin.delete_checkpoint(checkpoint.id).await?;
        deleted.push(RetentionDeletedSnapshot {
            id: checkpoint.id.to_string(),
            manifest_id: checkpoint.manifest_id,
            name: checkpoint.name,
            reasons,
        });
    }
    Ok(deleted)
}

fn snapshot_retention_audit_record(
    tenant: &str,
    volume: &str,
    deleted: &RetentionDeletedSnapshot,
) -> AuditRecord {
    let mut record = AuditRecord::new(
        AuditActor {
            plane: AuditPlane::Admin,
            principal: None,
            source_ip: None,
            client_agent: Some("slatefsd snapshot-retention".to_string()),
        },
        AuditAction::SnapshotRetentionDelete,
        AuditScope {
            tenant: Some(tenant.to_string()),
            volume: Some(volume.to_string()),
            node: None,
        },
        format!("snapshot-retention-{}", uuid::Uuid::new_v4()),
        AuditOutcome::Success,
    );
    record.details.insert(
        "snapshot_id".to_string(),
        slatefs_core::control::AuditDetailValue::String(deleted.id.clone()),
    );
    record.details.insert(
        "manifest_id".to_string(),
        slatefs_core::control::AuditDetailValue::U64(deleted.manifest_id),
    );
    record.details.insert(
        "name".to_string(),
        deleted
            .name
            .as_ref()
            .map(|name| slatefs_core::control::AuditDetailValue::String(name.clone()))
            .unwrap_or(slatefs_core::control::AuditDetailValue::Null),
    );
    record.details.insert(
        "reasons".to_string(),
        slatefs_core::control::AuditDetailValue::Array(
            deleted
                .reasons
                .iter()
                .map(|reason| slatefs_core::control::AuditDetailValue::String((*reason).into()))
                .collect(),
        ),
    );
    record
}

async fn enforce_snapshot_retention(
    reader: &ControlReader,
    object_store: Arc<dyn ObjectStore>,
    kms: Arc<dyn kms::Kms>,
    metrics: ExportMetrics,
) -> anyhow::Result<()> {
    let policies = reader.list_snapshot_retention_policies().await?;
    if policies.is_empty() {
        return Ok(());
    }
    let clone_parent_checkpoint_pins = active_clone_parent_checkpoint_pins(reader).await?;
    let mut audit_records = Vec::new();

    for policy in policies {
        if clone_parent_checkpoint_pins.requires_conservative_skip(&policy.tenant, &policy.volume) {
            tracing::warn!(
                tenant = policy.tenant.as_str(),
                volume = policy.volume.as_str(),
                "snapshot retention skipped: active clone parent has legacy or in-progress clone pins"
            );
            continue;
        }
        let Some(record) = reader
            .try_get_volume(&policy.tenant, &policy.volume)
            .await?
        else {
            continue;
        };
        if !matches!(record.state, slatefs_core::control::VolumeState::Active) {
            continue;
        }
        let pinned_checkpoints =
            clone_parent_checkpoint_pins.pinned_for(&policy.tenant, &policy.volume);
        let deleted = enforce_retention_for_policy(
            Arc::clone(&object_store),
            &record,
            &policy,
            &pinned_checkpoints,
        )
        .await?;
        if deleted.is_empty() {
            continue;
        }
        metrics.snapshot_retention_deleted(&policy.tenant, &policy.volume, deleted.len() as u64);
        tracing::info!(
            tenant = policy.tenant.as_str(),
            volume = policy.volume.as_str(),
            deleted = deleted.len(),
            "snapshot retention deleted checkpoints"
        );
        audit_records.extend(
            deleted
                .iter()
                .map(|deleted| {
                    snapshot_retention_audit_record(&policy.tenant, &policy.volume, deleted)
                })
                .collect::<Vec<_>>(),
        );
    }

    if !audit_records.is_empty() {
        let control = ControlPlane::open(object_store, kms).await?;
        control.append_audit_records(audit_records).await?;
        control.close().await?;
    }
    Ok(())
}

fn quota_rejection_audit(
    object_store: Arc<dyn ObjectStore>,
    kms: Arc<dyn kms::Kms>,
    tenant: String,
    volume: String,
    plane: AuditPlane,
) -> QuotaRejectionAudit {
    Arc::new(move |operation| {
        let object_store = Arc::clone(&object_store);
        let kms = Arc::clone(&kms);
        let tenant = tenant.clone();
        let volume = volume.clone();
        Box::pin(async move {
            let control = match ControlPlane::open(object_store, kms).await {
                Ok(control) => control,
                Err(error) => {
                    tracing::warn!(
                        tenant,
                        volume,
                        operation,
                        "quota rejection audit open failed: {error}"
                    );
                    return;
                }
            };
            let mut audit = AuditRecord::new(
                AuditActor {
                    plane,
                    principal: None,
                    source_ip: None,
                    client_agent: None,
                },
                AuditAction::QuotaRejected,
                AuditScope {
                    tenant: Some(tenant.clone()),
                    volume: Some(volume.clone()),
                    node: None,
                },
                format!("quota-rejected-{}", uuid::Uuid::new_v4()),
                AuditOutcome::Denied,
            );
            audit.details.insert(
                "operation".to_string(),
                AuditDetailValue::String(operation.to_string()),
            );
            if let Err(error) = control.append_audit_record(audit).await {
                tracing::warn!(
                    tenant,
                    volume,
                    operation,
                    "quota rejection audit append failed: {error}"
                );
            }
            if let Err(error) = control.close().await {
                tracing::warn!(
                    tenant,
                    volume,
                    operation,
                    "quota rejection audit close failed: {error}"
                );
            }
        })
    })
}

impl ExportManager {
    fn new(
        object_store: Arc<dyn ObjectStore>,
        kms: Arc<dyn kms::Kms>,
        fh_key: slatefs_core::crypto::Secret32,
        config: &Config,
        config_exports: Arc<Vec<ConfigExportRecord>>,
        metrics: ExportMetrics,
        targets: ExportManagerTargets,
    ) -> Self {
        Self {
            object_store,
            kms,
            fh_key,
            cache: config.cache.clone(),
            slatedb: config.slatedb.clone(),
            config_exports,
            metrics,
            metrics_targets: targets.metrics,
            admin_targets: targets.admin,
            admin_block_targets: targets.admin_blocks,
            running: HashMap::new(),
            open_backends: HashMap::new(),
            rate_limiters: HashMap::new(),
            live_share_count: 1,
        }
    }

    async fn reconcile(&mut self, reader: &ControlReader) -> anyhow::Result<()> {
        let desired = self.desired_exports(reader).await?;
        self.live_share_count = desired
            .iter()
            .filter(|export| export.config.snapshot.is_none())
            .map(|export| (export.config.tenant.clone(), export.config.volume.clone()))
            .collect::<std::collections::HashSet<_>>()
            .len()
            .max(1);
        let desired_by_key: HashMap<_, _> = desired
            .iter()
            .cloned()
            .map(|export| (export.key.clone(), export))
            .collect();

        let finished = self
            .running
            .iter()
            .filter(|(_, running)| running.task.is_finished())
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in finished {
            tracing::warn!(
                source = key.source.as_str(),
                id = key.id,
                "export listener exited; retrying on next reconcile"
            );
            self.metrics.failure();
            self.stop_export(&key).await;
        }

        let to_stop = self
            .running
            .iter()
            .filter(|(key, running)| desired_by_key.get(*key) != Some(&running.desired))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in to_stop {
            self.stop_export(&key).await;
        }

        for export in desired {
            if self.running.contains_key(&export.key) {
                continue;
            }
            if let Err(error) = self.start_export(reader, export.clone()).await {
                self.metrics.failure();
                tracing::error!(
                    source = export.key.source.as_str(),
                    id = export.key.id,
                    listen = export.config.listen,
                    "export reconcile skipped export: {error:#}"
                );
            }
        }
        Ok(())
    }

    async fn desired_exports(&self, reader: &ControlReader) -> anyhow::Result<Vec<DesiredExport>> {
        let mut desired = self
            .config_exports
            .iter()
            .map(|record| DesiredExport {
                key: ExportKey {
                    source: ExportSource::Config,
                    id: record.id.clone(),
                },
                config: record.export.clone(),
            })
            .collect::<Vec<_>>();
        let mut control_exports = reader.list_exports().await?;
        control_exports.sort_by(|a, b| a.id.cmp(&b.id));
        desired.extend(
            control_exports
                .into_iter()
                .filter(|record| record.enabled)
                .map(|record| DesiredExport {
                    key: ExportKey {
                        source: ExportSource::Control,
                        id: record.id.clone(),
                    },
                    config: record.to_config(),
                }),
        );
        Ok(desired)
    }

    async fn start_export(
        &mut self,
        reader: &ControlReader,
        desired: DesiredExport,
    ) -> anyhow::Result<()> {
        if let Some(conflict) = self.running.values().find(|running| {
            running.desired.config.listen == desired.config.listen
                && running.desired.key != desired.key
        }) {
            anyhow::bail!(
                "listen address {} already used by {} export {}",
                desired.config.listen,
                conflict.desired.key.source.as_str(),
                conflict.desired.key.id
            );
        }

        let (backend_key, backend, rate_limits) = self.backend_for(reader, &desired.config).await?;
        let rate_limiter = Some(self.rate_limiter_for(desired.config.tenant.clone(), rate_limits));
        let mut nbd_shutdown = None;
        let mut tls_reload = None;
        let bind_result = match desired.config.protocol {
            ExportProtocol::Nfs => {
                let BackendExport::Fs(volume) = backend else {
                    anyhow::bail!(
                        "NFS export {}/{} requires a filesystem volume",
                        desired.config.tenant,
                        desired.config.volume
                    );
                };
                let policy = SquashPolicy {
                    mode: desired.config.squash,
                    anon_uid: desired.config.anon_uid,
                    anon_gid: desired.config.anon_gid,
                };
                let listener =
                    slatefs_nfs::bind_export_with_allowlist_and_runtime_and_atime_policy(
                        Arc::clone(&volume),
                        self.fh_key.clone(),
                        policy,
                        desired.config.allowed_clients.clone(),
                        NfsExportRuntime {
                            rate_limiter,
                            quota_rejection_audit: Some(quota_rejection_audit(
                                Arc::clone(&self.object_store),
                                Arc::clone(&self.kms),
                                desired.config.tenant.clone(),
                                desired.config.volume.clone(),
                                AuditPlane::Nfs,
                            )),
                        },
                        desired.config.atime,
                        &desired.config.listen,
                    )
                    .await;
                listener.map(|listener| {
                    let port = listener.get_listen_port();
                    tracing::info!(
                        source = desired.key.source.as_str(),
                        id = desired.key.id,
                        tenant = desired.config.tenant,
                        volume = desired.config.volume,
                        snapshot = desired.config.snapshot.as_deref().unwrap_or("-"),
                        listen = desired.config.listen,
                        port,
                        "NFS export ready"
                    );
                    tokio::spawn(async move {
                        if let Err(error) = listener.handle_forever().await {
                            tracing::error!("NFS export listener exited: {error}");
                        }
                    })
                })
            }
            ExportProtocol::P9 => {
                let BackendExport::Fs(volume) = backend else {
                    anyhow::bail!(
                        "9P export {}/{} requires a filesystem volume",
                        desired.config.tenant,
                        desired.config.volume
                    );
                };
                let export_name = format!("/{}/{}", desired.config.tenant, desired.config.volume);
                let tls = match (&desired.config.p9_tls_cert, &desired.config.p9_tls_key) {
                    (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
                    (None, None) => None,
                    _ => anyhow::bail!(
                        "9P export {}/{} must set both p9_tls_cert and p9_tls_key, or neither",
                        desired.config.tenant,
                        desired.config.volume
                    ),
                };
                let listen = desired.config.listen.clone();
                let token = desired.config.p9_token.clone();
                let allowed_clients = desired.config.allowed_clients.clone();
                match tls {
                    Some((cert, key)) => {
                        let surface = tls_surface_for_export(&desired.key);
                        let kind = TlsReloadKind::P9 {
                            cert_path: cert,
                            key_path: key,
                        };
                        let loaded = load_tls_config(&kind).map_err(std::io::Error::other)?;
                        let shared = shared_server_config(Arc::clone(&loaded.config));
                        match slatefs_9p::bind_export_tls_with_reloadable_config_and_atime_policy(
                            Arc::clone(&volume),
                            export_name,
                            token,
                            allowed_clients,
                            rate_limiter,
                            desired.config.atime,
                            &listen,
                            Arc::clone(&shared),
                        )
                        .await
                        {
                            Ok(listener) => {
                                tls_reload = Some(Arc::new(TlsReloadTarget::new(
                                    surface,
                                    kind,
                                    shared,
                                    self.metrics.clone(),
                                    &loaded,
                                )));
                                Ok({
                                    tracing::info!(
                                        source = desired.key.source.as_str(),
                                        id = desired.key.id,
                                        tenant = desired.config.tenant,
                                        volume = desired.config.volume,
                                        snapshot =
                                            desired.config.snapshot.as_deref().unwrap_or("-"),
                                        listen,
                                        "TLS-wrapped 9P export ready"
                                    );
                                    tokio::spawn(async move {
                                        if let Err(error) = listener.handle_forever().await {
                                            tracing::error!(
                                                "9P TLS export listener exited: {error}"
                                            );
                                        }
                                    })
                                })
                            }
                            Err(error) => Err(error),
                        }
                    }
                    None => slatefs_9p::bind_export_with_allowlist_and_rate_limit_and_atime_policy(
                        Arc::clone(&volume),
                        export_name,
                        token,
                        allowed_clients,
                        rate_limiter,
                        desired.config.atime,
                        &listen,
                    )
                    .await
                    .map(|listener| {
                        tracing::info!(
                            source = desired.key.source.as_str(),
                            id = desired.key.id,
                            tenant = desired.config.tenant,
                            volume = desired.config.volume,
                            snapshot = desired.config.snapshot.as_deref().unwrap_or("-"),
                            listen,
                            "9P export ready"
                        );
                        tokio::spawn(async move {
                            if let Err(error) = listener.handle_forever().await {
                                tracing::error!("9P export listener exited: {error}");
                            }
                        })
                    }),
                }
            }
            ExportProtocol::Nbd => {
                let BackendExport::Block { device, shutdowns } = backend else {
                    anyhow::bail!(
                        "NBD export {}/{} requires a block volume",
                        desired.config.tenant,
                        desired.config.volume
                    );
                };
                let export_name = format!("/{}/{}", desired.config.tenant, desired.config.volume);
                let listen = desired.config.listen.clone();
                let allowed_clients = desired.config.allowed_clients.clone();
                let tls = match (&desired.config.nbd_tls_cert, &desired.config.nbd_tls_key) {
                    (Some(cert), Some(key)) => Some(slatefs_nbd::NbdTlsIdentity {
                        cert_path: cert.clone(),
                        key_path: key.clone(),
                        client_ca_path: desired.config.nbd_tls_client_ca.clone(),
                    }),
                    (None, None) if desired.config.nbd_tls_client_ca.is_none() => None,
                    (None, None) => anyhow::bail!(
                        "NBD export {}/{} sets nbd_tls_client_ca but does not set nbd_tls_cert and nbd_tls_key",
                        desired.config.tenant,
                        desired.config.volume
                    ),
                    _ => anyhow::bail!(
                        "NBD export {}/{} must set both nbd_tls_cert and nbd_tls_key, or neither",
                        desired.config.tenant,
                        desired.config.volume
                    ),
                };
                let bind = match tls {
                    Some(identity) => {
                        slatefs_nbd::bind_export_tls_with_allowlist_and_rate_limit(
                            &listen,
                            export_name,
                            device,
                            allowed_clients,
                            rate_limiter,
                            identity,
                        )
                        .await
                    }
                    None => {
                        slatefs_nbd::bind_export_with_allowlist_and_rate_limit(
                            &listen,
                            export_name,
                            device,
                            allowed_clients,
                            rate_limiter,
                        )
                        .await
                    }
                };
                bind.map(|listener| {
                    let shutdown = listener.shutdown_handle();
                    shutdowns
                        .lock()
                        .expect("NBD shutdown handles poisoned")
                        .push(shutdown.clone());
                    nbd_shutdown = Some(shutdown);
                    tracing::info!(
                        source = desired.key.source.as_str(),
                        id = desired.key.id,
                        tenant = desired.config.tenant,
                        volume = desired.config.volume,
                        snapshot = desired.config.snapshot.as_deref().unwrap_or("-"),
                        listen,
                        "NBD export ready"
                    );
                    tokio::spawn(async move {
                        if let Err(error) = listener.handle_forever().await {
                            tracing::error!("NBD export listener exited: {error}");
                        }
                    })
                })
            }
        };

        let task = match bind_result {
            Ok(task) => task,
            Err(error) => {
                self.close_backend_if_unused(&backend_key).await;
                return Err(error).with_context(|| format!("binding {}", desired.config.listen));
            }
        };
        if let Some(backend) = self.open_backends.get_mut(&backend_key) {
            backend.ref_count += 1;
        }
        self.metrics
            .started(desired.config.protocol, desired.key.source);
        self.running.insert(
            desired.key.clone(),
            RunningExport {
                desired,
                backend_key,
                nbd_shutdown,
                tls_reload,
                task,
            },
        );
        Ok(())
    }

    async fn backend_for(
        &mut self,
        reader: &ControlReader,
        export: &ExportConfig,
    ) -> anyhow::Result<((String, String, Option<String>), BackendExport, RateLimits)> {
        let backend_key = (
            export.tenant.clone(),
            export.volume.clone(),
            export.snapshot.clone(),
        );
        let tenant = reader.get_tenant(&export.tenant).await?;
        if let Some(backend) = self.open_backends.get(&backend_key) {
            let export_backend = match export.protocol {
                ExportProtocol::Nfs | ExportProtocol::P9 => BackendExport::Fs(
                    backend
                        .vfs
                        .as_ref()
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("cached backend is not a filesystem"))?,
                ),
                ExportProtocol::Nbd => BackendExport::Block {
                    device: block_export_device(
                        backend.block.as_ref().cloned().ok_or_else(|| {
                            anyhow::anyhow!("cached backend is not a block device")
                        })?,
                        export,
                    ),
                    shutdowns: Arc::clone(&backend.nbd_shutdowns),
                },
            };
            return Ok((backend_key, export_backend, tenant.rate_limits));
        }

        let record = reader
            .get_mountable_volume(&export.tenant, &export.volume)
            .await?;
        validate_export_volume_kind(export, record.kind).map_err(|error| match error {
            slatefs_core::error::Error::Config(message) => anyhow::anyhow!(message),
            error => anyhow::anyhow!(error),
        })?;
        let dek = reader.unwrap_volume_dek(&record).await?;
        let clone_parent_prefixes = clone_parent_prefixes_from_reader(reader, &record).await?;
        let backend: OpenBackend = match record.kind {
            VolumeKind::Filesystem => {
                self.open_filesystem_backend(export, &record, dek, clone_parent_prefixes)
                    .await?
            }
            VolumeKind::Block { .. } => {
                self.open_block_backend(export, &record, dek, clone_parent_prefixes)
                    .await?
            }
        };
        let export_backend =
            match export.protocol {
                ExportProtocol::Nfs | ExportProtocol::P9 => BackendExport::Fs(
                    backend
                        .vfs
                        .as_ref()
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("opened backend is not a filesystem"))?,
                ),
                ExportProtocol::Nbd => BackendExport::Block {
                    device: block_export_device(
                        backend.block.as_ref().cloned().ok_or_else(|| {
                            anyhow::anyhow!("opened backend is not a block device")
                        })?,
                        export,
                    ),
                    shutdowns: Arc::clone(&backend.nbd_shutdowns),
                },
            };
        self.open_backends.insert(backend_key.clone(), backend);
        Ok((backend_key, export_backend, tenant.rate_limits))
    }

    async fn open_filesystem_backend(
        &self,
        export: &ExportConfig,
        record: &VolumeRecord,
        dek: slatefs_core::crypto::Secret32,
        clone_parent_prefixes: Vec<String>,
    ) -> anyhow::Result<OpenBackend> {
        if let Some(snapshot) = &export.snapshot {
            let snapshot_volume = SnapshotVolume::open(
                record,
                dek,
                Arc::clone(&self.object_store),
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
            self.metrics_targets
                .lock()
                .expect("metrics targets poisoned")
                .push(MetricsTarget::Snapshot {
                    tenant: export.tenant.clone(),
                    volume_name: export.volume.clone(),
                    snapshot_id: snapshot.clone(),
                    volume: Arc::clone(&snapshot_volume),
                });
            Ok(OpenBackend {
                vfs: Some(snapshot_volume.clone()),
                block: None,
                writable: None,
                snapshot: Some(snapshot_volume),
                block_writable: None,
                block_snapshot: None,
                nbd_shutdowns: Arc::new(Mutex::new(Vec::new())),
                ref_count: 0,
            })
        } else {
            let mut caches = VolumeCaches::from_config(
                &self.cache,
                &self.slatedb,
                &export.tenant,
                &export.volume,
                self.live_share_count,
            );
            let recorder = Arc::new(AggregatingRecorder::default());
            caches.recorder = Some(Arc::clone(&recorder));
            let volume =
                Volume::open_with_caches(record, dek, Arc::clone(&self.object_store), &caches)
                    .await
                    .with_context(|| {
                        format!("opening volume {}/{}", export.tenant, export.volume)
                    })?;
            let watched = Arc::clone(&volume);
            let watched_tenant = export.tenant.clone();
            let watched_volume = export.volume.clone();
            tokio::spawn(async move {
                watched.wait_dead().await;
                tracing::error!(
                    tenant = watched_tenant,
                    volume = watched_volume,
                    "volume fenced; export listeners will fail until reconciled"
                );
            });
            self.metrics_targets
                .lock()
                .expect("metrics targets poisoned")
                .push(MetricsTarget::Writable {
                    tenant: export.tenant.clone(),
                    volume_name: export.volume.clone(),
                    recorder: Arc::clone(&recorder),
                    volume: Arc::clone(&volume),
                });
            self.admin_targets
                .lock()
                .expect("admin targets poisoned")
                .insert(
                    (export.tenant.clone(), export.volume.clone()),
                    Arc::clone(&volume),
                );
            Ok(OpenBackend {
                vfs: Some(volume.clone()),
                block: None,
                writable: Some(volume),
                snapshot: None,
                block_writable: None,
                block_snapshot: None,
                nbd_shutdowns: Arc::new(Mutex::new(Vec::new())),
                ref_count: 0,
            })
        }
    }

    async fn open_block_backend(
        &self,
        export: &ExportConfig,
        record: &VolumeRecord,
        dek: slatefs_core::crypto::Secret32,
        clone_parent_prefixes: Vec<String>,
    ) -> anyhow::Result<OpenBackend> {
        let nbd_shutdowns = Arc::new(Mutex::new(Vec::new()));
        if let Some(snapshot) = &export.snapshot {
            let snapshot_volume = SnapshotBlockVolume::open(
                record,
                dek,
                Arc::clone(&self.object_store),
                snapshot,
                clone_parent_prefixes,
            )
            .await
            .with_context(|| {
                format!(
                    "opening block snapshot {snapshot} for {}/{}",
                    export.tenant, export.volume
                )
            })?;
            let device: Arc<dyn BlockDev> = snapshot_volume.clone();
            self.metrics_targets
                .lock()
                .expect("metrics targets poisoned")
                .push(MetricsTarget::BlockSnapshot {
                    tenant: export.tenant.clone(),
                    volume_name: export.volume.clone(),
                    snapshot_id: snapshot.clone(),
                });
            Ok(OpenBackend {
                vfs: None,
                block: Some(device),
                writable: None,
                snapshot: None,
                block_writable: None,
                block_snapshot: Some(snapshot_volume),
                nbd_shutdowns,
                ref_count: 0,
            })
        } else {
            let caches = VolumeCaches::from_config(
                &self.cache,
                &self.slatedb,
                &export.tenant,
                &export.volume,
                self.live_share_count,
            );
            let volume =
                BlockVolume::open_with_caches(record, dek, Arc::clone(&self.object_store), &caches)
                    .await
                    .with_context(|| {
                        format!("opening block volume {}/{}", export.tenant, export.volume)
                    })?;
            let watched = Arc::clone(&volume);
            let watched_tenant = export.tenant.clone();
            let watched_volume = export.volume.clone();
            let watched_shutdowns = Arc::clone(&nbd_shutdowns);
            tokio::spawn(async move {
                watched.wait_dead().await;
                tracing::error!(
                    tenant = watched_tenant,
                    volume = watched_volume,
                    "block volume fenced; hard-closing NBD connections"
                );
                for shutdown in watched_shutdowns
                    .lock()
                    .expect("NBD shutdown handles poisoned")
                    .iter()
                {
                    shutdown.kill();
                }
            });
            let device: Arc<dyn BlockDev> = volume.clone();
            self.metrics_targets
                .lock()
                .expect("metrics targets poisoned")
                .push(MetricsTarget::BlockWritable {
                    tenant: export.tenant.clone(),
                    volume_name: export.volume.clone(),
                    volume: Arc::clone(&volume),
                });
            self.admin_block_targets
                .lock()
                .expect("admin block targets poisoned")
                .insert(
                    (export.tenant.clone(), export.volume.clone()),
                    Arc::clone(&volume),
                );
            Ok(OpenBackend {
                vfs: None,
                block: Some(device),
                writable: None,
                snapshot: None,
                block_writable: Some(volume),
                block_snapshot: None,
                nbd_shutdowns,
                ref_count: 0,
            })
        }
    }

    fn rate_limiter_for(&mut self, tenant: String, limits: RateLimits) -> Arc<RateLimiter> {
        if let Some(limiter) = self.rate_limiters.get(&tenant) {
            limiter.set_limits(limits);
            return Arc::clone(limiter);
        }
        let limiter = Arc::new(RateLimiter::new(limits));
        self.rate_limiters
            .insert(tenant.clone(), Arc::clone(&limiter));
        self.metrics_targets
            .lock()
            .expect("metrics targets poisoned")
            .push(MetricsTarget::TenantRateLimiter {
                tenant,
                limiter: Arc::clone(&limiter),
            });
        limiter
    }

    async fn reload_live_limits(&mut self, reader: &ControlReader) -> anyhow::Result<()> {
        for tenant in reader.list_tenants().await? {
            if let Some(limiter) = self.rate_limiters.get(&tenant.name)
                && limiter.set_limits(tenant.rate_limits)
            {
                tracing::info!(
                    tenant = tenant.name,
                    ops_per_second = ?tenant.rate_limits.ops_per_second,
                    bytes_per_second = ?tenant.rate_limits.bytes_per_second,
                    "tenant rate limits reloaded"
                );
            }
        }

        let open_writable = self
            .open_backends
            .iter()
            .filter_map(|((tenant, volume, snapshot), backend)| {
                if snapshot.is_some() {
                    return None;
                }
                backend
                    .writable
                    .as_ref()
                    .map(|writable| (tenant.clone(), volume.clone(), Arc::clone(writable)))
            })
            .collect::<Vec<_>>();
        let open_block_writable = self
            .open_backends
            .iter()
            .filter_map(|((tenant, volume, snapshot), backend)| {
                if snapshot.is_some() {
                    return None;
                }
                backend
                    .block_writable
                    .as_ref()
                    .map(|writable| (tenant.clone(), volume.clone(), Arc::clone(writable)))
            })
            .collect::<Vec<_>>();

        for (tenant, volume_name, volume) in open_writable {
            let Some(record) = reader.try_get_volume(&tenant, &volume_name).await? else {
                continue;
            };
            if volume.set_quota_limits(record.quota) {
                tracing::info!(
                    tenant,
                    volume = volume_name,
                    bytes_hard = ?record.quota.bytes.hard,
                    inodes_hard = ?record.quota.inodes.hard,
                    "volume quota limits reloaded"
                );
            }
        }
        for (tenant, volume_name, volume) in open_block_writable {
            let Some(record) = reader.try_get_volume(&tenant, &volume_name).await? else {
                continue;
            };
            if volume.set_quota_limits(record.quota) {
                tracing::info!(
                    tenant,
                    volume = volume_name,
                    bytes_hard = ?record.quota.bytes.hard,
                    "block volume quota limits reloaded"
                );
            }
        }
        Ok(())
    }

    async fn stop_export(&mut self, key: &ExportKey) {
        let Some(running) = self.running.remove(key) else {
            return;
        };
        if let Some(shutdown) = &running.nbd_shutdown {
            shutdown.kill();
        }
        if let Some(target) = &running.tls_reload {
            target.unregister();
        }
        running.task.abort();
        self.metrics
            .stopped(running.desired.config.protocol, running.desired.key.source);
        if let Some(backend) = self.open_backends.get_mut(&running.backend_key) {
            backend.ref_count = backend.ref_count.saturating_sub(1);
        }
        self.close_backend_if_unused(&running.backend_key).await;
        tracing::info!(
            source = running.desired.key.source.as_str(),
            id = running.desired.key.id,
            "export stopped"
        );
    }

    async fn close_backend_if_unused(&mut self, backend_key: &(String, String, Option<String>)) {
        if self
            .open_backends
            .get(backend_key)
            .is_some_and(|backend| backend.ref_count > 0)
        {
            return;
        }
        let Some(backend) = self.open_backends.remove(backend_key) else {
            return;
        };
        self.remove_metrics_target(backend_key);
        if let Some(volume) = backend.writable
            && let Err(error) = volume.shutdown().await
        {
            self.admin_targets
                .lock()
                .expect("admin targets poisoned")
                .remove(&(backend_key.0.clone(), backend_key.1.clone()));
            tracing::error!(
                tenant = backend_key.0,
                volume = backend_key.1,
                "volume shutdown: {error}"
            );
        }
        if backend_key.2.is_none() {
            self.admin_targets
                .lock()
                .expect("admin targets poisoned")
                .remove(&(backend_key.0.clone(), backend_key.1.clone()));
        }
        if let Some(snapshot) = backend.snapshot
            && let Err(error) = snapshot.shutdown().await
        {
            tracing::error!(
                tenant = backend_key.0,
                volume = backend_key.1,
                snapshot = backend_key.2.as_deref().unwrap_or("-"),
                "snapshot shutdown: {error}"
            );
        }
        if let Some(volume) = backend.block_writable {
            self.admin_block_targets
                .lock()
                .expect("admin block targets poisoned")
                .remove(&(backend_key.0.clone(), backend_key.1.clone()));
            if let Err(error) = volume.shutdown().await {
                tracing::error!(
                    tenant = backend_key.0,
                    volume = backend_key.1,
                    "block volume shutdown: {error}"
                );
            }
        }
        if let Some(snapshot) = backend.block_snapshot
            && let Err(error) = snapshot.shutdown().await
        {
            tracing::error!(
                tenant = backend_key.0,
                volume = backend_key.1,
                snapshot = backend_key.2.as_deref().unwrap_or("-"),
                "block snapshot shutdown: {error}"
            );
        }
    }

    fn remove_metrics_target(&self, backend_key: &(String, String, Option<String>)) {
        let mut targets = self
            .metrics_targets
            .lock()
            .expect("metrics targets poisoned");
        targets.retain(|target| match target {
            MetricsTarget::Writable {
                tenant,
                volume_name,
                ..
            } => {
                backend_key.2.is_some() || tenant != &backend_key.0 || volume_name != &backend_key.1
            }
            MetricsTarget::Snapshot {
                tenant,
                volume_name,
                snapshot_id,
                ..
            } => {
                backend_key.2.as_ref() != Some(snapshot_id)
                    || tenant != &backend_key.0
                    || volume_name != &backend_key.1
            }
            MetricsTarget::BlockWritable {
                tenant,
                volume_name,
                ..
            } => {
                backend_key.2.is_some() || tenant != &backend_key.0 || volume_name != &backend_key.1
            }
            MetricsTarget::BlockSnapshot {
                tenant,
                volume_name,
                snapshot_id,
            } => {
                backend_key.2.as_ref() != Some(snapshot_id)
                    || tenant != &backend_key.0
                    || volume_name != &backend_key.1
            }
            MetricsTarget::TenantRateLimiter { .. } => true,
        });
    }

    fn tls_reload_targets(&self) -> Vec<Arc<TlsReloadTarget>> {
        self.running
            .values()
            .filter_map(|running| running.tls_reload.as_ref().map(Arc::clone))
            .collect()
    }

    async fn shutdown(&mut self) {
        let keys = self.running.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            self.stop_export(&key).await;
        }
    }
}

async fn reload_tls_targets(
    manager: Arc<tokio::sync::Mutex<ExportManager>>,
    admin: Option<Arc<TlsReloadTarget>>,
    force: bool,
) {
    if let Some(target) = admin {
        target.reload_if_changed(force);
    }
    let targets = manager.lock().await.tls_reload_targets();
    for target in targets {
        target.reload_if_changed(force);
    }
}

#[cfg(unix)]
async fn serve_tls_reload_signal(
    manager: Arc<tokio::sync::Mutex<ExportManager>>,
    admin: Option<Arc<TlsReloadTarget>>,
) -> std::io::Result<()> {
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    loop {
        sighup.recv().await;
        tracing::info!("received SIGHUP; reloading TLS certificates");
        reload_tls_targets(Arc::clone(&manager), admin.clone(), true).await;
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

    let object_store = store::resolve_root(&config.object_store.url)
        .with_context(|| format!("resolving object store {}", config.object_store.url))?;
    let kms = kms::from_config(&config.kms)?;
    let admin_token = load_admin_token(&config.admin)?;
    let export_metrics = ExportMetrics::default();
    let admin_tls_loaded = load_admin_tls_config(&config.admin)?;
    let admin_tls = admin_tls_loaded.map(|loaded| {
        let shared = shared_server_config(Arc::clone(&loaded.config));
        let target = Arc::new(TlsReloadTarget::new(
            "admin".to_string(),
            TlsReloadKind::Admin {
                cert_path: config
                    .admin
                    .tls_cert
                    .as_ref()
                    .expect("admin TLS cert path")
                    .clone(),
                key_path: config
                    .admin
                    .tls_key
                    .as_ref()
                    .expect("admin TLS key path")
                    .clone(),
                client_ca_path: config.admin.tls_client_ca.clone(),
            },
            Arc::clone(&shared),
            export_metrics.clone(),
            &loaded,
        ));
        (shared, target)
    });
    let admin_tls_config = admin_tls.as_ref().map(|(shared, _)| Arc::clone(shared));
    let admin_tls_target = admin_tls.as_ref().map(|(_, target)| Arc::clone(target));
    let admin_cert_auth_allowed = config.admin.allow_cert_auth;
    if config.admin.listen.is_some() {
        if admin_token.is_none() && !admin_cert_auth_allowed {
            tracing::warn!(
                "slatefs admin API is unauthenticated; set admin.token/admin.token_file or enable mTLS cert auth on untrusted networks"
            );
        }
        if admin_token.is_some() && admin_tls.is_none() {
            tracing::warn!(
                "slatefs admin bearer tokens are accepted over cleartext HTTP; set admin.tls_cert and admin.tls_key on untrusted networks"
            );
        }
    }

    let config_exports = config_export_records(&config.exports);
    let metrics_targets = Arc::new(Mutex::new(Vec::new()));
    let admin_targets = Arc::new(Mutex::new(HashMap::new()));
    let admin_block_targets = Arc::new(Mutex::new(HashMap::new()));

    // Initialize deployment-wide server state that needs a writer, then use
    // read-only control handles for live reconciliation.
    let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
        .await
        .context("opening control-plane DB")?;
    let fh_key = control.server_fh_key().await?;
    control.close().await.context("closing control-plane DB")?;

    let mut servers = tokio::task::JoinSet::new();
    let manager = Arc::new(tokio::sync::Mutex::new(ExportManager::new(
        Arc::clone(&object_store),
        Arc::clone(&kms),
        fh_key,
        &config,
        Arc::clone(&config_exports),
        export_metrics.clone(),
        ExportManagerTargets {
            metrics: Arc::clone(&metrics_targets),
            admin: Arc::clone(&admin_targets),
            admin_blocks: Arc::clone(&admin_block_targets),
        },
    )));

    let control_reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
        .await
        .context("opening control-plane reader")?;
    {
        let mut manager_guard = manager.lock().await;
        manager_guard
            .reconcile(&control_reader)
            .await
            .context("initial export reconcile")?;
    }

    let watcher_manager = Arc::clone(&manager);
    let watcher_store = Arc::clone(&object_store);
    let watcher_kms = Arc::clone(&kms);
    let watcher_metrics = export_metrics.clone();
    let poll_interval = Duration::from_secs(config.export_control.poll_interval_secs);
    servers.spawn(async move {
        let mut tick = tokio::time::interval(poll_interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            let reader = ControlReader::open(Arc::clone(&watcher_store), Arc::clone(&watcher_kms))
                .await
                .map_err(std::io::Error::other)?;
            {
                let mut manager = watcher_manager.lock().await;
                if let Err(error) = manager.reconcile(&reader).await {
                    watcher_metrics.failure();
                    tracing::error!("export reconcile failed: {error:#}");
                }
                if let Err(error) = manager.reload_live_limits(&reader).await {
                    watcher_metrics.failure();
                    tracing::error!("live limit reload failed: {error:#}");
                }
            }
            if let Err(error) = enforce_snapshot_retention(
                &reader,
                Arc::clone(&watcher_store),
                Arc::clone(&watcher_kms),
                watcher_metrics.clone(),
            )
            .await
            {
                watcher_metrics.failure();
                tracing::error!("snapshot retention enforcement failed: {error:#}");
            }
            reader.close().await.map_err(std::io::Error::other)?;
        }
    });

    let tls_poll_manager = Arc::clone(&manager);
    let tls_poll_admin = admin_tls_target.clone();
    let tls_poll_interval = Duration::from_secs(config.tls.reload_poll_secs);
    servers.spawn(async move {
        let mut tick = tokio::time::interval(tls_poll_interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            reload_tls_targets(Arc::clone(&tls_poll_manager), tls_poll_admin.clone(), false).await;
        }
    });

    #[cfg(unix)]
    {
        let signal_manager = Arc::clone(&manager);
        let signal_admin = admin_tls_target.clone();
        servers.spawn(async move { serve_tls_reload_signal(signal_manager, signal_admin).await });
    }

    if let Some(listen) = config.admin.listen.clone() {
        let targets = Arc::clone(&admin_targets);
        let control = match ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms)).await {
            Ok(reader) => AdminControl::Available(Arc::new(reader)),
            Err(error) => {
                tracing::warn!(%error, "admin control reader unavailable at startup");
                AdminControl::Unavailable(error.to_string())
            }
        };
        let state = Arc::new(AdminState {
            targets,
            block_targets: Arc::clone(&admin_block_targets),
            control,
            object_store: Arc::clone(&object_store),
            kms: Arc::clone(&kms),
            config_exports: Arc::clone(&config_exports),
            export_metrics: export_metrics.clone(),
            started_at: Instant::now(),
            export_count: export_metrics.active_total(),
            snapshot_export_count: config
                .exports
                .iter()
                .filter(|export| export.snapshot.is_some())
                .count(),
            auth_token: admin_token,
            allow_cert_auth: admin_cert_auth_allowed,
            node_id: None,
        });
        servers.spawn(async move { serve_admin(listen, state, admin_tls_config).await });
    }

    if let Some(listen) = config.metrics.listen.clone() {
        servers.spawn(async move { serve_metrics(listen, metrics_targets, export_metrics).await });
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down on SIGINT");
        }
        Some(res) = servers.join_next() => {
            tracing::error!("daemon task exited unexpectedly: {res:?}");
        }
    }

    servers.abort_all();
    manager.lock().await.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use nfs3_server::nfs3_types::nfs3::{filename3, nfsstat3, sattr3, stable_how};
    use nfs3_server::nfs3_types::xdr_codec::Opaque;
    use nfs3_server::vfs::{NfsFileSystem, NfsReadFileSystem};
    use slatefs_core::config::Compression;
    use slatefs_core::control::{
        AuditAction, AuditActor, AuditOutcome, AuditPlane, AuditRecord, AuditScope, ControlPlane,
        DaemonMetrics, DaemonNodeState, QuotaLimit, QuotaLimits,
    };
    use slatefs_core::crypto::kms::{Kms, StaticKms};
    use slatefs_core::crypto::{Cipher, Secret32};
    use slatefs_core::meta::inode::ROOT_INO;
    use slatefs_core::snapshot::SnapshotVolume;
    use slatefs_core::vfs::{Credentials, Vfs};
    use slatefs_nbd::test_support::NbdTestClient;
    use slatefs_nfs::SlateFsNfs;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::ServerName;

    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };

    type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
    const ADMIN_TOKEN: &str = "secret-admin-token";

    fn create_opts() -> slatefs_core::volume::CreateVolumeOptions {
        slatefs_core::volume::CreateVolumeOptions {
            cipher: Cipher::Aes256Gcm,
            chunk_size: 4096,
            compression: Compression::Lz4,
            quota: QuotaLimits::default(),
            note: None,
        }
    }

    async fn write_root_file(
        control: &ControlPlane,
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume_name: &str,
        name: &[u8],
        contents: &[u8],
    ) {
        let record = control.get_volume(tenant, volume_name).await.unwrap();
        let dek = control.unwrap_volume_dek(&record).await.unwrap();
        let volume = Volume::open(&record, dek, object_store).await.unwrap();
        let creds = Credentials::root();
        let file = volume
            .create(&creds, ROOT_INO, name, 0o644, true)
            .await
            .unwrap();
        volume.write(&creds, file.ino, 0, contents).await.unwrap();
        volume.flush().await.unwrap();
        volume.shutdown().await.unwrap();
    }

    async fn read_root_file(
        control: &ControlPlane,
        object_store: Arc<dyn ObjectStore>,
        record: &VolumeRecord,
        name: &[u8],
    ) -> Vec<u8> {
        let dek = control.unwrap_volume_dek(record).await.unwrap();
        let volume = Volume::open(record, dek, object_store).await.unwrap();
        let creds = Credentials::root();
        let attr = volume.lookup(&creds, ROOT_INO, name).await.unwrap();
        let bytes = volume
            .read(&creds, attr.ino, 0, attr.size as u32)
            .await
            .unwrap()
            .to_vec();
        volume.shutdown().await.unwrap();
        bytes
    }

    fn create_block_opts(size_bytes: u64) -> slatefs_core::volume::CreateBlockVolumeOptions {
        slatefs_core::volume::CreateBlockVolumeOptions {
            cipher: Cipher::Aes256Gcm,
            chunk_size: 4096,
            compression: Compression::Lz4,
            quota: QuotaLimits::default(),
            note: None,
            size_bytes,
        }
    }

    async fn available_admin_state(
        object_store: Arc<dyn ObjectStore>,
        kms: Arc<dyn Kms>,
        targets: HashMap<(String, String), Arc<Volume>>,
        auth_token: Option<String>,
    ) -> Arc<AdminState> {
        Arc::new(AdminState {
            targets: Arc::new(Mutex::new(targets)),
            block_targets: Arc::new(Mutex::new(HashMap::new())),
            control: AdminControl::Available(Arc::new(
                ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
                    .await
                    .unwrap(),
            )),
            object_store,
            kms,
            config_exports: Arc::new(Vec::new()),
            export_metrics: ExportMetrics::default(),
            started_at: Instant::now(),
            export_count: 1,
            snapshot_export_count: 0,
            auth_token,
            allow_cert_auth: false,
            node_id: None,
        })
    }

    fn unavailable_admin_state(
        object_store: Arc<dyn ObjectStore>,
        targets: HashMap<(String, String), Arc<Volume>>,
        auth_token: Option<String>,
    ) -> Arc<AdminState> {
        Arc::new(AdminState {
            targets: Arc::new(Mutex::new(targets)),
            block_targets: Arc::new(Mutex::new(HashMap::new())),
            control: AdminControl::Unavailable("test unavailable".to_string()),
            object_store,
            kms: Arc::new(StaticKms::new(Secret32::from_bytes([251; 32]))),
            config_exports: Arc::new(Vec::new()),
            export_metrics: ExportMetrics::default(),
            started_at: Instant::now(),
            export_count: 1,
            snapshot_export_count: 0,
            auth_token,
            allow_cert_auth: false,
            node_id: None,
        })
    }

    async fn admin_exchange(state: Arc<AdminState>, request: &[u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_admin_connection(stream, state, None).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        server.await.unwrap();
        String::from_utf8(response).unwrap()
    }

    fn response_status(response: &str) -> u16 {
        response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap()
            .parse()
            .unwrap()
    }

    fn response_header(response: &str, name: &str) -> Option<String> {
        let head = response.split_once("\r\n\r\n").map(|(head, _)| head)?;
        head.lines().skip(1).find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    fn response_body(response: &str) -> &str {
        response.split_once("\r\n\r\n").unwrap().1
    }

    fn patch_request(path: &str, request_id: &str, body: &str) -> String {
        format!(
            "PATCH {path} HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {request_id}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    struct TlsAdminServer {
        addr: SocketAddr,
        task: JoinHandle<()>,
    }

    impl TlsAdminServer {
        async fn start(state: Arc<AdminState>, tls: SharedServerConfig) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                serve_admin_listener(listener, state, Some(tls))
                    .await
                    .unwrap();
            });
            Self { addr, task }
        }

        async fn shutdown(self) {
            self.task.abort();
            let _ = self.task.await;
        }
    }

    struct TestCerts {
        ca: PathBuf,
        ca_issuer: Issuer<'static, KeyPair>,
        server_cert: PathBuf,
        server_key: PathBuf,
        client_cert: PathBuf,
        client_key: PathBuf,
    }

    impl TestCerts {
        fn generate(dir: &Path) -> TestResult<Self> {
            let (ca_cert, ca_issuer) = new_ca()?;
            let (server_cert, server_key) = new_leaf(
                &ca_issuer,
                "slatefs-admin",
                &["localhost", "127.0.0.1", "cert-a.local"],
                ExtendedKeyUsagePurpose::ServerAuth,
            )?;
            let (client_cert, client_key) = new_leaf(
                &ca_issuer,
                "slatefs-client",
                &["slatefs-client"],
                ExtendedKeyUsagePurpose::ClientAuth,
            )?;

            let ca = dir.join("ca.pem");
            let server_cert_path = dir.join("server.pem");
            let server_key_path = dir.join("server-key.pem");
            let client_cert_path = dir.join("client.pem");
            let client_key_path = dir.join("client-key.pem");
            fs::write(&ca, ca_cert.pem())?;
            fs::write(&server_cert_path, server_cert.pem())?;
            fs::write(&server_key_path, server_key.serialize_pem())?;
            fs::write(&client_cert_path, client_cert.pem())?;
            fs::write(&client_key_path, client_key.serialize_pem())?;

            Ok(Self {
                ca,
                ca_issuer,
                server_cert: server_cert_path,
                server_key: server_key_path,
                client_cert: client_cert_path,
                client_key: client_key_path,
            })
        }

        fn overwrite_server_leaf(&self, marker_san: &str) -> TestResult<()> {
            let (server_cert, server_key) = new_leaf(
                &self.ca_issuer,
                "slatefs-admin-reloaded",
                &["localhost", "127.0.0.1", marker_san],
                ExtendedKeyUsagePurpose::ServerAuth,
            )?;
            fs::write(&self.server_cert, server_cert.pem())?;
            fs::write(&self.server_key, server_key.serialize_pem())?;
            Ok(())
        }
    }

    fn new_ca() -> TestResult<(Certificate, Issuer<'static, KeyPair>)> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "slatefs-test-ca");
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        Ok((cert, Issuer::new(params, key_pair)))
    }

    fn new_leaf(
        issuer: &Issuer<'static, KeyPair>,
        common_name: &str,
        sans: &[&str],
        eku: ExtendedKeyUsagePurpose,
    ) -> TestResult<(Certificate, KeyPair)> {
        let mut params =
            CertificateParams::new(sans.iter().map(|san| (*san).to_owned()).collect::<Vec<_>>())?;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.extended_key_usages.push(eku);
        let key_pair = KeyPair::generate()?;
        let cert = params.signed_by(&key_pair, issuer)?;
        Ok((cert, key_pair))
    }

    fn admin_tls_config(certs: &TestCerts, client_ca: bool) -> TestResult<SharedServerConfig> {
        let loaded = load_admin_tls_config(&AdminConfig {
            listen: None,
            token: None,
            token_file: None,
            tls_cert: Some(certs.server_cert.clone()),
            tls_key: Some(certs.server_key.clone()),
            tls_client_ca: client_ca.then(|| certs.ca.clone()),
            allow_cert_auth: false,
        })?
        .unwrap();
        Ok(shared_server_config(loaded.config))
    }

    fn tls_client_config(
        ca_path: &Path,
        identity: Option<(&Path, &Path)>,
    ) -> TestResult<Arc<tokio_rustls::rustls::ClientConfig>> {
        install_rustls_provider();
        let roots = load_admin_root_cert_store(ca_path)?;
        let builder = tokio_rustls::rustls::ClientConfig::builder().with_root_certificates(roots);
        let mut config = match identity {
            Some((cert_path, key_path)) => builder.with_client_auth_cert(
                load_admin_cert_chain(cert_path)?,
                load_admin_private_key(key_path)?,
            )?,
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    async fn tls_admin_exchange(
        addr: SocketAddr,
        ca_path: &Path,
        identity: Option<(&Path, &Path)>,
        request: &[u8],
    ) -> TestResult<String> {
        let stream = TcpStream::connect(addr).await?;
        let connector = TlsConnector::from(tls_client_config(ca_path, identity)?);
        let server_name = ServerName::try_from("localhost")?.to_owned();
        let mut stream = connector.connect(server_name, stream).await?;
        stream.write_all(request).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response)?)
    }

    async fn tls_admin_connect(
        addr: SocketAddr,
        ca_path: &Path,
    ) -> TestResult<tokio_rustls::client::TlsStream<TcpStream>> {
        let stream = TcpStream::connect(addr).await?;
        let connector = TlsConnector::from(tls_client_config(ca_path, None)?);
        let server_name = ServerName::try_from("localhost")?.to_owned();
        Ok(connector.connect(server_name, stream).await?)
    }

    fn peer_dns_names(
        stream: &tokio_rustls::client::TlsStream<TcpStream>,
    ) -> TestResult<Vec<String>> {
        let (_, connection) = stream.get_ref();
        let cert = connection
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| std::io::Error::other("missing peer certificate"))?;
        let (_, cert) = parse_x509_certificate(cert.as_ref())
            .map_err(|error| std::io::Error::other(format!("parse peer certificate: {error}")))?;
        let names = cert
            .subject_alternative_name()
            .map_err(|error| std::io::Error::other(format!("parse peer SAN: {error}")))?
            .map(|san| {
                san.value
                    .general_names
                    .iter()
                    .filter_map(|name| match name {
                        GeneralName::DNSName(value) => Some((*value).to_string()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(names)
    }

    async fn finish_tls_admin_request(
        stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    ) -> TestResult<String> {
        stream
            .write_all(b"GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response)?)
    }

    fn admin_reload_target(
        certs: &TestCerts,
        metrics: ExportMetrics,
    ) -> TestResult<(SharedServerConfig, Arc<TlsReloadTarget>, i64)> {
        let kind = TlsReloadKind::Admin {
            cert_path: certs.server_cert.clone(),
            key_path: certs.server_key.clone(),
            client_ca_path: None,
        };
        let loaded = load_tls_config(&kind)?;
        let expiry = loaded.expiry_timestamp_seconds;
        let shared = shared_server_config(Arc::clone(&loaded.config));
        let target = Arc::new(TlsReloadTarget::new(
            "admin".to_string(),
            kind,
            Arc::clone(&shared),
            metrics,
            &loaded,
        ));
        Ok((shared, target, expiry))
    }

    async fn tcp_exchange(addr: SocketAddr, request: &[u8]) -> std::io::Result<String> {
        let mut client = TcpStream::connect(addr).await?;
        client.write_all(request).await?;
        let _ = client.shutdown().await;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await?;
        Ok(String::from_utf8_lossy(&response).to_string())
    }

    async fn poll_live_limits_once(
        manager: Arc<tokio::sync::Mutex<ExportManager>>,
        object_store: Arc<dyn ObjectStore>,
        kms: Arc<dyn Kms>,
    ) {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        tick.tick().await;
        tick.tick().await;
        let reader = ControlReader::open(object_store, kms).await.unwrap();
        manager
            .lock()
            .await
            .reload_live_limits(&reader)
            .await
            .unwrap();
        reader.close().await.unwrap();
    }

    async fn poll_export_control_once(
        manager: Arc<tokio::sync::Mutex<ExportManager>>,
        object_store: Arc<dyn ObjectStore>,
        kms: Arc<dyn Kms>,
    ) {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        tick.tick().await;
        tick.tick().await;
        let reader = ControlReader::open(object_store, kms).await.unwrap();
        {
            let mut manager = manager.lock().await;
            manager.reconcile(&reader).await.unwrap();
            manager.reload_live_limits(&reader).await.unwrap();
        }
        reader.close().await.unwrap();
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
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([5; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
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

        let mut targets = HashMap::new();
        targets.insert(("t".to_string(), "v".to_string()), Arc::clone(&volume));
        let state =
            available_admin_state(Arc::clone(&object_store), Arc::clone(&kms), targets, None).await;

        let response = admin_exchange(
            Arc::clone(&state),
            b"POST /snapshot/t/v?name=admin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response_header(&response, REQUEST_ID_HEADER).is_some());
        let snapshot_id = response
            .lines()
            .find_map(|line| line.strip_prefix("id="))
            .expect("snapshot id")
            .to_string();

        let alias_response = admin_exchange(
            state,
            b"POST /admin/v1/tenants/t/volumes/v/snapshot?name=v1 HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: alias-req\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert_eq!(response_status(&alias_response), 200, "{alias_response}");
        assert_eq!(
            response_header(&alias_response, REQUEST_ID_HEADER).as_deref(),
            Some("alias-req")
        );
        let alias_body: Value = serde_json::from_str(response_body(&alias_response)).unwrap();
        assert_eq!(alias_body["snapshot"]["name"], "v1");

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_v1_errors_echo_request_id_with_json_envelope() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let state = unavailable_admin_state(object_store, HashMap::new(), None);
        let response = admin_exchange(
            state,
            b"GET /admin/v1/does-not-exist HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: req-123\r\n\r\n",
        )
        .await;
        assert_eq!(response_status(&response), 404, "{response}");
        assert_eq!(
            response_header(&response, REQUEST_ID_HEADER).as_deref(),
            Some("req-123")
        );
        let body: Value = serde_json::from_str(response_body(&response)).unwrap();
        assert_eq!(body["error"]["code"], "not_found");
        assert_eq!(body["error"]["request_id"], "req-123");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_v1_requires_bearer_token_when_configured() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let state = unavailable_admin_state(object_store, HashMap::new(), Some("secret".into()));
        let response = admin_exchange(
            state,
            b"GET /admin/v1/tenants HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: auth-req\r\n\r\n",
        )
        .await;
        assert_eq!(response_status(&response), 401, "{response}");
        assert_eq!(
            response_header(&response, REQUEST_ID_HEADER).as_deref(),
            Some("auth-req")
        );
        let body: Value = serde_json::from_str(response_body(&response)).unwrap();
        assert_eq!(body["error"]["code"], "unauthorized");
        assert_eq!(body["error"]["request_id"], "auth-req");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn https_admin_serves_tls_and_rejects_plain_http() -> TestResult<()> {
        let dir = tempfile::tempdir()?;
        let certs = TestCerts::generate(dir.path())?;
        let object_store = store::resolve_root("memory:///")?;
        let state = unavailable_admin_state(object_store, HashMap::new(), Some(ADMIN_TOKEN.into()));
        let server = TlsAdminServer::start(state, admin_tls_config(&certs, false)?).await;

        let response = tls_admin_exchange(
            server.addr,
            &certs.ca,
            None,
            b"GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await?;
        assert_eq!(response_status(&response), 200, "{response}");

        let plain = tcp_exchange(
            server.addr,
            b"GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert!(
            plain.as_deref().unwrap_or_default().is_empty()
                || !plain.unwrap().starts_with("HTTP/1.1 200"),
            "plain HTTP unexpectedly reached TLS listener"
        );

        server.shutdown().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_tls_reloads_certificates_without_dropping_existing_connections() -> TestResult<()>
    {
        let dir = tempfile::tempdir()?;
        let certs = TestCerts::generate(dir.path())?;
        let metrics = ExportMetrics::default();
        let (tls, target, initial_expiry) = admin_reload_target(&certs, metrics.clone())?;
        let object_store = store::resolve_root("memory:///")?;
        let state = unavailable_admin_state(object_store, HashMap::new(), Some(ADMIN_TOKEN.into()));
        let server = TlsAdminServer::start(state, tls).await;

        let mut existing = tls_admin_connect(server.addr, &certs.ca).await?;
        assert!(
            peer_dns_names(&existing)?
                .iter()
                .any(|name| name == "cert-a.local"),
            "initial TLS connection did not see cert A"
        );
        let rendered = render_daemon_metrics_with_exports(&[], &metrics);
        assert!(
            rendered.contains(&format!(
                "slatefs_tls_cert_expiry_timestamp_seconds{{surface=\"admin\"}} {initial_expiry}"
            )),
            "{rendered}"
        );

        certs.overwrite_server_leaf("cert-b.local")?;
        target.reload_if_changed(false);
        let mut reloaded = tls_admin_connect(server.addr, &certs.ca).await?;
        assert!(
            peer_dns_names(&reloaded)?
                .iter()
                .any(|name| name == "cert-b.local"),
            "new TLS connection did not see cert B"
        );
        let response = finish_tls_admin_request(&mut existing).await?;
        assert_eq!(response_status(&response), 200, "{response}");
        let response = finish_tls_admin_request(&mut reloaded).await?;
        assert_eq!(response_status(&response), 200, "{response}");
        let rendered = render_daemon_metrics_with_exports(&[], &metrics);
        assert!(
            rendered.contains("slatefs_tls_reloads_total{surface=\"admin\"} 1"),
            "{rendered}"
        );

        fs::write(&certs.server_key, b"not a pem key")?;
        target.reload_if_changed(false);
        let mut after_bad_reload = tls_admin_connect(server.addr, &certs.ca).await?;
        assert!(
            peer_dns_names(&after_bad_reload)?
                .iter()
                .any(|name| name == "cert-b.local"),
            "bad reload replaced the last good TLS config"
        );
        let response = finish_tls_admin_request(&mut after_bad_reload).await?;
        assert_eq!(response_status(&response), 200, "{response}");
        let rendered = render_daemon_metrics_with_exports(&[], &metrics);
        assert!(
            rendered.contains("slatefs_tls_reload_failures_total{surface=\"admin\"} 1"),
            "{rendered}"
        );

        server.shutdown().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mtls_requires_client_cert_and_allows_token_auth() -> TestResult<()> {
        let dir = tempfile::tempdir()?;
        let certs = TestCerts::generate(dir.path())?;
        let object_store = store::resolve_root("memory:///")?;
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([38; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms)).await?;
        control.close().await?;
        let state =
            available_admin_state(object_store, kms, HashMap::new(), Some(ADMIN_TOKEN.into()))
                .await;
        let server = TlsAdminServer::start(state, admin_tls_config(&certs, true)?).await;

        let rejected = tls_admin_exchange(
            server.addr,
            &certs.ca,
            None,
            format!(
                "GET /admin/v1/nodes HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {ADMIN_TOKEN}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
        assert!(
            rejected.is_err(),
            "mTLS listener accepted a request without client certificate"
        );

        let response = tls_admin_exchange(
            server.addr,
            &certs.ca,
            Some((&certs.client_cert, &certs.client_key)),
            format!(
                "GET /admin/v1/nodes HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {ADMIN_TOKEN}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
        assert_eq!(response_status(&response), 200, "{response}");

        server.shutdown().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mtls_cert_auth_records_cert_principal_in_audit() -> TestResult<()> {
        let dir = tempfile::tempdir()?;
        let certs = TestCerts::generate(dir.path())?;
        let object_store = store::resolve_root("memory:///")?;
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([37; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms)).await?;
        control.create_tenant("t", None).await?;
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await?;
        control.close().await?;

        let state = available_admin_state(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            HashMap::new(),
            Some(ADMIN_TOKEN.into()),
        )
        .await;
        let mut state = (*state).clone();
        state.allow_cert_auth = true;
        let server = TlsAdminServer::start(Arc::new(state), admin_tls_config(&certs, true)?).await;

        let quota_patch = patch_request(
            "/admin/v1/tenants/t/volumes/v/quota",
            "cert-quota",
            r#"{"bytes_soft":512}"#,
        );
        let response = tls_admin_exchange(
            server.addr,
            &certs.ca,
            Some((&certs.client_cert, &certs.client_key)),
            quota_patch.as_bytes(),
        )
        .await?;
        assert_eq!(response_status(&response), 200, "{response}");

        let control = ControlPlane::open(Arc::clone(&object_store), kms).await?;
        let (records, _) = control
            .list_audit(AuditQuery {
                action: Some(AuditAction::QuotaSet),
                newest_first: false,
                ..AuditQuery::default()
            })
            .await?;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].actor.principal.as_deref(),
            Some("cert:slatefs-client")
        );

        server.shutdown().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn readyz_degrades_when_control_reader_unavailable() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let state = unavailable_admin_state(object_store, HashMap::new(), Some("secret".into()));
        let response = admin_exchange(
            state,
            b"GET /readyz?verbose=1 HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: ready-req\r\n\r\n",
        )
        .await;
        assert_eq!(response_status(&response), 503, "{response}");
        assert_eq!(
            response_header(&response, REQUEST_ID_HEADER).as_deref(),
            Some("ready-req")
        );
        let body: Value = serde_json::from_str(response_body(&response)).unwrap();
        assert_eq!(body["status"], "degraded");
        assert_eq!(
            body["identity"]["server_version"],
            env!("CARGO_PKG_VERSION")
        );
        let control = body["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == "control_plane")
            .unwrap();
        assert_eq!(control["ok"], false);
    }

    fn audit_record(
        time: u64,
        request_id: &str,
        tenant: &str,
        volume: &str,
        action: AuditAction,
    ) -> AuditRecord {
        let mut record = AuditRecord::new(
            AuditActor {
                plane: AuditPlane::Admin,
                principal: None,
                source_ip: Some("127.0.0.1".to_string()),
                client_agent: Some("test".to_string()),
            },
            action,
            AuditScope {
                tenant: Some(tenant.to_string()),
                volume: Some(volume.to_string()),
                node: None,
            },
            request_id,
            AuditOutcome::Success,
        );
        record.time = time;
        record
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_v1_audit_filters_and_paginates() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([6; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control
            .append_audit_records([
                audit_record(10, "req-1", "t", "v", AuditAction::VolumeCreate),
                audit_record(20, "req-2", "t", "v", AuditAction::VolumeCreate),
                audit_record(30, "req-3", "t", "other", AuditAction::SnapshotCreate),
            ])
            .await
            .unwrap();
        let state =
            available_admin_state(Arc::clone(&object_store), kms, HashMap::new(), None).await;

        let first = admin_exchange(
            Arc::clone(&state),
            b"GET /admin/v1/audit?tenant=t&volume=v&action=VolumeCreate&limit=1&newest_first=false HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert_eq!(response_status(&first), 200, "{first}");
        let first_body: Value = serde_json::from_str(response_body(&first)).unwrap();
        assert_eq!(first_body["records"].as_array().unwrap().len(), 1);
        assert_eq!(first_body["records"][0]["request_id"], "req-1");
        let next = first_body["next_page_token"].as_str().unwrap();

        let second_request = format!(
            "GET /admin/v1/audit?tenant=t&volume=v&action=VolumeCreate&limit=1&newest_first=false&page_token={next} HTTP/1.1\r\nHost: localhost\r\n\r\n"
        );
        let second = admin_exchange(state, second_request.as_bytes()).await;
        let second_body: Value = serde_json::from_str(response_body(&second)).unwrap();
        assert_eq!(second_body["records"][0]["request_id"], "req-2");
        assert!(second_body["next_page_token"].is_null());
        control.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_v1_lists_tenants_volumes_and_nodes() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([7; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control
            .create_tenant("t", Some("Tenant".to_string()))
            .await
            .unwrap();
        let record = slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        control
            .register_daemon_node(
                "node-a",
                Some("10.0.0.10:2049".to_string()),
                Some("127.0.0.1:12081".to_string()),
                None,
                1,
            )
            .await
            .unwrap();
        control
            .assign_volume_to_node("t", "v", "node-a")
            .await
            .unwrap();
        control
            .heartbeat_daemon_node("node-a", DaemonNodeState::Healthy, DaemonMetrics::default())
            .await
            .unwrap();
        let dek = control.unwrap_volume_dek(&record).await.unwrap();
        let volume = Volume::open(&record, dek, Arc::clone(&object_store))
            .await
            .unwrap();
        let mut targets = HashMap::new();
        targets.insert(("t".to_string(), "v".to_string()), Arc::clone(&volume));
        let state = available_admin_state(Arc::clone(&object_store), kms, targets, None).await;

        let tenants = admin_exchange(
            Arc::clone(&state),
            b"GET /admin/v1/tenants HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        let tenants_body: Value = serde_json::from_str(response_body(&tenants)).unwrap();
        assert_eq!(tenants_body["tenants"][0]["name"], "t");
        assert_eq!(tenants_body["tenants"][0]["volume_count"], 1);

        let volumes = admin_exchange(
            Arc::clone(&state),
            b"GET /admin/v1/tenants/t/volumes HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        let volumes_body: Value = serde_json::from_str(response_body(&volumes)).unwrap();
        assert_eq!(volumes_body["volumes"][0]["name"], "v");
        assert_eq!(
            volumes_body["volumes"][0]["placement"]["primary_node"],
            "node-a"
        );
        assert!(volumes_body["volumes"][0]["quota"]["usage"]["bytes"].is_number());

        let nodes = admin_exchange(
            state,
            b"GET /admin/v1/nodes HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        let nodes_body: Value = serde_json::from_str(response_body(&nodes)).unwrap();
        assert_eq!(nodes_body["nodes"][0]["id"], "node-a");
        assert_eq!(nodes_body["nodes"][0]["state"], "Healthy");

        volume.shutdown().await.unwrap();
        control.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_v1_export_crud_and_audit() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([8; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        control.close().await.unwrap();

        let state = available_admin_state(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            HashMap::new(),
            None,
        )
        .await;
        let create = admin_exchange(
            Arc::clone(&state),
            b"POST /admin/v1/exports/exp1 HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: export-create\r\nContent-Type: application/json\r\nContent-Length: 108\r\n\r\n{\"tenant\":\"t\",\"volume\":\"v\",\"listen\":\"127.0.0.1:12049\",\"protocol\":\"nfs\",\"allowed_clients\":[\"127.0.0.1\"]}",
        )
        .await;
        assert_eq!(response_status(&create), 201, "{create}");
        let create_body: Value = serde_json::from_str(response_body(&create)).unwrap();
        assert_eq!(create_body["export"]["id"], "exp1");
        assert_eq!(create_body["export"]["source"], "control");

        tokio::time::sleep(Duration::from_millis(1200)).await;
        let list = admin_exchange(
            Arc::clone(&state),
            b"GET /admin/v1/exports HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert_eq!(response_status(&list), 200, "{list}");
        let list_body: Value = serde_json::from_str(response_body(&list)).unwrap();
        assert_eq!(list_body["exports"][0]["id"], "exp1");

        let patch = admin_exchange(
            Arc::clone(&state),
            b"PATCH /admin/v1/exports/exp1 HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: export-update\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"enabled\":false}",
        )
        .await;
        assert_eq!(response_status(&patch), 200, "{patch}");
        let patch_body: Value = serde_json::from_str(response_body(&patch)).unwrap();
        assert_eq!(patch_body["export"]["enabled"], false);

        let delete = admin_exchange(
            state,
            b"DELETE /admin/v1/exports/exp1 HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: export-delete\r\n\r\n",
        )
        .await;
        assert_eq!(response_status(&delete), 200, "{delete}");

        let control = ControlPlane::open(Arc::clone(&object_store), kms)
            .await
            .unwrap();
        let (records, _) = control
            .list_audit(AuditQuery {
                action: Some(AuditAction::ExportCreate),
                newest_first: false,
                ..AuditQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].request_id, "export-create");
        assert_eq!(records[0].scope.tenant.as_deref(), Some("t"));
        control.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_v1_config_exports_are_read_only() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let export = ExportConfig {
            tenant: "t".to_string(),
            volume: "v".to_string(),
            snapshot: None,
            listen: "127.0.0.1:12049".to_string(),
            allowed_clients: Vec::new(),
            protocol: ExportProtocol::Nfs,
            read_only: false,
            sync: NbdSyncMode::Default,
            nbd_tls_cert: None,
            nbd_tls_key: None,
            nbd_tls_client_ca: None,
            p9_token: None,
            p9_tls_cert: None,
            p9_tls_key: None,
            squash: Default::default(),
            atime: Default::default(),
            anon_uid: 65534,
            anon_gid: 65534,
        };
        let state = Arc::new(AdminState {
            targets: Arc::new(Mutex::new(HashMap::new())),
            block_targets: Arc::new(Mutex::new(HashMap::new())),
            control: AdminControl::Unavailable("unused".to_string()),
            object_store,
            kms: Arc::new(StaticKms::new(Secret32::from_bytes([9; 32]))),
            config_exports: Arc::new(vec![ConfigExportRecord {
                id: "config-0".to_string(),
                export,
            }]),
            export_metrics: ExportMetrics::default(),
            started_at: Instant::now(),
            export_count: 1,
            snapshot_export_count: 0,
            auth_token: None,
            allow_cert_auth: false,
            node_id: None,
        });

        let get = admin_exchange(
            Arc::clone(&state),
            b"GET /admin/v1/exports/config-0 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert_eq!(response_status(&get), 200, "{get}");
        let get_body: Value = serde_json::from_str(response_body(&get)).unwrap();
        assert_eq!(get_body["export"]["source"], "config");
        assert_eq!(get_body["export"]["read_only"], false);

        let patch = admin_exchange(
            state,
            b"PATCH /admin/v1/exports/config-0 HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"enabled\":false}",
        )
        .await;
        assert_eq!(response_status(&patch), 409, "{patch}");
        let patch_body: Value = serde_json::from_str(response_body(&patch)).unwrap();
        assert_eq!(patch_body["error"]["code"], "conflict");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_v1_quota_and_rate_patch_validate_clear_and_audit() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([33; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        control.close().await.unwrap();

        let state = available_admin_state(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            HashMap::new(),
            None,
        )
        .await;

        let quota_patch = patch_request(
            "/admin/v1/tenants/t/volumes/v/quota",
            "quota-set",
            r#"{"bytes_soft":512,"bytes_hard":1024,"bytes_grace":123,"inodes_hard":null}"#,
        );
        let quota_response = admin_exchange(Arc::clone(&state), quota_patch.as_bytes()).await;
        assert_eq!(response_status(&quota_response), 200, "{quota_response}");
        let quota_body: Value = serde_json::from_str(response_body(&quota_response)).unwrap();
        assert_eq!(quota_body["quota"]["limits"]["bytes"]["soft"], 512);
        assert_eq!(quota_body["quota"]["limits"]["bytes"]["hard"], 1024);
        assert_eq!(quota_body["quota"]["limits"]["bytes"]["grace_until"], 123);
        assert!(quota_body["quota"]["limits"]["inodes"]["hard"].is_null());
        assert!(quota_body["quota"]["usage"].is_null());

        let rate_patch = patch_request(
            "/admin/v1/tenants/t/rate",
            "rate-set",
            r#"{"ops_per_second":5,"bytes_per_second":null}"#,
        );
        let rate_response = admin_exchange(Arc::clone(&state), rate_patch.as_bytes()).await;
        assert_eq!(response_status(&rate_response), 200, "{rate_response}");
        let rate_body: Value = serde_json::from_str(response_body(&rate_response)).unwrap();
        assert_eq!(rate_body["rate_limits"]["ops_per_second"], 5);
        assert!(rate_body["rate_limits"]["bytes_per_second"].is_null());

        let empty_quota = patch_request("/admin/v1/tenants/t/volumes/v/quota", "quota-empty", "{}");
        let empty_response = admin_exchange(Arc::clone(&state), empty_quota.as_bytes()).await;
        assert_eq!(response_status(&empty_response), 400, "{empty_response}");
        let empty_body: Value = serde_json::from_str(response_body(&empty_response)).unwrap();
        assert_eq!(empty_body["error"]["code"], "bad_request");
        assert!(
            empty_body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("provide at least one quota field")
        );

        let invalid_rate = patch_request(
            "/admin/v1/tenants/t/rate",
            "rate-zero",
            r#"{"ops_per_second":0}"#,
        );
        let invalid_response = admin_exchange(Arc::clone(&state), invalid_rate.as_bytes()).await;
        assert_eq!(
            response_status(&invalid_response),
            400,
            "{invalid_response}"
        );
        let invalid_body: Value = serde_json::from_str(response_body(&invalid_response)).unwrap();
        assert_eq!(invalid_body["error"]["code"], "bad_request");
        assert!(
            invalid_body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("limit must be positive or none")
        );

        let control = ControlPlane::open(Arc::clone(&object_store), kms)
            .await
            .unwrap();
        let (quota_records, _) = control
            .list_audit(AuditQuery {
                action: Some(AuditAction::QuotaSet),
                newest_first: false,
                ..AuditQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(quota_records.len(), 1);
        assert_eq!(quota_records[0].request_id, "quota-set");
        assert_eq!(quota_records[0].scope.tenant.as_deref(), Some("t"));
        assert_eq!(quota_records[0].scope.volume.as_deref(), Some("v"));

        let (rate_records, _) = control
            .list_audit(AuditQuery {
                action: Some(AuditAction::TenantRateSet),
                newest_first: false,
                ..AuditQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(rate_records.len(), 1);
        assert_eq!(rate_records[0].request_id, "rate-set");
        assert_eq!(rate_records[0].scope.tenant.as_deref(), Some("t"));
        assert!(rate_records[0].scope.volume.is_none());
        control.close().await.unwrap();
    }

    fn test_config(exports: Vec<ExportConfig>) -> Config {
        let mut config = Config::parse(
            r#"
                [object_store]
                url = "memory:///"

                [kms]
                provider = "static"
                key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

                [export_control]
                poll_interval_secs = 1
            "#,
        )
        .unwrap();
        config.exports = exports;
        config
    }

    fn nfs_export(id: &str, listen: &str) -> ExportRecord {
        ExportRecord::from_config(
            id.to_string(),
            ExportConfig {
                tenant: "t".to_string(),
                volume: "v".to_string(),
                snapshot: None,
                listen: listen.to_string(),
                allowed_clients: Vec::new(),
                protocol: ExportProtocol::Nfs,
                read_only: false,
                sync: NbdSyncMode::Default,
                nbd_tls_cert: None,
                nbd_tls_key: None,
                nbd_tls_client_ca: None,
                p9_token: None,
                p9_tls_cert: None,
                p9_tls_key: None,
                squash: Default::default(),
                atime: Default::default(),
                anon_uid: 65534,
                anon_gid: 65534,
            },
            true,
        )
    }

    fn nbd_export(id: &str, listen: &str) -> ExportRecord {
        ExportRecord::from_config(
            id.to_string(),
            ExportConfig {
                tenant: "t".to_string(),
                volume: "b".to_string(),
                snapshot: None,
                listen: listen.to_string(),
                allowed_clients: Vec::new(),
                protocol: ExportProtocol::Nbd,
                read_only: false,
                sync: NbdSyncMode::Default,
                nbd_tls_cert: None,
                nbd_tls_key: None,
                nbd_tls_client_ca: None,
                p9_token: None,
                p9_tls_cert: None,
                p9_tls_key: None,
                squash: Default::default(),
                atime: Default::default(),
                anon_uid: 65534,
                anon_gid: 65534,
            },
            true,
        )
    }

    fn p9_tls_export(
        id: &str,
        listen: &str,
        cert_path: PathBuf,
        key_path: PathBuf,
    ) -> ExportRecord {
        ExportRecord::from_config(
            id.to_string(),
            ExportConfig {
                tenant: "t".to_string(),
                volume: "v".to_string(),
                snapshot: None,
                listen: listen.to_string(),
                allowed_clients: Vec::new(),
                protocol: ExportProtocol::P9,
                read_only: false,
                sync: NbdSyncMode::Default,
                nbd_tls_cert: None,
                nbd_tls_key: None,
                nbd_tls_client_ca: None,
                p9_token: None,
                p9_tls_cert: Some(cert_path),
                p9_tls_key: Some(key_path),
                squash: Default::default(),
                atime: Default::default(),
                anon_uid: 65534,
                anon_gid: 65534,
            },
            true,
        )
    }

    fn free_loopback_addr() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn export_manager_starts_and_stops_control_exports() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([10; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        let fh_key = control.server_fh_key().await.unwrap();
        control
            .create_export(nfs_export("exp1", "127.0.0.1:0"))
            .await
            .unwrap();
        control.close().await.unwrap();

        let config = test_config(Vec::new());
        let metrics = ExportMetrics::default();
        let mut manager = ExportManager::new(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            fh_key,
            &config,
            config_export_records(&config.exports),
            metrics.clone(),
            ExportManagerTargets {
                metrics: Arc::new(Mutex::new(Vec::new())),
                admin: Arc::new(Mutex::new(HashMap::new())),
                admin_blocks: Arc::new(Mutex::new(HashMap::new())),
            },
        );
        let reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        manager.reconcile(&reader).await.unwrap();
        assert_eq!(metrics.active_total(), 1);

        let control = ControlPlane::open(Arc::clone(&object_store), kms)
            .await
            .unwrap();
        control.disable_export("exp1").await.unwrap();
        control.close().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        manager.reconcile(&reader).await.unwrap();
        assert_eq!(metrics.active_total(), 0);
        manager.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn export_manager_serves_nbd_round_trip_and_disable_closes_session() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([44; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_block_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "b",
            create_block_opts(4096 * 2),
        )
        .await
        .unwrap();
        let fh_key = control.server_fh_key().await.unwrap();
        let listen = free_loopback_addr();
        control
            .create_export(nbd_export("nbd1", &listen))
            .await
            .unwrap();
        control.close().await.unwrap();

        let config = test_config(Vec::new());
        let metrics = ExportMetrics::default();
        let mut manager = ExportManager::new(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            fh_key,
            &config,
            config_export_records(&config.exports),
            metrics.clone(),
            ExportManagerTargets {
                metrics: Arc::new(Mutex::new(Vec::new())),
                admin: Arc::new(Mutex::new(HashMap::new())),
                admin_blocks: Arc::new(Mutex::new(HashMap::new())),
            },
        );
        let reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        manager.reconcile(&reader).await.unwrap();
        assert_eq!(metrics.active_total(), 1);

        let addr = listen.parse().unwrap();
        let mut client = NbdTestClient::connect(addr, "/t/b").await.unwrap();
        client
            .write_at(1, 512, Bytes::from_static(b"daemon-nbd"), true)
            .await
            .unwrap();
        assert_eq!(client.read_reply().await.unwrap().error, 0);
        client.read_at(2, 512, 10).await.unwrap();
        let reply = client.read_reply().await.unwrap();
        assert_eq!(reply.error, 0);
        assert_eq!(&reply.data[..], b"daemon-nbd");

        let control = ControlPlane::open(Arc::clone(&object_store), kms)
            .await
            .unwrap();
        control.disable_export("nbd1").await.unwrap();
        control.close().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        manager.reconcile(&reader).await.unwrap();
        assert_eq!(metrics.active_total(), 0);

        let write_after_disable = client.cache(3, 0, 1).await;
        if write_after_disable.is_ok() {
            let closed = tokio::time::timeout(Duration::from_secs(2), client.read_reply()).await;
            assert!(
                closed.is_ok(),
                "NBD session did not close after export disable"
            );
            assert!(closed.unwrap().is_err(), "expected closed NBD session");
        }
        manager.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn export_manager_wires_tls_reload_for_p9_exports() {
        let dir = tempfile::tempdir().unwrap();
        let certs = TestCerts::generate(dir.path()).unwrap();
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([45; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        let fh_key = control.server_fh_key().await.unwrap();
        let listen = free_loopback_addr();
        control
            .create_export(p9_tls_export(
                "p9tls",
                &listen,
                certs.server_cert.clone(),
                certs.server_key.clone(),
            ))
            .await
            .unwrap();
        control.close().await.unwrap();

        let config = test_config(Vec::new());
        let metrics = ExportMetrics::default();
        let mut manager = ExportManager::new(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            fh_key,
            &config,
            config_export_records(&config.exports),
            metrics.clone(),
            ExportManagerTargets {
                metrics: Arc::new(Mutex::new(Vec::new())),
                admin: Arc::new(Mutex::new(HashMap::new())),
                admin_blocks: Arc::new(Mutex::new(HashMap::new())),
            },
        );
        let reader = ControlReader::open(Arc::clone(&object_store), kms)
            .await
            .unwrap();
        manager.reconcile(&reader).await.unwrap();
        assert_eq!(metrics.active_total(), 1);
        let targets = manager.tls_reload_targets();
        assert_eq!(targets.len(), 1);
        let rendered = render_daemon_metrics_with_exports(&[], &metrics);
        assert!(
            rendered.contains(
                "slatefs_tls_cert_expiry_timestamp_seconds{surface=\"p9:control:p9tls\"}"
            ),
            "{rendered}"
        );

        certs.overwrite_server_leaf("p9-cert-b.local").unwrap();
        targets[0].reload_if_changed(false);
        let rendered = render_daemon_metrics_with_exports(&[], &metrics);
        assert!(
            rendered.contains("slatefs_tls_reloads_total{surface=\"p9:control:p9tls\"} 1"),
            "{rendered}"
        );
        manager.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn export_manager_skips_conflicting_control_export() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([11; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        let fh_key = control.server_fh_key().await.unwrap();
        control
            .create_export(nfs_export("conflict", "127.0.0.1:0"))
            .await
            .unwrap();
        control.close().await.unwrap();

        let config = test_config(vec![nfs_export("ignored", "127.0.0.1:0").to_config()]);
        let metrics = ExportMetrics::default();
        let mut manager = ExportManager::new(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            fh_key,
            &config,
            config_export_records(&config.exports),
            metrics.clone(),
            ExportManagerTargets {
                metrics: Arc::new(Mutex::new(Vec::new())),
                admin: Arc::new(Mutex::new(HashMap::new())),
                admin_blocks: Arc::new(Mutex::new(HashMap::new())),
            },
        );
        let reader = ControlReader::open(Arc::clone(&object_store), kms)
            .await
            .unwrap();
        manager.reconcile(&reader).await.unwrap();
        assert_eq!(metrics.active_total(), 1);
        assert_eq!(
            metrics.reconcile_failures.load(Ordering::Relaxed),
            1,
            "conflicting control export should be skipped and counted"
        );
        manager.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn export_manager_reloads_live_quota_and_rate_limits() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([12; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        control
            .set_tenant_rate_limits(
                "t",
                RateLimits {
                    ops_per_second: Some(1),
                    bytes_per_second: None,
                },
            )
            .await
            .unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        let fh_key = control.server_fh_key().await.unwrap();
        control
            .create_export(nfs_export("exp-live", "127.0.0.1:0"))
            .await
            .unwrap();
        control.close().await.unwrap();

        let config = test_config(Vec::new());
        let metrics = ExportMetrics::default();
        let mut manager = ExportManager::new(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            fh_key,
            &config,
            config_export_records(&config.exports),
            metrics,
            ExportManagerTargets {
                metrics: Arc::new(Mutex::new(Vec::new())),
                admin: Arc::new(Mutex::new(HashMap::new())),
                admin_blocks: Arc::new(Mutex::new(HashMap::new())),
            },
        );
        let reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        manager.reconcile(&reader).await.unwrap();
        let volume = manager
            .open_backends
            .get(&("t".to_string(), "v".to_string(), None))
            .and_then(|backend| backend.writable.as_ref())
            .cloned()
            .expect("writable backend");
        let limiter = manager
            .rate_limiters
            .get("t")
            .cloned()
            .expect("tenant limiter");
        assert_eq!(limiter.limits().ops_per_second, Some(1));

        let creds = Credentials::root();
        let file = volume
            .create(&creds, ROOT_INO, b"file", 0o644, true)
            .await
            .unwrap();
        volume
            .write(&creds, file.ino, 0, b"12345678")
            .await
            .unwrap();

        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control
            .set_volume_quota(
                "t",
                "v",
                QuotaLimits {
                    bytes: QuotaLimit {
                        hard: Some(8),
                        ..Default::default()
                    },
                    inodes: QuotaLimit::default(),
                },
            )
            .await
            .unwrap();
        control
            .set_tenant_rate_limits(
                "t",
                RateLimits {
                    ops_per_second: Some(10),
                    bytes_per_second: Some(1024),
                },
            )
            .await
            .unwrap();
        control.close().await.unwrap();

        let fresh_reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        manager.reload_live_limits(&fresh_reader).await.unwrap();
        assert_eq!(volume.quota_hard_limits().0, Some(8));
        assert_eq!(
            limiter.limits(),
            RateLimits {
                ops_per_second: Some(10),
                bytes_per_second: Some(1024),
            }
        );
        assert!(matches!(
            volume.write(&creds, file.ino, 8, b"x").await,
            Err(slatefs_core::vfs::FsError::QuotaExceeded)
        ));

        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control
            .set_volume_quota(
                "t",
                "v",
                QuotaLimits {
                    bytes: QuotaLimit {
                        hard: Some(9),
                        ..Default::default()
                    },
                    inodes: QuotaLimit::default(),
                },
            )
            .await
            .unwrap();
        control.close().await.unwrap();
        let fresh_reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        manager.reload_live_limits(&fresh_reader).await.unwrap();
        volume.write(&creds, file.ino, 8, b"x").await.unwrap();
        manager.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_v1_quota_and_rate_patch_reload_on_watcher_poll() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([31; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        let fh_key = control.server_fh_key().await.unwrap();
        control
            .create_export(nfs_export("exp-http-limits", "127.0.0.1:0"))
            .await
            .unwrap();
        control.close().await.unwrap();

        let config = test_config(Vec::new());
        let admin_targets = Arc::new(Mutex::new(HashMap::new()));
        let admin_block_targets = Arc::new(Mutex::new(HashMap::new()));
        let mut manager = ExportManager::new(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            fh_key,
            &config,
            config_export_records(&config.exports),
            ExportMetrics::default(),
            ExportManagerTargets {
                metrics: Arc::new(Mutex::new(Vec::new())),
                admin: Arc::clone(&admin_targets),
                admin_blocks: Arc::clone(&admin_block_targets),
            },
        );
        let reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        manager.reconcile(&reader).await.unwrap();
        reader.close().await.unwrap();
        let manager = Arc::new(tokio::sync::Mutex::new(manager));
        let (volume, limiter) = {
            let manager = manager.lock().await;
            let volume = manager
                .open_backends
                .get(&("t".to_string(), "v".to_string(), None))
                .and_then(|backend| backend.writable.as_ref())
                .cloned()
                .expect("writable backend");
            let limiter = manager
                .rate_limiters
                .get("t")
                .cloned()
                .expect("tenant limiter");
            (volume, limiter)
        };

        let state = Arc::new(AdminState {
            targets: Arc::clone(&admin_targets),
            block_targets: Arc::new(Mutex::new(HashMap::new())),
            control: AdminControl::Available(Arc::new(
                ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
                    .await
                    .unwrap(),
            )),
            object_store: Arc::clone(&object_store),
            kms: Arc::clone(&kms),
            config_exports: Arc::new(Vec::new()),
            export_metrics: ExportMetrics::default(),
            started_at: Instant::now(),
            export_count: 1,
            snapshot_export_count: 0,
            auth_token: None,
            allow_cert_auth: false,
            node_id: None,
        });

        let creds = Credentials::root();
        let file = volume
            .create(&creds, ROOT_INO, b"file", 0o644, true)
            .await
            .unwrap();
        volume
            .write(&creds, file.ino, 0, b"12345678")
            .await
            .unwrap();

        let quota_patch = patch_request(
            "/admin/v1/tenants/t/volumes/v/quota",
            "quota-patch",
            r#"{"bytes_hard":8}"#,
        );
        let quota_response = admin_exchange(Arc::clone(&state), quota_patch.as_bytes()).await;
        assert_eq!(response_status(&quota_response), 200, "{quota_response}");
        let quota_body: Value = serde_json::from_str(response_body(&quota_response)).unwrap();
        assert_eq!(quota_body["quota"]["limits"]["bytes"]["hard"], 8);
        assert!(
            quota_body["quota"]["usage"]["bytes"].is_number(),
            "{quota_body}"
        );

        let rate_patch = patch_request(
            "/admin/v1/tenants/t/rate",
            "rate-patch",
            r#"{"bytes_per_second":1}"#,
        );
        let rate_response = admin_exchange(Arc::clone(&state), rate_patch.as_bytes()).await;
        assert_eq!(response_status(&rate_response), 200, "{rate_response}");
        let rate_body: Value = serde_json::from_str(response_body(&rate_response)).unwrap();
        assert_eq!(rate_body["rate_limits"]["bytes_per_second"], 1);

        poll_live_limits_once(
            Arc::clone(&manager),
            Arc::clone(&object_store),
            Arc::clone(&kms),
        )
        .await;

        assert_eq!(volume.quota_hard_limits().0, Some(8));
        assert!(matches!(
            volume.write(&creds, file.ino, 8, b"x").await,
            Err(slatefs_core::vfs::FsError::QuotaExceeded)
        ));

        assert_eq!(limiter.limits().bytes_per_second, Some(1));
        let nfs_volume: Arc<dyn Vfs> = volume.clone();
        let nfs = SlateFsNfs::new_with_rate_limiter(
            nfs_volume,
            Secret32::from_bytes([32; 32]),
            SquashPolicy::trust_as_root(),
            Some(Arc::clone(&limiter)),
        );
        let root = nfs.root_dir();
        let name = filename3(Opaque::borrowed(b"rate-limited"));
        let (rate_file, _) = nfs.create(&root, &name, sattr3::default()).await.unwrap();
        let limited = nfs.write(&rate_file, 0, b"xx", stable_how::UNSTABLE).await;
        assert!(
            matches!(limited, Err(nfsstat3::NFS3ERR_JUKEBOX)),
            "expected frontend rate rejection, got {limited:?}"
        );

        manager.lock().await.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_export_quota_patch_is_enforced_by_nfs_and_audited() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([33; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        let fh_key = control.server_fh_key().await.unwrap();
        control.close().await.unwrap();

        let config = test_config(Vec::new());
        let admin_targets = Arc::new(Mutex::new(HashMap::new()));
        let mut manager = ExportManager::new(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            fh_key.clone(),
            &config,
            config_export_records(&config.exports),
            ExportMetrics::default(),
            ExportManagerTargets {
                metrics: Arc::new(Mutex::new(Vec::new())),
                admin: Arc::clone(&admin_targets),
                admin_blocks: Arc::new(Mutex::new(HashMap::new())),
            },
        );
        let reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        manager.reconcile(&reader).await.unwrap();
        reader.close().await.unwrap();
        let manager = Arc::new(tokio::sync::Mutex::new(manager));

        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control
            .create_export(nfs_export("exp-quota-nfs", "127.0.0.1:0"))
            .await
            .unwrap();
        control.close().await.unwrap();
        poll_export_control_once(
            Arc::clone(&manager),
            Arc::clone(&object_store),
            Arc::clone(&kms),
        )
        .await;

        let volume = {
            let manager = manager.lock().await;
            manager
                .open_backends
                .get(&("t".to_string(), "v".to_string(), None))
                .and_then(|backend| backend.writable.as_ref())
                .cloned()
                .expect("writable backend")
        };
        let state = Arc::new(AdminState {
            targets: Arc::clone(&admin_targets),
            block_targets: Arc::new(Mutex::new(HashMap::new())),
            control: AdminControl::Available(Arc::new(
                ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
                    .await
                    .unwrap(),
            )),
            object_store: Arc::clone(&object_store),
            kms: Arc::clone(&kms),
            config_exports: Arc::new(Vec::new()),
            export_metrics: ExportMetrics::default(),
            started_at: Instant::now(),
            export_count: 1,
            snapshot_export_count: 0,
            auth_token: None,
            allow_cert_auth: false,
            node_id: None,
        });

        let nfs_volume: Arc<dyn Vfs> = volume.clone();
        let nfs = SlateFsNfs::new_with_rate_limiter_and_atime_policy_and_quota_audit(
            nfs_volume,
            fh_key,
            SquashPolicy::trust_as_root(),
            AtimeMode::Relatime,
            None,
            Some(quota_rejection_audit(
                Arc::clone(&object_store),
                Arc::clone(&kms),
                "t".to_string(),
                "v".to_string(),
                AuditPlane::Nfs,
            )),
        );
        let root = nfs.root_dir();
        let name = filename3(Opaque::borrowed(b"quota-live"));
        let (file, _) = nfs.create(&root, &name, sattr3::default()).await.unwrap();
        let initial = vec![7_u8; 8192];
        nfs.write(&file, 0, &initial, stable_how::UNSTABLE)
            .await
            .unwrap();
        assert_eq!(volume.quota_usage().0, 8192);

        let quota_patch = patch_request(
            "/admin/v1/tenants/t/volumes/v/quota",
            "quota-live-patch",
            r#"{"bytes_hard":1024}"#,
        );
        let quota_response = admin_exchange(Arc::clone(&state), quota_patch.as_bytes()).await;
        assert_eq!(response_status(&quota_response), 200, "{quota_response}");
        let quota_body: Value = serde_json::from_str(response_body(&quota_response)).unwrap();
        assert_eq!(quota_body["quota"]["limits"]["bytes"]["hard"], 1024);
        assert_eq!(quota_body["quota"]["usage"]["bytes"], 8192);

        poll_export_control_once(
            Arc::clone(&manager),
            Arc::clone(&object_store),
            Arc::clone(&kms),
        )
        .await;
        assert_eq!(volume.quota_hard_limits().0, Some(1024));

        let rejected = nfs.write(&file, 8192, b"x", stable_how::UNSTABLE).await;
        assert!(
            matches!(rejected, Err(nfsstat3::NFS3ERR_DQUOT)),
            "expected DQUOT, got {rejected:?}"
        );
        assert_eq!(volume.quota_rejections(), 1);

        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        let (records, _) = control
            .list_audit(AuditQuery {
                tenant: Some("t"),
                volume: Some("v"),
                action: Some(AuditAction::QuotaRejected),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].actor.plane, AuditPlane::Nfs);
        assert_eq!(records[0].outcome, AuditOutcome::Denied);
        assert_eq!(
            records[0].details.get("operation"),
            Some(&AuditDetailValue::String("write".to_string()))
        );
        control.close().await.unwrap();
        manager.lock().await.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_retention_deletes_audits_and_leaves_policyless_volumes() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([13; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "untouched",
            create_opts(),
        )
        .await
        .unwrap();
        let _old_named = slatefs_core::volume::create_snapshot(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            Some("named-old".to_string()),
        )
        .await
        .unwrap();
        let _middle = slatefs_core::volume::create_snapshot(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            None,
        )
        .await
        .unwrap();
        let newest = slatefs_core::volume::create_snapshot(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            Some("newest".to_string()),
        )
        .await
        .unwrap();
        let untouched = slatefs_core::volume::create_snapshot(
            &control,
            Arc::clone(&object_store),
            "t",
            "untouched",
            None,
        )
        .await
        .unwrap();
        control
            .set_snapshot_retention_policy("t", "v", Some(1), None)
            .await
            .unwrap();
        control.close().await.unwrap();

        let reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        let metrics = ExportMetrics::default();
        enforce_snapshot_retention(
            &reader,
            Arc::clone(&object_store),
            Arc::clone(&kms),
            metrics.clone(),
        )
        .await
        .unwrap();
        reader.close().await.unwrap();

        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        let remaining = slatefs_core::volume::list_snapshots(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            None,
        )
        .await
        .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, newest.id);
        let untouched_remaining = slatefs_core::volume::list_snapshots(
            &control,
            Arc::clone(&object_store),
            "t",
            "untouched",
            None,
        )
        .await
        .unwrap();
        assert_eq!(untouched_remaining.len(), 1);
        assert_eq!(untouched_remaining[0].id, untouched.id);

        let (records, _) = control
            .list_audit(AuditQuery {
                tenant: Some("t"),
                volume: Some("v"),
                action: Some(AuditAction::SnapshotRetentionDelete),
                newest_first: false,
                ..AuditQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        let rendered = render_daemon_metrics_with_exports(&[], &metrics);
        assert!(
            rendered
                .contains("slatefs_snapshots_retention_deleted_total{tenant=\"t\",volume=\"v\"} 2"),
            "{rendered}"
        );
        control.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_retention_skips_only_clone_pinned_checkpoints() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([14; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            create_opts(),
        )
        .await
        .unwrap();
        write_root_file(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            b"file",
            b"clone-safe",
        )
        .await;
        let old_unpinned = slatefs_core::volume::create_snapshot(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            Some("old-unpinned".to_string()),
        )
        .await
        .unwrap();
        let parent_snapshot = slatefs_core::volume::create_snapshot(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            Some("parent".to_string()),
        )
        .await
        .unwrap();
        let newer_unpinned = slatefs_core::volume::create_snapshot(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            Some("newer-unpinned".to_string()),
        )
        .await
        .unwrap();
        let clone = slatefs_core::volume::clone_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            "clone",
            slatefs_core::volume::CloneVolumeOptions {
                source_snapshot_id: Some(parent_snapshot.id.clone()),
                note: None,
            },
        )
        .await
        .unwrap();
        let clone_pins = clone
            .clone_parent_checkpoint_ids
            .clone()
            .expect("new clone should record source checkpoint pins");
        assert!(clone_pins.contains(&parent_snapshot.id));
        assert!(
            clone_pins.len() >= 2,
            "clone should record the requested checkpoint plus SlateDB's final checkpoint: {clone_pins:?}"
        );
        control
            .set_snapshot_retention_policy("t", "src", Some(0), None)
            .await
            .unwrap();
        control.close().await.unwrap();

        let reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        enforce_snapshot_retention(
            &reader,
            Arc::clone(&object_store),
            Arc::clone(&kms),
            ExportMetrics::default(),
        )
        .await
        .unwrap();
        reader.close().await.unwrap();

        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        let remaining = slatefs_core::volume::list_snapshots(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            None,
        )
        .await
        .unwrap();
        assert!(
            !remaining
                .iter()
                .any(|snapshot| snapshot.id == old_unpinned.id),
            "old unpinned checkpoint should be removed despite active clone"
        );
        assert!(
            remaining
                .iter()
                .any(|snapshot| snapshot.id == parent_snapshot.id),
            "explicit clone source checkpoint must be retained while the clone is active"
        );
        assert!(
            !remaining
                .iter()
                .any(|snapshot| snapshot.id == newer_unpinned.id),
            "newer unpinned checkpoint should be removed despite active clone"
        );
        let (records, _) = control
            .list_audit(AuditQuery {
                tenant: Some("t"),
                volume: Some("src"),
                action: Some(AuditAction::SnapshotRetentionDelete),
                newest_first: false,
                ..AuditQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        let clone = control.get_volume("t", "clone").await.unwrap();
        assert_eq!(
            read_root_file(&control, Arc::clone(&object_store), &clone, b"file").await,
            b"clone-safe"
        );
        let source_scrub =
            slatefs_core::volume::scrub_volume(&control, Arc::clone(&object_store), "t", "src")
                .await
                .unwrap();
        assert!(source_scrub.is_clean(), "source scrub: {source_scrub:?}");
        let clone_scrub =
            slatefs_core::volume::scrub_volume(&control, Arc::clone(&object_store), "t", "clone")
                .await
                .unwrap();
        assert!(clone_scrub.is_clean(), "clone scrub: {clone_scrub:?}");

        control.delete_volume("t", "clone").await.unwrap();
        control.close().await.unwrap();

        let reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        enforce_snapshot_retention(
            &reader,
            Arc::clone(&object_store),
            Arc::clone(&kms),
            ExportMetrics::default(),
        )
        .await
        .unwrap();
        reader.close().await.unwrap();

        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        let remaining = slatefs_core::volume::list_snapshots(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            None,
        )
        .await
        .unwrap();
        assert!(
            !remaining
                .iter()
                .any(|snapshot| snapshot.id == parent_snapshot.id),
            "clone deletion should release the explicit source checkpoint pin"
        );
        for pin in &clone_pins {
            assert!(
                !remaining.iter().any(|snapshot| snapshot.id == pin.as_str()),
                "clone deletion should release pin {pin}"
            );
        }
        control.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_retention_legacy_clone_record_keeps_conservative_skip() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([44; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            create_opts(),
        )
        .await
        .unwrap();
        let old_unpinned = slatefs_core::volume::create_snapshot(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            Some("old-unpinned".to_string()),
        )
        .await
        .unwrap();
        let parent_snapshot = slatefs_core::volume::create_snapshot(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            Some("parent".to_string()),
        )
        .await
        .unwrap();
        let mut clone = slatefs_core::volume::clone_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            "clone",
            slatefs_core::volume::CloneVolumeOptions {
                source_snapshot_id: Some(parent_snapshot.id.clone()),
                note: None,
            },
        )
        .await
        .unwrap();
        clone.clone_parent_checkpoint_ids = None;
        control.put_volume(&clone).await.unwrap();
        control
            .set_snapshot_retention_policy("t", "src", Some(0), None)
            .await
            .unwrap();
        control.close().await.unwrap();

        let reader = ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        enforce_snapshot_retention(
            &reader,
            Arc::clone(&object_store),
            Arc::clone(&kms),
            ExportMetrics::default(),
        )
        .await
        .unwrap();
        reader.close().await.unwrap();

        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        let remaining = slatefs_core::volume::list_snapshots(
            &control,
            Arc::clone(&object_store),
            "t",
            "src",
            None,
        )
        .await
        .unwrap();
        assert!(
            remaining
                .iter()
                .any(|snapshot| snapshot.id == old_unpinned.id)
        );
        assert!(
            remaining
                .iter()
                .any(|snapshot| snapshot.id == parent_snapshot.id)
        );
        let (records, _) = control
            .list_audit(AuditQuery {
                tenant: Some("t"),
                volume: Some("src"),
                action: Some(AuditAction::SnapshotRetentionDelete),
                newest_first: false,
                ..AuditQuery::default()
            })
            .await
            .unwrap();
        assert!(records.is_empty());
        control.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_v1_snapshot_retention_get_patch_and_clear() {
        let object_store = store::resolve_root("memory:///").unwrap();
        let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([15; 32])));
        let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
            .await
            .unwrap();
        control.create_tenant("t", None).await.unwrap();
        slatefs_core::volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            create_opts(),
        )
        .await
        .unwrap();
        control.close().await.unwrap();

        let state = available_admin_state(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            HashMap::new(),
            None,
        )
        .await;
        let patch = admin_exchange(
            Arc::clone(&state),
            b"PATCH /admin/v1/tenants/t/volumes/v/snapshot-retention HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"keep_last\":2,\"max_age_secs\":3600}",
        )
        .await;
        assert_eq!(response_status(&patch), 200, "{patch}");
        let patch_body: Value = serde_json::from_str(response_body(&patch)).unwrap();
        assert_eq!(patch_body["retention"]["keep_last"], 2);
        assert_eq!(patch_body["retention"]["max_age_secs"], 3600);
        assert_eq!(patch_body["retention"]["named_snapshots_exempt"], false);

        let fresh_state = available_admin_state(
            Arc::clone(&object_store),
            Arc::clone(&kms),
            HashMap::new(),
            None,
        )
        .await;
        let get = admin_exchange(
            Arc::clone(&fresh_state),
            b"GET /admin/v1/tenants/t/volumes/v/snapshot-retention HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert_eq!(response_status(&get), 200, "{get}");
        let get_body: Value = serde_json::from_str(response_body(&get)).unwrap();
        assert_eq!(get_body["retention"]["keep_last"], 2);

        let clear = admin_exchange(
            fresh_state,
            b"PATCH /admin/v1/tenants/t/volumes/v/snapshot-retention HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{\"clear\":true}",
        )
        .await;
        assert_eq!(response_status(&clear), 200, "{clear}");
        let clear_body: Value = serde_json::from_str(response_body(&clear)).unwrap();
        assert!(clear_body["retention"].is_null());
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
