//! slatefsd — serves SlateFS volumes over NFSv3 and 9P2000.L.
//!
//! Startup: read config → open control plane just long enough to resolve
//! exports, DEKs, and the fh-HMAC key → close it (so the CLI can use the
//! control DB while the daemon runs) → open volumes → one listener per export
//! (DD-10).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;
use serde_json::{Value, json};
use slatedb::object_store::ObjectStore;
use slatefs_core::config::{AdminConfig, Config, ExportProtocol};
use slatefs_core::control::{
    AuditAction, AuditQuery, ControlPlane, ControlReader, TenantRecord, VolumePlacementRecord,
    VolumeRecord,
};
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
use tracing::Instrument;

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
    write_http_response_with_headers(stream, status, content_type, &[], body).await
}

async fn write_http_response_with_headers(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    headers: &[(&str, String)],
    body: String,
) -> std::io::Result<()> {
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

const REQUEST_ID_HEADER: &str = "X-Request-Id";
const ADMIN_API_PREFIX: &str = "/admin/v1";
const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 1_000;
const SLATEDB_VERSION: &str = "0.14.1";

#[derive(Clone)]
enum AdminControl {
    Available(Arc<ControlReader>),
    Unavailable(String),
}

#[derive(Clone)]
struct AdminState {
    targets: AdminTargets,
    control: AdminControl,
    object_store: Arc<dyn ObjectStore>,
    started_at: Instant,
    export_count: usize,
    snapshot_export_count: usize,
    auth_token: Option<String>,
    node_id: Option<String>,
}

struct AdminHttpRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    request_id: String,
    peer: Option<SocketAddr>,
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

fn require_admin_auth(state: &AdminState, request: &AdminHttpRequest) -> Result<(), AdminError> {
    let Some(expected) = state.auth_token.as_deref() else {
        return Ok(());
    };
    let Some(header) = request.headers.get("authorization") else {
        return Err(AdminError {
            status: 401,
            message: "missing bearer token".to_string(),
        });
    };
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return Err(AdminError {
            status: 401,
            message: "missing bearer token".to_string(),
        });
    };
    if token_matches(expected, presented) {
        Ok(())
    } else {
        Err(AdminError {
            status: 401,
            message: "invalid bearer token".to_string(),
        })
    }
}

async fn read_admin_request(
    stream: &mut TcpStream,
    peer: Option<SocketAddr>,
) -> Result<Option<AdminHttpRequest>, AdminError> {
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
    let mut lines = request.lines();
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
        .get(&(tenant.clone(), volume.clone()))
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
) -> Result<Value, AdminError> {
    let quota_usage = targets
        .get(&(record.tenant.clone(), record.name.clone()))
        .map(|volume| {
            let (bytes, inodes) = volume.quota_usage();
            json!({ "bytes": bytes, "inodes": inodes })
        })
        .unwrap_or(Value::Null);
    Ok(json!({
        "tenant": record.tenant,
        "name": record.name,
        "state": format!("{:?}", record.state),
        "fsid": format!("{:016x}", record.fsid),
        "cipher": record.cipher.to_string(),
        "chunk_size": record.chunk_size,
        "compression": format!("{:?}", record.compression),
        "quota": {
            "limits": quota_limits_json(&record),
            "usage": quota_usage,
        },
        "clone_parent": record.clone_parent,
        "placement": placement_json(placement)?,
        "created_at": record.created_at,
    }))
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
        out.push(volume_json(volume, placement, &state.targets)?);
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
        json!({ "volume": volume_json(record, placement, &state.targets)? }),
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
    AdminHttpResponse::text(
        200,
        format!(
            "status=ok\nexports={}\nwritable_volumes={}\nsnapshot_exports={}\n",
            state.export_count,
            state.targets.len(),
            state.snapshot_export_count
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
        let dead_writers = state
            .targets
            .values()
            .filter(|volume| volume.is_dead())
            .count();
        let exports_ok = state.export_count > 0 && dead_writers == 0;
        checks.push(json!({
            "name": "exports_serving",
            "ok": exports_ok,
            "detail": if exports_ok {
                format!(
                    "exports serving; exports={} writable_volumes={} snapshot_exports={}",
                    state.export_count,
                    state.targets.len(),
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
        let mut identity = json!({
            "server_version": env!("CARGO_PKG_VERSION"),
            "slatedb_version": SLATEDB_VERSION,
            "control_role": "standalone",
            "uptime_seconds": state.started_at.elapsed().as_secs(),
            "open_repos": state.targets.len(),
            "open_volumes": state.targets.len(),
            "snapshot_exports": state.snapshot_export_count,
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
    request: &AdminHttpRequest,
) -> Result<AdminHttpResponse, AdminError> {
    if request.path.starts_with(ADMIN_API_PREFIX) {
        require_admin_auth(state, request)?;
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
        ("GET", ["admin", "v1", "tenants"]) => list_tenants_response(state, request).await,
        ("GET", ["admin", "v1", "tenants", tenant, "volumes"]) => {
            list_volumes_response(state, request, tenant).await
        }
        ("GET", ["admin", "v1", "tenants", tenant, "volumes", volume]) => {
            get_volume_response(state, tenant, volume).await
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

async fn handle_admin_connection(
    mut stream: TcpStream,
    state: Arc<AdminState>,
    peer: Option<SocketAddr>,
) -> std::io::Result<()> {
    let request = match read_admin_request(&mut stream, peer).await {
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

    let span = tracing::info_span!(
        "admin_request",
        method = %request.method,
        path = %request.path,
        request_id = %request.request_id,
        peer = request.peer.map(|addr| addr.to_string()).unwrap_or_default(),
    );
    let mut response = async {
        match route_admin_request(&state, &request).await {
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

async fn serve_admin(listen: String, state: Arc<AdminState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&listen).await?;
    tracing::info!(listen, "admin endpoint ready");
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = handle_admin_connection(stream, state, Some(peer)).await {
                tracing::debug!(%peer, "admin request failed: {error}");
            }
        });
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
    let admin_token = load_admin_token(&config.admin)?;

    // Resolve everything we need from the control plane, then release it.
    let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
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
        let control = match ControlReader::open(Arc::clone(&object_store), Arc::clone(&kms)).await {
            Ok(reader) => AdminControl::Available(Arc::new(reader)),
            Err(error) => {
                tracing::warn!(%error, "admin control reader unavailable at startup");
                AdminControl::Unavailable(error.to_string())
            }
        };
        let state = Arc::new(AdminState {
            targets,
            control,
            object_store: Arc::clone(&object_store),
            started_at: Instant::now(),
            export_count: config.exports.len(),
            snapshot_export_count: config
                .exports
                .iter()
                .filter(|export| export.snapshot.is_some())
                .count(),
            auth_token: admin_token,
            node_id: None,
        });
        servers.spawn(async move { serve_admin(listen, state).await });
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
    use slatefs_core::control::{
        AuditAction, AuditActor, AuditOutcome, AuditPlane, AuditRecord, AuditScope, ControlPlane,
        DaemonMetrics, DaemonNodeState, QuotaLimits,
    };
    use slatefs_core::crypto::kms::{Kms, StaticKms};
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

    async fn available_admin_state(
        object_store: Arc<dyn ObjectStore>,
        kms: Arc<dyn Kms>,
        targets: HashMap<(String, String), Arc<Volume>>,
        auth_token: Option<String>,
    ) -> Arc<AdminState> {
        Arc::new(AdminState {
            targets: Arc::new(targets),
            control: AdminControl::Available(Arc::new(
                ControlReader::open(Arc::clone(&object_store), kms)
                    .await
                    .unwrap(),
            )),
            object_store,
            started_at: Instant::now(),
            export_count: 1,
            snapshot_export_count: 0,
            auth_token,
            node_id: None,
        })
    }

    fn unavailable_admin_state(
        object_store: Arc<dyn ObjectStore>,
        targets: HashMap<(String, String), Arc<Volume>>,
        auth_token: Option<String>,
    ) -> Arc<AdminState> {
        Arc::new(AdminState {
            targets: Arc::new(targets),
            control: AdminControl::Unavailable("test unavailable".to_string()),
            object_store,
            started_at: Instant::now(),
            export_count: 1,
            snapshot_export_count: 0,
            auth_token,
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
