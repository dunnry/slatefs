//! NBD fixed-newstyle frontend for SlateFS block volumes.
//!
//! This crate intentionally stops at listener/session/server entry points.
//! Daemon config, export reconciliation, and TLS policy wiring are separate
//! phases.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use bytes::Bytes;
use slatefs_core::block::{BlockDev, BlockGeometry};
use slatefs_core::config::ClientAddrRule;
use slatefs_core::metrics::PrometheusSample;
use slatefs_core::rate::RateLimiter;
use slatefs_core::vfs::FsError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

const INIT_PASSWD: u64 = 0x4e42_444d_4147_4943;
const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
const OPTION_REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
const REQUEST_MAGIC: u32 = 0x2560_9513;
const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;

const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;
const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1 << 0;
const NBD_FLAG_C_NO_ZEROES: u32 = 1 << 1;
const SUPPORTED_CLIENT_FLAGS: u32 = NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES;

const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
const NBD_FLAG_READ_ONLY: u16 = 1 << 1;
const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
const NBD_FLAG_SEND_FUA: u16 = 1 << 3;
const NBD_FLAG_SEND_TRIM: u16 = 1 << 5;
const NBD_FLAG_SEND_WRITE_ZEROES: u16 = 1 << 6;
const NBD_FLAG_CAN_MULTI_CONN: u16 = 1 << 8;

const NBD_OPT_EXPORT_NAME: u32 = 1;
const NBD_OPT_ABORT: u32 = 2;
const NBD_OPT_LIST: u32 = 3;
const NBD_OPT_STARTTLS: u32 = 5;
const NBD_OPT_INFO: u32 = 6;
const NBD_OPT_GO: u32 = 7;

const NBD_REP_ACK: u32 = 1;
const NBD_REP_SERVER: u32 = 2;
const NBD_REP_INFO: u32 = 3;
const NBD_REP_ERR_UNSUP: u32 = (1 << 31) + 1;
const NBD_REP_ERR_POLICY: u32 = (1 << 31) + 2;
const NBD_REP_ERR_INVALID: u32 = (1 << 31) + 3;
const NBD_REP_ERR_TLS_REQD: u32 = (1 << 31) + 5;
const NBD_REP_ERR_UNKNOWN: u32 = (1 << 31) + 6;
const NBD_REP_ERR_TOO_BIG: u32 = (1 << 31) + 9;

const NBD_INFO_EXPORT: u16 = 0;
const NBD_INFO_BLOCK_SIZE: u16 = 3;

const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;
const NBD_CMD_TRIM: u16 = 4;
const NBD_CMD_CACHE: u16 = 5;
const NBD_CMD_WRITE_ZEROES: u16 = 6;

const NBD_CMD_FLAG_FUA: u16 = 1 << 0;
const NBD_CMD_FLAG_NO_HOLE: u16 = 1 << 1;
const NBD_CMD_FLAG_FAST_ZERO: u16 = 1 << 4;

const NBD_EPERM: u32 = 1;
const NBD_EIO: u32 = 5;
const NBD_EINVAL: u32 = 22;
const NBD_ENOSPC: u32 = 28;
const NBD_EOVERFLOW: u32 = 75;

const MAX_OPTION_DATA: u32 = 64 * 1024;
const DISCARD_BUF_LEN: usize = 8192;

static RUSTLS_PROVIDER: Once = Once::new();

/// Default number of concurrent in-flight requests per NBD connection.
pub const DEFAULT_MAX_INFLIGHT: usize = 64;

/// Default total wait for tenant rate-limit tokens before a request fails.
pub const DEFAULT_RATE_LIMIT_WAIT: Duration = Duration::from_secs(10);

/// PEM certificate/key pair for an NBD export that requires STARTTLS.
#[derive(Clone, Debug)]
pub struct NbdTlsIdentity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Optional PEM bundle of client CA certificates. When set, clients must
    /// present a certificate chaining to one of these roots.
    pub client_ca_path: Option<PathBuf>,
}

#[derive(Clone)]
struct NbdTlsConfig {
    acceptor: TlsAcceptor,
    requires_client_auth: bool,
}

trait NbdStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> NbdStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

#[derive(Debug, Default)]
struct NbdMetricSeries {
    requests_total: AtomicU64,
    latency_count: AtomicU64,
    latency_sum_bits: AtomicU64,
}

impl NbdMetricSeries {
    fn observe(&self, latency: Duration) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        add_f64(&self.latency_sum_bits, latency.as_secs_f64());
    }
}

#[derive(Debug, Default)]
struct NbdExportMetrics {
    tenant: String,
    volume: String,
    read: NbdMetricSeries,
    write: NbdMetricSeries,
    disc: NbdMetricSeries,
    flush: NbdMetricSeries,
    trim: NbdMetricSeries,
    cache: NbdMetricSeries,
    write_zeroes: NbdMetricSeries,
    unknown: NbdMetricSeries,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    inflight: AtomicU64,
    sessions_active: AtomicU64,
    rejected_allowlist: AtomicU64,
    rejected_busy: AtomicU64,
    rejected_name: AtomicU64,
    rejected_invalid: AtomicU64,
}

impl NbdExportMetrics {
    fn new(export_name: &str) -> Self {
        let (tenant, volume) = export_labels(export_name);
        Self {
            tenant,
            volume,
            ..Self::default()
        }
    }

    fn series(&self, cmd: &str) -> &NbdMetricSeries {
        match cmd {
            "read" => &self.read,
            "write" => &self.write,
            "disc" => &self.disc,
            "flush" => &self.flush,
            "trim" => &self.trim,
            "cache" => &self.cache,
            "write_zeroes" => &self.write_zeroes,
            _ => &self.unknown,
        }
    }

    fn request_finished(&self, cmd: &str, latency: Duration, command: u16, bytes: u64, ok: bool) {
        self.series(cmd).observe(latency);
        if !ok {
            return;
        }
        match command {
            NBD_CMD_READ => {
                self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
            }
            NBD_CMD_WRITE | NBD_CMD_WRITE_ZEROES => {
                self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn inflight_guard(&self) -> NbdCounterGuard<'_> {
        self.inflight.fetch_add(1, Ordering::Relaxed);
        NbdCounterGuard {
            counter: &self.inflight,
        }
    }

    fn session_guard(&self) -> NbdCounterGuard<'_> {
        self.sessions_active.fetch_add(1, Ordering::Relaxed);
        NbdCounterGuard {
            counter: &self.sessions_active,
        }
    }

    fn attach_rejected(&self, reason: &str) {
        let counter = match reason {
            "allowlist" => &self.rejected_allowlist,
            "busy" => &self.rejected_busy,
            "name" => &self.rejected_name,
            _ => &self.rejected_invalid,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn samples(&self) -> Vec<PrometheusSample> {
        let mut samples = Vec::new();
        let labels = [
            ("tenant", self.tenant.as_str()),
            ("volume", self.volume.as_str()),
        ];
        for (cmd, series) in [
            ("read", &self.read),
            ("write", &self.write),
            ("disc", &self.disc),
            ("flush", &self.flush),
            ("trim", &self.trim),
            ("cache", &self.cache),
            ("write_zeroes", &self.write_zeroes),
            ("unknown", &self.unknown),
        ] {
            let requests = series.requests_total.load(Ordering::Relaxed);
            if requests == 0 {
                continue;
            }
            samples.push(PrometheusSample::new(
                "slatefs_nbd_requests_total",
                [
                    ("tenant", self.tenant.as_str()),
                    ("volume", self.volume.as_str()),
                    ("cmd", cmd),
                ],
                requests as f64,
            ));
            samples.push(PrometheusSample::new(
                "slatefs_nbd_request_latency_seconds_count",
                [
                    ("tenant", self.tenant.as_str()),
                    ("volume", self.volume.as_str()),
                    ("cmd", cmd),
                ],
                series.latency_count.load(Ordering::Relaxed) as f64,
            ));
            samples.push(PrometheusSample::new(
                "slatefs_nbd_request_latency_seconds_sum",
                [
                    ("tenant", self.tenant.as_str()),
                    ("volume", self.volume.as_str()),
                    ("cmd", cmd),
                ],
                f64::from_bits(series.latency_sum_bits.load(Ordering::Relaxed)),
            ));
        }
        samples.push(PrometheusSample::new(
            "slatefs_nbd_bytes_read_total",
            labels,
            self.bytes_read.load(Ordering::Relaxed) as f64,
        ));
        samples.push(PrometheusSample::new(
            "slatefs_nbd_bytes_written_total",
            labels,
            self.bytes_written.load(Ordering::Relaxed) as f64,
        ));
        samples.push(PrometheusSample::new(
            "slatefs_nbd_inflight",
            labels,
            self.inflight.load(Ordering::Relaxed) as f64,
        ));
        samples.push(PrometheusSample::new(
            "slatefs_nbd_sessions_active",
            labels,
            self.sessions_active.load(Ordering::Relaxed) as f64,
        ));
        for (reason, counter) in [
            ("allowlist", &self.rejected_allowlist),
            ("busy", &self.rejected_busy),
            ("name", &self.rejected_name),
            ("invalid", &self.rejected_invalid),
        ] {
            let value = counter.load(Ordering::Relaxed);
            if value == 0 {
                continue;
            }
            samples.push(PrometheusSample::new(
                "slatefs_nbd_attach_rejected_total",
                [
                    ("tenant", self.tenant.as_str()),
                    ("volume", self.volume.as_str()),
                    ("reason", reason),
                ],
                value as f64,
            ));
        }
        samples
    }
}

struct NbdCounterGuard<'a> {
    counter: &'a AtomicU64,
}

impl Drop for NbdCounterGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

fn add_f64(slot: &AtomicU64, value: f64) {
    let mut current = slot.load(Ordering::Relaxed);
    loop {
        let next = (f64::from_bits(current) + value).to_bits();
        match slot.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

fn export_labels(export_name: &str) -> (String, String) {
    let trimmed = export_name.strip_prefix('/').unwrap_or(export_name);
    match trimmed.split_once('/') {
        Some((tenant, volume)) if !tenant.is_empty() && !volume.is_empty() => {
            (tenant.to_string(), volume.to_string())
        }
        _ => ("-".to_string(), export_name.to_string()),
    }
}

static NBD_METRICS: OnceLock<Mutex<std::collections::HashMap<String, Arc<NbdExportMetrics>>>> =
    OnceLock::new();

fn nbd_metrics_for_export(export_name: &str) -> Arc<NbdExportMetrics> {
    let mut metrics = NBD_METRICS
        .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
        .lock()
        .expect("NBD metrics poisoned");
    Arc::clone(
        metrics
            .entry(export_name.to_string())
            .or_insert_with(|| Arc::new(NbdExportMetrics::new(export_name))),
    )
}

/// Snapshot all NBD frontend metrics for Prometheus rendering.
pub fn prometheus_samples() -> Vec<PrometheusSample> {
    let Some(metrics) = NBD_METRICS.get() else {
        return Vec::new();
    };
    let metrics = metrics.lock().expect("NBD metrics poisoned");
    let mut samples = metrics
        .values()
        .flat_map(|export| export.samples())
        .collect::<Vec<_>>();
    samples.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.labels.cmp(&b.labels)));
    samples
}

/// Tunables for an NBD listener.
#[derive(Debug, Clone, Copy)]
pub struct NbdServerOptions {
    pub max_inflight: usize,
    pub rate_limit_wait: Duration,
}

impl Default for NbdServerOptions {
    fn default() -> Self {
        Self {
            max_inflight: DEFAULT_MAX_INFLIGHT,
            rate_limit_wait: DEFAULT_RATE_LIMIT_WAIT,
        }
    }
}

/// A bound NBD listener for one SlateFS block export.
pub struct NbdTcpListener {
    listener: TcpListener,
    state: Arc<ServerState>,
    allowed_clients: Vec<ClientAddrRule>,
    shutdown: broadcast::Sender<()>,
}

impl NbdTcpListener {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn shutdown_handle(&self) -> NbdShutdownHandle {
        NbdShutdownHandle {
            shutdown: self.shutdown.clone(),
        }
    }

    pub async fn handle_forever(self) -> io::Result<()> {
        let mut shutdown_rx = self.shutdown.subscribe();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, peer) = accepted?;
                    if !self.allowed_clients.is_empty()
                        && !self.allowed_clients.iter().any(|rule| rule.contains(peer.ip()))
                    {
                        self.state.metrics.attach_rejected("allowlist");
                        tracing::warn!(%peer, export = %self.state.export_name, "rejected NBD client");
                        continue;
                    }
                    if let Err(error) = stream.set_nodelay(true) {
                        tracing::warn!(%peer, "failed to set TCP_NODELAY for NBD client: {error}");
                    }
                    let state = Arc::clone(&self.state);
                    let shutdown = self.shutdown.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_connection(stream, peer, state, shutdown).await {
                            tracing::warn!(%peer, "NBD connection ended with error: {error}");
                        }
                    });
                }
                _ = shutdown_rx.recv() => {
                    return Ok(());
                }
            }
        }
    }
}

/// Handle returned by [`serve_export_with_allowlist_and_rate_limit`].
pub struct NbdServerHandle {
    local_addr: SocketAddr,
    shutdown: NbdShutdownHandle,
    join: JoinHandle<io::Result<()>>,
}

impl NbdServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown_handle(&self) -> NbdShutdownHandle {
        self.shutdown.clone()
    }

    pub fn shutdown(&self) {
        self.shutdown.shutdown();
    }

    pub fn kill(&self) {
        self.shutdown.kill();
    }

    pub async fn join(self) -> io::Result<()> {
        match self.join.await {
            Ok(result) => result,
            Err(error) => Err(io::Error::other(format!("NBD server task failed: {error}"))),
        }
    }
}

/// Cloneable hard-close hook for all listener connections.
#[derive(Clone)]
pub struct NbdShutdownHandle {
    shutdown: broadcast::Sender<()>,
}

impl NbdShutdownHandle {
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    pub fn kill(&self) {
        self.shutdown();
    }
}

fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn load_cert_chain(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(file))
            .collect::<std::result::Result<_, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no certificates found in {}", path.display()),
        ));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    rustls_pemfile::private_key(&mut std::io::BufReader::new(file))?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no private key found in {}", path.display()),
        )
    })
}

fn load_root_cert_store(path: &Path) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in load_cert_chain(path)? {
        roots.add(cert).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid client CA certificate in {}: {error}",
                    path.display()
                ),
            )
        })?;
    }
    Ok(roots)
}

fn load_tls_config(identity: &NbdTlsIdentity) -> io::Result<NbdTlsConfig> {
    install_rustls_provider();

    let certs = load_cert_chain(&identity.cert_path)?;
    let key = load_private_key(&identity.key_path)?;
    let builder = ServerConfig::builder();
    let requires_client_auth = identity.client_ca_path.is_some();
    let builder = match identity.client_ca_path.as_deref() {
        Some(path) => {
            let verifier = WebPkiClientVerifier::builder(Arc::new(load_root_cert_store(path)?))
                .build()
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid NBD client CA bundle {}: {error}", path.display()),
                    )
                })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let config = builder.with_single_cert(certs, key).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid NBD TLS certificate/key pair: {error}"),
        )
    })?;
    Ok(NbdTlsConfig {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        requires_client_auth,
    })
}

/// Bind and spawn an NBD export listener.
pub async fn serve_export(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
) -> io::Result<NbdServerHandle> {
    serve_export_with_allowlist_and_rate_limit(listen, export_name, device, Vec::new(), None).await
}

/// Bind and spawn an NBD export listener with source-IP allowlist rules.
pub async fn serve_export_with_allowlist(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
    allowed_clients: Vec<ClientAddrRule>,
) -> io::Result<NbdServerHandle> {
    serve_export_with_allowlist_and_rate_limit(listen, export_name, device, allowed_clients, None)
        .await
}

/// Bind and spawn an NBD export listener with source-IP and tenant rate gates.
pub async fn serve_export_with_allowlist_and_rate_limit(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
) -> io::Result<NbdServerHandle> {
    serve_export_with_options(
        listen,
        export_name,
        device,
        allowed_clients,
        rate_limiter,
        NbdServerOptions::default(),
    )
    .await
}

/// Bind and spawn an NBD export listener that requires STARTTLS.
pub async fn serve_export_tls_with_allowlist_and_rate_limit(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
    identity: NbdTlsIdentity,
) -> io::Result<NbdServerHandle> {
    serve_export_tls_with_options(
        listen,
        export_name,
        device,
        allowed_clients,
        rate_limiter,
        NbdServerOptions::default(),
        identity,
    )
    .await
}

/// Bind and spawn an NBD export listener with explicit server options.
pub async fn serve_export_with_options(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
    options: NbdServerOptions,
) -> io::Result<NbdServerHandle> {
    let listener = bind_export_with_options(
        listen,
        export_name,
        device,
        allowed_clients,
        rate_limiter,
        options,
    )
    .await?;
    let local_addr = listener.local_addr()?;
    let shutdown = listener.shutdown_handle();
    let join = tokio::spawn(listener.handle_forever());
    Ok(NbdServerHandle {
        local_addr,
        shutdown,
        join,
    })
}

/// Bind and spawn an NBD STARTTLS-required listener with explicit server options.
pub async fn serve_export_tls_with_options(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
    options: NbdServerOptions,
    identity: NbdTlsIdentity,
) -> io::Result<NbdServerHandle> {
    let listener = bind_export_tls_with_options(
        listen,
        export_name,
        device,
        allowed_clients,
        rate_limiter,
        options,
        identity,
    )
    .await?;
    let local_addr = listener.local_addr()?;
    let shutdown = listener.shutdown_handle();
    let join = tokio::spawn(listener.handle_forever());
    Ok(NbdServerHandle {
        local_addr,
        shutdown,
        join,
    })
}

/// Bind an NBD listener without spawning its accept loop.
pub async fn bind_export_with_allowlist_and_rate_limit(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
) -> io::Result<NbdTcpListener> {
    bind_export_with_options(
        listen,
        export_name,
        device,
        allowed_clients,
        rate_limiter,
        NbdServerOptions::default(),
    )
    .await
}

/// Bind an NBD STARTTLS-required listener without spawning its accept loop.
pub async fn bind_export_tls_with_allowlist_and_rate_limit(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
    identity: NbdTlsIdentity,
) -> io::Result<NbdTcpListener> {
    bind_export_tls_with_options(
        listen,
        export_name,
        device,
        allowed_clients,
        rate_limiter,
        NbdServerOptions::default(),
        identity,
    )
    .await
}

/// Bind an NBD listener with explicit server options.
pub async fn bind_export_with_options(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
    options: NbdServerOptions,
) -> io::Result<NbdTcpListener> {
    bind_export_with_options_and_tls(
        listen,
        export_name,
        device,
        allowed_clients,
        rate_limiter,
        options,
        None,
    )
    .await
}

/// Bind an NBD STARTTLS-required listener with explicit server options.
pub async fn bind_export_tls_with_options(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
    options: NbdServerOptions,
    identity: NbdTlsIdentity,
) -> io::Result<NbdTcpListener> {
    let tls = Some(load_tls_config(&identity)?);
    bind_export_with_options_and_tls(
        listen,
        export_name,
        device,
        allowed_clients,
        rate_limiter,
        options,
        tls,
    )
    .await
}

async fn bind_export_with_options_and_tls(
    listen: &str,
    export_name: String,
    device: Arc<dyn BlockDev>,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
    options: NbdServerOptions,
    tls: Option<NbdTlsConfig>,
) -> io::Result<NbdTcpListener> {
    if export_name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NBD export name must not be empty",
        ));
    }
    if options.max_inflight == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NBD max_inflight must be greater than zero",
        ));
    }

    let listener = TcpListener::bind(listen).await?;
    let geometry = device.geometry();
    let (shutdown, _) = broadcast::channel(16);
    Ok(NbdTcpListener {
        listener,
        state: Arc::new(ServerState {
            export_name: export_name.clone(),
            device,
            rate_limiter,
            leases: SessionLeases::new(export_name.clone(), geometry.read_only),
            options,
            metrics: nbd_metrics_for_export(&export_name),
            tls,
        }),
        allowed_clients,
        shutdown,
    })
}

struct ServerState {
    export_name: String,
    device: Arc<dyn BlockDev>,
    rate_limiter: Option<Arc<RateLimiter>>,
    leases: SessionLeases,
    options: NbdServerOptions,
    metrics: Arc<NbdExportMetrics>,
    tls: Option<NbdTlsConfig>,
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<ServerState>,
    shutdown: broadcast::Sender<()>,
) -> io::Result<()> {
    let mut shutdown_rx = shutdown.subscribe();
    let negotiated = tokio::select! {
        result = negotiate(stream, peer.ip(), Arc::clone(&state)) => result?,
        _ = shutdown_rx.recv() => return Ok(()),
    };
    let Some(negotiated) = negotiated else {
        return Ok(());
    };
    let session_metrics = Arc::clone(&state.metrics);
    let _session = session_metrics.session_guard();
    transmit(negotiated.stream, state, negotiated.lease, shutdown).await
}

struct Negotiated {
    stream: Box<dyn NbdStream>,
    lease: SessionLease,
}

async fn negotiate<S>(
    stream: S,
    peer_ip: IpAddr,
    state: Arc<ServerState>,
) -> io::Result<Option<Negotiated>>
where
    S: NbdStream + 'static,
{
    let mut stream: Box<dyn NbdStream> = Box::new(stream);
    let mut tls_established = false;
    let mut session_identity = SessionIdentity::Ip(peer_ip);
    stream.write_all(&server_handshake()).await?;

    let client_flags = match read_u32(&mut stream).await {
        Ok(flags) => flags,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    if client_flags & !SUPPORTED_CLIENT_FLAGS != 0 {
        return Ok(None);
    }
    let client_no_zeroes = client_flags & NBD_FLAG_C_NO_ZEROES != 0;

    loop {
        let header = match read_option_header(&mut stream).await {
            Ok(header) => header,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        };
        if header.magic != IHAVEOPT {
            return Ok(None);
        }

        if let Some(tls) = state.tls.as_ref().filter(|_| !tls_established) {
            match header.option {
                NBD_OPT_ABORT => {
                    discard_exact(&mut stream, header.length as u64).await?;
                    write_option_reply(&mut stream, header.option, NBD_REP_ACK, &[]).await?;
                    return Ok(None);
                }
                NBD_OPT_STARTTLS => {
                    discard_exact(&mut stream, header.length as u64).await?;
                    write_option_reply(&mut stream, header.option, NBD_REP_ACK, &[]).await?;
                    let tls_stream = tls.acceptor.accept(stream).await.map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("NBD TLS handshake failed: {error}"),
                        )
                    })?;
                    if tls.requires_client_auth {
                        let Some(identity) = client_cert_identity(&tls_stream) else {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "NBD TLS client certificate was required but not presented",
                            ));
                        };
                        session_identity = SessionIdentity::ClientCert(identity);
                    }
                    stream = Box::new(tls_stream);
                    tls_established = true;
                }
                NBD_OPT_EXPORT_NAME => {
                    return Ok(None);
                }
                _ => {
                    discard_exact(&mut stream, header.length as u64).await?;
                    write_option_reply(
                        &mut stream,
                        header.option,
                        NBD_REP_ERR_TLS_REQD,
                        b"NBD STARTTLS is required for this export",
                    )
                    .await?;
                }
            }
            continue;
        }

        match header.option {
            NBD_OPT_ABORT => {
                discard_exact(&mut stream, header.length as u64).await?;
                write_option_reply(&mut stream, header.option, NBD_REP_ACK, &[]).await?;
                return Ok(None);
            }
            NBD_OPT_LIST => {
                if header.length != 0 {
                    discard_exact(&mut stream, header.length as u64).await?;
                    write_option_reply(
                        &mut stream,
                        header.option,
                        NBD_REP_ERR_INVALID,
                        b"NBD_OPT_LIST payload must be empty",
                    )
                    .await?;
                    continue;
                }
                let mut payload = Vec::with_capacity(4 + state.export_name.len());
                payload.extend_from_slice(&(state.export_name.len() as u32).to_be_bytes());
                payload.extend_from_slice(state.export_name.as_bytes());
                write_option_reply(&mut stream, header.option, NBD_REP_SERVER, &payload).await?;
                write_option_reply(&mut stream, header.option, NBD_REP_ACK, &[]).await?;
            }
            NBD_OPT_STARTTLS => {
                discard_exact(&mut stream, header.length as u64).await?;
                if tls_established {
                    write_option_reply(
                        &mut stream,
                        header.option,
                        NBD_REP_ERR_INVALID,
                        b"NBD STARTTLS was already negotiated",
                    )
                    .await?;
                } else {
                    write_option_reply(
                        &mut stream,
                        header.option,
                        NBD_REP_ERR_UNSUP,
                        b"NBD STARTTLS is not enabled for this export",
                    )
                    .await?;
                }
            }
            NBD_OPT_INFO | NBD_OPT_GO => {
                let Some(data) = read_bounded_data(&mut stream, header.length).await? else {
                    write_option_reply(
                        &mut stream,
                        header.option,
                        NBD_REP_ERR_TOO_BIG,
                        b"option payload too large",
                    )
                    .await?;
                    continue;
                };
                let request = match parse_info_request(&data) {
                    Ok(request) => request,
                    Err(_) => {
                        write_option_reply(
                            &mut stream,
                            header.option,
                            NBD_REP_ERR_INVALID,
                            b"invalid NBD_OPT_INFO/GO payload",
                        )
                        .await?;
                        continue;
                    }
                };
                if request.name.as_slice() != state.export_name.as_bytes() {
                    state.metrics.attach_rejected("name");
                    write_option_reply(
                        &mut stream,
                        header.option,
                        NBD_REP_ERR_UNKNOWN,
                        b"unknown export",
                    )
                    .await?;
                    continue;
                }

                let lease = if header.option == NBD_OPT_GO {
                    match state.leases.acquire(session_identity.clone()) {
                        Ok(lease) => Some(lease),
                        Err(message) => {
                            state.metrics.attach_rejected("busy");
                            write_option_reply(
                                &mut stream,
                                header.option,
                                NBD_REP_ERR_POLICY,
                                message.as_bytes(),
                            )
                            .await?;
                            continue;
                        }
                    }
                } else {
                    None
                };

                let geometry = state.device.geometry();
                write_export_info(&mut stream, header.option, geometry).await?;
                write_block_size_info(&mut stream, header.option, geometry).await?;
                write_option_reply(&mut stream, header.option, NBD_REP_ACK, &[]).await?;
                if let Some(lease) = lease {
                    return Ok(Some(Negotiated { stream, lease }));
                }
            }
            NBD_OPT_EXPORT_NAME => {
                let Some(data) = read_bounded_data(&mut stream, header.length).await? else {
                    return Ok(None);
                };
                if data.as_slice() != state.export_name.as_bytes() {
                    state.metrics.attach_rejected("name");
                    return Ok(None);
                }
                let lease = match state.leases.acquire(session_identity.clone()) {
                    Ok(lease) => lease,
                    Err(_) => {
                        state.metrics.attach_rejected("busy");
                        return Ok(None);
                    }
                };
                let geometry = state.device.geometry();
                let mut response = Vec::with_capacity(8 + 2 + 124);
                response.extend_from_slice(&geometry.size_bytes.to_be_bytes());
                response.extend_from_slice(&transmission_flags(geometry).to_be_bytes());
                if !client_no_zeroes {
                    response.extend_from_slice(&[0; 124]);
                }
                stream.write_all(&response).await?;
                return Ok(Some(Negotiated { stream, lease }));
            }
            _ => {
                discard_exact(&mut stream, header.length as u64).await?;
                write_option_reply(
                    &mut stream,
                    header.option,
                    NBD_REP_ERR_UNSUP,
                    b"unsupported NBD option",
                )
                .await?;
            }
        }
    }
}

async fn transmit(
    stream: Box<dyn NbdStream>,
    state: Arc<ServerState>,
    _lease: SessionLease,
    shutdown: broadcast::Sender<()>,
) -> io::Result<()> {
    let (reader, writer) = tokio::io::split(stream);
    let (response_tx, response_rx) = mpsc::channel(state.options.max_inflight);
    let permits = Arc::new(Semaphore::new(state.options.max_inflight));
    let reader_state = Arc::clone(&state);
    let reader_shutdown = shutdown.subscribe();
    let reader_task = tokio::spawn(async move {
        read_requests(reader, reader_state, response_tx, permits, reader_shutdown).await
    });
    write_responses(
        writer,
        response_rx,
        reader_task,
        shutdown.clone(),
        shutdown.subscribe(),
    )
    .await
}

fn client_cert_identity<IO>(stream: &tokio_rustls::server::TlsStream<IO>) -> Option<Vec<u8>> {
    let (_, connection) = stream.get_ref();
    connection
        .peer_certificates()?
        .first()
        .map(|cert| cert.as_ref().to_vec())
}

async fn read_requests<R>(
    mut reader: R,
    state: Arc<ServerState>,
    response_tx: mpsc::Sender<Response>,
    permits: Arc<Semaphore>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    loop {
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => {
                permit.map_err(|_| io::Error::other("NBD request semaphore closed"))?
            }
            _ = shutdown_rx.recv() => return Ok(()),
        };
        let header = tokio::select! {
            result = read_request_header(&mut reader) => match result {
                Ok(header) => header,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            },
            _ = shutdown_rx.recv() => return Ok(()),
        };
        if header.magic != REQUEST_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid NBD request magic",
            ));
        }
        if header.command == NBD_CMD_DISC {
            drop(permit);
            return Ok(());
        }

        let geometry = state.device.geometry();
        let validation_error = validate_request(&header, geometry);
        let payload = if header.command == NBD_CMD_WRITE {
            if header.length > geometry.max_payload {
                discard_exact(&mut reader, header.length as u64).await?;
                Some(Err(NBD_EOVERFLOW))
            } else if let Some(error) = validation_error {
                discard_exact(&mut reader, header.length as u64).await?;
                Some(Err(error))
            } else {
                let mut data = vec![0; header.length as usize];
                reader.read_exact(&mut data).await?;
                Some(Ok(Bytes::from(data)))
            }
        } else {
            None
        };

        if let Some(error) = validation_error.filter(|_| header.command != NBD_CMD_WRITE) {
            let _ = response_tx
                .send(Response::error(header.handle, error, false, permit))
                .await;
            continue;
        }
        if let Some(Err(error)) = payload {
            let _ = response_tx
                .send(Response::error(header.handle, error, false, permit))
                .await;
            continue;
        }
        let payload = payload.and_then(Result::ok);

        let worker_state = Arc::clone(&state);
        let tx = response_tx.clone();
        tokio::spawn(async move {
            let response = execute_request(worker_state, header, payload, permit).await;
            let _ = tx.send(response).await;
        });
    }
}

async fn write_responses<W>(
    mut writer: W,
    mut response_rx: mpsc::Receiver<Response>,
    reader_task: JoinHandle<io::Result<()>>,
    shutdown: broadcast::Sender<()>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let reader_task = reader_task;
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                reader_task.abort();
                return Ok(());
            }
            response = response_rx.recv() => {
                let Some(response) = response else {
                    return match reader_task.await {
                        Ok(result) => result,
                        Err(error) => Err(io::Error::other(format!("NBD reader task failed: {error}"))),
                    };
                };
                let fatal = response.fatal;
                write_simple_reply(&mut writer, response).await?;
                if fatal {
                    let _ = shutdown.send(());
                    reader_task.abort();
                    return Ok(());
                }
            }
        }
    }
}

async fn execute_request(
    state: Arc<ServerState>,
    header: RequestHeader,
    payload: Option<Bytes>,
    permit: OwnedSemaphorePermit,
) -> Response {
    let cmd = cmd_label(header.command);
    let started = Instant::now();
    let _inflight = state.metrics.inflight_guard();
    let metric_bytes = match header.command {
        NBD_CMD_READ | NBD_CMD_WRITE | NBD_CMD_WRITE_ZEROES => header.length as u64,
        _ => 0,
    };
    let result = match header.command {
        NBD_CMD_READ => {
            if let Err(error) = wait_for_rate_limit(
                state.rate_limiter.as_deref(),
                header.length as u64,
                state.options.rate_limit_wait,
            )
            .await
            {
                Err(RequestFailure {
                    error,
                    fatal: false,
                })
            } else {
                state
                    .device
                    .read(header.offset, header.length)
                    .await
                    .map(Some)
                    .map_err(backend_failure)
            }
        }
        NBD_CMD_WRITE => {
            let data = payload.unwrap_or_default();
            if let Err(error) = wait_for_rate_limit(
                state.rate_limiter.as_deref(),
                data.len() as u64,
                state.options.rate_limit_wait,
            )
            .await
            {
                Err(RequestFailure {
                    error,
                    fatal: false,
                })
            } else {
                state
                    .device
                    .write(header.offset, data, header.flags & NBD_CMD_FLAG_FUA != 0)
                    .await
                    .map(|_| None)
                    .map_err(backend_failure)
            }
        }
        NBD_CMD_FLUSH => state
            .device
            .flush()
            .await
            .map(|_| None)
            .map_err(backend_failure),
        NBD_CMD_TRIM => {
            let result = state
                .device
                .trim(header.offset, header.length as u64)
                .await
                .map_err(backend_failure);
            if result.is_ok()
                && header.flags & NBD_CMD_FLAG_FUA != 0
                && let Err(error) = state.device.flush().await
            {
                Err(backend_failure(error))
            } else {
                result.map(|_| None)
            }
        }
        NBD_CMD_CACHE => Ok(None),
        NBD_CMD_WRITE_ZEROES => {
            if let Err(error) = wait_for_rate_limit(
                state.rate_limiter.as_deref(),
                header.length as u64,
                state.options.rate_limit_wait,
            )
            .await
            {
                Err(RequestFailure {
                    error,
                    fatal: false,
                })
            } else {
                state
                    .device
                    .write_zeroes(
                        header.offset,
                        header.length as u64,
                        header.flags & NBD_CMD_FLAG_FUA != 0,
                    )
                    .await
                    .map(|_| None)
                    .map_err(backend_failure)
            }
        }
        _ => Err(RequestFailure {
            error: NBD_EINVAL,
            fatal: false,
        }),
    };
    let ok = result.is_ok();
    state
        .metrics
        .request_finished(cmd, started.elapsed(), header.command, metric_bytes, ok);

    match result {
        Ok(data) => Response {
            handle: header.handle,
            error: 0,
            data,
            fatal: false,
            _permit: permit,
        },
        Err(failure) => Response {
            handle: header.handle,
            error: failure.error,
            data: None,
            fatal: failure.fatal,
            _permit: permit,
        },
    }
}

fn cmd_label(command: u16) -> &'static str {
    match command {
        NBD_CMD_READ => "read",
        NBD_CMD_WRITE => "write",
        NBD_CMD_DISC => "disc",
        NBD_CMD_FLUSH => "flush",
        NBD_CMD_TRIM => "trim",
        NBD_CMD_CACHE => "cache",
        NBD_CMD_WRITE_ZEROES => "write_zeroes",
        _ => "unknown",
    }
}

async fn wait_for_rate_limit(
    limiter: Option<&RateLimiter>,
    bytes: u64,
    max_wait: Duration,
) -> Result<(), u32> {
    let Some(limiter) = limiter else {
        return Ok(());
    };
    let start = Instant::now();
    loop {
        match limiter.check(bytes) {
            Ok(()) => return Ok(()),
            Err(FsError::WouldBlock) => {
                let elapsed = start.elapsed();
                if elapsed >= max_wait {
                    return Err(NBD_EIO);
                }
                let remaining = max_wait.saturating_sub(elapsed);
                tokio::time::sleep(remaining.min(Duration::from_millis(50))).await;
            }
            Err(_) => return Err(NBD_EIO),
        }
    }
}

struct RequestFailure {
    error: u32,
    fatal: bool,
}

fn backend_failure(error: FsError) -> RequestFailure {
    match error {
        FsError::Invalid => RequestFailure {
            error: NBD_EINVAL,
            fatal: false,
        },
        FsError::QuotaExceeded | FsError::NoSpace | FsError::FileTooBig => RequestFailure {
            error: NBD_ENOSPC,
            fatal: false,
        },
        FsError::ReadOnly | FsError::NotPermitted | FsError::AccessDenied => RequestFailure {
            error: NBD_EPERM,
            fatal: false,
        },
        _ => RequestFailure {
            error: NBD_EIO,
            fatal: true,
        },
    }
}

fn validate_request(header: &RequestHeader, geometry: BlockGeometry) -> Option<u32> {
    if header.command != NBD_CMD_WRITE && header.length > geometry.max_payload {
        return Some(NBD_EOVERFLOW);
    }

    match header.command {
        NBD_CMD_READ => {
            if header.flags & !NBD_CMD_FLAG_FUA != 0 {
                return Some(NBD_EINVAL);
            }
            validate_extent(header.offset, header.length as u64, geometry.size_bytes)
        }
        NBD_CMD_WRITE => {
            if header.flags & !NBD_CMD_FLAG_FUA != 0 {
                return Some(NBD_EINVAL);
            }
            if geometry.read_only {
                return Some(NBD_EPERM);
            }
            validate_extent(header.offset, header.length as u64, geometry.size_bytes)
        }
        NBD_CMD_FLUSH => {
            if header.offset != 0 || header.length != 0 || header.flags & !NBD_CMD_FLAG_FUA != 0 {
                Some(NBD_EINVAL)
            } else {
                None
            }
        }
        NBD_CMD_TRIM => {
            if header.flags & !NBD_CMD_FLAG_FUA != 0 {
                return Some(NBD_EINVAL);
            }
            if geometry.read_only {
                return Some(NBD_EPERM);
            }
            validate_extent(header.offset, header.length as u64, geometry.size_bytes)
        }
        NBD_CMD_CACHE => {
            if header.flags & !NBD_CMD_FLAG_FUA != 0 {
                return Some(NBD_EINVAL);
            }
            validate_extent(header.offset, header.length as u64, geometry.size_bytes)
        }
        NBD_CMD_WRITE_ZEROES => {
            if header.flags & NBD_CMD_FLAG_FAST_ZERO != 0 {
                return Some(NBD_EINVAL);
            }
            if header.flags & !(NBD_CMD_FLAG_FUA | NBD_CMD_FLAG_NO_HOLE) != 0 {
                return Some(NBD_EINVAL);
            }
            if geometry.read_only {
                return Some(NBD_EPERM);
            }
            validate_extent(header.offset, header.length as u64, geometry.size_bytes)
        }
        _ => Some(NBD_EINVAL),
    }
}

fn validate_extent(offset: u64, len: u64, size: u64) -> Option<u32> {
    match offset.checked_add(len) {
        Some(end) if offset <= size && end <= size => None,
        _ => Some(NBD_EINVAL),
    }
}

struct Response {
    handle: u64,
    error: u32,
    data: Option<Bytes>,
    fatal: bool,
    _permit: OwnedSemaphorePermit,
}

impl Response {
    fn error(handle: u64, error: u32, fatal: bool, permit: OwnedSemaphorePermit) -> Self {
        Self {
            handle,
            error,
            data: None,
            fatal,
            _permit: permit,
        }
    }
}

async fn write_simple_reply<W>(writer: &mut W, response: Response) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(&SIMPLE_REPLY_MAGIC.to_be_bytes());
    header.extend_from_slice(&response.error.to_be_bytes());
    header.extend_from_slice(&response.handle.to_be_bytes());
    writer.write_all(&header).await?;
    if response.error == 0
        && let Some(data) = response.data
    {
        writer.write_all(&data).await?;
    }
    writer.flush().await
}

#[derive(Clone)]
struct SessionLeases {
    export_name: String,
    read_only: bool,
    writable: Arc<Mutex<Option<WritableSession>>>,
}

#[derive(Debug)]
struct WritableSession {
    identity: SessionIdentity,
    connections: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SessionIdentity {
    Ip(IpAddr),
    ClientCert(Vec<u8>),
}

impl std::fmt::Display for SessionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::ClientCert(_) => f.write_str("client certificate"),
        }
    }
}

impl SessionLeases {
    fn new(export_name: String, read_only: bool) -> Self {
        Self {
            export_name,
            read_only,
            writable: Arc::new(Mutex::new(None)),
        }
    }

    fn acquire(&self, identity: SessionIdentity) -> Result<SessionLease, String> {
        if self.read_only {
            return Ok(SessionLease { inner: None });
        }
        let mut guard = self.writable.lock().expect("NBD session lease poisoned");
        match guard.as_mut() {
            Some(session) if session.identity == identity => {
                session.connections += 1;
                Ok(SessionLease {
                    inner: Some(SessionLeaseInner {
                        identity,
                        state: Arc::clone(&self.writable),
                    }),
                })
            }
            Some(session) => Err(format!(
                "export {} already has a writable session from {}",
                self.export_name, session.identity
            )),
            None => {
                *guard = Some(WritableSession {
                    identity: identity.clone(),
                    connections: 1,
                });
                Ok(SessionLease {
                    inner: Some(SessionLeaseInner {
                        identity,
                        state: Arc::clone(&self.writable),
                    }),
                })
            }
        }
    }
}

struct SessionLease {
    inner: Option<SessionLeaseInner>,
}

struct SessionLeaseInner {
    identity: SessionIdentity,
    state: Arc<Mutex<Option<WritableSession>>>,
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut guard = inner.state.lock().expect("NBD session lease poisoned");
        let Some(session) = guard.as_mut() else {
            return;
        };
        if session.identity != inner.identity {
            return;
        }
        session.connections = session.connections.saturating_sub(1);
        if session.connections == 0 {
            *guard = None;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OptionHeader {
    magic: u64,
    option: u32,
    length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequestHeader {
    magic: u32,
    flags: u16,
    command: u16,
    handle: u64,
    offset: u64,
    length: u32,
}

struct InfoRequest {
    name: Vec<u8>,
    _requests: Vec<u16>,
}

fn parse_info_request(data: &[u8]) -> Result<InfoRequest, ()> {
    if data.len() < 6 {
        return Err(());
    }
    let name_len = u32::from_be_bytes(data[0..4].try_into().map_err(|_| ())?) as usize;
    if name_len > data.len().saturating_sub(6) {
        return Err(());
    }
    let name_end = 4 + name_len;
    let count_offset = name_end;
    if data.len() < count_offset + 2 {
        return Err(());
    }
    let count = u16::from_be_bytes(
        data[count_offset..count_offset + 2]
            .try_into()
            .map_err(|_| ())?,
    ) as usize;
    if data.len() != count_offset + 2 + count * 2 {
        return Err(());
    }
    let mut requests = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    let mut cursor = count_offset + 2;
    for _ in 0..count {
        let request = u16::from_be_bytes(data[cursor..cursor + 2].try_into().map_err(|_| ())?);
        if !seen.insert(request) {
            return Err(());
        }
        requests.push(request);
        cursor += 2;
    }
    Ok(InfoRequest {
        name: data[4..name_end].to_vec(),
        _requests: requests,
    })
}

fn server_handshake() -> [u8; 18] {
    let mut out = [0; 18];
    out[0..8].copy_from_slice(&INIT_PASSWD.to_be_bytes());
    out[8..16].copy_from_slice(&IHAVEOPT.to_be_bytes());
    out[16..18].copy_from_slice(&(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES).to_be_bytes());
    out
}

fn transmission_flags(geometry: BlockGeometry) -> u16 {
    let mut flags = NBD_FLAG_HAS_FLAGS
        | NBD_FLAG_SEND_FLUSH
        | NBD_FLAG_SEND_FUA
        | NBD_FLAG_SEND_TRIM
        | NBD_FLAG_SEND_WRITE_ZEROES
        | NBD_FLAG_CAN_MULTI_CONN;
    if geometry.read_only {
        flags |= NBD_FLAG_READ_ONLY;
    }
    flags
}

async fn write_export_info<W>(
    writer: &mut W,
    option: u32,
    geometry: BlockGeometry,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
    payload.extend_from_slice(&geometry.size_bytes.to_be_bytes());
    payload.extend_from_slice(&transmission_flags(geometry).to_be_bytes());
    write_option_reply(writer, option, NBD_REP_INFO, &payload).await
}

async fn write_block_size_info<W>(
    writer: &mut W,
    option: u32,
    geometry: BlockGeometry,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut payload = Vec::with_capacity(14);
    payload.extend_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
    payload.extend_from_slice(&geometry.min_block.to_be_bytes());
    payload.extend_from_slice(&geometry.preferred_block.to_be_bytes());
    payload.extend_from_slice(&geometry.max_payload.to_be_bytes());
    write_option_reply(writer, option, NBD_REP_INFO, &payload).await
}

async fn write_option_reply<W>(
    writer: &mut W,
    option: u32,
    reply_type: u32,
    payload: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(20 + payload.len());
    out.extend_from_slice(&OPTION_REPLY_MAGIC.to_be_bytes());
    out.extend_from_slice(&option.to_be_bytes());
    out.extend_from_slice(&reply_type.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    writer.write_all(&out).await?;
    writer.flush().await
}

async fn read_option_header<R>(reader: &mut R) -> io::Result<OptionHeader>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0; 16];
    reader.read_exact(&mut bytes).await?;
    decode_option_header(&bytes)
}

fn decode_option_header(bytes: &[u8]) -> io::Result<OptionHeader> {
    if bytes.len() != 16 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated NBD option header",
        ));
    }
    Ok(OptionHeader {
        magic: u64::from_be_bytes(bytes[0..8].try_into().expect("u64 slice")),
        option: u32::from_be_bytes(bytes[8..12].try_into().expect("u32 slice")),
        length: u32::from_be_bytes(bytes[12..16].try_into().expect("u32 slice")),
    })
}

#[cfg(test)]
fn decode_option_frame(bytes: &[u8]) -> io::Result<OptionHeader> {
    let header = decode_option_header(bytes.get(..16).ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "truncated NBD option frame")
    })?)?;
    if header.length > MAX_OPTION_DATA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NBD option payload too large",
        ));
    }
    let expected = 16usize
        .checked_add(header.length as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NBD option length overflow"))?;
    if bytes.len() < expected {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated NBD option payload",
        ));
    }
    Ok(header)
}

async fn read_request_header<R>(reader: &mut R) -> io::Result<RequestHeader>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0; 28];
    reader.read_exact(&mut bytes).await?;
    Ok(RequestHeader {
        magic: u32::from_be_bytes(bytes[0..4].try_into().expect("u32 slice")),
        flags: u16::from_be_bytes(bytes[4..6].try_into().expect("u16 slice")),
        command: u16::from_be_bytes(bytes[6..8].try_into().expect("u16 slice")),
        handle: u64::from_be_bytes(bytes[8..16].try_into().expect("u64 slice")),
        offset: u64::from_be_bytes(bytes[16..24].try_into().expect("u64 slice")),
        length: u32::from_be_bytes(bytes[24..28].try_into().expect("u32 slice")),
    })
}

async fn read_u32<R>(reader: &mut R) -> io::Result<u32>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes).await?;
    Ok(u32::from_be_bytes(bytes))
}

async fn read_bounded_data<R>(reader: &mut R, len: u32) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    if len > MAX_OPTION_DATA {
        discard_exact(reader, len as u64).await?;
        return Ok(None);
    }
    let mut data = vec![0; len as usize];
    reader.read_exact(&mut data).await?;
    Ok(Some(data))
}

async fn discard_exact<R>(reader: &mut R, mut len: u64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0; DISCARD_BUF_LEN];
    while len > 0 {
        let n = len.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..n]).await?;
        len -= n as u64;
    }
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use std::collections::HashMap;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{
        ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
    };

    use super::{
        IHAVEOPT, INIT_PASSWD, NBD_CMD_CACHE, NBD_CMD_DISC, NBD_CMD_FLAG_FUA, NBD_CMD_FLUSH,
        NBD_CMD_READ, NBD_CMD_TRIM, NBD_CMD_WRITE, NBD_CMD_WRITE_ZEROES, NBD_FLAG_C_FIXED_NEWSTYLE,
        NBD_FLAG_C_NO_ZEROES, NBD_INFO_BLOCK_SIZE, NBD_INFO_EXPORT, NBD_OPT_GO, NBD_OPT_STARTTLS,
        NBD_REP_ACK, NBD_REP_INFO, NbdStream, OPTION_REPLY_MAGIC,
    };

    const NBD_REQUEST_MAGIC: u32 = super::REQUEST_MAGIC;
    const NBD_SIMPLE_REPLY_MAGIC: u32 = super::SIMPLE_REPLY_MAGIC;

    #[derive(Debug)]
    pub struct NbdReply {
        pub handle: u64,
        pub error: u32,
        pub data: Bytes,
    }

    pub struct NbdTestClient {
        stream: Box<dyn NbdStream>,
        pending_reads: HashMap<u64, usize>,
        pub size_bytes: u64,
        pub transmission_flags: u16,
        pub block_size: Option<(u32, u32, u32)>,
    }

    pub struct NbdNegotiationTestClient {
        stream: Box<dyn NbdStream>,
    }

    #[derive(Clone, Debug)]
    pub struct NbdTestClientTlsOptions {
        pub server_name: String,
        pub server_ca_pem: Option<String>,
        pub danger_accept_invalid_certs: bool,
        pub client_cert_pem: Option<String>,
        pub client_key_pem: Option<String>,
    }

    impl NbdTestClient {
        pub async fn connect(addr: SocketAddr, export_name: &str) -> io::Result<Self> {
            Self::connect_with_tls(addr, export_name, None).await
        }

        pub async fn connect_tls(
            addr: SocketAddr,
            export_name: &str,
            tls: NbdTestClientTlsOptions,
        ) -> io::Result<Self> {
            Self::connect_with_tls(addr, export_name, Some(tls)).await
        }

        async fn connect_with_tls(
            addr: SocketAddr,
            export_name: &str,
            tls: Option<NbdTestClientTlsOptions>,
        ) -> io::Result<Self> {
            let mut stream: Box<dyn NbdStream> = Box::new(TcpStream::connect(addr).await?);
            let mut handshake = [0; 18];
            stream.read_exact(&mut handshake).await?;
            if u64::from_be_bytes(handshake[0..8].try_into().expect("u64 slice")) != INIT_PASSWD
                || u64::from_be_bytes(handshake[8..16].try_into().expect("u64 slice")) != IHAVEOPT
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid NBD server handshake",
                ));
            }
            stream
                .write_all(&(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES).to_be_bytes())
                .await?;

            if let Some(tls) = tls {
                write_option(&mut stream, NBD_OPT_STARTTLS, &[]).await?;
                let (option, reply_type, payload) = read_option_reply(&mut stream).await?;
                if option != NBD_OPT_STARTTLS || reply_type != NBD_REP_ACK {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        String::from_utf8_lossy(&payload).into_owned(),
                    ));
                }
                stream = connect_tls_stream(stream, tls).await?;
            }

            let mut payload = Vec::new();
            payload.extend_from_slice(&(export_name.len() as u32).to_be_bytes());
            payload.extend_from_slice(export_name.as_bytes());
            payload.extend_from_slice(&1u16.to_be_bytes());
            payload.extend_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
            write_option(&mut stream, NBD_OPT_GO, &payload).await?;

            let mut size_bytes = 0;
            let mut transmission_flags = 0;
            let mut block_size = None;
            loop {
                let (option, reply_type, payload) = read_option_reply(&mut stream).await?;
                if option != NBD_OPT_GO {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected NBD option reply",
                    ));
                }
                match reply_type {
                    NBD_REP_INFO => {
                        if payload.len() < 2 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated NBD info reply",
                            ));
                        }
                        match u16::from_be_bytes(payload[0..2].try_into().expect("u16 slice")) {
                            NBD_INFO_EXPORT => {
                                if payload.len() != 12 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "bad NBD_INFO_EXPORT length",
                                    ));
                                }
                                size_bytes =
                                    u64::from_be_bytes(payload[2..10].try_into().expect("u64"));
                                transmission_flags =
                                    u16::from_be_bytes(payload[10..12].try_into().expect("u16"));
                            }
                            NBD_INFO_BLOCK_SIZE if payload.len() == 14 => {
                                block_size = Some((
                                    u32::from_be_bytes(payload[2..6].try_into().expect("u32")),
                                    u32::from_be_bytes(payload[6..10].try_into().expect("u32")),
                                    u32::from_be_bytes(payload[10..14].try_into().expect("u32")),
                                ));
                            }
                            NBD_INFO_BLOCK_SIZE => {}
                            _ => {}
                        }
                    }
                    NBD_REP_ACK => break,
                    error if error & (1 << 31) != 0 => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            String::from_utf8_lossy(&payload).into_owned(),
                        ));
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected NBD option reply type",
                        ));
                    }
                }
            }

            Ok(Self {
                stream,
                pending_reads: HashMap::new(),
                size_bytes,
                transmission_flags,
                block_size,
            })
        }

        pub async fn read_at(&mut self, handle: u64, offset: u64, len: u32) -> io::Result<()> {
            self.pending_reads.insert(handle, len as usize);
            self.command(NBD_CMD_READ, 0, handle, offset, len, &[])
                .await
        }

        pub async fn write_at(
            &mut self,
            handle: u64,
            offset: u64,
            data: Bytes,
            fua: bool,
        ) -> io::Result<()> {
            let flags = if fua { NBD_CMD_FLAG_FUA } else { 0 };
            self.command(
                NBD_CMD_WRITE,
                flags,
                handle,
                offset,
                data.len() as u32,
                &data,
            )
            .await
        }

        pub async fn flush(&mut self, handle: u64) -> io::Result<()> {
            self.command(NBD_CMD_FLUSH, 0, handle, 0, 0, &[]).await
        }

        pub async fn trim(&mut self, handle: u64, offset: u64, len: u32) -> io::Result<()> {
            self.command(NBD_CMD_TRIM, 0, handle, offset, len, &[])
                .await
        }

        pub async fn write_zeroes(
            &mut self,
            handle: u64,
            offset: u64,
            len: u32,
            fua: bool,
        ) -> io::Result<()> {
            let flags = if fua { NBD_CMD_FLAG_FUA } else { 0 };
            self.command(NBD_CMD_WRITE_ZEROES, flags, handle, offset, len, &[])
                .await
        }

        pub async fn cache(&mut self, handle: u64, offset: u64, len: u32) -> io::Result<()> {
            self.command(NBD_CMD_CACHE, 0, handle, offset, len, &[])
                .await
        }

        pub async fn disconnect(&mut self) -> io::Result<()> {
            self.command(NBD_CMD_DISC, 0, 0, 0, 0, &[]).await
        }

        pub async fn read_reply(&mut self) -> io::Result<NbdReply> {
            let mut header = [0; 16];
            self.stream.read_exact(&mut header).await?;
            let magic = u32::from_be_bytes(header[0..4].try_into().expect("u32 slice"));
            if magic != NBD_SIMPLE_REPLY_MAGIC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid NBD simple reply magic",
                ));
            }
            let error = u32::from_be_bytes(header[4..8].try_into().expect("u32 slice"));
            let handle = u64::from_be_bytes(header[8..16].try_into().expect("u64 slice"));
            let read_len = self.pending_reads.remove(&handle).unwrap_or(0);
            let mut data = vec![0; if error == 0 { read_len } else { 0 }];
            if !data.is_empty() {
                self.stream.read_exact(&mut data).await?;
            }
            Ok(NbdReply {
                handle,
                error,
                data: Bytes::from(data),
            })
        }

        async fn command(
            &mut self,
            command: u16,
            flags: u16,
            handle: u64,
            offset: u64,
            len: u32,
            payload: &[u8],
        ) -> io::Result<()> {
            let mut out = Vec::with_capacity(28 + payload.len());
            out.extend_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
            out.extend_from_slice(&flags.to_be_bytes());
            out.extend_from_slice(&command.to_be_bytes());
            out.extend_from_slice(&handle.to_be_bytes());
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(payload);
            self.stream.write_all(&out).await
        }
    }

    impl NbdNegotiationTestClient {
        pub async fn connect_tls(
            addr: SocketAddr,
            tls: NbdTestClientTlsOptions,
        ) -> io::Result<Self> {
            let mut stream: Box<dyn NbdStream> = Box::new(TcpStream::connect(addr).await?);
            let mut handshake = [0; 18];
            stream.read_exact(&mut handshake).await?;
            if u64::from_be_bytes(handshake[0..8].try_into().expect("u64 slice")) != INIT_PASSWD
                || u64::from_be_bytes(handshake[8..16].try_into().expect("u64 slice")) != IHAVEOPT
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid NBD server handshake",
                ));
            }
            stream
                .write_all(&(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES).to_be_bytes())
                .await?;
            write_option(&mut stream, NBD_OPT_STARTTLS, &[]).await?;
            let (option, reply_type, payload) = read_option_reply(&mut stream).await?;
            if option != NBD_OPT_STARTTLS || reply_type != NBD_REP_ACK {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    String::from_utf8_lossy(&payload).into_owned(),
                ));
            }
            Ok(Self {
                stream: connect_tls_stream(stream, tls).await?,
            })
        }

        pub async fn send_option(&mut self, option: u32, payload: &[u8]) -> io::Result<()> {
            write_option(&mut self.stream, option, payload).await
        }

        pub async fn read_option_reply(&mut self) -> io::Result<(u32, u32, Vec<u8>)> {
            read_option_reply(&mut self.stream).await
        }
    }

    async fn connect_tls_stream(
        stream: Box<dyn NbdStream>,
        options: NbdTestClientTlsOptions,
    ) -> io::Result<Box<dyn NbdStream>> {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        let builder = ClientConfig::builder();
        let builder = if options.danger_accept_invalid_certs {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
        } else {
            let mut roots = RootCertStore::empty();
            let ca_pem = options.server_ca_pem.as_deref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NBD TLS test client requires server_ca_pem unless danger_accept_invalid_certs is set",
                )
            })?;
            for cert in certs_from_pem(ca_pem)? {
                roots.add(cert).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid NBD TLS test CA certificate: {error}"),
                    )
                })?;
            }
            builder.with_root_certificates(roots)
        };
        let config = match (
            options.client_cert_pem.as_deref(),
            options.client_key_pem.as_deref(),
        ) {
            (Some(cert), Some(key)) => builder
                .with_client_auth_cert(certs_from_pem(cert)?, private_key_from_pem(key)?)
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid NBD TLS client certificate/key pair: {error}"),
                    )
                })?,
            (None, None) => builder.with_no_client_auth(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NBD TLS test client must set both client_cert_pem and client_key_pem, or neither",
                ));
            }
        };
        let server_name = ServerName::try_from(options.server_name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let connector = TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("NBD TLS client handshake failed: {error}"),
                )
            })?;
        Ok(Box::new(stream))
    }

    fn certs_from_pem(pem: &str) -> io::Result<Vec<CertificateDer<'static>>> {
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(pem.as_bytes()))
                .collect::<std::result::Result<_, _>>()?;
        if certs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no certificates found in PEM",
            ));
        }
        Ok(certs)
    }

    fn private_key_from_pem(pem: &str) -> io::Result<PrivateKeyDer<'static>> {
        rustls_pemfile::private_key(&mut std::io::BufReader::new(pem.as_bytes()))?.ok_or_else(
            || io::Error::new(io::ErrorKind::InvalidInput, "no private key found in PEM"),
        )
    }

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }

    async fn write_option<W>(stream: &mut W, option: u32, payload: &[u8]) -> io::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin + ?Sized,
    {
        let mut out = Vec::with_capacity(16 + payload.len());
        out.extend_from_slice(&IHAVEOPT.to_be_bytes());
        out.extend_from_slice(&option.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        stream.write_all(&out).await
    }

    async fn read_option_reply<R>(stream: &mut R) -> io::Result<(u32, u32, Vec<u8>)>
    where
        R: tokio::io::AsyncRead + Unpin + ?Sized,
    {
        let mut header = [0; 20];
        stream.read_exact(&mut header).await?;
        if u64::from_be_bytes(header[0..8].try_into().expect("u64 slice")) != OPTION_REPLY_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid NBD option reply magic",
            ));
        }
        let option = u32::from_be_bytes(header[8..12].try_into().expect("u32 slice"));
        let reply_type = u32::from_be_bytes(header[12..16].try_into().expect("u32 slice"));
        let len = u32::from_be_bytes(header[16..20].try_into().expect("u32 slice"));
        let mut payload = vec![0; len as usize];
        stream.read_exact(&mut payload).await?;
        Ok((option, reply_type, payload))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use bytes::Bytes;
    use proptest::prelude::*;
    use slatefs_core::block::{BlockDev, BlockGeometry, BlockVolume, SnapshotBlockVolume};
    use slatefs_core::config::{ClientAddrRule, Compression};
    use slatefs_core::control::{ControlPlane, QuotaLimit, QuotaLimits, VolumeRecord};
    use slatefs_core::crypto::kms::{Kms, StaticKms};
    use slatefs_core::crypto::{Cipher, Secret32};
    use slatefs_core::meta::superblock::VolumeKind;
    use slatefs_core::rate::{RateLimiter, RateLimits};
    use slatefs_core::store::{self, ObjectStore};
    use slatefs_core::vfs::{FsError, FsResult};
    use slatefs_core::volume::{self, CreateBlockVolumeOptions};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::test_support::{NbdNegotiationTestClient, NbdTestClient, NbdTestClientTlsOptions};
    use super::*;

    const CHUNK: u32 = 4096;
    const EXPORT: &str = "/t/b";
    const TEST_CA: &str = include_str!("../tests/certs/ca.pem");
    const TEST_CLIENT_CERT: &str = include_str!("../tests/certs/client.pem");
    const TEST_CLIENT_KEY: &str = include_str!("../tests/certs/client.key");

    fn kms() -> Arc<dyn Kms> {
        Arc::new(StaticKms::new(Secret32::from_bytes([9; 32])))
    }

    fn block_opts(size_bytes: u64, quota_bytes: Option<u64>) -> CreateBlockVolumeOptions {
        CreateBlockVolumeOptions {
            cipher: Cipher::Aes256Gcm,
            chunk_size: CHUNK,
            compression: Compression::Lz4,
            quota: QuotaLimits {
                bytes: QuotaLimit {
                    hard: quota_bytes,
                    ..Default::default()
                },
                inodes: QuotaLimit::default(),
            },
            note: None,
            size_bytes,
        }
    }

    async fn fresh_block(
        size_bytes: u64,
        quota_bytes: Option<u64>,
    ) -> (
        Arc<dyn ObjectStore>,
        VolumeRecord,
        Secret32,
        Arc<BlockVolume>,
    ) {
        let object_store = store::resolve_root("memory:///").expect("memory store");
        let control = ControlPlane::open(Arc::clone(&object_store), kms())
            .await
            .expect("control");
        control.create_tenant("t", None).await.expect("tenant");
        let record = volume::create_block_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            "b",
            block_opts(size_bytes, quota_bytes),
        )
        .await
        .expect("create block");
        let dek = control.unwrap_volume_dek(&record).await.expect("dek");
        control.close().await.expect("close control");
        let block = BlockVolume::open(&record, dek.clone(), Arc::clone(&object_store))
            .await
            .expect("open block");
        (object_store, record, dek, block)
    }

    async fn serve_dev(device: Arc<dyn BlockDev>) -> NbdServerHandle {
        serve_export_with_allowlist_and_rate_limit(
            "127.0.0.1:0",
            EXPORT.to_string(),
            device,
            Vec::new(),
            None,
        )
        .await
        .expect("serve nbd")
    }

    async fn serve_dev_tls(
        device: Arc<dyn BlockDev>,
        require_client_cert: bool,
    ) -> NbdServerHandle {
        serve_export_tls_with_allowlist_and_rate_limit(
            "127.0.0.1:0",
            EXPORT.to_string(),
            device,
            Vec::new(),
            None,
            NbdTlsIdentity {
                cert_path: cert_path("server.pem"),
                key_path: cert_path("server.key"),
                client_ca_path: require_client_cert.then(|| cert_path("ca.pem")),
            },
        )
        .await
        .expect("serve nbd tls")
    }

    fn cert_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("certs")
            .join(name)
    }

    fn tls_options(with_client_cert: bool) -> NbdTestClientTlsOptions {
        NbdTestClientTlsOptions {
            server_name: "localhost".to_string(),
            server_ca_pem: Some(TEST_CA.to_string()),
            danger_accept_invalid_certs: false,
            client_cert_pem: with_client_cert.then(|| TEST_CLIENT_CERT.to_string()),
            client_key_pem: with_client_cert.then(|| TEST_CLIENT_KEY.to_string()),
        }
    }

    async fn negotiate_bytes(
        state: Arc<ServerState>,
        peer_ip: IpAddr,
        client_payload: Vec<u8>,
    ) -> Vec<u8> {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let _ = negotiate(server, peer_ip, state).await;
        });
        let mut out = Vec::new();
        let mut handshake = [0; 18];
        client.read_exact(&mut handshake).await.expect("handshake");
        out.extend_from_slice(&handshake);
        client
            .write_all(&(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES).to_be_bytes())
            .await
            .expect("client flags");
        client
            .write_all(&client_payload)
            .await
            .expect("client options");
        client.shutdown().await.expect("client shutdown");
        client.read_to_end(&mut out).await.expect("server replies");
        task.await.expect("negotiation task");
        out
    }

    fn option(option: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + payload.len());
        out.extend_from_slice(&IHAVEOPT.to_be_bytes());
        out.extend_from_slice(&option.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn go_payload(name: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(name.len() as u32).to_be_bytes());
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
        payload
    }

    fn reply(option: u32, reply_type: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + payload.len());
        out.extend_from_slice(&OPTION_REPLY_MAGIC.to_be_bytes());
        out.extend_from_slice(&option.to_be_bytes());
        out.extend_from_slice(&reply_type.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    async fn read_option_reply_async<R>(reader: &mut R) -> io::Result<(u32, u32, Vec<u8>)>
    where
        R: AsyncRead + Unpin,
    {
        let mut header = [0; 20];
        reader.read_exact(&mut header).await?;
        assert_eq!(
            u64::from_be_bytes(header[0..8].try_into().expect("u64 slice")),
            OPTION_REPLY_MAGIC
        );
        let option = u32::from_be_bytes(header[8..12].try_into().expect("u32 slice"));
        let reply_type = u32::from_be_bytes(header[12..16].try_into().expect("u32 slice"));
        let len = u32::from_be_bytes(header[16..20].try_into().expect("u32 slice"));
        let mut payload = vec![0; len as usize];
        reader.read_exact(&mut payload).await?;
        Ok((option, reply_type, payload))
    }

    fn state_for(device: Arc<dyn BlockDev>) -> Arc<ServerState> {
        Arc::new(ServerState {
            export_name: EXPORT.to_string(),
            rate_limiter: None,
            leases: SessionLeases::new(EXPORT.to_string(), device.geometry().read_only),
            options: NbdServerOptions::default(),
            metrics: nbd_metrics_for_export(EXPORT),
            tls: None,
            device,
        })
    }

    #[tokio::test]
    async fn golden_go_happy_path() {
        let dev: Arc<dyn BlockDev> = Arc::new(TestBlockDev::new(false));
        let state = state_for(dev);
        let bytes = negotiate_bytes(
            state,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            option(NBD_OPT_GO, &go_payload(EXPORT)),
        )
        .await;

        let geometry = TestBlockDev::geometry_for(false);
        let mut export = Vec::new();
        export.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
        export.extend_from_slice(&geometry.size_bytes.to_be_bytes());
        export.extend_from_slice(&transmission_flags(geometry).to_be_bytes());
        let mut block = Vec::new();
        block.extend_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
        block.extend_from_slice(&geometry.min_block.to_be_bytes());
        block.extend_from_slice(&geometry.preferred_block.to_be_bytes());
        block.extend_from_slice(&geometry.max_payload.to_be_bytes());

        let mut expected = Vec::new();
        expected.extend_from_slice(&server_handshake());
        expected.extend_from_slice(&reply(NBD_OPT_GO, NBD_REP_INFO, &export));
        expected.extend_from_slice(&reply(NBD_OPT_GO, NBD_REP_INFO, &block));
        expected.extend_from_slice(&reply(NBD_OPT_GO, NBD_REP_ACK, &[]));
        assert_eq!(bytes, expected);
    }

    #[tokio::test]
    async fn golden_unknown_option_then_abort() {
        let dev: Arc<dyn BlockDev> = Arc::new(TestBlockDev::new(false));
        let state = state_for(dev);
        let mut client = option(0xdead_beef, b"skip-me");
        client.extend_from_slice(&option(NBD_OPT_ABORT, &[]));
        let bytes = negotiate_bytes(state, IpAddr::V4(Ipv4Addr::LOCALHOST), client).await;

        let mut expected = Vec::new();
        expected.extend_from_slice(&server_handshake());
        expected.extend_from_slice(&reply(
            0xdead_beef,
            NBD_REP_ERR_UNSUP,
            b"unsupported NBD option",
        ));
        expected.extend_from_slice(&reply(NBD_OPT_ABORT, NBD_REP_ACK, &[]));
        assert_eq!(bytes, expected);
    }

    #[tokio::test]
    async fn golden_starttls_without_tls_still_unsupported() {
        let dev: Arc<dyn BlockDev> = Arc::new(TestBlockDev::new(false));
        let state = state_for(dev);
        let bytes = negotiate_bytes(
            state,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            option(NBD_OPT_STARTTLS, &[]),
        )
        .await;

        let mut expected = Vec::new();
        expected.extend_from_slice(&server_handshake());
        expected.extend_from_slice(&reply(
            NBD_OPT_STARTTLS,
            NBD_REP_ERR_UNSUP,
            b"NBD STARTTLS is not enabled for this export",
        ));
        assert_eq!(bytes, expected);
    }

    #[tokio::test]
    async fn golden_wrong_export_name() {
        let dev: Arc<dyn BlockDev> = Arc::new(TestBlockDev::new(false));
        let state = state_for(dev);
        let bytes = negotiate_bytes(
            state,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            option(NBD_OPT_GO, &go_payload("/t/other")),
        )
        .await;

        let mut expected = Vec::new();
        expected.extend_from_slice(&server_handshake());
        expected.extend_from_slice(&reply(NBD_OPT_GO, NBD_REP_ERR_UNKNOWN, b"unknown export"));
        assert_eq!(bytes, expected);
    }

    #[tokio::test]
    async fn golden_second_session_refusal() {
        let dev: Arc<dyn BlockDev> = Arc::new(TestBlockDev::new(false));
        let state = state_for(dev);
        let _lease = state
            .leases
            .acquire(SessionIdentity::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
            .expect("first lease");
        let bytes = negotiate_bytes(
            state,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            option(NBD_OPT_GO, &go_payload(EXPORT)),
        )
        .await;

        let mut expected = Vec::new();
        expected.extend_from_slice(&server_handshake());
        expected.extend_from_slice(&reply(
            NBD_OPT_GO,
            NBD_REP_ERR_POLICY,
            b"export /t/b already has a writable session from 127.0.0.1",
        ));
        assert_eq!(bytes, expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forcedtls_refuses_go_before_starttls() {
        let dev: Arc<dyn BlockDev> = Arc::new(TestBlockDev::new(false));
        let server = serve_dev_tls(dev, false).await;
        let mut stream = TcpStream::connect(server.local_addr())
            .await
            .expect("connect");
        let mut handshake = [0; 18];
        stream.read_exact(&mut handshake).await.expect("handshake");
        stream
            .write_all(&(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES).to_be_bytes())
            .await
            .expect("client flags");
        stream
            .write_all(&option(NBD_OPT_GO, &go_payload(EXPORT)))
            .await
            .expect("go");

        let (option, reply_type, payload) =
            read_option_reply_async(&mut stream).await.expect("reply");
        assert_eq!(option, NBD_OPT_GO);
        assert_eq!(reply_type, NBD_REP_ERR_TLS_REQD);
        assert_eq!(payload, b"NBD STARTTLS is required for this export");
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forcedtls_hard_closes_export_name_before_starttls() {
        let dev: Arc<dyn BlockDev> = Arc::new(TestBlockDev::new(false));
        let server = serve_dev_tls(dev, false).await;
        let mut stream = TcpStream::connect(server.local_addr())
            .await
            .expect("connect");
        let mut handshake = [0; 18];
        stream.read_exact(&mut handshake).await.expect("handshake");
        stream
            .write_all(&(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES).to_be_bytes())
            .await
            .expect("client flags");
        stream
            .write_all(&option(NBD_OPT_EXPORT_NAME, EXPORT.as_bytes()))
            .await
            .expect("export name");
        let mut bytes = Vec::new();
        match tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
            .await
            .expect("server should close")
        {
            Ok(read) => {
                assert_eq!(read, 0);
                assert!(bytes.is_empty());
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("unexpected hard-close error: {error}"),
        }
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_starttls_after_tls_is_invalid() {
        let dev: Arc<dyn BlockDev> = Arc::new(TestBlockDev::new(false));
        let server = serve_dev_tls(dev, false).await;
        let mut client =
            NbdNegotiationTestClient::connect_tls(server.local_addr(), tls_options(false))
                .await
                .expect("tls negotiation client");
        client
            .send_option(NBD_OPT_STARTTLS, &[])
            .await
            .expect("second starttls");
        let (option, reply_type, payload) = client.read_option_reply().await.expect("second reply");
        assert_eq!(option, NBD_OPT_STARTTLS);
        assert_eq!(reply_type, NBD_REP_ERR_INVALID);
        assert_eq!(payload, b"NBD STARTTLS was already negotiated");
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn starttls_then_go_and_io_round_trip_over_tls() {
        let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 2, None).await;
        let dev: Arc<dyn BlockDev> = block.clone();
        let server = serve_dev_tls(dev, false).await;
        let mut client =
            NbdTestClient::connect_tls(server.local_addr(), EXPORT, tls_options(false))
                .await
                .expect("tls client");

        let data = Bytes::from_static(b"hello over nbd tls");
        client
            .write_at(11, 512, data.clone(), true)
            .await
            .expect("write");
        assert_ok(client.read_reply().await, 11);
        client
            .read_at(12, 512, data.len() as u32)
            .await
            .expect("read");
        let reply = client.read_reply().await.expect("reply");
        assert_eq!(reply.error, 0);
        assert_eq!(reply.data, data);
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plaintext_client_cannot_reach_transmission_on_tls_export() {
        let dev: Arc<dyn BlockDev> = Arc::new(TestBlockDev::new(false));
        let server = serve_dev_tls(dev, false).await;
        let error = match NbdTestClient::connect(server.local_addr(), EXPORT).await {
            Ok(_) => panic!("plaintext client should be refused"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("STARTTLS is required"));
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mutual_tls_rejects_missing_client_cert_and_accepts_valid_cert() {
        let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 2, None).await;
        let dev: Arc<dyn BlockDev> = block.clone();
        let server = serve_dev_tls(dev, true).await;

        let error =
            match NbdTestClient::connect_tls(server.local_addr(), EXPORT, tls_options(false)).await
            {
                Ok(_) => panic!("client without certificate should fail"),
                Err(error) => error,
            };
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::InvalidData
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
            ),
            "{error:?}"
        );

        let mut client = NbdTestClient::connect_tls(server.local_addr(), EXPORT, tls_options(true))
            .await
            .expect("mTLS client");
        let data = Bytes::from_static(b"hello mtls");
        client
            .write_at(21, 1024, data.clone(), false)
            .await
            .expect("write");
        assert_ok(client.read_reply().await, 21);
        client
            .read_at(22, 1024, data.len() as u32)
            .await
            .expect("read");
        let reply = client.read_reply().await.expect("reply");
        assert_eq!(reply.error, 0);
        assert_eq!(reply.data, data);
        server.shutdown();
    }

    proptest! {
        #[test]
        fn option_frame_parser_does_not_panic(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = decode_option_frame(&input);
        }

        #[test]
        fn malformed_option_lengths_error_without_allocating(option in any::<u32>(), len in (MAX_OPTION_DATA + 1)..u32::MAX) {
            let mut frame = Vec::new();
            frame.extend_from_slice(&IHAVEOPT.to_be_bytes());
            frame.extend_from_slice(&option.to_be_bytes());
            frame.extend_from_slice(&len.to_be_bytes());
            prop_assert!(decode_option_frame(&frame).is_err());
        }
    }

    #[test]
    fn truncated_option_frame_errors() {
        for len in 0..16 {
            assert!(decode_option_frame(&vec![0; len]).is_err());
        }
        let mut frame = option(NBD_OPT_LIST, b"abc");
        frame.truncate(18);
        assert!(decode_option_frame(&frame).is_err());
    }

    #[test]
    fn writable_session_lease_allows_same_ip_only_until_dropped() {
        let leases = SessionLeases::new(EXPORT.to_string(), false);
        let first_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let second_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let first = leases
            .acquire(SessionIdentity::Ip(first_ip))
            .expect("first");
        let second_same = leases
            .acquire(SessionIdentity::Ip(first_ip))
            .expect("same ip joins");
        assert!(leases.acquire(SessionIdentity::Ip(second_ip)).is_err());
        drop(first);
        assert!(leases.acquire(SessionIdentity::Ip(second_ip)).is_err());
        drop(second_same);
        let _second = leases
            .acquire(SessionIdentity::Ip(second_ip))
            .expect("different ip after close");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wire_unaligned_multi_chunk_round_trip_and_holes_are_zero() {
        let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 4, None).await;
        let dev: Arc<dyn BlockDev> = block.clone();
        let server = serve_dev(dev).await;
        let mut client = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client");
        assert_eq!(client.size_bytes, CHUNK as u64 * 4);

        let data = Bytes::from(vec![0x5a; CHUNK as usize + 37]);
        client
            .write_at(1, CHUNK as u64 - 13, data.clone(), false)
            .await
            .expect("write");
        assert_ok(client.read_reply().await, 1);
        client
            .read_at(2, CHUNK as u64 - 29, CHUNK + 80)
            .await
            .expect("read");
        let reply = client.read_reply().await.expect("reply");
        assert_eq!(reply.error, 0);
        assert_eq!(&reply.data[..16], &[0; 16]);
        assert_eq!(&reply.data[16..16 + data.len()], &data[..]);
        assert_eq!(&reply.data[16 + data.len()..], &[0; 27]);
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wire_flush_fua_trim_and_write_zeroes() {
        let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 4, None).await;
        let dev: Arc<dyn BlockDev> = block.clone();
        let server = serve_dev(dev).await;
        let mut client = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client");

        client
            .write_at(1, 0, Bytes::from(vec![0x11; CHUNK as usize * 3]), true)
            .await
            .expect("fua write");
        assert_ok(client.read_reply().await, 1);
        client.flush(2).await.expect("flush");
        assert_ok(client.read_reply().await, 2);
        assert_eq!(block.quota_usage().0, CHUNK as i64 * 3);

        client.trim(3, CHUNK as u64, CHUNK).await.expect("trim");
        assert_ok(client.read_reply().await, 3);
        assert_eq!(block.quota_usage().0, CHUNK as i64 * 2);

        client
            .write_zeroes(4, CHUNK as u64 - 4, 16, true)
            .await
            .expect("zeroes");
        assert_ok(client.read_reply().await, 4);
        client.read_at(5, CHUNK as u64 - 8, 24).await.expect("read");
        let reply = client.read_reply().await.expect("reply");
        assert_eq!(reply.error, 0);
        assert_eq!(&reply.data[..4], &[0x11; 4]);
        assert_eq!(&reply.data[4..20], &[0; 16]);
        assert_eq!(&reply.data[20..], &[0; 4]);
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wire_oob_and_quota_errors() {
        let (_store, _record, _dek, block) = fresh_block(CHUNK as u64, Some(CHUNK as u64)).await;
        let dev: Arc<dyn BlockDev> = block;
        let server = serve_dev(dev).await;
        let mut client = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client");

        client
            .read_at(1, CHUNK as u64 - 1, 2)
            .await
            .expect("oob read");
        assert_error(client.read_reply().await, 1, NBD_EINVAL);

        client
            .write_at(2, 0, Bytes::from(vec![1; CHUNK as usize]), false)
            .await
            .expect("first write");
        assert_ok(client.read_reply().await, 2);
        client
            .write_at(3, 1, Bytes::from(vec![2; CHUNK as usize]), false)
            .await
            .expect("quota write");
        assert_error(client.read_reply().await, 3, NBD_EINVAL);
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wire_enospc_on_quota_exhaustion() {
        let (_store, _record, _dek, block) =
            fresh_block(CHUNK as u64 * 2, Some(CHUNK as u64)).await;
        let dev: Arc<dyn BlockDev> = block;
        let server = serve_dev(dev).await;
        let mut client = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client");

        client
            .write_at(1, 0, Bytes::from(vec![1; CHUNK as usize]), false)
            .await
            .expect("first write");
        assert_ok(client.read_reply().await, 1);
        client
            .write_at(2, CHUNK as u64, Bytes::from(vec![2; CHUNK as usize]), false)
            .await
            .expect("quota write");
        assert_error(client.read_reply().await, 2, NBD_ENOSPC);
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn read_only_export_rejects_write_and_allows_two_sessions() {
        let (store, record, dek, block) = fresh_block(CHUNK as u64 * 2, None).await;
        block
            .write(0, Bytes::from_static(b"snapshot-data"), true)
            .await
            .expect("seed");
        let snap = block
            .create_live_snapshot(Some("snap".to_string()))
            .await
            .expect("snapshot");
        let parent_prefixes = match record.kind {
            VolumeKind::Block { .. } => Vec::new(),
            _ => unreachable!("block"),
        };
        let snapshot = SnapshotBlockVolume::open(&record, dek, store, &snap.id, parent_prefixes)
            .await
            .expect("open snapshot");
        let dev: Arc<dyn BlockDev> = snapshot;
        let server = serve_dev(dev).await;

        let mut c1 = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client1");
        let mut c2 = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client2");
        assert!(c1.transmission_flags & NBD_FLAG_READ_ONLY != 0);
        c1.write_at(1, 0, Bytes::from_static(b"x"), false)
            .await
            .expect("write");
        assert_error(c1.read_reply().await, 1, NBD_EPERM);
        c2.read_at(2, 0, 13).await.expect("read");
        let reply = c2.read_reply().await.expect("reply");
        assert_eq!(reply.error, 0);
        assert_eq!(&reply.data[..], b"snapshot-data");
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn writable_export_allows_two_localhost_multi_conn_sessions() {
        let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 2, None).await;
        let dev: Arc<dyn BlockDev> = block;
        let server = serve_dev(dev).await;
        let mut c1 = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client1");
        let mut c2 = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client2");
        c1.cache(1, 0, 1).await.expect("cache");
        c2.cache(2, 1, 1).await.expect("cache");
        assert_ok(c1.read_reply().await, 1);
        assert_ok(c2.read_reply().await, 2);
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn source_allowlist_rejects_client_before_handshake() {
        let (_store, _record, _dek, block) = fresh_block(CHUNK as u64, None).await;
        let dev: Arc<dyn BlockDev> = block;
        let denied: ClientAddrRule = "192.0.2.0/24".parse().expect("rule");
        let server =
            serve_export_with_allowlist("127.0.0.1:0", EXPORT.to_string(), dev, vec![denied])
                .await
                .expect("serve");

        let mut stream = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .expect("connect");
        let mut handshake = [0; 18];
        let result =
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut handshake)).await;
        assert!(result.is_ok(), "allowlist rejection did not close promptly");
        assert!(
            result.expect("timeout").is_err(),
            "disallowed client unexpectedly received a handshake"
        );
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rate_limit_timeout_fails_request_with_eio() {
        let (_store, _record, _dek, block) = fresh_block(CHUNK as u64, None).await;
        let dev: Arc<dyn BlockDev> = block;
        let server = serve_export_with_options(
            "127.0.0.1:0",
            EXPORT.to_string(),
            dev,
            Vec::new(),
            Some(Arc::new(RateLimiter::new(RateLimits {
                ops_per_second: None,
                bytes_per_second: Some(1),
            }))),
            NbdServerOptions {
                rate_limit_wait: Duration::from_millis(50),
                ..NbdServerOptions::default()
            },
        )
        .await
        .expect("serve");

        let mut client = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client");
        client.read_at(1, 0, 2).await.expect("read");
        assert_error(client.read_reply().await, 1, NBD_EIO);
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn disc_cleanly_closes_after_inflight_replies() {
        let (_store, _record, _dek, block) = fresh_block(CHUNK as u64, None).await;
        let dev: Arc<dyn BlockDev> = block;
        let server = serve_dev(dev).await;
        let mut client = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client");
        client.cache(1, 0, 1).await.expect("cache");
        client.disconnect().await.expect("disc");
        assert_ok(client.read_reply().await, 1);
        let eof = tokio::time::timeout(Duration::from_secs(2), client.read_reply()).await;
        assert!(eof.is_ok(), "disconnect did not close");
        assert!(eof.expect("timeout").is_err(), "expected EOF after DISC");
        server.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn out_of_order_completion_is_allowed() {
        let dev: Arc<dyn BlockDev> = Arc::new(SlowReadBlockDev);
        let server = serve_dev(dev).await;
        let mut client = NbdTestClient::connect(server.local_addr(), EXPORT)
            .await
            .expect("client");
        client.read_at(1, 0, 1).await.expect("slow read");
        client.read_at(2, 1, 1).await.expect("fast read");
        let first = client.read_reply().await.expect("first reply");
        assert_eq!(first.handle, 2);
        assert_eq!(first.error, 0);
        let second = client.read_reply().await.expect("second reply");
        assert_eq!(second.handle, 1);
        assert_eq!(second.error, 0);
        server.shutdown();
    }

    fn assert_ok(reply: std::io::Result<test_support::NbdReply>, handle: u64) {
        let reply = reply.expect("reply");
        assert_eq!(reply.handle, handle);
        assert_eq!(reply.error, 0);
    }

    fn assert_error(reply: std::io::Result<test_support::NbdReply>, handle: u64, error: u32) {
        let reply = reply.expect("reply");
        assert_eq!(reply.handle, handle);
        assert_eq!(reply.error, error);
    }

    struct TestBlockDev {
        geometry: BlockGeometry,
    }

    impl TestBlockDev {
        fn new(read_only: bool) -> Self {
            Self {
                geometry: Self::geometry_for(read_only),
            }
        }

        fn geometry_for(read_only: bool) -> BlockGeometry {
            BlockGeometry {
                size_bytes: 1024 * 1024,
                min_block: 512,
                preferred_block: 4096,
                max_payload: 128 * 1024,
                read_only,
            }
        }
    }

    #[async_trait]
    impl BlockDev for TestBlockDev {
        fn geometry(&self) -> BlockGeometry {
            self.geometry
        }

        async fn read(&self, _offset: u64, len: u32) -> FsResult<Bytes> {
            Ok(Bytes::from(vec![0; len as usize]))
        }

        async fn write(&self, _offset: u64, _data: Bytes, _fua: bool) -> FsResult<()> {
            if self.geometry.read_only {
                Err(FsError::ReadOnly)
            } else {
                Ok(())
            }
        }

        async fn flush(&self) -> FsResult<()> {
            Ok(())
        }

        async fn trim(&self, _offset: u64, _len: u64) -> FsResult<()> {
            if self.geometry.read_only {
                Err(FsError::ReadOnly)
            } else {
                Ok(())
            }
        }

        async fn write_zeroes(&self, _offset: u64, _len: u64, _fua: bool) -> FsResult<()> {
            if self.geometry.read_only {
                Err(FsError::ReadOnly)
            } else {
                Ok(())
            }
        }
    }

    struct SlowReadBlockDev;

    #[async_trait]
    impl BlockDev for SlowReadBlockDev {
        fn geometry(&self) -> BlockGeometry {
            BlockGeometry {
                size_bytes: 4096,
                min_block: 512,
                preferred_block: 4096,
                max_payload: 4096,
                read_only: false,
            }
        }

        async fn read(&self, offset: u64, len: u32) -> FsResult<Bytes> {
            if offset == 0 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Ok(Bytes::from(vec![offset as u8; len as usize]))
        }

        async fn write(&self, _offset: u64, _data: Bytes, _fua: bool) -> FsResult<()> {
            Ok(())
        }

        async fn flush(&self) -> FsResult<()> {
            Ok(())
        }

        async fn trim(&self, _offset: u64, _len: u64) -> FsResult<()> {
            Ok(())
        }

        async fn write_zeroes(&self, _offset: u64, _len: u64, _fua: bool) -> FsResult<()> {
            Ok(())
        }
    }
}
