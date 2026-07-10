//! 9P2000.L frontend for SlateFS (plan §9.3, Phase 4).
//!
//! # Library evaluation (plan §9.3, decided 2026-06-12)
//!
//! The plan said "evaluate `rs9p` first; expect to write our own". The
//! 2025 revival of rs9p (github.com/rs9p/rs9p, 0.13) changed the calculus:
//! - **License**: verbatim BSD-3-Clause text (crates.io shows
//!   "non-standard" only because it's declared via `license-file`).
//! - **Maintenance**: edition-2024 codebase, modern tokio, releases in
//!   2025 under a dedicated org.
//! - **API fit**: typed per-fid aux state (`Filesystem::FId`), `rattach`
//!   exposes `aname`/`uname`/`n_uname` (volume binding, bearer-token
//!   channel, and numeric uid for credentials), complete 9P2000.L message
//!   coverage, errno-based error replies, and a public codec
//!   (`fcall`/`serialize`) we reuse for in-process wire tests.
//! - **Size**: ~3.2k lines — easily vendorable with the same playbook as
//!   `crates/nfs3-server` if patches become necessary.
//!
//! Identity & auth (DD-10): the export's bearer token rides in `uname`
//! (`mount -t 9p -o uname=<token>,aname=/tenant/volume`) and authenticates
//! the **connection** — v9fs only sends the mount-option uname on the
//! first attach; `access=user` re-attaches carry an empty uname and the
//! caller's numeric uid in `n_uname` (NONUNAME on the initial mount attach
//! maps to the mount identity). Exports can be wrapped in rustls with
//! `p9_tls_cert`/`p9_tls_key`; Linux's kernel v9fs client does not speak
//! TLS directly, so that mode is for TLS-capable clients or sidecar tunnels.
//!
//! DAC posture: 9P2000.L carries no per-op gid/supplementary groups, and
//! v9fs enforces permissions client-side under `access=user`, so the
//! connection is marked trusted (`Credentials::trusted`) — real uid/gid
//! retained for ownership, server-side access gates skipped (it can't redo
//! them correctly). The token is therefore the tenant boundary; see
//! `docs/threat-model.md` and `docs/pjdfstest-exclusions.md`.

pub mod filesystem;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Once, RwLock};

use slatefs_core::config::{AtimeMode, ClientAddrRule};
use slatefs_core::rate::RateLimiter;
use slatefs_core::vfs::Vfs;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub use filesystem::SlateFs9p;

static RUSTLS_PROVIDER: Once = Once::new();

/// PEM certificate chain and private key for a TLS-wrapped 9P listener.
#[derive(Clone, Debug)]
pub struct TlsIdentity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

pub type ReloadableTlsConfig = Arc<RwLock<Arc<ServerConfig>>>;

/// Configuration for a 9P export listener.
#[derive(Clone)]
pub struct P9ExportOptions {
    pub token: Option<String>,
    pub allowed_clients: Vec<ClientAddrRule>,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub atime_policy: AtimeMode,
}

impl Default for P9ExportOptions {
    fn default() -> Self {
        Self {
            token: None,
            allowed_clients: Vec::new(),
            rate_limiter: None,
            atime_policy: AtimeMode::Relatime,
        }
    }
}

pub struct P9TcpListener {
    listener: TcpListener,
    fs: SlateFs9p,
    allowed_clients: Vec<ClientAddrRule>,
}

impl P9TcpListener {
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn handle_forever(self) -> std::io::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            if !self.allowed_clients.is_empty()
                && !self
                    .allowed_clients
                    .iter()
                    .any(|rule| rule.contains(peer.ip()))
            {
                tracing::warn!(%peer, "rejected 9P client");
                continue;
            }
            let fs = self.fs.clone();
            tokio::spawn(async move {
                if let Err(error) = rs9p::srv::srv_async_stream(fs, stream).await {
                    tracing::error!(%peer, "9p connection error: {error:?}");
                }
            });
        }
    }
}

pub struct P9TlsListener {
    listener: TcpListener,
    fs: SlateFs9p,
    tls: ReloadableTlsConfig,
    allowed_clients: Vec<ClientAddrRule>,
}

impl P9TlsListener {
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn handle_forever(self) -> std::io::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            if !self.allowed_clients.is_empty()
                && !self
                    .allowed_clients
                    .iter()
                    .any(|rule| rule.contains(peer.ip()))
            {
                tracing::warn!(%peer, "rejected 9P TLS client");
                continue;
            }

            let fs = self.fs.clone();
            let tls = Arc::clone(&self.tls);
            tokio::spawn(async move {
                let tls = TlsAcceptor::from(tls.read().expect("9P TLS config poisoned").clone());
                let stream = match tls.accept(stream).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::warn!(%peer, "9p TLS handshake failed: {error}");
                        return;
                    }
                };
                if let Err(error) = rs9p::srv::srv_async_stream(fs, stream).await {
                    tracing::error!(%peer, "9p TLS connection error: {error:?}");
                }
            });
        }
    }
}

fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Serve one volume export over 9P2000.L TCP. Runs until the listener
/// errors; spawn it like the NFS exports.
pub async fn serve_export(
    volume: Arc<dyn Vfs>,
    export_name: String,
    listen: &str,
    options: P9ExportOptions,
) -> std::io::Result<()> {
    bind_export(volume, export_name, listen, options)
        .await?
        .handle_forever()
        .await
}

pub async fn bind_export(
    volume: Arc<dyn Vfs>,
    export_name: String,
    listen: &str,
    options: P9ExportOptions,
) -> std::io::Result<P9TcpListener> {
    let allowed_clients = options.allowed_clients.clone();
    let fs = SlateFs9p::new(volume, export_name, options);
    let listener = TcpListener::bind(listen).await?;
    Ok(P9TcpListener {
        listener,
        fs,
        allowed_clients,
    })
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> std::io::Result<Arc<ServerConfig>> {
    install_rustls_provider();

    let cert_file = std::fs::File::open(cert_path)?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
            .collect::<std::result::Result<_, _>>()?;
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("no certificates found in {}", cert_path.display()),
        ));
    }

    let key_file = std::fs::File::open(key_path)?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("no private key found in {}", key_path.display()),
            )
        })?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid TLS certificate/key pair: {error}"),
            )
        })?;
    Ok(Arc::new(config))
}

pub fn reloadable_tls_config_from_identity(
    identity: &TlsIdentity,
) -> std::io::Result<ReloadableTlsConfig> {
    Ok(Arc::new(RwLock::new(load_tls_config(
        &identity.cert_path,
        &identity.key_path,
    )?)))
}

enum P9TlsReadyLog {
    Reloadable,
    Identity { cert_path: PathBuf },
}

/// Serve one volume export over TLS-wrapped 9P2000.L TCP.
pub async fn serve_export_tls(
    volume: Arc<dyn Vfs>,
    export_name: String,
    listen: &str,
    options: P9ExportOptions,
    identity: TlsIdentity,
) -> std::io::Result<()> {
    let tls = reloadable_tls_config_from_identity(&identity)?;
    bind_export_tls_with_log(
        volume,
        export_name,
        listen,
        options,
        tls,
        P9TlsReadyLog::Identity {
            cert_path: identity.cert_path,
        },
    )
    .await?
    .handle_forever()
    .await
}

pub async fn bind_export_tls(
    volume: Arc<dyn Vfs>,
    export_name: String,
    listen: &str,
    options: P9ExportOptions,
    tls: ReloadableTlsConfig,
) -> std::io::Result<P9TlsListener> {
    bind_export_tls_with_log(
        volume,
        export_name,
        listen,
        options,
        tls,
        P9TlsReadyLog::Reloadable,
    )
    .await
}

async fn bind_export_tls_with_log(
    volume: Arc<dyn Vfs>,
    export_name: String,
    listen: &str,
    options: P9ExportOptions,
    tls: ReloadableTlsConfig,
    ready_log: P9TlsReadyLog,
) -> std::io::Result<P9TlsListener> {
    let allowed_clients = options.allowed_clients.clone();
    let fs = SlateFs9p::new(volume, export_name, options);
    let listener = TcpListener::bind(listen).await?;
    match ready_log {
        P9TlsReadyLog::Reloadable => {
            tracing::info!(listen, "9p TLS listener ready");
        }
        P9TlsReadyLog::Identity { cert_path } => {
            tracing::info!(
                listen,
                cert = %cert_path.display(),
                "9p TLS listener ready"
            );
        }
    }
    Ok(P9TlsListener {
        listener,
        fs,
        tls,
        allowed_clients,
    })
}
