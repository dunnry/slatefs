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
//! maps to the mount identity). TLS via rustls remains a follow-up.

pub mod filesystem;

use std::sync::Arc;

use slatefs_core::volume::Volume;

pub use filesystem::SlateFs9p;

/// Serve one volume export over 9P2000.L TCP. Runs until the listener
/// errors; spawn it like the NFS exports.
pub async fn serve_export(
    volume: Arc<Volume>,
    export_name: String,
    token: Option<String>,
    listen: &str,
) -> std::io::Result<()> {
    let fs = SlateFs9p::new(volume, export_name, token);
    rs9p::srv::srv_async_tcp(fs, listen)
        .await
        .map_err(|e| std::io::Error::other(format!("9p server: {e}")))
}
