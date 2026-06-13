//! NFSv3 frontend for SlateFS (plan §9.2, Phase 2).
//!
//! # Library spike outcome (plan §14 Phase 2, decided 2026-06-12)
//!
//! **Chosen: `nfs3_server` 0.11 (github.com/Vaiz/nfs3, BSD-3-Clause).**
//! Against the §9.2 criteria:
//! - *readdir cookie control*: real `u64` cookies with streaming iterators —
//!   our stable per-directory dirent ids map 1:1 (plan §5). `nfsserve` 0.11
//!   instead conflates the cookie with `fileid3` (`start_after`), exactly the
//!   weakness the plan flagged.
//! - *WRITE stable-flag exposure (DD-7)*: `write(.., stable_how)` returns the
//!   achieved stability and `commit()` exists — UNSTABLE acks from the WAL
//!   buffer, COMMIT/FILE_SYNC map to `Db::flush`. `nfsserve` has neither.
//! - *READDIRPLUS*: native (`ReadDirPlusIterator`); `nfsserve` synthesizes.
//! - *handles*: custom `FileHandle` types (56 bytes for us) carry
//!   `{fsid, ino, generation, HMAC}` per plan §5, and
//!   `bind_with_generation` keeps handles valid across server restarts.
//! - *testability*: sibling `nfs3_client` crate allows rootless in-process
//!   mount tests.
//! - *license/maintenance*: BSD-3-Clause, actively maintained.
//!   `zerofs_nfsserve` was excluded outright (unsuitable license).
//!
//! The three gaps found in the spike (no LINK/MKNOD, no per-request
//! AUTH_UNIX credentials, hardcoded FSSTAT) are fixed by the vendored fork
//! in `crates/nfs3-server` (search `[slatefs patch]`; intended for an
//! upstream PR). Exports now enforce per-caller permissions under a
//! configurable squash policy ([`adapter::SquashPolicy`]).

pub mod adapter;
pub mod fh;

use std::io;
use std::sync::Arc;

use nfs3_server::tcp::NFSTcpListener;
use slatefs_core::config::ClientAddrRule;
use slatefs_core::crypto::Secret32;
use slatefs_core::rate::RateLimiter;
use slatefs_core::vfs::Vfs;

pub use adapter::{SlateFsNfs, SquashPolicy};
pub use nfs3_server::tcp::NFSTcp;

/// Bind an NFS listener for one volume export.
///
/// The handle generation is pinned to the volume fsid, so file handles stay
/// valid across daemon restarts and across nodes after failover (plan §5).
pub async fn bind_export(
    volume: Arc<dyn Vfs>,
    fh_key: Secret32,
    policy: SquashPolicy,
    listen: &str,
) -> io::Result<NFSTcpListener<SlateFsNfs>> {
    bind_export_with_allowlist(volume, fh_key, policy, Vec::new(), listen).await
}

/// Bind an NFS listener with a source-IP allowlist. Empty `allowed_clients`
/// means allow all clients.
pub async fn bind_export_with_allowlist(
    volume: Arc<dyn Vfs>,
    fh_key: Secret32,
    policy: SquashPolicy,
    allowed_clients: Vec<ClientAddrRule>,
    listen: &str,
) -> io::Result<NFSTcpListener<SlateFsNfs>> {
    bind_export_with_allowlist_and_rate_limit(volume, fh_key, policy, allowed_clients, None, listen)
        .await
}

/// Bind an NFS listener with source-IP and tenant rate-limit gates.
pub async fn bind_export_with_allowlist_and_rate_limit(
    volume: Arc<dyn Vfs>,
    fh_key: Secret32,
    policy: SquashPolicy,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
    listen: &str,
) -> io::Result<NFSTcpListener<SlateFsNfs>> {
    let fsid = volume.fsid();
    let fs = SlateFsNfs::new_with_rate_limiter(volume, fh_key, policy, rate_limiter);
    let mut listener = NFSTcpListener::bind_with_generation(listen, fs, fsid).await?;
    if !allowed_clients.is_empty() {
        listener.with_client_filter(move |peer| {
            allowed_clients.iter().any(|rule| rule.contains(peer.ip()))
        });
    }
    Ok(listener)
}
