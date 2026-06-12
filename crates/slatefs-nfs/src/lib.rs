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
//! Known gaps in nfs3_server 0.11, tracked for a vendored patch or upstream
//! PR before the pjdfstest milestone:
//! - LINK and MKNOD return `PROC_UNAVAIL` (no trait methods);
//! - per-request AUTH_UNIX credentials are not threaded into the traits, so
//!   each export runs under one squash identity ([`adapter::ExportIdentity`]);
//! - FSSTAT is hardcoded in the handler (df can't see quotas yet).

pub mod adapter;
pub mod fh;

use std::io;
use std::sync::Arc;

use nfs3_server::tcp::NFSTcpListener;
use slatefs_core::crypto::Secret32;
use slatefs_core::volume::Volume;

pub use adapter::{ExportIdentity, SlateFsNfs};
pub use nfs3_server::tcp::NFSTcp;

/// Bind an NFS listener for one volume export.
///
/// The handle generation is pinned to the volume fsid, so file handles stay
/// valid across daemon restarts and across nodes after failover (plan §5).
pub async fn bind_export(
    volume: Arc<Volume>,
    fh_key: Secret32,
    identity: &ExportIdentity,
    listen: &str,
) -> io::Result<NFSTcpListener<SlateFsNfs>> {
    let fsid = volume.fsid();
    let fs = SlateFsNfs::new(volume, fh_key, identity);
    NFSTcpListener::bind_with_generation(listen, fs, fsid).await
}
