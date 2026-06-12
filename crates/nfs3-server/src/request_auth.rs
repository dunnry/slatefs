//! [slatefs patch] Per-request `AUTH_UNIX` credentials.
//!
//! The filesystem traits don't carry the RPC caller's identity, so a
//! multi-user server cannot enforce per-uid permissions. Rather than change
//! every trait method signature, the dispatcher scopes the request's
//! `auth_unix` into a task-local that filesystem implementations may read.
//!
//! Candidate for upstreaming as a proper trait-level context parameter.

use nfs3_types::rpc::auth_unix;

tokio::task_local! {
    pub(crate) static CURRENT_AUTH: auth_unix;
}

/// `AUTH_UNIX` credentials of the RPC call currently being served, if the
/// caller supplied any and the current task is an RPC handler.
///
/// Trust model is the caller's problem: `AUTH_SYS` is an unauthenticated
/// assertion (plan DD-10) — apply squash policy accordingly.
pub fn current_rpc_auth() -> Option<auth_unix> {
    CURRENT_AUTH.try_with(Clone::clone).ok()
}
