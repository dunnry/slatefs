# Upstreaming plan for the slatefs patch set

Base: `nfs3_server` 0.11.0 (github.com/Vaiz/nfs3). All changes are marked
`[slatefs patch]` in-source. Three logically independent PRs, smallest first:

## PR 1 — LINK + MKNOD support
`NFSPROC3_LINK`/`NFSPROC3_MKNOD` currently answer `PROC_UNAVAIL`, which
makes hardlink-using workloads (git, rsync --link-dest, pjdfstest) fail.
Adds `NfsFileSystem::link` / `NfsFileSystem::mknod` with
`NFS3ERR_NOTSUPP` defaults (no breakage for existing impls) plus handlers
following the existing mkdir/remove wcc patterns.
Note: `LINK3resfail`/`MKNOD3resfail` lack `Default` in nfs3_types — either
derive it there (nicer) or keep the local constructors.

## PR 2 — FSSTAT + ACCESS delegation
`nfsproc3_fsstat` hardcodes 1 TiB free and `nfsproc3_access` grants every
requested bit, so `df` lies and clients can't discover permissions. Adds
`NfsReadFileSystem::fsstat` / `::access` hooks whose defaults reproduce
the current behavior exactly.

## PR 3 — per-request AUTH_UNIX credentials
The traits never see the RPC caller's identity, so multi-user servers
cannot enforce per-uid permissions. The minimal-churn version (this fork):
scope `RPCContext.auth` into a tokio task-local around dispatch and expose
`current_rpc_auth()`. Upstream may prefer the explicit version — a
`&CallContext` parameter on every trait method — at the cost of breaking
all implementors; offer both, let the maintainer choose.

## PR 4 — write verifier must not be the (pinnable) handle generation
`FileHandleConverter::verf()` returned the generation number. With
`with_generation_number` (the advertised load-balancer/restart-stable
mode) the verifier then never changes across server instances, so clients
never learn that a restarted server lost their acked-but-uncommitted
UNSTABLE writes — silent data loss instead of the RFC 1813 §3.3.7
retransmit. Fixed: a per-instance verifier (boot nanos ⊕ pid ⊕ counter),
independent of the handle generation.

## PR 5 (candidate) — demote expected client errors in handler logs
Handlers log every errno returned to a client at `error!` level; under a
permission-testing workload (pjdfstest) or any multi-user production use,
EPERM/EACCES/ENOENT/EEXIST flood the logs. Expected request-level errors
belong at `debug!`, reserving `error!` for server-side faults. Not yet
applied in this fork (pure log-noise issue, no behavior change).

## Divergence tracking
When bumping the vendored base, re-apply by searching `[slatefs patch]`;
the diff is confined to: `lib.rs` (module + re-export), `request_auth.rs`
(new), `nfs_handlers.rs` (dispatch wrapper, fsstat/access bodies, link +
mknod handlers), `vfs/mod.rs` (four trait methods with defaults),
`README.md`/`Cargo.toml` (provenance, version metadata, publish=false).
