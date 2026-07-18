# Consumer live data plane

`slatefsd` optionally serves `/consumer/v1` on `[consumer].listen`. The listener
must be loopback. It authenticates only `[admin.tenant_tokens]` and
`[admin.tenant_token_files]`; token files are read on every request so an active
and previous token can overlap during atomic rotation. The global admin token,
admin mTLS identities, and request-supplied tenant/uid/gid values are never
consumer credentials.

Every configured tenant has one fixed, unprivileged uid/gid. New filesystem
roots are `root:root 0755`, so setup must deliberately create and chown a
writable tenant directory (recommended) or deliberately adjust the root.

The daemon holds all active filesystem volumes for configured consumer tenants,
including unexported volumes. Those holds share the exact `Arc<Volume>` used by
NFS/9P exports and are independent of export reference counts, preserving the
one active writer invariant. Block volumes appear as `browsable:false`.

Read-only entry, content/range, and xattr requests support `view=snapshot` or
`view=version` with a required `ref`. Snapshot refs are exact checkpoint UUIDs.
Version refs may be exact commits, tags, or branches; symbolic refs resolve
once and responses return `resolved_commit` (content also uses
`X-SlateFS-Resolved-Commit`). Clients should pin later navigation to that exact
commit. Readers are cached by tenant, volume, kind, and exact immutable ID,
bounded by `consumer.historical_view_cache_entries`, and closed on eviction or
daemon shutdown. Historical mutation selectors return `read_only_view` before
any live VFS operation. Paths are root-relative and are
looked up one component at a time without following symlinks. Entry and page
identifiers are signed and bind filesystem/inode generations and directory
cookies. Consumer xattrs are restricted to the byte prefix `user.`; names and
values are returned losslessly in base64, and PATCH accepts either UTF-8 map
keys or the `set_bytes`/`remove_bytes_base64` lossless selectors.

Downloads support one bounded byte range. Multiple or malformed ranges return
400; unsatisfiable or over-limit ranges return 416. Upload replacements use a
hidden sibling, bounded chunks, `fsync`, and atomic rename. A cancellation
guard removes the staged sibling on body errors or a dropped request. Recursive
delete measures the complete tree before changing it, enforces configured entry
and byte limits, and never follows symlinks. Copy preserves regular-file bytes and mode, symlink
targets, and readable `user.*` xattrs where feasible. Destinations are owned by
the fixed tenant identity; timestamps and source ownership are not preserved.

Copy and hardlink reject `overwrite`; only VFS-atomic move and staged upload
support that policy, avoiding delete-then-fail data loss. Weak ETags serialize consumer mutations with keyed destination locks. Concurrent
NFS/9P mutation remains best-effort because the VFS has no atomic conditional
rename primitive. Compound-operation idempotency is an in-memory, tenant/volume
scoped cache and is lost on daemon restart; key reuse with a different request
returns 409, and concurrent duplicate keys execute only once. Other mutation
families are not advertised as idempotent in Phase 1. Replacement uploads
require `If-Match`; create-through-parent uploads do not.

Compound operations are synchronous and fail fast. Their preview recursively
measures all source trees before mutation, but the VFS has no multi-source
transaction: a later permission, quota, or concurrent conflict can leave prior
sources completed. The Phase 1 response does not promise per-entry partial
failure results; clients should refresh after an operation error.
