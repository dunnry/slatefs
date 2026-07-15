# SlateFS

A multi-tenant POSIX filesystem served over **NFSv3** and **9P2000.L**, with
[SlateDB](https://slatedb.io) as the storage engine (object storage as the
durable backend), compression + encryption at rest, and tiered local caches.

Design and roadmap: [slatefs-plan.md](slatefs-plan.md).
Architecture docs: [docs/architecture.md](docs/architecture.md) and
[docs/deployment-architecture.md](docs/deployment-architecture.md).

## Status

**Phase 0 complete** (scaffolding & control plane): encrypted control-plane DB,
master-KEK → tenant-KEK → volume-DEK key hierarchy (age or static KMS),
per-volume SlateDB with an AEAD block transformer (AES-256-GCM /
XChaCha20-Poly1305 after LZ4/Zstd compression), `slatefs tenant|volume`
CLI, volume `mkfs` writing an encrypted superblock.

**Phase 1 complete** (VFS core): the full `Vfs` trait implemented on
SlateDB — inodes/dirents with AES-SIV-encrypted names (DD-3), chunked
sparse-aware I/O (DD-6), atomic rename with cycle checks, hardlinks,
symlinks, xattrs, orphan handling for unlinked-but-open files,
merge-operator quota counters with exact `EDQUOT` enforcement (DD-9),
striped lock manager + advisory byte-range locks (DD-5), `slatefs fsck
--recount`. Verified by model-based property tests (real vs in-memory
reference FS, errno-exact) and a crash-consistency loop (abort →
reopen/reap → clean fsck), both scaled up nightly in CI.

**Phase 2 in progress** (NFSv3 frontend): library spike decided —
`nfs3_server` 0.11 (BSD-3-Clause; real u64 readdir cookies, WRITE
`stable_how` + COMMIT for the DD-7 durability mapping, READDIRPLUS,
restart-stable custom file handles; see `slatefs-nfs/src/lib.rs` for the
full rationale). Implemented: HMAC'd file handles (`{fsid, ino, gen}` under
a control-plane server key), the full `Vfs → NfsFileSystem` adapter,
`[[exports]]` config + `slatefsd` listeners, and an in-process wire-level
integration suite via `nfs3_client` (no root needed): UNSTABLE/COMMIT,
cookie pagination, server-restart handle survival, DQUOT, forged-handle
rejection. A real Linux kernel-client mount test runs in CI
(`scripts/nfs-kernel-mount-test.sh`).

The spike's three library gaps are closed by a vendored fork
(`crates/nfs3-server`, BSD-3-Clause with attribution, patches marked
`[slatefs patch]` and intended for an upstream PR): per-request AUTH_UNIX
credentials (squash policies `none` / `root_squash` / `all_squash` /
`trust_as_root` now enforce real per-uid permissions), LINK + MKNOD
handlers, and FSSTAT/ACCESS trait hooks so `df` reflects quotas. All
verified over the wire by `slatefs-nfs/tests/nfs_creds.rs`.

**pjdfstest over a Linux kernel mount: 8796/8798** (238 files, suite run
via `scripts/docker-kernel-mount-test.sh scripts/pjdfstest-over-nfs.sh` —
a real kernel NFS client in a privileged container). The two remaining
failures are protocol-inherent and documented with reasons in
[docs/pjdfstest-exclusions.md](docs/pjdfstest-exclusions.md) (NFS silly
rename; NFSv3 u32 timestamps). Three genuine bugs the suite caught are
fixed: mkdir mode pass-through, EPERM on non-owner same-value chown, and
write-permission enforcement on cross-parent directory renames.

**Phase 3 in progress** (encryption hardening + cache tiers): the §7
filter-block question is closed — slatedb 0.13 runs data, index, filter,
and stats blocks through the transformer (verified in source; only SST
first/last keys and manifests are plaintext, see
[docs/threat-model.md](docs/threat-model.md)). Cache tiers wired per §8:
per-volume RAM block cache + ciphertext NVMe part cache (`[cache]` config;
shared-cache spike found cross-volume WAL-id aliasing, so caches stay
per-volume), moka attr/negative-dentry cache with synchronous
write-through, sequential read-ahead, engine metrics with periodic cache
hit-rate logs, feature-gated AWS KMS provider. AC tests: deep no-plaintext
scan through every FS surface, wrong-DEK fail-closed, warm-restart reads
with **zero** object-store GETs, and a read-latency bench harness (warm
128 KiB p99 ≈ 60 µs on a local store in release).

**Phase 4 in progress** (9P2000.L frontend): the §9.3 spike picked the
2025-revived `rs9p` (BSD-3-Clause; typed per-fid state, full 9P2000.L
coverage, public codec reused for wire tests) over writing our own —
vendored into `crates/rs9p` with two `[slatefs patch]`s (portable statvfs
for macOS builds; Rreaddir decode treated the byte-length prefix as an
entry count). `slatefs-9p` implements the full op surface on the shared
`Vfs` with per-connection bearer-token auth at `Tattach`
(`mount -t 9p -o trans=tcp,version=9p2000.L,uname=<token>,aname=/t/v`).
Verified: in-process wire tests, **cross-protocol coherence** (one volume
served over NFS and 9P simultaneously, writes visible both ways,
attr-coherent), and a real kernel v9fs mount exercising I/O, hardlinks,
xattrs, and readdir (`scripts/p9-kernel-mount-test.sh`, in CI). The QEMU
guest path is covered by [scripts/qemu-p9-tcp-smoke.sh](scripts/qemu-p9-tcp-smoke.sh)
and documented in [docs/client-support.md](docs/client-support.md). 9P exports
can also be rustls-wrapped with `p9_tls_cert`/`p9_tls_key` for TLS-capable
clients or sidecar tunnels. The daemon now shares one `Volume` across all
exports of the same tenant/volume (single SlateDB writer, DD-5).

**pjdfstest over a Linux kernel 9P mount: 8796/8798** (same suite as NFS,
`scripts/pjdfstest-over-9p.sh`, in CI). Under `access=user` v9fs enforces
DAC client-side and the protocol carries no per-op gid/groups, so the 9P
connection is marked *trusted* (keeps real uid/gid for ownership, skips
access checks it can't do correctly; setuid-clearing and device-node
creation still gate on genuine privilege). The two failures are a v9fs
client limitation — sub-second timestamps truncated by the 1 s default
`s_time_gran` before they reach the server (the server round-trips full
nanoseconds; proven by an in-process wire test) — documented in
[docs/pjdfstest-exclusions.md](docs/pjdfstest-exclusions.md). 9P *passes*
the two assertions NFSv3 cannot (open-file unlink `nlink==0`; y2106 time).

**Phase 5 started** (multi-tenant hardening & quotas UX): tenants can now be
suspended/resumed via `slatefs tenant suspend|resume`; suspended tenants retain
their encrypted metadata and keys, but new volume creates and `slatefsd` export
resolution fail closed until resumed. Per-export source-IP allowlists
(`allowed_clients = ["127.0.0.1", "10.0.0.0/8"]`) are enforced by both NFS and
9P before request decoding. Tenant frontend rate limits (`slatefs tenant rate
show|set`) add shared token buckets for ops/s and request bytes/s across all
exports of a tenant. Export definitions can now live in the encrypted control
plane and be managed live with `slatefs export
add|list|show|update|remove|enable|disable`; static `[[exports]]` TOML entries
remain supported as immutable bootstrap/compatibility exports. `slatefsd`
reconciles static config exports plus enabled control-plane exports on startup
and then polls `[export_control].poll_interval_secs` (default 30). New enabled
control exports are started, removed/disabled exports are stopped, and the
last listener using a volume/snapshot closes that backend. A control-plane
export whose listen address conflicts with an active listener is logged,
counted, skipped, and retried on the next poll; the daemon does not crash.
Quota limits are operator-manageable with `slatefs quota
show|set`, including hard limits and soft limits that become enforcing after
their grace deadline expires. `slatefs volume scrub` runs the structural checker
through a read-only SlateDB reader, so it can compare counters/recount while the
volume is being served. `slatefsd` also reloads changed tenant rate limits and
served-volume quota limits on the `[export_control].poll_interval_secs` loop:
rate buckets are resized in place, and quota changes apply on the next mutation
check without reopening the volume.
Filesystem exports honor `atime = "relatime" | "strict" | "noatime"` per
export for both NFS and 9P. `relatime` is the default and follows Linux-style
updates when atime lags mtime/ctime or is older than 24 hours; `strict`
persists atime on every successful read, which adds a metadata write on hot
read paths; `noatime` suppresses read-side atime updates. Snapshot exports are
read-only and never persist atime updates regardless of policy.

| Export field | Default | Applies to | Notes |
| --- | --- | --- | --- |
| `atime` | `relatime` | NFS, 9P | Per-export read atime policy: `strict`, `relatime`, or `noatime`. |

`slatefs tenant delete --yes` and `slatefs volume delete --yes` mark records
deleting, drop wrapped keys from the current control-plane state, and delete
the affected volume object-store prefixes.

**Opt-in file versioning:** Prolly-backed history is disabled by default for
every volume and is never part of the normal NFS/9P read or write path. Enable
it explicitly with `slatefs versioning enable <tenant> <volume>`, then create
versions of selected regular files with `slatefs versioning commit` and its
tenant, volume, path, and `-m <message>` arguments. Each immutable commit also
hashes its content author, publishing committer, origin, and request ID. Live
commits default the author to the server-derived committer identity;
authenticated requests use their principal and permitted unauthenticated
loopback requests use an explicit marker. `--author` may name a different
content author.
Offline commits require `--author` and record that claimed identity as both
author and committer. `versioning log`,
`versioning diff`, `versioning show`, and `versioning restore` inspect, compare,
and recover those commits. `versioning tag`, `tags`, and `untag` manage
immutable names for important commits. `versioning branch`, `branches`, and
`delete-branch` manage durable branch references; a branch name can be used
where a commit or tag is accepted. `commit --branch <name>` advances an
existing branch instead of `main`, and `log --branch <name>` follows that
branch's history. `protect-branch` durably blocks reset, deletion, and reflog
recovery;
repeatable `--allow-committer <identity>` arguments can restrict those
publications to exact committer identities. An empty allowlist permits any
committer. Repeatable `--allow-manager <identity>` arguments independently
restrict live policy changes and removal; an empty manager list permits any
authorized live operator. Successful and denied live policy changes are
durably audited with both identity lists, trusted signer IDs, and the resolved
signature quorum. Denied protected-branch commits and merges also record their
server-derived author/committer and target metadata,
and rejected reset, delete, recovery, and protected-history purge attempts are
recorded as denied maintenance actions. Audits never contain messages, file
contents, signatures, or bearer tokens.

Commit attestations are a second, independently opt-in layer. Generate an
Ed25519 key pair with
`versioning attestation-keygen --out <private.key> --public-out <public.key>`.
`versioning attest <tenant> <volume>
<commit-or-ref> --key-id <name> --key-file <private.key>` signs a canonical
statement containing the repository's stable logical UUID, commit ID, key ID,
algorithm, public key, and timestamp; the private key remains in the CLI
process and never enters SlateFS. Tenant and volume names are local placement
coordinates and are not part of the signature.
`versioning attestations ... --trusted-public-key <public.key>`
independently verifies every returned signature against the resolved commit and
requires at least one from that exact public key. Add `--live` to sign or
inspect through `slatefsd`.
`versioning export-attestations ... --out <bundle.json>` writes the resolved
repository UUID, commit, and its signatures as a portable version-2 bundle.
`versioning verify-attestation-bundle --in <bundle.json> --trusted-public-key <public.key>`
verifies it without loading a SlateFS config or contacting a repository or
daemon.

Complete repositories are portable independently of attestation-only bundles.
The export-repository command writes a checksummed .slatevcs binary bundle
containing the repository identity, commits, attestations, Prolly nodes,
content blobs, branches, tags, reflogs, and pruned-parent markers. The
import-repository command, with explicit --yes confirmation, validates every
envelope checksum, object hash, commit invariant, signature, and reference
before one atomic import into an uninitialized,
versioning-enabled destination repository. Enabling versioning alone does not
initialize the repository. The destination retains the source
repository UUID while SlateDB re-encrypts the logical records with the
destination volume's key. Retention settings, branch protection, leases, and
retry-idempotency records are local operational state and do not travel. Both
commands support --live; the daemon transports the native binary media type
without base64 conversion. Successful export, inspection, and import reports
include `bundle_sha256`; live export also returns it as
`X-SlateFS-Bundle-Sha256` for out-of-band transfer verification. Live imports
are limited to a 512 MiB request body;
larger repositories can use the offline commands while the involved volumes
are quiesced.

For ongoing replication, `versioning push` and `versioning pull` synchronize a
single branch directly with another `slatefsd` admin endpoint. The receiver
advertises its repository UUID and current branch head; the sender then emits a
checksummed `SLATESYN` pack containing only missing commits, attestations,
Prolly nodes, blobs, and pruned-parent markers. Applying the pack and moving the
branch are one atomic compare-and-swap. Fast-forward is the default: a stale
advertisement or divergent destination is rejected. `--force` permits an
explicit divergent replacement only when the destination branch is
unprotected; protected branches always reject force and still enforce their
local committer and attestation rules. Retention, protection, tags, and reflogs
do not travel, although the receiver records its own `sync` reflog entry and
audit event. An uninitialized, versioning-enabled destination adopts the source
repository UUID. Sync changes version history only; it does not restore files
into the live filesystem.

A protected branch can additionally trust one or more exact signer keys with
repeatable `--trust-attestation-key <key-id>=<public.key>`. Enabling that rule
requires the branch's current head to satisfy the configured signature quorum.
The default is one signature from any configured key; use
`--require-attestations <N>` to require N distinct trusted signers. New work is
committed on an unprotected candidate branch, attested by enough signers, and
then fast-forwarded into the protected branch. Candidates below quorum, direct
commits, and newly created unsigned merge commits are rejected. An empty
trusted-key list keeps signature enforcement disabled and requires a zero
quorum. `versioning quorum-status <tenant> <volume> <protected-branch>
<candidate>` resolves the candidate and reports the required count, matching
trusted key IDs, and whether promotion is ready without moving either branch.
Add `--check` to exit non-zero when the candidate is below quorum.

`unprotect-branch --yes` removes that guard. `versioning reflog <branch>` lists
the retained head transitions even after branch deletion. Every create, commit, fast-forward,
merge, reset, and delete records its ref change atomically; retained reflog
heads are GC roots, so this recovery window takes precedence over stricter
count or age retention. `recover-branch <name> <reflog-sequence> --yes`
atomically restores the head that preceded that exact transition, recreating a
deleted branch when necessary. `reset-branch <name> <commit-or-ref> --yes` deliberately
moves any existing branch, including `main`, without rewriting commits or file
data; the previous head remains recoverable while its reflog entry is retained.
`versioning merge <source> <target>` fast-forwards when possible or creates an
atomic two-parent three-way merge commit for divergent trees. The default
`--conflict-strategy fail` leaves both branches unchanged on a conflict.
`ours` keeps the target's complete value for each conflicting logical path;
`theirs` keeps the source's complete value. Both strategies still combine
non-conflicting changes from both branches.
`versioning merge-preview` reports the merge base, ahead/behind counts,
fast-forward state, and every conflicting logical path without writing.
`versioning cherry-pick <commit-or-ref> <target>` applies only the selected
commit's change relative to its parent and publishes the result as a new
single-parent commit on the target branch. Use `cherry-pick-preview` to inspect
the complete changed-path set and conflicts first. A target path that already
matches the selected commit is skipped; a target path that differs from both
the selected commit and its parent is a conflict, and any conflict leaves the
entire target branch unchanged. Cherry-picking a merge commit requires a
one-based `--mainline <parent-number>`; root and ordinary commits reject that
option. `--idempotency-key` makes an uncertain retry return the first result.
Cherry-pick changes version history only and never restores content into the
live filesystem.
`versioning inspect <commit-or-ref>` resolves a commit ID, tag, or branch and
shows the complete parent list, including both parents of a merge commit.
`versioning status [path] --reference <commit-or-ref>` compares the live
working tree with versioned metadata and bounded file contents, reporting
added, modified, deleted, and type-changed paths without writing either side.
`versioning restore-preview <commit-or-ref> <path> --mode overlay|exact`
translates that comparison into create, replace, and delete actions. Overlay
preserves live-only paths; exact includes the deletions needed for an exact
match. The preview returns a token binding the resolved commit, plan, and live
subtree fingerprint. `versioning restore` requires that token and `--yes`, and
rejects stale plans before mutation. File replacements are staged atomically;
multi-path restores are serialized but not globally atomic.
`versioning policy` reports opt-in and repository-lease state.

Any commit, immutable tag, or branch head can also be served as its own
read-only NFS or 9P export without restoring it into the live filesystem:

```sh
slatefs export add release-view --tenant <tenant> --volume <volume> \
  --version <commit-or-tag-or-branch> --protocol nfs --listen 127.0.0.1:12050
```

SlateFS resolves the supplied reference once and persists the exact commit ID,
so later branch movement cannot change an existing export. The daemon builds a
stable inode/directory view directly from that commit's Prolly tree and pins
the encrypted version store with an internal checkpoint for the lifetime of
the export. It does not copy content, restore files, or modify the live volume.
Historical exports are filesystem-only, always read-only, mutually exclusive
with `snapshot`, and support NFS or 9P but not NBD. Static `[[exports]]`
configuration uses `version = "<64-character-commit-id>"`; symbolic references
are accepted by the CLI and admin API because they are resolved before the
durable export record is written.
Show and restore stream versioned data in bounded chunks rather than loading a
complete large file into memory.
`versioning disable` stops all version operations but retains existing history;
ordinary filesystem I/O continues unchanged. A commit accepts multiple paths
and recursively captures directories, regular files, and symlinks in one
Prolly-root update. Selecting a missing path records its deletion; passing both
old and new paths records a rename as delete-plus-add. For a volume currently
served by `slatefsd`, pass `--live` to any versioning command; the CLI uses the
tenant-scoped authenticated admin API for policy, history, ranged content,
commits, restores, retention, stats, GC, and purge. Without `--live`,
repository operations are offline and must use a stopped or otherwise
quiesced volume.
Live commits verify and flush the volume writer lease before capture and again
before publishing the Prolly head. A fenced daemon returns `503` without
creating a commit so the caller can retry the promoted primary.

History lifecycle remains opt-in. `versioning retention` sets `--keep-last`,
`--max-age`, a hard `--max-bytes` history quota, and/or
`--reflog-keep-last` (1 to 100,000). The reflog window defaults to 100 transitions per branch;
lowering it immediately prunes older recovery entries and releases their GC
roots, while raising it applies to future transitions. For an enabled volume
served by `slatefsd`, the daemon applies count and age retention on its normal
export-control poll; disabled, unserved, policyless, and never-committed
volumes are untouched. `versioning gc` runs the same collection explicitly in
deterministic batches of at most 10,000 unreachable objects by default;
`--max-deletions` may select 1 to 1,000,000. The report exposes
`remaining_objects` and `complete`, so repeat until complete. `--dry-run`
reports the next batch without deleting it. `versioning stats` reports logical
usage, configured history quota, remaining headroom, percentage used, and an
explicit over-limit state. Automatic retention processes one default-sized
batch per poll.
Tags and branch heads pin their commit and Prolly tree through both automatic
and explicit GC until the reference is deleted. `show`, `restore`, and `diff`
accept a commit ID, tag name, or branch name.
`versioning verify` checks the reachable commit DAG, every detached
attestation and protected-branch trust rule, and every referenced Prolly node
and content blob.
`versioning purge --yes` permanently removes the physical history prefix while
leaving versioning enabled for a fresh next commit. Protected branches block
purge until their guards are explicitly removed. Commit, attestation, restore,
retention, GC, and purge actions emit durable audit records, and live daemon
operations
increment `slatefs_version_operations_total{tenant,volume,operation}`. An
automatic collection uses the `gc-auto` operation label. Protected-operation
rejections increment
`slatefs_version_operation_denials_total{tenant,volume,operation}`.
Native synchronization additionally reports cumulative bytes and objects,
failures, and the last successful transfer timestamp per `sent` or `received`
direction through `slatefs_version_sync_bytes_total`,
`slatefs_version_sync_objects_total`, `slatefs_version_sync_failures_total`,
and `slatefs_version_sync_last_success_timestamp_seconds`.

Every explicit repository operation and purge acquires a per-volume lease with
an atomic object-store conditional write. The lease is renewed while work is
active and permits stale-owner takeover after expiry on CAS-capable stores,
coordinating CLI and multiple daemon processes without opening a competing
SlateDB writer. A
contender receives HTTP `409` (or an `already exists` CLI error) and should
retry after the current operation finishes. The local `file://` backend lacks
conditional update; normal release is still automatic, but a lease orphaned by
a crashed process must be removed by an operator after confirming no owner is
active.

**Phase 6 started** (snapshots/clones, HA, performance, GA polish):
`slatefs snapshot create|list|delete` manages SlateDB checkpoints for a volume.
The CLI create path opens the volume as the writer so SlateDB can flush before
checkpointing; do not run it against a volume currently served by `slatefsd`.
For served volumes, configure loopback-only `[admin].listen` on `slatefsd` and
use `slatefs snapshot create --live <tenant> <volume>` to checkpoint through
the live writer.
`slatefs clone create <tenant> <source-volume> <clone-volume>`
creates an instant writable same-tenant clone, optionally from a checkpoint
with `--snapshot <id>`. Clones get distinct fsids and independent writes, but
they intentionally share source SSTs, so deleting a source volume is refused
while active clones point at it. `[[exports]] snapshot = "<checkpoint-id>"`
serves that checkpoint through the normal NFS or 9P frontend as a read-only
mount; live writes after the checkpoint are not visible there. `slatefs snapshot
retention show|set <tenant> <volume> [--keep-last N] [--max-age SECS] [--clear]`
stores a per-volume retention policy in the control plane. `slatefsd` enforces
policies on the same poll loop family by deleting checkpoints beyond
`keep_last` (newest kept) or older than `max_age`; named snapshots are not
exempt. If a volume is the parent of an active clone, retention preserves the
source checkpoint IDs recorded on that clone, including SlateDB's clone pin
checkpoint, while deleting unpinned checkpoints that match the policy. Legacy
clone records without recorded pin IDs keep the old conservative whole-parent
skip. Deletions write
`SnapshotRetentionDelete` audit records and increment
`slatefs_snapshots_retention_deleted_total{tenant,volume}`. `slatefs key
rotate-kek <tenant>` rotates that tenant's KEK by rewrapping active volume DEKs
in the control plane; volume data blocks are not rewritten. Optional
`[metrics].listen = "ip:port"` exposes Prometheus text at `/metrics`, including
SlateDB cache/flush samples per writable volume, `slatefs_volume_dead`,
`slatefs_exports_active{protocol,source}`, and
`slatefs_export_reconcile_failures_total`, plus live version commit/restore
counters.
`[admin].listen = "127.0.0.1:port"` exposes the daemon admin listener. It
keeps the legacy live-writer snapshot route and serves admin API v1:

| Method | Route | Notes |
| --- | --- | --- |
| `GET` | `/livez` | Process liveness JSON. |
| `GET` | `/readyz` | Readiness JSON; `?verbose=1` adds identity fields. |
| `GET` | `/status` | Legacy text status. |
| `POST` | `/snapshot/{tenant}/{volume}?name=` | Legacy live-writer snapshot. |
| `GET` | `/admin/v1/audit` | Audit records with `since`, `until`, `tenant`, `volume`, `action`, `limit`, `page_token`, `newest_first`. |
| `GET` | `/admin/v1/exports` | All exports with `source=config|control`; config exports are read-only. |
| `GET` | `/admin/v1/exports/{id}` | Export detail. |
| `POST` | `/admin/v1/exports` | Create an enabled control-plane export from JSON fields including `name`, `tenant`, `volume`, `protocol`, `listen`, `allowed_clients`, `read_only`, `sync`, and mutually exclusive `snapshot` or `version`; a symbolic version reference is persisted as its exact commit ID. |
| `PATCH` | `/admin/v1/exports/{id}` | Update a control-plane export; use JSON `null` to clear optional fields. Setting `version` resolves it against the resulting tenant and volume. |
| `DELETE` | `/admin/v1/exports/{id}` | Remove a control-plane export. |
| `GET` | `/admin/v1/tenants` | Tenant inventory with `limit` and `page_token`. |
| `PATCH` | `/admin/v1/tenants/{tenant}/rate` | Set nullable `ops_per_second` and/or `bytes_per_second`; `null` means unlimited. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes` | Volume inventory with `limit` and `page_token`. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}` | Volume detail. |
| `PATCH` | `/admin/v1/tenants/{tenant}/volumes/{volume}/quota` | Set nullable quota fields: `bytes_soft`, `bytes_hard`, `bytes_grace`, `inodes_soft`, `inodes_hard`, `inodes_grace`; returns limits and live usage. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/clones` | Create a writable clone from `{"clone_volume":"...","snapshot_id":"..."}`. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/snapshot?name=` | v1 live-writer snapshot alias. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/snapshots` | Checkpoint inventory with `limit`, `page_token`, and optional `name`. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/snapshot-retention` | Snapshot retention policy; named snapshots are not exempt. |
| `PATCH` | `/admin/v1/tenants/{tenant}/volumes/{volume}/snapshot-retention` | Set nullable `keep_last` and/or `max_age_secs`, or `{"clear":true}`. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning` | Opt-in state, retention policy, and current or last repository lease. |
| `PATCH` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning` | Enable or disable with `{"enabled":true|false}`; disabling retains history. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/bundle` | Export the complete checksummed repository as `application/vnd.slatefs.version-repository`. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/bundle` | Import a native bundle body into an uninitialized repository; the admin request-body limit is 512 MiB. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/sync/branches/{branch}` | Advertise the repository identity and current branch head, or `null` when the version repository is uninitialized. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/sync/branches/{branch}` | Negotiate an incremental `application/vnd.slatefs.version-sync` pack from JSON `{"have":"commit-or-null"}`. |
| `PUT` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/sync/branches/{branch}` | Atomically apply a sync pack with compare-and-swap and fast-forward enforcement; `?force=true` permits divergent replacement only for an unprotected branch. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/status` | Compare the live working tree with query `reference` (default `main`) and `path` (default `/`) without modifying either side. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/restore-preview` | Preview `create`, `replace`, and `delete` actions for required `commit` and `path`, with optional `mode=overlay|exact`. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/commits` | Commit history with optional `branch` (default `main`), `path`, `limit`, and exclusive `page_token`; returns `next_page_token`. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/commits/{commit-or-ref}` | Resolve a commit ID, tag, or branch and return `repository_id` plus the commit with its complete parent list. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/diff` | Added, modified, and deleted paths between required `from` and `to` commit IDs or tags; supports `limit` and exclusive path `page_token`. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/tags` | List immutable commit tags. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/tags` | Create a retention-pinning tag from `{"name":"...","commit":"..."}`. |
| `DELETE` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/tags/{name}` | Delete a tag without deleting its commit immediately. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches` | List branch heads, including `main`. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{name}/reflog` | List retained head transitions, newest first, including deleted branches; optional `limit` cannot exceed the configured per-branch recovery window. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches` | Create a branch from `{"name":"...","commit":"commit-or-ref"}`. |
| `PUT` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{name}/protection` | Protect a branch with optional `allowed_committers`, `allowed_managers`, `trusted_attestation_keys` objects containing `key_id`, `algorithm`, and `public_key`, and `required_attestations`. Trusted keys default to a 1-of-M signature quorum; the explicit count must be between 1 and M. |
| `DELETE` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{name}/protection` | Remove destructive-ref protection from a branch. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{name}/attestation-quorum?commit=` | Resolve a candidate commit or named reference and report its matching trusted key IDs and readiness against the branch's current signature quorum without moving the branch. |
| `DELETE` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{name}` | Delete a non-main branch without deleting its commit immediately. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{name}/reset` | Compare-and-swap an existing branch, including `main`, to `{"commit":"commit-or-ref"}`. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{name}/recover` | Restore the head preceding a retained reflog entry from `{"sequence":42}`, recreating a deleted branch when needed. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{target}/merge` | Fast-forward or three-way merge a target from `{"source":"...","conflict_strategy":"fail|ours|theirs","author":"..."}`; strategy defaults to `fail`, author defaults to the server-derived committer, and conflicts return `409`. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{target}/merge?source=` | Preview ancestry and logical-path conflicts without moving either branch. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{target}/cherry-pick` | Atomically apply one parent-relative commit delta from `{"source":"commit-or-ref","mainline":1,"author":"...","idempotency_key":"..."}`; optional `mainline` is required only for merge commits, and conflicts return `409`. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/branches/{target}/cherry-pick?source=&mainline=` | Preview the canonical source, selected parent, changed paths, already-applied state, and conflicts without moving the target branch. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/commits` | Atomically commit selected paths through the live writer from `{"paths":["..."],"message":"...","author":"...","idempotency_key":"...","branch":"main"}`; author, retry key, and branch are optional and singular `path` remains accepted. The response includes hash-bound `provenance`. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/commits/{commit-or-ref}/attestations` | Verify and immutably attach a detached Ed25519 attestation. Reposting the identical record is idempotent. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/commits/{commit-or-ref}/attestations` | List detached commit attestations ordered by key ID. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/commits/{commit-or-tag}/content?path=&offset=&length=` | Read a bounded file or symlink range as base64 JSON; defaults to 1 MiB and rejects ranges over 4 MiB. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/restore` | Apply a current preview through the live writer from `{"commit":"...","path":"...","mode":"overlay|exact","token":"..."}`; stale tokens return `409`. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/stats` | Logical history bytes, configured `max_bytes`, available bytes, usage percentage, over-limit state, nodes, blobs, commits, and attestations. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/verify` | Verify the reachable commit DAG, attestations, branch trust rules, Prolly nodes, and content blobs. |
| `GET` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/retention` | Current history retention and quota policy. |
| `PATCH` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/retention` | Set `keep_last`, `max_age_secs`, `max_bytes`, and/or positive `reflog_keep_last`, or `{"clear":true}`. Lowering the reflog limit prunes immediately. |
| `POST` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/gc` | Apply one bounded retention batch, or preview it with `{"dry_run":true,"max_deletions":10000}`. The response reports deleted objects by type, stale idempotency records, remaining objects, and whether collection is complete. |
| `DELETE` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/lease` | Break an expired lease with its exact observed `owner` and `{"confirm":true}`. |
| `DELETE` | `/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/history` | Permanently purge history; requires `{"confirm":true}` and no protected branches. |
| `GET` | `/admin/v1/nodes` | Daemon node inventory with `limit` and `page_token`. |

Every admin response includes `X-Request-Id`; callers may provide it or the
daemon generates a UUID. v1 errors use `{"error":{"code","message","request_id"}}`.
Version commit callers can separately provide an `idempotency_key` of up to
256 UTF-8 bytes. Repeating the same key with the same branch, canonical paths,
message, author, and committer returns the original commit and its original
request ID with `"replayed":true`; using it for a different request returns
HTTP 409. Retry records are retained and collected with their commits.
Unauthenticated loopback remains the default. To bind the admin listener
outside loopback, configure `[admin].token = "..."`, `token_file = "..."`, or
mTLS cert auth. Per-customer bearer tokens may be configured in
`[admin.tenant_tokens]`; each token is authorized only for its matching
`/admin/v1/tenants/{tenant}/...` subtree. `/admin/v1` routes require the configured app-level
authentication; `/livez` and `/readyz` remain unauthenticated but are still
served over HTTPS/mTLS when admin TLS is enabled.

For restart-free customer credential rotation, map tenants to files in
`[admin.tenant_token_files]`. Each file contains one token per line. The daemon
re-reads it for every authenticated request and accepts every listed token;
the CLI sends the first token. Put the new token first and retain the old token
on a second line during the overlap window, atomically replace the file, update
clients, then atomically replace it again with only the new token. Empty,
duplicate, whitespace-containing, unreadable, or cross-tenant ambiguous token
sources fail closed.

Enable HTTPS on the admin listener with `[admin].tls_cert` and
`[admin].tls_key`. Add `[admin].tls_client_ca` to require and verify client
certificates. Set `[admin].allow_cert_auth = true` only when a verified client
certificate should authenticate `/admin/v1` routes without a bearer token.
Certificate auth records audit principals as `cert:<SAN-or-CN>`. If a bearer
token is configured without TLS, startup warns that the token is accepted over
cleartext HTTP.

The `slatefs ... versioning ... --live` client uses HTTPS whenever an admin TLS
client field is configured. Set `[admin].tls_server_ca` for a private server CA
and `[admin].tls_server_name` when the certificate name differs from the
listener IP. For mTLS, also set `[admin].tls_client_cert` and
`[admin].tls_client_key`. Public WebPKI roots remain trusted. A shared
daemon-and-CLI config may omit `tls_server_ca`; the CLI then trusts `tls_cert`.

Admin TLS certificates and TLS-wrapped 9P export certificates are reloaded for
new connections without restarting `slatefsd`; existing TLS sessions continue
on the config they handshook with. The daemon polls cert/key/client-CA file
mtime and content hash every `[tls].reload_poll_secs` seconds (default `60`)
and also reloads immediately on `SIGHUP`. Reload failures keep serving the last
good config and emit `slatefs_tls_reload_failures_total{surface=...}`; successful
reloads emit `slatefs_tls_reloads_total{surface=...}` and
`slatefs_tls_cert_expiry_timestamp_seconds{surface=...}`.

| Mode | Admin config | Admin route authentication | Audit principal |
| --- | --- | --- | --- |
| Token-only | `token` or `token_file` | Bearer token over HTTP; startup warns about cleartext token transport. | `X-Admin-Principal` after token validation, otherwise no principal. |
| Tenant token | `[admin.tenant_tokens]` entry | Bearer token is restricted to the matching tenant subtree. | `tenant:<tenant>`. |
| TLS + token | Token plus `tls_cert` and `tls_key` | Bearer token over HTTPS. | Same as token-only. |
| mTLS + token | TLS + token plus `tls_client_ca` | Verified client certificate and bearer token are both required. | Same as token-only. |
| mTLS cert auth | mTLS plus `allow_cert_auth = true` | A verified client certificate is sufficient; bearer token is still accepted when configured. | `cert:<SAN-or-CN>` for cert-authenticated requests. |

Example mTLS admin config:

```toml
[admin]
listen = "0.0.0.0:12081"
token_file = "/run/slatefs/admin-token"
tls_cert = "/etc/slatefs/admin.pem"
tls_key = "/etc/slatefs/admin.key"
tls_client_ca = "/etc/slatefs/admin-ca.pem"
tls_server_ca = "/etc/slatefs/admin-ca.pem"
tls_server_name = "slatefs-admin.internal"
tls_client_cert = "/etc/slatefs/operator.pem"
tls_client_key = "/etc/slatefs/operator.key"
allow_cert_auth = false

[admin.tenant_tokens]
customer-a = "replace-with-customer-token"

# Prefer this file-backed form when customer credentials must rotate live.
[admin.tenant_token_files]
customer-b = "/run/slatefs/customer-b.tokens"
```

For a local lab CA and leaf certificates:

```sh
mkdir -p certs
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -keyout certs/ca.key -out certs/ca.pem -subj "/CN=slatefs-admin-ca"

openssl req -newkey rsa:3072 -nodes \
  -keyout certs/admin.key -out certs/admin.csr -subj "/CN=slatefs-admin"
cat > certs/admin.ext <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in certs/admin.csr -CA certs/ca.pem -CAkey certs/ca.key \
  -CAcreateserial -out certs/admin.pem -days 365 -extfile certs/admin.ext

openssl req -newkey rsa:3072 -nodes \
  -keyout certs/client.key -out certs/client.csr -subj "/CN=slatefs-operator"
cat > certs/client.ext <<'EOF'
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in certs/client.csr -CA certs/ca.pem -CAkey certs/ca.key \
  -CAcreateserial -out certs/client.pem -days 365 -extfile certs/client.ext
```

`slate-admind` supports `ca_cert`, `client_cert`, and
`insecure_skip_verify` client settings for calling slatefsd HTTPS or mTLS
admin URLs.

The control plane now also stores fleet placement: daemon node health/load,
per-volume primary ownership, standby lists, stable endpoints, drain/rebalance
state, read replicas, and snapshot-serving pools. `slatefs fleet node ...` and
`slatefs fleet volume ...` register nodes, heartbeat metrics, assign new
volumes to the lowest-load healthy daemon, promote standbys after failure, and
move stable endpoints when a drained volume is opened elsewhere.
Starter alert rules live in [monitoring/slatefs-prometheus-rules.yml](monitoring/slatefs-prometheus-rules.yml);
the starter Grafana dashboard lives in
[monitoring/slatefs-grafana-dashboard.json](monitoring/slatefs-grafana-dashboard.json);
outage, fence, restore, and key-rotation drills live in
[docs/operations-runbook.md](docs/operations-runbook.md), with an automated
NFS takeover drill in [scripts/nfs-failover-drill.sh](scripts/nfs-failover-drill.sh)
that can run under fio load, enforce the Phase 6 failover-time target, and
optionally run fsx after takeover.
The live snapshot mount drill is
[scripts/live-snapshot-over-nfs.sh](scripts/live-snapshot-over-nfs.sh); it also
mounts a writable clone restored from the checkpoint.
The NFS fio performance matrix is documented in
[docs/performance.md](docs/performance.md) and runnable via
[scripts/fio-over-nfs.sh](scripts/fio-over-nfs.sh). The production-like Azure
Blob cross-VM harness is [scripts/azure-prodtest.sh](scripts/azure-prodtest.sh);
it provisions a fresh rig, runs the matrix, starts local Prometheus/Grafana,
collects artifacts, and deallocates VMs by default.
The Phase 6 security review is recorded in
[docs/security-review.md](docs/security-review.md).
The current pre-GA on-disk format and explicit no-backwards-compatibility
upgrade policy live in [docs/on-disk-format.md](docs/on-disk-format.md).

**Block-device/NBD support implemented** (plan
[docs/block-device-plan.md](docs/block-device-plan.md)): SlateFS now has
`kind = block` volumes backed by the same encrypted per-volume SlateDB store,
an NBD frontend with fixed-newstyle negotiation, READ/WRITE/FLUSH/TRIM/
WRITE_ZEROES, single-writer session leases, optional TLS/mTLS, daemon export
reconciliation, CLI/admin support, and Prometheus metrics. Kernel ext4-over-NBD
and crash-recovery coverage lives in
[scripts/nbd-kernel-attach-test.sh](scripts/nbd-kernel-attach-test.sh);
QEMU userspace and ZFS showcase smokes are
[scripts/qemu-nbd-smoke.sh](scripts/qemu-nbd-smoke.sh) and
[scripts/zfs-over-nbd-smoke.sh](scripts/zfs-over-nbd-smoke.sh). Remaining
pre-GA items are the NBD fio/chunk-size matrix, the <10s failover timing gate,
the ext4 fstrim allocation-drop investigation, and ZFS validation on kernels
with zfs.ko.

> Testing against kernel NFS clients: always mount with
> `soft,intr,timeo=…` and bound every command touching the mountpoint
> with a timeout — a `hard,nointr` mount to a misbehaving dev server
> wedges macOS's global NFS client state until reboot/root intervention.

## Workspace

| Crate | Purpose |
|---|---|
| `slatefs-core` | protocol-independent core: crypto, control plane, volumes; VFS in Phase 1 |
| `slatefs-cli` | `slatefs` management CLI |
| `slatefs-daemon` | `slatefsd` server (stub until Phase 2) |
| `slatefs-nfs` | NFSv3 frontend (Phase 2) |
| `slatefs-9p` | 9P2000.L frontend (Phase 4) |
| `slatefs-nbd` | NBD block-device frontend |

## Quickstart (local MinIO)

```sh
docker compose up -d        # MinIO at :9000, bucket slatefs-test

export AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_ENDPOINT=http://localhost:9000 AWS_ALLOW_HTTP=true AWS_REGION=us-east-1

cargo build

# master key + config
./target/debug/slatefs keygen --out ./master.key
cp examples/slatefs.toml ./slatefs.toml   # edit: keyfile = "./master.key"

./target/debug/slatefs -c ./slatefs.toml tenant create t1
./target/debug/slatefs -c ./slatefs.toml volume create t1 v1
./target/debug/slatefs -c ./slatefs.toml volume info t1 v1
```

## Object Store URLs

SlateFS accepts object_store URLs in `[object_store].url`. For Azure Blob,
prefer either:

```toml
url = "https://account.blob.core.windows.net/container/prefix"
# or, with AZURE_STORAGE_ACCOUNT_NAME plus AZURE_STORAGE_ACCOUNT_KEY/AZURE_STORAGE_ACCESS_KEY:
url = "az://container/prefix"
```

For compatibility with older SlateFS deployments, `az://account/container/prefix`
is also accepted when `account` matches `AZURE_STORAGE_ACCOUNT_NAME`,
`account_name`, or `AccountName` in `AZURE_STORAGE_CONNECTION_STRING`. In that
case SlateFS treats the host as the storage account, the first path segment as
the container, and the remaining path as the root prefix. If no account env var
is available, SlateFS uses that legacy interpretation only for storage-account-
shaped hosts with a plausible container segment and an additional prefix
segment; otherwise object_store's native `az://container/prefix` form wins.

## Tests

```sh
cargo test --workspace                 # unit + file://-backed integration
SLATEFS_TEST_URL=s3://slatefs-test/it \
  cargo test -p slatefs-core --test phase0   # same harness against MinIO
```

The Phase 0 integration test creates a tenant and volume carrying known marker
strings, then downloads every raw object and asserts the markers never appear
at rest; wrong-key opens must fail closed.
