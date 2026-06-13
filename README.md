# SlateFS

A multi-tenant POSIX filesystem served over **NFSv3** and **9P2000.L**, with
[SlateDB](https://slatedb.io) as the storage engine (object storage as the
durable backend), compression + encryption at rest, and tiered local caches.

Design and roadmap: [slatefs-plan.md](slatefs-plan.md).

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
xattrs, and readdir (`scripts/p9-kernel-mount-test.sh`, in CI). The
daemon now shares one `Volume` across all exports of the same
tenant/volume (single SlateDB writer, DD-5).

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
Remaining: QEMU virtio-9p smoke, rustls.

**Phase 5 started** (multi-tenant hardening & quotas UX): tenants can now be
suspended/resumed via `slatefs tenant suspend|resume`; suspended tenants retain
their encrypted metadata and keys, but new volume creates and `slatefsd` export
resolution fail closed until resumed. Per-export source-IP allowlists
(`allowed_clients = ["127.0.0.1", "10.0.0.0/8"]`) are enforced by both NFS and
9P before request decoding. Tenant frontend rate limits (`slatefs tenant rate
show|set`) add shared token buckets for ops/s and request bytes/s across all
exports of a tenant. Quota limits are operator-manageable with `slatefs quota
show|set`, including hard limits and soft limits that become enforcing after
their grace deadline expires. `slatefs volume scrub` runs the structural checker
through a read-only SlateDB reader, so it can compare counters/recount while the
volume is being served. Live quota enforcement still uses the limits loaded when
a volume is opened, so changed limits apply on the next serve/open cycle.
`slatefs tenant delete --yes` and `slatefs volume delete --yes` mark records
deleting, drop wrapped keys from the current control-plane state, and delete
the affected volume object-store prefixes.

**Phase 6 started** (snapshots/clones, HA, performance, GA polish):
`slatefs snapshot create|list|delete` manages SlateDB checkpoints for a volume.
The current create path opens the volume as the writer so SlateDB can flush
before checkpointing; do not run it against a volume currently served by
`slatefsd`. `slatefs clone create <tenant> <source-volume> <clone-volume>`
creates an instant writable same-tenant clone, optionally from a checkpoint
with `--snapshot <id>`. Clones get distinct fsids and independent writes, but
they intentionally share source SSTs, so deleting a source volume is refused
while active clones point at it. `[[exports]] snapshot = "<checkpoint-id>"`
serves that checkpoint through the normal NFS or 9P frontend as a read-only
mount; live writes after the checkpoint are not visible there. `slatefs key
rotate-kek <tenant>` rotates that tenant's KEK by rewrapping active volume DEKs
in the control plane; volume data blocks are not rewritten. Optional
`[metrics].listen = "ip:port"` exposes Prometheus text at `/metrics`, including
SlateDB cache/flush samples per writable volume and `slatefs_volume_dead`.
Starter alert rules live in [monitoring/slatefs-prometheus-rules.yml](monitoring/slatefs-prometheus-rules.yml);
outage, fence, restore, and key-rotation drills live in
[docs/operations-runbook.md](docs/operations-runbook.md), with an automated
NFS takeover drill in [scripts/nfs-failover-drill.sh](scripts/nfs-failover-drill.sh).
The current pre-GA on-disk format and explicit no-backwards-compatibility
upgrade policy live in [docs/on-disk-format.md](docs/on-disk-format.md).

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

## Tests

```sh
cargo test --workspace                 # unit + file://-backed integration
SLATEFS_TEST_URL=s3://slatefs-test/it \
  cargo test -p slatefs-core --test phase0   # same harness against MinIO
```

The Phase 0 integration test creates a tenant and volume carrying known marker
strings, then downloads every raw object and asserts the markers never appear
at rest; wrong-key opens must fail closed.
