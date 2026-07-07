# SlateFS — Block Device (NBD) Plan

Virtual block devices backed by SlateDB, exported over the **NBD** (Network Block Device)
protocol, alongside the existing NFSv3/9P filesystem frontends. A block volume is a new
volume *kind* that reuses the existing per-volume SlateDB database, encryption, caching,
quota, and snapshot machinery — but exposes a flat byte range instead of a POSIX tree.

> Status: IMPLEMENTED through Phase B4 (v1, 2026-07-07). Core block volumes,
> NBD server, daemon exports, CLI/admin, TLS/mTLS, metrics, dashboard, and
> kernel/QEMU/ZFS smoke scripts are in-tree. Remaining work is explicit in §6:
> fio matrix + chunk-size default confirmation (BD-2), NBD failover timing gate
> (<10s AC), ext4 fstrim allocation-drop root cause, and continued ZFS
> validation where the host kernel provides zfs.ko.
> Design-decision numbers here are **BD-n** to avoid colliding with the master
> plan's **DD-n**; DD references below are to the master plan.

---

## 0. Why block devices

The NFS/9P frontends expose *file* semantics. A block device exposes *sector* semantics,
which unlocks workloads the POSIX layer cannot serve:

- **VM disk images** — QEMU/KVM/Proxmox attach NBD devices directly as virtual disks.
- **Foreign filesystems** — ZFS/ext4/XFS/btrfs on object storage (ZeroFS's flagship demo is
  `zpool create` on an NBD device).
- **Databases** — Postgres/MySQL get true local-FS semantics (locking, `O_DIRECT`, fsync
  guarantees) on an ext4-over-NBD that NFSv3 cannot provide.
- **Kubernetes raw block PVs** (`volumeMode: Block`), swap devices, legacy software that
  expects a disk.

Prior art: ZeroFS (§0 of the master plan) ships NBD-on-SlateDB and validates the
architecture. Same license caution applies: behavioral reference only unless its license is
confirmed permissive.

Protocol reference: the canonical NBD spec is
https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md (fixed-newstyle
negotiation + transmission phase). Linux `nbd.ko` + `nbd-client`, and QEMU's NBD client, are
the reference clients.

## 1. Goals and non-goals

### Goals
1. **Block volumes**: a `kind = block` volume with a fixed virtual size, thin-provisioned
   (unwritten regions cost nothing and read as zeros), living under the existing tenant /
   volume / DEK / quota model.
2. **NBD server frontend** (`crates/slatefs-nbd`): fixed-newstyle negotiation, `READ`,
   `WRITE` (+FUA), `FLUSH`, `TRIM`, `WRITE_ZEROES`, `DISC`; optional TLS.
3. **Crash consistency**: every `WRITE` is one atomic SlateDB commit; `FLUSH`/FUA map to the
   DD-7 durability contract, so a guest filesystem's journal recovery works exactly as it
   does on a local disk with a volatile write cache.
4. **Snapshots/clones of block volumes** via the existing checkpoint/clone machinery,
   including read-only NBD exports of snapshots.
5. **Ops parity**: control-plane export records with live reconciliation, admin API, CLI,
   Prometheus metrics, kernel-client CI tests — mirroring what NFS/9P already have.

### Non-goals (record as explicit deferrals)
- Multi-writer block volumes (same single-writer model as DD-5; scale-out = many volumes).
- iSCSI, virtio-blk / vhost-user-blk exports (NBD covers QEMU and Linux natively; revisit
  with the virtio-9p transport question in [client-support.md](client-support.md)).
- Online shrink (grow is supported; shrink is refused).
- Exporting a regular *file* from a filesystem volume as an NBD device (loopback-style).
  Attractive later, but it couples block semantics to the POSIX open-file/coherence model;
  a dedicated volume kind is simpler and safer for v1.
- A Kubernetes CSI driver (natural follow-on; out of scope for this plan).
- NBD structured replies / extended headers, `BLOCK_STATUS`, and `NBD_CMD_CACHE` beyond a
  no-op (v1 uses simple replies; revisit if sparse-read performance demands it).

## 2. Design decisions

**BD-1: A block volume is a new volume kind, not a file inside a filesystem volume.**
The control-plane `VolumeRecord` and the volume superblock gain a `kind` field
(`Filesystem` | `Block { size_bytes }`). A block volume's keyspace is a small subset of the
filesystem schema: the superblock `M`, content chunks, and quota counters — no inodes,
dirents, name encryption, xattrs, or orphan records. Rationale: (a) everything expensive to
get right (per-volume Db, DEK + AEAD transformer, compression, cache tiers, fencing,
checkpoints, quota merge counters) is inherited unchanged via DD-1/2/8/9; (b) none of the
POSIX machinery (locks on rename, permission checks, handle table) applies, so routing block
I/O through the `Vfs` trait would be all cost and no benefit. Block volumes get their own
narrow trait (BD-3).

**BD-2: Chunk layer is reused verbatim; a block volume is "one big sparse file".**
Content lives at the existing chunk keys `c/<BLOCK_INO>/<chunk_idx>` with a reserved
`BLOCK_INO` constant, so `data.rs` (`read_range`, `plan_write`, `plan_truncate`) and the
`billed_chunk_bytes` accounting rule (DD-6, DD-9) apply without modification. Absent chunk ⇒
zeros, which makes thin provisioning native. Chunk size remains an mkfs-time constant;
default for block volumes is **64 KiB** (vs 128 KiB for filesystem volumes) because guest
filesystems issue many 4–64 KiB random writes and the read-modify-write cost dominates —
confirm with the Phase B1 bench matrix (32/64/128/256 KiB under fio randwrite) before GA.

**BD-3: A dedicated `BlockDev` trait, implemented twice.**
```rust
#[async_trait]
pub trait BlockDev: Send + Sync {
    fn geometry(&self) -> BlockGeometry;   // size_bytes, min/preferred/max block sizes, read_only
    async fn read(&self, offset: u64, len: u32) -> FsResult<Bytes>;
    async fn write(&self, offset: u64, data: Bytes, fua: bool) -> FsResult<()>;
    async fn flush(&self) -> FsResult<()>;
    async fn trim(&self, offset: u64, len: u64) -> FsResult<()>;
    async fn write_zeroes(&self, offset: u64, len: u64, fua: bool) -> FsResult<()>;
}
```
Implementations: `BlockVolume` (writable, wraps the volume `Db`, quota tracker, striped
chunk locks) and `SnapshotBlockVolume` (read-only over `DbReader::with_checkpoint`,
mirroring `SnapshotVolume`; all mutating ops return `EROFS`). The NBD frontend depends only
on this trait, exactly as NFS/9P depend only on `Vfs`.

**BD-4: Durability mapping extends DD-7 one-to-one.**
- `WRITE` → chunk `WriteBatch` with `await_durable: false` (ack from memtable + WAL buffer).
- `FLUSH` → `Db::flush()`; reply only after it returns.
- FUA flag on `WRITE`/`WRITE_ZEROES` → commit, then `Db::flush()` before replying.
- Advertised transmission flags: `HAS_FLAGS | SEND_FLUSH | SEND_FUA | SEND_TRIM |
  SEND_WRITE_ZEROES | CAN_MULTI_CONN` (+ `READ_ONLY` for snapshot exports).
This is precisely the "local disk with a volatile write cache" contract journaling
filesystems are designed for: ext4/XFS/ZFS issue FLUSH/FUA at commit points, and un-fsynced
data may be lost up to `flush_interval` on crash. `CAN_MULTI_CONN` is safe *by construction*:
all connections hit the same single-writer `Db`, and `Db::flush()` is volume-wide, so a
FLUSH on any connection covers completed writes on all connections (the spec's requirement).
A per-export `sync = "strict"` forces `await_durable: true` per write, as with NFS.

**BD-5: TRIM and WRITE_ZEROES deallocate; reads of holes return zeros.**
`TRIM(offset, len)` and `WRITE_ZEROES(offset, len)` delete fully-covered chunks
(batched deletes, same crash-safe pattern as truncate reaping — quota `merge`
deltas commit with each delete batch) and RMW-zero partial-chunk edges, so both
are exact. NBD permits trimmed regions to read as zero; exact edge handling is
required in practice because Linux ext4/fstrim may issue free extents at
filesystem block granularity, not SlateFS chunk granularity. Both return quota:
`billed_chunk_bytes` already bills only existing chunks. Direct NBD discard
over freed extents (`blkdiscard`) shrinks object-store usage; ext4 `fstrim`
over a deleted file still did not lower allocation in the local Docker/OrbStack
kernel run and remains a Phase B3 investigation item.

**BD-6: Exclusive writer session; many readers for snapshots.**
Block devices have no cross-client cache coherence, so a writable export admits **one client
session at a time**: the first successful negotiation takes an in-process session lease
(keyed by export); further attaches are refused during negotiation until all of the holder's
connections close. Multiple TCP connections presenting within an existing session's grace
are treated as the same client's multi-connection setup (`nbd-client -C n`). Plain exports
key the session by client IP, matching the DD-10 network-isolation posture; mTLS exports key
the session by verified client-certificate identity. Read-only snapshot exports admit
unlimited concurrent sessions.
Cross-*node* safety remains SlateDB writer fencing (DD-5): on `Error::Fenced` the daemon
hard-closes the export's NBD connections immediately via the export shutdown handle.

**BD-7: Request concurrency with per-chunk striping.**
NBD clients pipeline requests; the server executes them concurrently (bounded, e.g. 64 in
flight per connection) and may reply out of order (handles are echoed back). Correctness:
overlapping in-flight writes are undefined behavior per the NBD spec, but we still serialize
conflicting extents via the existing striped `LockManager`, keyed by `(BLOCK_INO,
chunk_idx)`, so a buggy client corrupts only its own data, never our invariants. Multi-chunk
reads use a `Db::snapshot()` (already done in `read_range`) so they can't tear.

**BD-8: Tenancy and auth follow DD-10.**
NBD has no in-protocol authentication. A writable NBD export binds to a distinct
(listen-address, port) with per-tenant `allowed_clients` CIDR rules, and deployment guidance
mandates network-layer isolation — identical posture to NFSv3. NBD TLS exports run
FORCEDTLS: clients must negotiate `NBD_OPT_STARTTLS` before any export option, and optional
client-CA configuration requires a verified client certificate. Plain NBD exports still refuse
`NBD_OPT_STARTTLS`.
The client's requested export name in `NBD_OPT_GO` must equal the export's configured
`/tenant/volume` name (defense in depth against misdirected clients; `NBD_OPT_LIST` returns
only that one name).

**BD-9: Geometry, sizing, resize.**
`size_bytes` is fixed at create time and stored in both the control record and the
superblock (superblock is authoritative; mismatch fails open, loudly). Constraints:
`size_bytes` must be a multiple of 4096; max = `chunk_size × 2^32` (16 TiB @ 4 KiB … 16 PiB
@ 4 MiB; 4 TiB at the 64 KiB default × 2^26 chunks is ample — same u32 chunk-index bound as
files). Advertised block sizes: minimum 512 (RMW handles sub-chunk writes), preferred =
`chunk_size`, maximum payload 32 MiB (spec default; large requests are split into per-chunk
batches internally). **Grow** (`slatefs volume resize --grow`) is metadata-only (bump both
size records) and requires the volume offline or the daemon to renegotiate — v1: offline
only. **Shrink is refused.** Quota: `qB` bills allocated chunk bytes as today (thin);
`qI` is fixed at 1. Operators who want thick semantics set the byte quota to `size_bytes`.

## 3. Keyspace (block volumes)

| Key | Value | Notes |
|---|---|---|
| `M` | `Superblock { …, kind: Block { size_bytes } }` | format_version bump; `name_enc` unused |
| `c/<BLOCK_INO:u64>/<chunk:u32>` | raw chunk bytes (≤ chunk_size) | absent ⇒ zeros; identical to file chunks (BD-2) |
| `q/usage/bytes` (`qB`) | i64 merge counter | billed_chunk_bytes rule, DD-9 |
| `q/usage/inodes` (`qI`) | i64 = 1 | kept for uniform quota plumbing |

`slatefs volume fsck` on a block volume checks: no keys outside this set, no chunk beyond
`size_bytes`, no chunk value longer than `chunk_size`, `qB` == recount. `--recount` rebuilds
`qB` by scan, same as filesystem volumes.

## 4. Protocol mapping (transmission phase)

| NBD command | SlateFS action | Errors |
|---|---|---|
| `NBD_CMD_READ` | `read_range` (snapshot for multi-chunk); zero-fill holes; reject reads past `size_bytes` | `EINVAL` OOB |
| `NBD_CMD_WRITE` | quota `reserve` → `plan_write` → atomic batch (+FUA ⇒ flush) | `ENOSPC` on EDQUOT (see below), `EINVAL` OOB, `EROFS` |
| `NBD_CMD_FLUSH` | `Db::flush()` | `EIO` on storage failure |
| `NBD_CMD_TRIM` | delete covered chunks, batched | best-effort per spec |
| `NBD_CMD_WRITE_ZEROES` | delete covered + RMW edges (+FUA ⇒ flush) | as WRITE |
| `NBD_CMD_DISC` | drain in-flight, drop connection (no implicit flush, per spec) | — |
| `NBD_CMD_CACHE` | no-op success | — |

`EDQUOT` has no NBD equivalent; report `ENOSPC`, which guests handle as a full disk. Rate
limiting reuses the tenant `RateLimiter` (charge by payload bytes); an empty bucket delays
the request rather than erroring (block clients treat errors as I/O failures, unlike NFS's
retriable JUKEBOX) — token-bucket wait, bounded by the in-flight cap for backpressure.

Fencing / fatal storage errors: reply `EIO` to in-flight requests, then hard-close all
connections of the export and mark the volume dead (same handling as the FS frontends).
Failover recipe is unchanged (floating IP → new node opens the Db); document that clients
should use `nbd-client -persist` / QEMU `reconnect-delay` for transparent retry.

## 5. Repository changes

```
crates/
├── slatefs-core/      # + BlockDev trait, BlockVolume, SnapshotBlockVolume, superblock/record kind,
│                      #   block fsck arm, resize; data.rs untouched (BD-2)
├── slatefs-nbd/       # NEW: codec (negotiation + transmission), server loop, session lease,
│                      #   TLS, in-process test client
├── slatefs-daemon/    # exports: protocol = "nbd", reconciliation arm, metrics
└── slatefs-cli/       # volume create --kind block --size, volume resize --grow,
                       #   export add --protocol nbd
```

Config/export surface: `[[exports]]` and control-plane `ExportRecord` gain
`protocol = "nbd"` plus `read_only` and `sync`; NBD TLS fields are intentionally deferred.
Admin API needs no new routes — the existing `/admin/v1/exports` CRUD and
volume/quota routes cover block volumes; `GET …/volumes/<v>` additionally reports
`kind`, `size_bytes`, and allocated bytes.

Metrics (naming per existing conventions): `slatefs_nbd_requests_total{cmd,tenant,volume}`,
per-cmd latency histograms, `slatefs_nbd_bytes_{read,written}_total`,
`slatefs_nbd_inflight`, `slatefs_nbd_sessions_active`,
`slatefs_nbd_attach_rejected_total{reason=busy|auth|name}`, flush latency. Grafana: add an
NBD row to the existing dashboard.

## 6. Phased milestones

### Phase B1 — Block volume core (no wire protocol)
`kind` in superblock + control record; `BlockDev` trait; `BlockVolume` over `data.rs`
(read/write/flush/trim/write_zeroes, quota, striped chunk locks); `SnapshotBlockVolume`;
CLI `volume create --kind block --size … | info | delete | fsck [--recount] | resize --grow`;
chunk-size bench matrix to confirm the 64 KiB default.
Tests, copying the Phase 1 culture: **model-based property tests** — random
read/write/trim/zeroes/flush sequences against `BlockVolume` (memory:// store) and a plain
`Vec<u8>` reference, byte- and errno-exact, quota compared to recount after every sequence;
**crash loop** — seeded churn child `abort()`s mid-stream, parent reopens, fsck clean,
flushed prefix intact.
**AC**: 100k-op property runs clean across 1000 seeds; crash loop (500 kill-points) clean;
`qB` exact to the byte; TRIM provably returns quota; snapshot of a live block volume reads
consistently while writes continue.

**Implemented**: block volume kind and superblock/control-plane records are in
[crates/slatefs-core/src/meta/superblock.rs](../crates/slatefs-core/src/meta/superblock.rs),
[crates/slatefs-core/src/control.rs](../crates/slatefs-core/src/control.rs), and
[crates/slatefs-core/src/config.rs](../crates/slatefs-core/src/config.rs). The
`BlockDev`, `BlockVolume`, exact `TRIM`/`WRITE_ZEROES`, snapshots, quota, fsck,
and resize core live in [crates/slatefs-core/src/block.rs](../crates/slatefs-core/src/block.rs)
with coverage in `crates/slatefs-core/tests/block*.rs`. The CLI has
`volume create --kind block`, `volume info`, `volume fsck|scrub`, and offline
`volume resize --size` in [crates/slatefs-cli/src/main.rs](../crates/slatefs-cli/src/main.rs).
Remaining B1 work: run and record the fio chunk-size matrix to confirm the
64 KiB default from BD-2 before GA.

### Phase B2 — NBD server
`slatefs-nbd`: fixed-newstyle negotiation (`OPT_GO`/`INFO`/`LIST`/`ABORT`/`STARTTLS`),
transmission loop with bounded out-of-order execution (BD-7), session lease (BD-6),
durability flags (BD-4); daemon export wiring + live reconciliation; a minimal in-crate NBD
*client* for tests (the protocol is small; existing Rust NBD client crates are immature —
evaluate `nbd` crate first, expect to write our own test client).
Tests: golden-frame tests for negotiation, frame fuzzing on the codec (mirroring the 9P
approach), and an **in-process wire suite** (no root, like `slatefs-nfs/tests/`): read/write
round-trips at unaligned offsets, FLUSH/FUA ordering, TRIM, second-attach refusal, read-only
snapshot export, forged/wrong export name rejection, server restart → client reconnect,
fencing kills connections.
**AC**: wire suite green in CI; fuzzer finds no panics; a stock `nbd-client`/`qemu-img info
nbd://…` interoperates in a manual smoke.

**Implemented**: [crates/slatefs-nbd/src/lib.rs](../crates/slatefs-nbd/src/lib.rs)
implements fixed-newstyle negotiation (`OPT_GO`/`INFO`/`LIST`/`ABORT`/`STARTTLS`),
simple replies, read/write/flush/trim/write-zeroes/cache/disconnect,
bounded in-flight request execution, multi-connection session leases, mTLS-aware
identity, source allowlists, rate limiting, metrics, and an in-process test
client/wire suite. Daemon reconciliation and NBD export binding are wired in
[crates/slatefs-daemon/src/main.rs](../crates/slatefs-daemon/src/main.rs).

### Phase B3 — Kernel-client integration & durability proof
Privileged docker CI (extend `scripts/docker-kernel-mount-test.sh` pattern):
`scripts/nbd-kernel-attach-test.sh` — `nbd-client` attach (multi-conn), `mkfs.ext4`, mount,
fsstress, `fstrim` attempt + deleted-extent `blkdiscard` allocation-drop proof, clean detach; **crash-recovery drill** —
kill `slatefsd` mid-fio-on-ext4, restart, reattach, mount must replay the journal cleanly
(`e2fsck -f` clean), no acknowledged-FLUSH data lost; fio matrix (seq/rand × R/W × 4k/64k/1M)
recorded in [performance.md](performance.md) alongside the NFS numbers.
**AC**: ext4-over-NBD kernel test green in CI including the crash drill; fio numbers
documented with chunk-size conclusion; failover drill (floating-endpoint recipe) < 10s to
resumed I/O, zero corruption.

**Implemented**: [scripts/nbd-kernel-attach-test.sh](../scripts/nbd-kernel-attach-test.sh)
creates a block volume, attaches a real Linux `nbd-client`, formats ext4,
mounts ext4, exercises file operations, attempts `fstrim`, verifies a
deleted-extent `blkdiscard` fallback lowers allocated bytes, kills/restarts `slatefsd` mid-load, remounts for journal
replay, and requires `e2fsck -f -p` clean. The privileged CI job is
`kernel-nbd` in [.github/workflows/ci.yml](../.github/workflows/ci.yml).
Remaining B3 work: record the fio seq/rand × R/W × 4 KiB/64 KiB/1 MiB matrix
add the NBD failover drill timing gate (<10s resumed I/O, zero corruption),
and finish the ext4 fstrim allocation-drop investigation.
TRIM outcome: Linux `nbd.ko`/`nbd-client` do not propagate the NBD preferred
block size into discard granularity, so exact TRIM now handles partial edge
chunks. However, local ext4 `fstrim` still did not lower allocation after
deleting a file; it reported only small or zero FITRIM coverage even when
targeted at captured file extents. The kernel smoke records
`SLATEFS_NBD_FSTRIM_NO_ALLOC_DROP` and uses a deleted-extent `blkdiscard`
fallback to keep the rest of the kernel/crash drill covered.

### Phase B4 — TLS, ops polish, showcase workloads
`STARTTLS`/`FORCEDTLS` with rustls (+ client-cert option); metrics + Grafana row + alert
rules (attach-rejection spikes, flush latency); runbook section (attach/detach, resize,
failover, snapshot-restore drills); client support matrix update; **ZFS smoke test** —
`zpool create` on an NBD export, write/scrub/snapshot, `zpool status` clean (the marquee
demo); QEMU guest boot-from-NBD smoke.
**AC**: TLS-required export refuses plaintext; ZFS and QEMU smokes green (manual or CI where
practical); docs/runbook/dashboard shipped; `/security-review` run over the new listener
surface.

**Implemented**: NBD `STARTTLS` is forced when `nbd_tls_cert`/`nbd_tls_key` are
configured, and `nbd_tls_client_ca` requires a verified client certificate.
Metrics are emitted as `slatefs_nbd_*`, with dashboard panels in
[monitoring/slatefs-grafana-dashboard.json](../monitoring/slatefs-grafana-dashboard.json)
and attach-rejection alerts in
[monitoring/slatefs-prometheus-rules.yml](../monitoring/slatefs-prometheus-rules.yml).
The QEMU userspace smoke is [scripts/qemu-nbd-smoke.sh](../scripts/qemu-nbd-smoke.sh);
the ZFS showcase smoke is [scripts/zfs-over-nbd-smoke.sh](../scripts/zfs-over-nbd-smoke.sh)
and skips cleanly when zfs.ko is unavailable. Client support and operational
recipes are synced in [client-support.md](client-support.md) and
[operations-runbook.md](operations-runbook.md). Remaining B4 work is environment
validation for ZFS on runner/production kernels that actually ship the ZFS
module.

## 7. Risks & open questions

1. **RMW write amplification** on small random writes (the workload block devices attract).
   Mitigation: 64 KiB default + B1 bench matrix; if 4k-heavy workloads still suffer,
   consider a smaller-chunk volume option (mkfs-time, already supported down to 4 KiB).
2. **Plain-NBD session identity is still source-IP based** (BD-6). This is
   weak identity under NAT, but acceptable only under the DD-10 network-isolation
   posture. The stronger path is implemented: mTLS exports key writable sessions
   by verified client-certificate identity.
3. **Linux discard granularity is smaller than SlateFS chunks**. Linux
   `nbd.ko` sets discard support from `NBD_FLAG_SEND_TRIM` and logical/physical
   block size from the userspace `NBD_SET_BLKSIZE` value; it does not advertise
   the NBD preferred block size as discard granularity. `nbd-client` also
   ignores `NBD_INFO_BLOCK_SIZE` in `OPT_GO` and defaults its block size to 512
   unless `-b` is supplied. ext4/fstrim may therefore emit filesystem-block-scale
   free extents. Mitigation implemented: exact TRIM RMW-zeroes partial edge
   chunks and keeps batched deletes for fully-covered chunks; the cost is extra
   RMW writes on trim edges. Open finding: in the local Docker/OrbStack kernel,
   ext4 `fstrim` did not issue the deleted file extents even after remount and
   targeted `fstrim -o/-l`; direct `blkdiscard` over the captured extents did.
4. **Linux `nbd.ko` quirks**: reconnect semantics, `-persist` behavior across server
   restarts, timeout-induced device errors wedging mounts. Same discipline as the NFS kernel
   tests (soft timeouts, forced cleanup); capture findings in client-support.md.
5. **Blocking on rate limit** (§4) interacts with client timeouts — bound the wait below the
   kernel's default nbd timeout and document tenant-limit sizing.
6. **`NBD_OPT_LIST`/name privacy** — listing returns only the export's own name; verify no
   cross-tenant metadata leaks from negotiation replies.
7. **Structured replies** deferred: sparse reads currently transmit zeros for holes. If VM
   images prove hole-heavy over slow links, revisit `BLOCK_STATUS` + structured reads.
8. **Resize-while-attached** deferred (offline grow only); QEMU supports live resize via
   `block_resize` — demand may pull this forward.
9. **ZeroFS license** before reading its NBD source (master plan §0 caution applies).
