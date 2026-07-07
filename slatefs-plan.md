# SlateFS — Implementation Plan

A multi-tenant POSIX filesystem served over **NFSv3** and **9P2000.L**, with **SlateDB** as the
storage engine (object storage as the durable backend), **compression + encryption at rest**, and
**local memory/disk caches** so warm reads never touch the object store.

> Status: PLAN (v1, 2026-06-12). Written against SlateDB `0.13.0` as checked out at
> `/Users/dunnry/src/slatedb`. All SlateDB API references below were verified against that tree;
> re-verify if the pinned version changes.

---

## 0. Prior art & references

- **ZeroFS** (https://github.com/Barre/zerofs) is an existing 9P/NFS/NBD-on-SlateDB filesystem and
  validates this exact architecture (ChaCha20-Poly1305 encryption, compress-then-encrypt, tiered
  caches, microsecond warm reads). Use it as a *behavioral* reference and for protocol edge cases.
  **⚠ Before copying any code, check its license** — if it is not permissive, treat it as a
  black-box reference only (read docs/behavior, not source).
- NFSv3 server crates: `nfsserve` (https://github.com/xetdata/nfsserve, implement
  `vfs::NFSFileSystem`), the maintained fork `zerofs_nfsserve` (https://lib.rs/crates/zerofs_nfsserve),
  and the more recent fork `nfs3_server` (https://docs.rs/nfs3_server, split
  `NfsReadFileSystem`/`NfsFileSystem` traits). Phase 2 includes a selection spike.
- 9P2000.L protocol spec: https://github.com/chaos/diod/blob/master/protocol.md (the de-facto
  9P2000.L reference); Linux v9fs is the reference client.
- SlateDB docs: `slatedb/README.md`, examples in `examples/src/`, DST harness in `slatedb-dst/`.

### SlateDB capabilities this design is built on (verified in-tree)

| Capability | API | Where |
|---|---|---|
| Ordered KV, range & prefix scans | `Db::{get,put,delete,scan,scan_prefix}` | `slatedb/src/db.rs` |
| Atomic multi-key writes | `WriteBatch`, `Db::write` | `slatedb/src/batch.rs` |
| Transactions (SI / SSI) | `Db::begin(IsolationLevel)` → `DbTransaction::commit` | `slatedb/src/db_transaction.rs` |
| Consistent point-in-time reads | `Db::snapshot()` → `DbSnapshot` | `slatedb/src/db_snapshot.rs` |
| Counters via read-modify-write | `MergeOperator` trait, `Db::merge`, `WriteBatch::merge` | `slatedb/src/merge_operator.rs` |
| Compression (engine-level) | `Settings::compression_codec` (Snappy/Zlib/Lz4/Zstd), per-block | `slatedb/src/config.rs` |
| Encryption hook (engine-level) | `BlockTransformer` trait via `DbBuilder::with_block_transformer`; applied **after compression**, checksums computed over transformed bytes; **also applied to WAL SSTs** | `slatedb/src/format/sst.rs`, `slatedb/src/wal/wal_sst_builder.rs` |
| In-memory block cache | `DbCache` trait; foyer/moka impls, `DbBuilder::with_db_cache` | `slatedb/src/db_cache/` |
| Local-disk read cache (ciphertext) | `Settings::object_store_cache_options` (`ObjectStoreCacheOptions { root_folder, max_cache_size_bytes, part_size_bytes, … }`); `CachedObjectStore` wraps the object store *below* SST decode, so it caches post-transformer (encrypted) bytes | `slatedb/src/cached_object_store/`, `slatedb/src/db/builder.rs:481` |
| Single-writer fencing | manifest `writer_epoch` + WAL fence; stale writer gets `Error::Fenced` | `slatedb/src/fence.rs` |
| Read replicas / point-in-time readers | `DbReader` (+ `.with_checkpoint(uuid)`) | `slatedb/src/db_reader.rs` |
| Snapshots & writable clones | `Db::create_checkpoint`, `CloneBuilder` | `slatedb/src/checkpoint.rs`, `slatedb/src/clone.rs` |
| Durability control | `WriteOptions::await_durable`, `Db::flush`, `Settings::flush_interval`, separate WAL store via `with_wal_object_store` | `slatedb/src/config.rs` |
| Object store backends | `Db::resolve_object_store("s3://…" / "gs://…" / "az://…" / "file://…" / "memory://")` | `slatedb/src/object_stores.rs` |
| Deterministic simulation testing | seeded harness, fault-injecting object stores | `slatedb-dst/` |

---

## 1. Goals and non-goals

### Goals (v1)
1. POSIX-compliant-as-protocol-allows filesystem: files, directories, symlinks, hardlinks, device
   nodes, permissions, xattrs, sparse files, atomic rename. Target: pass the applicable
   `pjdfstest` suite over both NFS and 9P mounts.
2. Two wire protocols against one shared VFS core: **NFSv3** (universal client support) and
   **9P2000.L** (richer POSIX mapping, virtio-capable for VMs).
3. All data and metadata at rest is **compressed then encrypted** (object store *and* WAL).
   Per-tenant keys; losing the bucket leaks nothing but sizes/access patterns.
4. **Warm reads from local caches**: RAM (plaintext blocks) → local NVMe (ciphertext object parts)
   → object store. No object-store round trip for cache hits.
5. **Multi-tenancy**: hard isolation between tenants, per-tenant encryption keys, per-volume byte
   and inode **quotas** enforced at write time, accurate `statfs`/`df`.
6. Crash consistency: every FS mutation is one atomic SlateDB commit; `kill -9` at any point never
   yields a torn filesystem.
7. Instant snapshots and writable clones of volumes (SlateDB checkpoints/clones).

### Non-goals (v1) — record as explicit deferrals
- NFSv4.x (stateful: leases, delegations, compound ops). NLM/NSM sideband locking for NFSv3
  (clients mount with `nolock` / `local_lock=all`).
- Multi-writer / distributed write path per volume (SlateDB is single-writer per DB; we scale by
  volume sharding and read replicas, not multi-master).
- SMB/Windows, FUSE (trivial to add later on the same VFS, but out of scope).
- Dedup, tiering policies, NBD block devices.
- Cross-client cache coherence guarantees stronger than NFSv3 close-to-open.

---

## 2. System overview

```
                    ┌────────────────────────── slatefsd (one process) ──────────────────────────┐
 NFSv3 client ──────► nfs frontend (zerofs_nfsserve / nfs3_server)  ─┐                            │
 (Linux/mac/BSD)    │                                                ├─► VFS core ─► Volume layer │
 9P client ─────────► 9p frontend (own 9P2000.L impl)               ─┘    │  │            │       │
 (v9fs, QEMU)       │                                                     │  │   one slatedb::Db  │
                    │   auth / tenant resolution / rate limits            │  │   per volume       │
                    │   in-proc lock mgr, attr cache, open-file table ────┘  │        │           │
                    └────────────────────────────────────────────────────────┼────────┼───────────┘
                                                                             │        │
                                              control-plane DB (tenants, ────┘        │
                                              volumes, wrapped keys, quotas)          │
                                                                                      ▼
                                                       SlateDB: memtable → WAL SSTs → L0 → compacted
                                                        │ block cache (RAM, plaintext blocks)
                                                        │ CachedObjectStore (NVMe, ciphertext parts)
                                                        ▼
                                                       Object store (S3 / GCS / Azure / MinIO)
```

One `slatefsd` process hosts many volumes. Each **volume** is an independent SlateDB database
(own keyspace, own DEK, own quota). Each **tenant** owns 1..N volumes. Both protocol frontends
call the same async `Vfs` trait, so semantics are implemented exactly once.

---

## 3. Foundational design decisions

Numbered so later phases can reference them. Each was chosen deliberately; do not silently revisit.

**DD-1: One SlateDB database per volume (not a shared DB with tenant prefixes).**
Rationale: (a) per-tenant encryption keys become trivial — the `BlockTransformer` is per-`Db`, so
every SST/WAL block of a volume is encrypted with that volume's DEK; a shared DB would mix tenants
inside one block and force app-level crypto; (b) hard isolation — no bug class where a key-prefix
mistake leaks tenant B's data; (c) tenant deletion = delete the DB path; (d) per-volume
checkpoints/clones/quotas for free. Cost: per-open-volume memory + WAL/compaction object-store
request amplification with many volumes → mitigate by lazy-opening volumes on first mount and
closing idle volumes; revisit multiplexing only if >O(1000) hot volumes per node.

**DD-2: Compression and encryption happen inside SlateDB, not in the FS layer.**
`Settings::compression_codec = Some(Lz4 | Zstd)` compresses each SST block; our
`BlockTransformer` then AEAD-encrypts the compressed block. Verified: transform applies to data
blocks, index blocks, and **WAL SSTs** (`wal/wal_sst_builder.rs:74`), and checksums cover the
transformed bytes, so corruption/tamper is detected before decrypt-fail. This gives
compress-then-encrypt ordering automatically and encrypts *metadata keyspace too* (inodes,
dirent values, xattrs) since it's all SST blocks. Cost: plaintext exists in RAM caches (fine) —
see DD-4 — and **key bytes themselves are not block-encrypted** (manifests/indexes store key
ranges) → see DD-3.

**DD-3: Filename confidentiality via deterministic per-directory name encryption.**
SlateDB keys appear in manifests and bloom/index structures that are not all covered by the block
transformer; our keys embed directory entry *names*. Storing plaintext names in keys would leak
paths to anyone with bucket access. Therefore the dirent key uses
`ENC_name = AES-SIV(dir_key, name)` (deterministic ⇒ exact-match `lookup()` still works as a
point `get`), and the plaintext name is stored in the dirent *value* (which IS block-encrypted).
Readdir order becomes ciphertext order — POSIX does not require any particular readdir order, so
this is correct; stable iteration cookies come from a separate dirent-id index (see §5).
`dir_key = HKDF(volume_DEK, "dirname" ‖ parent_ino)`, so equal names in *different* directories
don't correlate. This mirrors fscrypt's design. All other key components are numeric ids (inode
numbers, chunk indexes) which leak only structure sizes — accepted.

**DD-4: Cache tiers and what's plaintext where.**
- Tier 1: SlateDB in-memory block cache (foyer) — **plaintext** decoded blocks, RAM only. Sized
  per node (e.g. 25% RAM).
- Tier 2: SlateDB `CachedObjectStore` on local NVMe — caches raw object parts, which are
  **ciphertext** (verified: it wraps the object store beneath SST decode,
  `db/builder.rs:481-490`). Safe even on untrusted local disks.
- Tier 3: object store.
- Do **not** enable `FoyerHybridCache` (its disk tier would write plaintext blocks to disk) unless
  a deployment explicitly opts in with documented full-disk-encryption.
- VFS-level caches (attr/negative-dentry/open-handle) are in-process RAM and coherent by
  construction because this process is the volume's only writer (DD-5).

**DD-5: Concurrency control is in-process; SlateDB fencing enforces the single-writer invariant.**
Exactly one `slatefsd` owns a volume at a time (SlateDB manifest `writer_epoch` fences stale
writers with `Error::Fenced` — on receiving it, the daemon must immediately stop serving that
volume). Because we are the only writer, POSIX atomicity is implemented with an in-process lock
manager (striped per-inode async RwLocks; rename takes both parent locks in inode order; directory
renames additionally serialize on a per-volume rename mutex and perform the ancestor-cycle check
under it) + atomic `WriteBatch` commits. SlateDB transactions (`begin(SerializableSnapshot)`) are
reserved for multi-read-modify-write paths where the read set matters (e.g. `create O_EXCL`,
link-count updates) as belt-and-braces; the lock manager is the primary mechanism.

**DD-6: File content is chunked; chunk size is a volume-format constant (default 128 KiB).**
Key `c/<ino>/<chunk_idx>` → chunk bytes (plaintext from the app's perspective; engine compresses +
encrypts). Absent chunk ⇒ holes/zeros (sparse files are free). 128 KiB balances NFS
rsize/wsize (typically 64K–1M), random-write read-modify-write cost, and SlateDB value sizes;
make it configurable at `mkfs` time only (changing it later would require rewriting data).

**DD-7: Durability contract.**
Normal writes use `WriteOptions { await_durable: false }` (ack from memtable+WAL buffer);
`Settings::flush_interval` is set small (default 100ms) so the WAL hits the object store
continuously. `fsync`/`fdatasync` (9P `Tfsync`) and NFSv3 `COMMIT` / `stable=FILE_SYNC|DATA_SYNC`
writes map to `Db::flush()` and only ack after it returns. This matches Linux NFS async-export
semantics; a per-export `sync=strict` option forces `await_durable: true` on every write for
paranoid workloads. Document loudly: un-fsynced data may be lost up to `flush_interval` on crash —
same as a local disk with a write cache.

**DD-8: Envelope encryption with KMS-agnostic key hierarchy.**
`master KEK` (from AWS KMS / GCP KMS / local age keyfile for dev) wraps per-tenant KEKs; tenant
KEK wraps per-volume DEKs (random 32B at volume create, stored wrapped in the control DB). Cipher
for block transform: **AES-256-GCM** when AES-NI is present, **XChaCha20-Poly1305** otherwise
(recorded as a volume-format flag; both via RustCrypto crates). Random 24B/12B nonce stored with
each block; AEAD tag gives integrity on top of SlateDB checksums. KEK rotation = rewrap DEKs
(cheap, metadata-only). DEK rotation = volume rewrite via SlateDB clone with new transformer
(documented, later phase).

**DD-9: Quotas are merge-operator counters updated atomically with each mutation.**
Every mutating batch includes `merge(q/usage/bytes, Δi64)` / `merge(q/usage/inodes, Δi64)` so the
counters can never drift from a crash (same atomic commit). Enforcement reads an authoritative
in-memory counter (loaded at volume mount, updated synchronously — valid because single writer)
and rejects with `EDQUOT`/`ENOSPC` *before* building the batch. An offline
`slatefs volume fsck --recount <tenant> <volume>` rebuilds counters by scan; an online
`slatefs volume scrub <tenant> <volume>` compares and alerts.

**DD-10: Tenant→export mapping per protocol.**
NFSv3 auth is AUTH_SYS (uid/gid assertions, no cryptographic identity). Tenancy therefore binds to
*export endpoints*, not credentials: each volume export = a distinct (listen-address, port) or
path on a shared listener with per-tenant source-IP allowlists; deployment guidance mandates
network-layer isolation (per-tenant VPC/WireGuard/VLAN). 9P attaches name the volume
(`aname=/tenant/volume`) and authenticate with a per-tenant bearer token at `Tattach`
(and optionally TLS via rustls on the 9P listener). Root squash (`root_squash`, `all_squash`,
anon uid/gid) is per-export config.

---

## 4. Repository & workspace layout

New repo `slatefs/` (do **not** build inside the slatedb repo; depend on the crates).

```
slatefs/
├── Cargo.toml                  # workspace; slatedb = "0.13" (features: lz4, zstd, foyer)
├── crates/
│   ├── slatefs-core/           # everything protocol-independent
│   │   ├── src/vfs.rs          # the Vfs trait (single source of FS semantics)
│   │   ├── src/volume.rs       # Volume: open/close, slatedb Db wiring, fencing handler
│   │   ├── src/meta/           # key schema, inode/dirent/xattr codecs, allocator
│   │   ├── src/data.rs         # chunked read/write/truncate paths
│   │   ├── src/locks.rs        # striped inode locks, rename mutex, byte-range lock table
│   │   ├── src/quota.rs        # counters, enforcement, merge operator
│   │   ├── src/crypto/         # BlockTransformer impl, AES-SIV name codec, key hierarchy, KMS
│   │   ├── src/control.rs      # control-plane DB: tenants, volumes, wrapped keys, exports
│   │   └── src/model_test/     # in-memory reference FS for model-based tests
│   ├── slatefs-nfs/            # NFSv3 frontend (adapter: Vfs -> nfsserve-family trait)
│   ├── slatefs-9p/             # 9P2000.L codec + server + adapter (Vfs -> fid table)
│   ├── slatefs-daemon/         # main bin: config (TOML), listeners, metrics, lifecycle
│   └── slatefs-cli/            # mgmt: tenant/volume/quota/key/snapshot/clone
└── tests/                      # integration & compliance harnesses (privileged, see §16)
```

Rust edition 2024, tokio multi-thread runtime, `tracing` + `metrics` crates throughout.

---

## 5. Metadata model (per-volume keyspace)

All integers big-endian fixed-width so lexicographic key order == numeric order. Single-byte
record-type tag first. Values are `postcard`-encoded structs, each starting with a `u8` format
version (engine encrypts them; we never store plaintext secrets in *keys*, per DD-3).

| Key | Value | Notes |
|---|---|---|
| `M` | `Superblock { format_version, fsid: u64, cipher, chunk_size, name_enc: bool, created_at }` | written by `mkfs`, immutable fields |
| `i/<ino:u64>` | `Inode { version, kind, mode, uid, gid, nlink, size, atime, mtime, ctime (ns), rdev, gen: u32, flags }` | `gen` bumps on inode-number reuse → stale NFS handles |
| `d/<parent_ino:u64>/<enc_name>` | `Dirent { name: String, child_ino: u64, kind, dirent_id: u64 }` | `enc_name = AES-SIV(dir_key, name)` (DD-3); point `get` for lookup |
| `e/<parent_ino:u64>/<dirent_id:u64>` | `enc_name` bytes | iteration/resume index: readdir cookie = `dirent_id` (monotonic per directory, never reused) |
| `c/<ino:u64>/<chunk:u32>` | raw chunk bytes (≤ chunk_size) | absent ⇒ zeros (sparse) |
| `s/<ino:u64>` | symlink target bytes | |
| `x/<ino:u64>/<name>` | xattr value | xattr names not secret-classed in v1 (documented) |
| `o/<ino:u64>` | `()` | orphan: nlink==0 but handle open; reaped at mount |
| `q/usage/bytes`, `q/usage/inodes` | i64 (merge-operator sum of deltas) | DD-9 |
| `a/next_ino` | u64 high-water mark | allocator leases blocks of 65536 inos; crash burns ≤ one lease |

Mechanics:
- **lookup(parent, name)** → `get(d/parent/SIV(name))` — one point read.
- **readdir(parent, cookie)** → `scan(e/parent/(cookie+1)..)`, join each `enc_name` to its `d/`
  record (or duplicate `child_ino`+`kind` into the `e/` value to make readdir single-scan —
  do this; it's a pure denormalization updated in the same batch).
- **NFS readdir cookies**: the wire cookie is our `dirent_id` (stable, monotonic). ⚠ `nfsserve`'s
  trait signature passes `start_after: fileid3` (it conflates cookie with child fileid) — part of
  the Phase 2 library spike is confirming the chosen fork lets us control `cookie3`; if not, patch
  the vendored trait (small) rather than weaken the schema.
- **9P readdir offsets**: 9P2000.L requires `offset` be 0 or a previously-returned offset — our
  `dirent_id` satisfies this as an opaque value.
- **Hardlinks**: multiple `d/` entries → same ino; `nlink` in inode; both dirents have distinct
  `dirent_id`s so iteration is unambiguous.
- **NFS file handles**: `fh = {fsid: u64, ino: u64, gen: u32}` (+ HMAC under a server key to
  prevent handle forging across tenants). Survives daemon restarts; `gen` mismatch ⇒ `ESTALE`.

### Control-plane DB
A separate small SlateDB at `<root>/control`, encrypted with a DEK wrapped directly by the master
KEK. Keys: `t/<tenant_id>` → tenant record (name, state, wrapped tenant-KEK, IP allowlists, 9p
token hash); `v/<tenant_id>/<volume_id>` → volume record (path, wrapped DEK, cipher, chunk_size,
quota limits {bytes, inodes}, export config); `audit/<ts>/<seq>` → admin-action audit log.

---

## 6. Data path

**read(ino, offset, len)** — compute chunk span; single chunk ⇒ point `get`; multi-chunk ⇒ take a
`Db::snapshot()` and read all chunks from it (a concurrent write can't tear the read). Holes →
zero-fill. Then trim to inode `size`.

**write(ino, offset, data)** — under the inode write lock: read partial first/last chunks
(read-modify-write), assemble one `WriteBatch`: full-chunk puts, updated inode (size/mtime/ctime),
`merge(q/usage/bytes, Δ)`. Commit with `await_durable:false` (DD-7). Newly allocated bytes are
quota-checked before building the batch (DD-9). Single-chunk-aligned writes skip the RMW read.

**truncate(ino, new_size)** — shrink: delete chunks beyond new end (scan `c/<ino>/` range; if the
file is huge, delete in batches of ~1k keys per commit, with the inode size updated **first** in
batch one so a crash mid-truncate leaves only unreachable-but-harmless trailing chunks for fsck to
reap); zero the partial tail chunk. Grow: just update size (sparse).

**unlink/last-close** — `unlink` removes the dirent and decrements `nlink`; if `nlink==0` and the
open-handle table still references the ino, write `o/<ino>` and defer chunk deletion to last
close. Mount-time reaper deletes any `o/` leftovers from a crash.

**fsync/COMMIT** — `Db::flush()` (DD-7), per volume.

All mutations follow the invariant: **one logical FS operation = one atomic WriteBatch/txn
commit**. No mutation ever spans two commits except batched truncate/unlink chunk reaping, which
is crash-safe by construction (metadata commits first, orphaned data is unreachable and reaped).

---

## 7. Encryption & key management (details)

- `crypto::SlateBlockTransformer` implements `slatedb::BlockTransformer`
  (`format/sst.rs`): `encode` = AEAD-seal(compressed block) with fresh nonce, output
  `nonce ‖ ciphertext ‖ tag`; `decode` = open-or-error. Constructed per volume with that volume's
  DEK. Registered via `DbBuilder::with_block_transformer`. Compression stays engine-side
  (`Settings::compression_codec = Some(Lz4)` default; `Zstd` for cold/archival volumes).
- Filename codec: AES-SIV (`aes-siv` crate) with per-directory subkey (DD-3).
- Key hierarchy & wrapping per DD-8; KMS abstraction trait with `AwsKms`, `LocalAgeKey` (dev),
  `StaticKey` (tests) impls.
- **Fail closed**: a volume whose DEK can't unwrap, or any block whose AEAD tag fails, returns
  `EIO` and raises an alert; never serve plaintext-questionable data.
- Threat model doc (write in Phase 3): bucket compromise ⇒ attacker sees object sizes, key
  *structure* (numeric ids), encrypted names, timing — no contents, no filenames. Local NVMe
  compromise ⇒ ciphertext only (DD-4). Memory compromise ⇒ game over (out of scope).
- What is NOT covered: SlateDB manifest *structure* (SST lists, seq numbers) is plaintext;
  acceptable. Verify at Phase 3 whether bloom-filter blocks pass through the transformer
  (`filter` blocks in `format/sst.rs`); if not, either upstream a patch to slatedb or accept the
  leak (filters hash keys — our keys are ids + SIV-ciphertext, so leakage is minimal either way).

---

## 8. Caching (details)

Per-volume SlateDB wiring (in `volume.rs`):
- Block cache: `DbBuilder::with_db_cache(FoyerCache)` — share **one** process-wide cache instance
  across volumes if the `DbCache` handle allows (spike in Phase 1; otherwise per-volume caps with
  a global budget allocator). Config: `cache.memory_bytes` (default: 25% of RAM).
- Disk cache: `Settings::object_store_cache_options = ObjectStoreCacheOptions { root_folder:
  /var/cache/slatefs/<volume>, max_cache_size_bytes, part_size_bytes: 4MiB,
  preload_disk_cache_on_startup: Some(L0Sst), .. }`. Ciphertext at rest (DD-4). Global disk
  budget divided across open volumes; closed volumes keep their cache dir (warm restart) subject
  to LRU eviction by the cache's own accounting.
- VFS attr/dentry cache: small per-volume moka LRU keyed by ino (and (parent,name) for negative
  entries), invalidated synchronously by the write path (coherent per DD-5). This avoids a
  SlateDB read for the GETATTR-storm NFS clients generate.
- Read-ahead: sequential-read detector per open handle issues `scan` with
  `ScanOptions::read_ahead_bytes` over upcoming chunk keys to prefetch into block cache.
- Client-side: document recommended mount options (`actimeo`, `nconnect`, rsize/wsize=1M for NFS;
  `msize=1M`, `cache=loose` vs `cache=none` for 9P) in ops docs.

---

## 9. Protocol frontends

### 9.1 The `Vfs` trait (slatefs-core) — single source of truth
Async trait, all ops take `Credentials { uid, gid, groups }` and return `errno`-style errors:
`lookup, getattr, setattr, read, write, create(+excl), mkdir, mknod, symlink, readlink, link,
unlink, rmdir, rename, readdir(cookie), xattr {get,set,list,remove}, statfs, fsync, open/close
(handle table), lock/unlock (advisory)`. Permission checks (mode bits + owner/group semantics,
sticky-bit deletion rules) live HERE, once, behind the trait — frontends only translate.

### 9.2 NFSv3 (`slatefs-nfs`)
- Phase 2 spike: choose between `zerofs_nfsserve` and `nfs3_server` on: cookie control (§5),
  WRITE `stable`-flag exposure (DD-7), READDIRPLUS support, maintenance, license. Vendor + patch
  if needed; both are small codebases.
- Adapter maps trait calls → `Vfs`; `fileid3 = ino`; fh per §5; mount path → volume via export
  table; AUTH_SYS uid/gid (+squash rules) → `Credentials`.
- Listeners per DD-10. Portmapper not required (clients use `mount -o port=… ,mountport=…`).

### 9.3 9P2000.L (`slatefs-9p`)
- Implement the codec ourselves (9P framing is simple: little-endian `size[4] type[1] tag[2]`
  bodies; ~30 message types for 2000.L). Evaluate `rs9p` first; expect to write our own for
  maintenance reasons (ZeroFS did).
- Server: per-connection fid table `fid -> {volume, ino, open_state, iounit}`; implement
  `version/attach/walk/lopen/lcreate/read/write/getattr/setattr/readdir/fsync/link/symlink/mknod/
  rename(at)/unlinkat/remove/clunk/statfs/lock/getlock/xattrwalk/xattrcreate/flush`.
- `Tattach`: `aname=/tenant/volume`, bearer-token auth, optional rustls listener (DD-10).
- `uname`/`n_uname` → uid mapping table per export.

### 9.4 Cross-protocol coherence
Both frontends share the volume's open-file table, lock table, and attr cache, so a write via NFS
is immediately visible to a 9P read on the same server (single process, single writer). Byte-range
locks (9P `Tlock`, and NFS clients' local locks) share one in-memory advisory table; v1 documents
that NFSv3 clients without NLM see locks only via 9P-side enforcement.

---

## 10. POSIX semantics — decision matrix

| Concern | Decision |
|---|---|
| rename | atomic batch: remove old dirent, upsert new (capturing replaced target), bump ctimes; replaced target's nlink-- (orphan if open). Directory moves update no child keys (ino-based schema). Cycle check under per-volume rename mutex (DD-5) |
| O_EXCL create | parent lock + `begin(SerializableSnapshot)` txn: get dirent, fail `EEXIST`, else put dirent+inode+merge(quota); commit |
| atime | `relatime` semantics by default (update only if atime < mtime or > 24h old); `noatime` per-export option; never a write-per-read |
| timestamps | nanosecond, from a monotonic-corrected wall clock; ctime bumps on every metadata change |
| permissions | full mode-bit + sticky + setuid/setgid evaluation in `Vfs`; supplementary groups from AUTH_SYS (≤16) honored |
| sparse files | native (absent chunks); `SEEK_HOLE/SEEK_DATA` not exposed by NFSv3/9P — skip |
| max sizes | name ≤ 255 bytes, path unlimited (per-component ops), file ≤ chunk_size × 2³² (= 512 TiB @128 KiB) |
| special files | mknod for fifo/sock/chr/blk stored as inode kind+rdev (server never opens them; clients interpret) |
| statfs | from quota counters: `f_blocks=limit/bsize`, `f_bfree=f_bavail=(limit−usage)/bsize`, files/ffree from inode quota; unlimited volumes report configured nominal size |

---

## 11. Tenancy (details)

- Tenant lifecycle: `slatefs tenant create|suspend|delete`. Suspend = refuse new mounts + fence
  active sessions. Delete = (1) mark deleting in control DB, (2) destroy volume DBs (object-store
  prefix delete), (3) drop wrapped keys — **crypto-shredding**: even surviving objects are
  unreadable once the wrapped DEK is gone.
- Isolation enforcement points (test each, §16): export resolution (can't name another tenant's
  volume), NFS fh HMAC (can't forge handles), 9P token check at attach, per-DB keyspace (DD-1 —
  no shared keyspace to mis-prefix), per-volume DEK (even a routing bug yields undecryptable
  blocks).
- Noisy neighbor: per-tenant token-bucket rate limits (ops/s and bytes/s) in both frontends,
  configured in the tenant record; per-volume SlateDB caches bound memory (§8).

## 12. Quotas (details)

- Limits in control DB; usage counters per DD-9. Enforcement: hard limit → `EDQUOT` on the
  offending op (writes, creates, mkdir, setattr-grow, xattr-set). Reads/deletes always succeed.
- Soft limits + grace windows: phase 6 (record schema now: `{soft, hard, grace_until}`).
- Accounting rule: bytes = sum of inode `size` rounded up to chunk granularity? **No** — account
  *logical* size (sum of `size`), because compression makes physical accounting moot and sparse
  files shouldn't bill for holes… **Decision**: bill `bytes_used = Σ allocated chunk bytes`
  (sparse-friendly, predictable: a hole costs 0, a 1-byte chunk costs chunk overhead is invisible
  — we bill `min(size − chunk_start, chunk_size)` per *existing* chunk). fsck recomputes the same.
- `slatefs volume fsck --recount <tenant> <volume>` (offline per volume) and
  `slatefs volume scrub <tenant> <volume>` (DbReader on latest state, compare, alert on drift > 0)
  — drift should be impossible (atomic merges) so any drift is a bug.

---

## 13. Failure handling, HA & operations

- **Fencing**: on `Error::Fenced` from any SlateDB call → mark volume dead, drop exports, alert
  (another node took over). Failover recipe: floating IP/DNS → new node opens the same DB path
  (SlateDB bumps `writer_epoch`); NFS hard-mount clients retry transparently; expected blip =
  open+WAL-replay time. Measure in Phase 6; target < 10s.
- **Object store outage**: reads of cached data keep working (tiers 1–2); writes queue until
  `max_unflushed_bytes` then backpressure (NFS clients retry). Surface a degraded-mode metric.
- Config: TOML (`/etc/slatefs/slatefs.toml`): object-store URL(s), cache dirs/budgets, KMS,
  listeners, export defaults. Secrets via env/KMS only.
- Metrics (Prometheus): per-op latency histograms per protocol, cache hit ratios (slatedb
  `with_metrics_recorder` + `CachedObjectStore` part-hit stats), quota usage, flush latency,
  fencing events, AEAD failures (security signal!).
- `slatefs` CLI: `tenant create|suspend|resume|delete|list|rate`,
  `volume create|info|list|fsck|scrub|delete`, `quota set|show`,
  `key rotate-kek`, `snapshot create|list|delete` (SlateDB checkpoints), and
  `clone create` (CloneBuilder → new writable volume, instant, shares SSTs). Runtime stats are
  exposed through the daemon `/metrics` endpoint.
- Snapshots: `Db::create_checkpoint` per volume; expose read-only mounts of snapshots via
  `DbReader::with_checkpoint` volumes (read-only exports). Clones for dev/test workflows.

---

## 14. Phased milestones

Each phase ends with: code + tests green in CI, docs updated, and the listed **acceptance
criteria (AC)** demonstrably met. Don't start phase N+1 with phase N's AC red.

### Phase 0 — Scaffolding & control plane (≈ small)
Workspace, CI (fmt/clippy/test + privileged integration job), config loading, control DB,
key hierarchy with `LocalAgeKey`, `slatefs tenant|volume create` against MinIO
(`docker compose` with MinIO in-repo), volume `mkfs` writing the superblock through an encrypted
Db (BlockTransformer wired with a static key).
**AC**: `slatefs volume create t1 v1 && slatefs volume info t1 v1` round-trips against MinIO; raw
bucket objects contain no plaintext marker strings; unit tests for key wrap/unwrap incl.
wrong-key fail-closed.

### Phase 1 — VFS core on SlateDB (the heart; biggest phase)
`meta/` codecs + allocator, `Vfs` impl: lookup/getattr/setattr/create/mkdir/symlink/readlink/
link/unlink/rmdir/rename/readdir/xattrs/statfs; chunked read/write/truncate; lock manager;
orphan handling; quota counters + enforcement; name encryption (DD-3).
Tests: **model-based property tests** — random op sequences (proptest) executed against both the
real `Vfs` (memory:// object store) and an in-memory reference FS; assert identical observable
state including errno. Crash-consistency test: run ops against `file://` store, abort the process
at random points (or use slatedb-dst-style fault injection on the object store), reopen, fsck,
re-verify model invariants (nlink correctness, no orphan dirents, quota == recount).
**AC**: 100k-op property runs clean across 1000 seeds; crash loop (500 kill-points) clean;
quota enforcement exact to the byte in property tests.

### Phase 2 — NFSv3 frontend
Library spike (§9.2) → adapter → exports/squash → readdir cookies → durability mapping (DD-7).
Integration harness: privileged Linux CI container mounts via kernel NFS client.
**AC**: `mount -t nfs -o vers=3,nolock,hard …` works on Linux + macOS; **pjdfstest** passes
(documented exclusion list with reasons, e.g. NFSv3-impossible cases); **fsx** 10M ops clean;
`fsstress` 1h clean; restart server mid-workload → clients recover, zero `ESTALE` on surviving
files, no acknowledged-fsync data lost.

### Phase 3 — Encryption/compression hardening + cache tiers
Per-volume DEKs end-to-end with real KMS impl; cipher per DD-8; verify filter-block coverage
(§7); cache wiring per §8 incl. shared-cache spike; read-ahead.
**AC**: bucket scan proves zero plaintext (automated: write known markers via FS, `grep` every
object + manifest); wrong-DEK open fails closed; warm-read p99 < 1ms (RAM) / < 10ms (NVMe tier)
for 128 KiB reads on the bench rig, cold-read = object-store latency + decode; cache hit-rate
metrics exported; restart with warm NVMe cache serves first reads without object-store GETs
(verify via MinIO access logs).

### Phase 4 — 9P2000.L frontend
Codec (frame fuzz tests + recorded-frame golden tests), server, fid table, attach auth, TLS.
**AC**: Linux `mount -t 9p -o trans=tcp,version=9p2000.L,msize=1048576` works; pjdfstest over 9P
passes (own exclusion list); cross-protocol test — write NFS / read 9P and inverse, same server —
byte-identical, attr-coherent; QEMU guest 9P TCP smoke test.

### Phase 5 — Multi-tenant hardening & quotas UX
Rate limits, IP allowlists, fh HMAC, suspend/delete with crypto-shred, statfs/df accuracy,
`fsck --recount`, online scrub, soft quotas.
**AC**: isolation test suite (forged handles rejected; cross-tenant attach/export attempts fail;
two tenants' workloads can't read each other's bytes even with manual key probing); `df` matches
recount exactly under concurrent load; EDQUOT at precisely the limit; tenant delete leaves
no readable data (attempt decrypt with retained objects fails).

### Phase 6 — Snapshots/clones, HA, performance, GA polish
Checkpoint/clone CLI + read-only snapshot exports; fencing failover drill; perf pass (fio matrix:
seq/rand × R/W × 4k/128k/1M, metadata ops/s, targets set from Phase 3 bench baseline);
dashboards + alert rules; ops runbook; security review (run `/security-review`); versioned
on-disk-format doc with upgrade policy ([docs/on-disk-format.md](docs/on-disk-format.md)).
Perf harness: [docs/performance.md](docs/performance.md) and
[scripts/fio-over-nfs.sh](scripts/fio-over-nfs.sh).
Dashboard: [monitoring/slatefs-grafana-dashboard.json](monitoring/slatefs-grafana-dashboard.json).
Security review: [docs/security-review.md](docs/security-review.md).
Multi-volume overhead harness for DD-1:
[scripts/multi-volume-overhead.sh](scripts/multi-volume-overhead.sh).
Failover drill with optional fio load, a <10s timing gate, and post-takeover fsx:
[scripts/nfs-failover-drill.sh](scripts/nfs-failover-drill.sh).
Client support matrix and QEMU guest smoke:
[docs/client-support.md](docs/client-support.md),
[scripts/qemu-p9-tcp-smoke.sh](scripts/qemu-p9-tcp-smoke.sh).
Served-volume snapshots use `slatefs snapshot create --live <tenant> <volume>`,
which calls the loopback daemon admin endpoint so checkpoints are created by
the live writer instead of taking a second writer lease.
Kernel-client live snapshot + writable clone restore drill:
[scripts/live-snapshot-over-nfs.sh](scripts/live-snapshot-over-nfs.sh).
**AC**: failover under fio load < 10s with zero corruption (fsx continues clean post-failover);
documented perf table vs targets; runbook covers outage/fence/restore/key-rotation drills;
snapshot mount of a live volume reads consistently while writes continue.

### Backlog (post-v1, explicitly out of scope)
NFSv4.1, NLM, FUSE/SMB frontends, DbReader read-replica fan-out for read-heavy volumes,
NBD block devices (now planned separately: [docs/block-device-plan.md](docs/block-device-plan.md)),
dedup, DEK rotation via clone, per-tenant qos classes, multi-region.

---

## 15. Risks & open questions (track as issues from day 1)

1. **NFS library cookie/stable-flag control** (§9.2) — mitigations: vendor & patch; both crates
   are small. Resolve in Phase 2 spike week 1.
2. **Filter/manifest block transformer coverage** (§7) — if bloom filters bypass the transformer,
   decide: upstream slatedb PR (we have the repo at hand) vs accept hashed-key leakage. Resolve
   in Phase 3.
3. **Per-volume Db overhead at high volume counts** (DD-1) — lazy open/close; measure memory and
   object-store request rates with 100 idle + 20 hot volumes in Phase 6.
4. **Random small writes** → RMW on 128 KiB chunks + SlateDB write amp — chunk size is mkfs-time
   configurable; bench 32/64/128/256 KiB in Phase 3 and set defaults from data.
5. **9P client quirks** (msize negotiation, cache modes, macOS lacking 9p) — golden-frame tests
   against Linux v9fs and QEMU; document client support matrix.
6. **Readdir on huge directories** (millions of entries) — schema supports streaming scans;
   guard with readdir pagination tests at 10M entries in Phase 1.
7. **Clock requirements** — SlateDB monotonic clock + TTL semantics assume sane wall clock;
   the operations runbook documents NTP/clock-drift requirements. FS timestamps tolerate skew
   (no ordering dependency).
8. **Shallow-clone online readers** — SlateDB `DbReader` currently misses the external-SST path
   resolver used by writer opens. SlateFS wraps read-only clone scrubs and snapshot exports with
   an ancestor SST fallback store so online reads work; remove that shim when the reader resolver
   is fixed upstream.
9. **ZeroFS license** before reading its source (§0).

---

## Appendix A — SlateDB study list for implementing agents

Read before Phase 1: `slatedb/src/db.rs` (public API), `slatedb/src/config.rs` (Settings/
options), `slatedb/src/batch.rs`, `slatedb/src/db_transaction.rs`, `slatedb/src/merge_operator.rs`,
`slatedb/src/format/sst.rs` (BlockTransformer contract: encode after compression, checksum over
transformed bytes), `slatedb/src/cached_object_store/mod.rs`, `slatedb/src/db_cache/foyer.rs`,
`slatedb/src/fence.rs` (fencing semantics), `slatedb/src/checkpoint.rs` + `clone.rs`,
`examples/src/full_example.rs`, and `slatedb-dst/README.md` (copy its seeded-harness pattern for
our crash tests).

## Appendix B — Default tuning (starting points, revisit with Phase 3/6 data)

| Setting | Default | Why |
|---|---|---|
| chunk_size | 128 KiB | NFS wsize alignment vs RMW cost |
| `Settings::compression_codec` | `Lz4` (hot) / `Zstd` (cold volumes) | latency vs ratio |
| cipher | AES-256-GCM (AES-NI) else XChaCha20-Poly1305 | hw accel |
| `Settings::flush_interval` | 100 ms | durability window (DD-7) |
| `sst_block_size` | `Block4Kib` default; test 16/32 KiB (chunk values are large) | read amp for 128 KiB values |
| block cache | 25% RAM, process-wide | warm metadata + hot chunks |
| `ObjectStoreCacheOptions.part_size_bytes` | 4 MiB | matches slatedb default |
| NVMe cache budget | configurable, e.g. 80% of cache disk | tier-2 capacity |
| `max_unflushed_bytes` | 512 MiB per volume | backpressure bound |
