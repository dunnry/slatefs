# SlateFS On-Disk Format

This document records the current SlateFS-owned format as implemented by the
codebase. It is intentionally a pre-GA contract, not a compatibility promise.

## Upgrade Policy

SlateFS has no deployed format contract yet. Until GA, the current code and
this document are authoritative, and we do not carry backwards-compatibility
readers for old records. If a format changes, the acceptable upgrade paths are:

- delete and recreate throwaway volumes;
- run a one-off destructive migration against known test data;
- export data through a mounted filesystem and import it into a fresh volume.

Do not add compatibility shims for old buckets during this phase. A format bump
may deliberately reject previous records, wrapped keys, or blocks.

## Ownership Boundary

SlateDB owns its physical layout: manifests, WAL SSTs, compacted SSTs,
checkpoints, and object naming below each database path. SlateFS owns:

- the object-store paths it asks SlateDB to use;
- control-plane records and wrapped key files;
- per-volume logical key/value records;
- the block-transformer ciphertext format applied to SlateDB blocks.

SlateFS structured records use this value envelope:

```text
u8 format_version || postcard(payload)
```

User payload values are raw bytes: file chunks, symlink targets, and xattr
values are stored exactly as the VFS receives them before SlateDB compression
and encryption. Quota counters and allocator marks are fixed-width integers as
called out below.

## Object-Store Layout

All paths are relative to the configured object-store root.

| Path | Owner | Contents |
|---|---|---|
| `control.dek` | SlateFS raw object | `CONTROL_KEYFILE_VERSION=1` envelope containing `ControlKeyFile` |
| `control` | SlateDB | encrypted control-plane database |
| `volumes/<tenant>/<volume>` | SlateDB | one encrypted database per volume |

The control-plane DB at `control` is encrypted with `SlateBlockTransformer`.
Its DEK is wrapped directly by the configured master KMS and stored in
`control.dek`.

Each volume DB is encrypted with its own volume DEK. SlateDB compresses blocks
first, then the SlateFS block transformer AEAD-seals the compressed bytes, and
SlateDB checksums the transformed bytes.

## Key Hierarchy

All keys are 32-byte secrets. Key wrap blobs use AES-256-GCM with the context
as AAD, regardless of the volume data cipher.

| Key | Wrapped by | Wrap context |
|---|---|---|
| control DEK | master KMS | `slatefs/control-dek/v1` |
| tenant KEK | master KMS | `slatefs/tenant-kek/v1/<tenant>` |
| volume DEK | tenant KEK | `slatefs/volume-dek/v1/<tenant>/<volume>` |

The local age KMS stores the same context inside the age payload and verifies it
on unwrap, because age itself has no AAD.

## Block Transformer

Block-transformer format version is bound through AEAD AAD:

```text
AAD = "slatefs/block/v1"
blob = nonce || ciphertext || tag
```

Nonce length is 12 bytes for AES-256-GCM and 24 bytes for
XChaCha20-Poly1305. The AEAD tag is the RustCrypto-provided 16-byte tag
appended to the ciphertext.

Changing the AAD or cipher semantics is a hard format break. Readers under the
current code fail closed when the key, AAD, nonce, ciphertext, or tag does not
match.

## Control-Plane Records

Control DB keys are UTF-8 byte strings.

| Key | Version | Value |
|---|---:|---|
| `t/<tenant>` | 1 | `TenantRecord` |
| `v/<tenant>/<volume>` | 1 | `VolumeRecord` |
| `k/fhmac` | internal | server file-handle HMAC key |

`control.dek` is not inside the control DB. It is a raw object containing a
versioned `ControlKeyFile { cipher, wrapped_dek }`.

Current record payloads:

- `TenantRecord { name, display_name, state, rate_limits, wrapped_kek, created_at }`
- `VolumeRecord { tenant, name, state, clone_parent, fsid, wrapped_dek, cipher, chunk_size, compression, quota, note, created_at }`
- `CloneParent { tenant, volume }`
- `QuotaLimits { bytes, inodes }`
- `QuotaLimit { soft, hard, grace_until }`

Current enum sets:

- `TenantState`: `Active`, `Suspended`, `Deleting`
- `VolumeState`: `Creating`, `Active`, `Deleting`
- `Cipher`: `Aes256Gcm`, `XChaCha20Poly1305`
- `Compression`: `None`, `Lz4`, `Zstd`

Postcard encodes enum variants by index, so variant order is part of the
current format. Pre-GA, reordering a variant is allowed only as a deliberate
format reset.

## Per-Volume Keyspace

Volume keys start with a single byte record tag. Fixed-width integers are
big-endian so lexicographic order matches numeric order. There are no path
separators in binary keys.

| Key | Value format | Notes |
|---|---|---|
| `M` | v1 `Superblock` | immutable mkfs record |
| `i <ino:8>` | v1 `Inode` | inode metadata |
| `d <parent:8> <enc_name>` | v1 `Dirent` | point lookup by encrypted name |
| `e <parent:8> <dirent_id:8>` | v1 `DirentIdx` | stable readdir cookie index |
| `c <ino:8> <chunk:4>` | raw bytes | file content chunk, at most `chunk_size` |
| `s <ino:8>` | raw bytes | symlink target |
| `x <ino:8> <name>` | raw bytes | xattr value; xattr names are not secret-classed in v1 |
| `o <ino:8>` | v1 `Orphan` | unlink/reaping marker |
| `qB` | little-endian i64 | quota byte counter, merge-operator sum |
| `qI` | little-endian i64 | quota inode counter, merge-operator sum |
| `a` | big-endian u64 | next inode high-water mark |

Current structured payloads:

- `Superblock { fsid, cipher, chunk_size, name_enc, created_at }`
- `Inode { kind, mode, uid, gid, nlink, size, atime, mtime, ctime, rdev, generation, flags, next_dirent_id, billed_bytes, parent_dir }`
- `Timespec { secs, nanos }`
- `Dirent { name, child_ino, kind, dirent_id }`
- `DirentIdx { enc_name, child_ino, kind }`
- `Orphan { size, kind }`

Current `FileKind` variants are `File`, `Dir`, `Symlink`, `Fifo`, `Socket`,
`CharDev`, and `BlockDev`.

## Operational Invariants

- `VolumeRecord.fsid` must match `Superblock.fsid`.
- `cipher`, `chunk_size`, and `name_enc` are immutable for the volume lifetime.
- `chunk_size` is chosen at mkfs time. Changing it requires rewriting into a
  new volume.
- Directory-entry lookup keys contain only AES-SIV encrypted names. The
  plaintext entry name appears only in the encrypted `Dirent` value.
- `Dirent.dirent_id` and `DirentIdx` are written in the same batch. Directory
  `next_dirent_id` is monotonic and starts at 3; 1 and 2 are reserved for
  frontend synthetic `.` and `..`.
- Quota counters are little-endian `i64` merge-operator counters. Every
  mutating batch carries the usage delta for the operation it commits.
- The inode allocator writes `a` as a high-water mark. Crashes may burn a
  leased range of inode numbers; they must not reuse them.
- `o` orphan markers are reaped at mount/open or when the last open handle for
  the unlinked inode closes.
- Snapshot exports serve SlateDB checkpoints read-only. Writable clones get a
  new `VolumeRecord`, new fsid, and cloned superblock while sharing source SSTs
  through SlateDB until compaction naturally separates them.

## Format Change Checklist

Before changing any item in this document:

- update the relevant version constant or intentionally document a format reset;
- update this file in the same commit as the code change;
- add or adjust round-trip and wrong-version tests for structured records;
- run the workspace tests that cover the changed record path;
- avoid compatibility readers unless the project explicitly declares a GA
  format contract.
