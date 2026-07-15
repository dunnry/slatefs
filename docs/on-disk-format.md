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
| `versions/<tenant>/<volume>` | SlateDB + Prolly | optional encrypted per-volume file-version repository |
| `version-leases/<tenant>/<volume>` | SlateFS raw object | version-operation lease metadata; no secrets or file data |

The control-plane DB at `control` is encrypted with `SlateBlockTransformer`.
Its DEK is wrapped directly by the configured master KMS and stored in
`control.dek`.

Each volume DB and its optional version DB are encrypted with the same volume
DEK. SlateDB compresses blocks
first, then the SlateFS block transformer AEAD-seals the compressed bytes, and
SlateDB checksums the transformed bytes.

## Portable Version Repository Bundle

The external .slatevcs format is a logical transfer format, not a copy of the
encrypted object-store prefix. Its binary envelope is the eight-byte SLATEVCS
magic, one-byte format version, big-endian 64-bit payload length, postcard
payload, and a 32-byte SHA-256 payload checksum. Format version 1 carries the
stable repository identity and a strictly ordered list of key/value records.

Portable records are commits, detached attestations, Prolly nodes, content
blobs, branches, tags, reflogs, and pruned-parent markers. Import recomputes
content hashes, verifies attestations against the repository identity, checks
all graph and reference targets, and then writes one SlateDB batch. Volume
encryption, retention policy, branch protection, maintenance leases, and
idempotency retry records are destination-local and are not represented.

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
| `vr/<tenant>/<volume>` | 1 | optional `VersioningPolicy`; absence means disabled |
| `vrr/<tenant>/<volume>` | 1 | optional `VersioningRetentionPolicy` with commit count, age, byte, and reflog-window limits |
| `k/fhmac` | internal | server file-handle HMAC key |

`control.dek` is not inside the control DB. It is a raw object containing a
versioned `ControlKeyFile { cipher, wrapped_dek }`.

Current record payloads:

- `TenantRecord { name, display_name, state, rate_limits, wrapped_kek, created_at }`
- `VolumeRecord { tenant, name, state, clone_parent, clone_parent_checkpoint_ids, fsid, wrapped_dek, cipher, chunk_size, compression, quota, kind, note, created_at }`
- `CloneParent { tenant, volume }`
- `QuotaLimits { bytes, inodes }`
- `QuotaLimit { soft, hard, grace_until }`
- `VersioningPolicy { tenant, volume, enabled, updated_at }`
- `VersioningRetentionPolicy { tenant, volume, keep_last, max_age_secs, max_bytes, reflog_keep_last, updated_at }`

## Optional Version Repository Records

The `versions/<tenant>/<volume>` database is created lazily and is not read by
the live VFS request path. Its logical key prefixes are:

| Prefix/key | Version | Value |
|---|---:|---|
| `pm/repository-identity` | 1 | immutable logical repository UUID and creation time |
| `pn/<prolly-node-key>` | Prolly | immutable Prolly node bytes |
| `pb/<content-id>` | Prolly | content-addressed file chunk blob |
| `pc/<sha256-commit-id>` | 2 | `VersionCommit`, including hash-bound provenance |
| `pa/<sha256-commit-id>/<key-id>` | 1 | detached Ed25519 attestation over the version-2 repository UUID statement |
| `pi/<sha256-idempotency-key>` | 1 | commit ID and branch-aware canonical request fingerprint |
| `pr/heads/<name>` | 1 | mutable branch `VersionRef`; `main` is the default commit head |
| `pr/protected/<name>` | 1 | durable destructive-ref protection and normalized publisher and policy-manager allowlists for an existing branch |
| `pr/logs/<name>/<sequence>` | 1 | bounded branch-head transition record; the configured newest entries per name are retained (default 100) |
| `pr/tags/<name>` | 1 | immutable named commit reference and creation time |

Entry metadata (`m/<canonical-path>`) and file chunk references
(`c/<canonical-path> NUL <u32-be-index>`) live inside the Prolly tree. SlateFS
prefixes its structured values with `u8 format_version` and postcard-encodes
the payload. Entry metadata version 1 distinguishes regular files,
directories, and symlinks.
The repository identity is generated when the encrypted version database is
first opened and remains stable across subsequent opens. It is independent of
the local tenant and volume names so future verified exports can preserve
history identity while re-encrypting objects for a destination volume. An empty
destination may be initialized with a requested identity; opening an existing
repository with a different requested identity fails closed.
A commit records zero, one, or two parents, its root manifest, creation time,
message, selected paths, and provenance containing origin, author, committer,
and request ID. All fields are covered by the commit ID. Two parents identify
a three-way merge commit. Version 2 is the initial deployed contract; SlateFS
does not migrate the earlier development-only version-1 record shape.
An idempotency record is written atomically with its commit and head;
garbage collection removes it when that commit is pruned. Version repository
tags keep their referenced commit and tree reachable through garbage
collection. Version repository history is retained when the policy is disabled
and removed with the volume.
Branch protection records name their branch, creation time, and up to 64
normalized identities in each of the allowed committer and policy-manager
lists. Empty lists permit any committer to publish or any authorized live manager
to change the policy, respectively. Verification rejects a record whose
payload does not match its key or whose branch no longer exists.

`version-leases/<tenant>/<volume>` is a version-1 postcard record containing
`tenant`, `volume`, an ephemeral owner UUID, operation name, acquisition time,
and expiry time. It is created and renewed with object-store conditional
writes. The record lives outside the version database prefix so purge cannot
delete its own lock; an expired record is replaced with compare-and-swap, and
a stale owner cannot overwrite or release its successor. Stores without
conditional update do not automatically take over an expired record.

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
  through SlateDB until compaction naturally separates them. New clone records
  store `clone_parent_checkpoint_ids` for the source-side checkpoints retention
  must preserve. Legacy clone records where that field is absent decode with
  `None`; retention treats those as unknown and keeps the old conservative
  whole-parent-volume skip.

## Format Change Checklist

Before changing any item in this document:

- update the relevant version constant or intentionally document a format reset;
- update this file in the same commit as the code change;
- add or adjust round-trip and wrong-version tests for structured records;
- run the workspace tests that cover the changed record path;
- avoid compatibility readers unless the project explicitly declares a GA
  format contract.
