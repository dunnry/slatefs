# SlateFS threat model (plan §7, written at Phase 3)

Scope: one SlateFS deployment — object store bucket, local cache disks,
`slatefsd` hosts, control plane. Per-volume DEKs under tenant KEKs under a
master KEK (DD-8); every volume is its own SlateDB (DD-1).

## What an attacker with **bucket access** sees

Verified against slatedb 0.13.1 source (`format/sst.rs`,
`wal/wal_sst_builder.rs`) and by the automated marker-scan tests:

| Artifact | At rest | Notes |
|---|---|---|
| Data blocks (file chunks, inodes, dirents, xattrs) | **encrypted** | compress → AEAD (`SlateBlockTransformer`), incl. WAL SSTs |
| Index blocks | **encrypted** | `compress_and_transform` in footer build |
| Bloom-filter blocks | **encrypted** | verified 0.13.1: composite filter block goes through the transformer — plan risk #2 **closed, no upstream patch needed** |
| Stats blocks | **encrypted** | same path |
| `SsTableInfo` (SST footer) | plaintext | leaks **first/last key** per SST + block offsets |
| Manifest | plaintext | leaks SST list, sequence numbers, writer epoch |
| Object names/sizes/timestamps | plaintext | standard object-store metadata |

The first/last-key leak is bounded by the key schema (plan §5, DD-3): keys
are record-type tags plus numeric ids (inos, chunk indexes, dirent ids) and
**AES-SIV-encrypted filenames** with per-directory subkeys. An attacker
learns structure (how many inodes/chunks, directory fan-out, churn timing)
but no contents, no filenames, and no cross-directory name correlation.

**Documented v1 exception (plan §5): xattr *names*.** They are key
material (`x/<ino>/<name>`) and can surface in SST-footer first/last keys
— confirmed empirically by the Phase 3 deep-scan test. Xattr *values* are
always block-encrypted. Treating xattr names like filenames (per-ino SIV)
is a possible later hardening.

**Conclusion: bucket compromise yields sizes, structure, and access
patterns — no plaintext data, metadata values, or names.**

## What an attacker with a **cache disk** sees (DD-4)

- Tier 2 (`CachedObjectStore`, NVMe): raw object **parts = ciphertext**
  (it wraps the store *below* SST decode). Safe on untrusted disks.
- Tier 1 (block cache) is RAM-only plaintext; `FoyerHybridCache` (disk
  spill) must stay disabled unless a deployment documents full-disk
  encryption (enforced by simply not wiring it).

## Shared-cache isolation (Phase 3 spike result)

One process-wide block cache across volumes is **unsafe** in slatedb
0.13.1: the cache key is `(SsTableId, block)` and `SsTableId::Wal(u64)` is
a per-DB sequence number — volume A's WAL block #(5,0) would alias volume
B's, serving plaintext across tenants. SlateFS therefore uses **per-volume
caches** with a global budget divided across open volumes (plan §8's
fallback). Upstream fix would be a per-DB discriminator in the cache key.

## Key compromise blast radius

- Volume DEK → that volume only.
- Tenant KEK → that tenant's volumes.
- Master KEK/KMS → everything; KMS access is the crown jewel (audit it).
- fh HMAC server key → forge NFS handles for any volume **ino**, but data
  still arrives only through a `slatefsd` that enforces export → volume
  binding; combine with network isolation per DD-10.
- Wrapped blobs are AAD-bound to their tenant/volume context — a blob
  copied between records fails to unwrap.

## Fail-closed inventory

- AEAD decrypt failure on any block → `EIO`, logged (alert metric: Phase 6
  dashboards); never serves questionable plaintext.
- Wrong/undecryptable DEK or KEK → volume/control open fails.
- Tampered or foreign NFS file handles → constant-time HMAC reject.
- SIV name decrypt failure → `EIO` on that dirent.

## Out of scope (v1, per plan)

- Host memory compromise (plaintext blocks + DEKs in RAM).
- AUTH_SYS identity spoofing — mitigated by export squash policy plus
  network-layer tenant isolation (DD-10), not cryptography.
- Traffic analysis, object-store-side replay/rollback (SlateDB fencing
  protects single-writer integrity, not history rollback by the store
  operator).
