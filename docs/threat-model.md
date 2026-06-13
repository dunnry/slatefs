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

## Frontend access model (DD-10)

- **NFSv3** authenticates with AUTH_SYS (uid/gid assertions, no
  cryptographic identity). Per-export squash policy (`none` / `root_squash`
  / `all_squash` / `trust_as_root`) plus the server's own DAC enforcement
  gate every op; tenancy binds to the export endpoint, not the credential.
- **9P2000.L** authenticates the *connection* with a per-tenant bearer
  token at `Tattach` (`uname`), and `aname` binds the volume. After that,
  the connection is **trusted for DAC**: 9P2000.L carries no per-operation
  gid or supplementary groups, and the Linux v9fs client under
  `access=user` already enforces permissions client-side with the caller's
  full credentials, so the server cannot re-derive a correct check. SlateFS
  keeps the asserted uid/gid for *ownership attribution* but skips
  redundant access gates (`Credentials::trusted`). Implication: a client
  that has authenticated the connection token and can forge arbitrary
  `n_uname` values is **not** constrained by server-side DAC — the token
  *is* the tenant boundary. Deploy 9P exports behind the same network-layer
  tenant isolation as NFS, and treat the bearer token as a tenant-wide
  secret. Rules tied to genuine privilege (setuid/setgid clearing,
  device-node creation) still gate on the real uid, not the trust flag.

## Out of scope (v1, per plan)

- Host memory compromise (plaintext blocks + DEKs in RAM).
- AUTH_SYS identity spoofing — mitigated by export squash policy plus
  network-layer tenant isolation (DD-10), not cryptography.
- 9P intra-tenant uid spoofing — a holder of a tenant's bearer token may
  assert any uid within that tenant (see Frontend access model); the token,
  not server DAC, is the boundary. TLS-wrapped tokens + network isolation
  are the mitigation; per-uid cryptographic identity is not a v1 goal.
- Traffic analysis, object-store-side replay/rollback (SlateDB fencing
  protects single-writer integrity, not history rollback by the store
  operator).
