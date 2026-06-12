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

Remaining for Phase 2 AC: vendored patch (or upstream PR) for per-request
AUTH_UNIX credentials, LINK/MKNOD, and a quota-aware FSSTAT hook in
nfs3_server; then the pjdfstest/fsx/fsstress runs.

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
