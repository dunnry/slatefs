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

Next: Phase 2 — the NFSv3 frontend (library spike, exports, pjdfstest/fsx
over a kernel mount) per plan §14.

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
