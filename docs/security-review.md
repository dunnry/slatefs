# SlateFS Security Review

Date: 2026-06-13

Scope: current pre-GA SlateFS codebase, including the control plane, encrypted
volume format, NFSv3 and 9P frontends, metrics/alerts, and operational docs.
There is no backwards-compatibility constraint for this review; direct format
or behavior changes are preferred until a GA contract exists.

## Reviewed Controls

| Area | Current control | Evidence |
|---|---|---|
| Block confidentiality | SlateDB blocks are compressed, AEAD-sealed, and checksummed after transformation. | `SlateBlockTransformer`; `crypto::transformer::tests` |
| Block tamper response | AEAD open failure returns an error, logs, increments `slatefs_block_decode_failures_total`, and never serves questionable plaintext. | `monitoring/slatefs-prometheus-rules.yml`; dashboard panel |
| Key hierarchy | Master KMS wraps control DEK and tenant KEKs; tenant KEKs wrap volume DEKs with AAD-bound contexts. | `crypto::kms::contexts`; `docs/on-disk-format.md` |
| Filename confidentiality | Directory-entry lookup keys use deterministic AES-SIV encrypted names; plaintext names are in encrypted values. | `crypto::names`; `docs/threat-model.md` |
| Control/volume isolation | One SlateDB per volume; per-volume DEK and cache namespace. | `store::volume_db_path`; `VolumeCaches` |
| NFS handle integrity | File handles include `{fsid, ino, generation}` and HMAC verification rejects forged or foreign handles. | `slatefs-nfs/src/fh.rs` tests |
| 9P transport protection | 9P listeners can be rustls-wrapped with `p9_tls_cert`/`p9_tls_key`; source allowlists run before TLS handshakes. | `p9_tls_end_to_end`; config validation tests |
| Daemon admin surface | Optional admin listener is config-validated to loopback and currently exposes live-writer snapshot creation only. | `admin_listener_must_be_loopback`; `admin_snapshot_endpoint_creates_live_checkpoint` |
| Single-writer safety | SlateDB fencing marks stale volumes dead and drops daemon exports. | `fenced_writer_marks_volume_dead`; failover drill |
| Quota and deletion safety | Quota counters are committed with mutations; tenant/volume delete drops wrapped keys before deleting prefixes. | `quota` tests; control-plane delete paths |
| Operator visibility | Prometheus rules cover fenced volumes, missing scrapes, and block decode failures; Grafana dashboard surfaces liveness and decode failures. | `monitoring/` |

## Open Findings

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| SR-1 | Medium | Plaintext 9P exports remain available for Linux kernel v9fs and still carry tenant bearer tokens in-band. A token holder is the tenant boundary and may assert any uid inside that tenant's 9P connection. | Use rustls-wrapped 9P for TLS-capable clients/sidecars. Keep plaintext kernel v9fs exports behind tenant network isolation or an external TLS tunnel. |
| SR-2 | Medium | NFSv3 AUTH_SYS identities are unauthenticated uid/gid assertions. | Accepted by DD-10. Use per-export source allowlists, squash policy, and network isolation. |
| SR-3 | Low | Xattr names are plaintext key suffixes and can appear in SST first/last-key metadata. Xattr values are encrypted. | Documented v1 exception. Future hardening can SIV-encrypt xattr names like filenames. |
| SR-4 | Low | Object-store rollback/history replay is out of scope; SlateDB fencing protects live single-writer integrity, not malicious bucket rollback. | Documented out of scope. Use bucket versioning, object lock, audit logs, and cloud IAM controls in production. |
| SR-5 | Low | `slatefs_block_decode_failures_total` covers served writable volumes and snapshot exports. Control-plane decode failures still fail closed and log, but are not counted by that per-volume metric. | Accept for current Phase 6 alerting. Revisit when control-plane metrics targets are added. |

## Verification Run

The security-metric slice was verified with:

```sh
cargo test -p slatefs-core crypto::transformer::tests
cargo test -p slatefs-core metrics::tests
cargo test -p slatefs-core fenced_writer_marks_volume_dead
cargo check -p slatefs-daemon
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
jq empty monitoring/slatefs-grafana-dashboard.json
```

The earlier Phase 6 operational harnesses were also exercised:

```sh
scripts/docker-kernel-mount-test.sh scripts/nfs-failover-drill.sh
SKIP_SMOKE=1 FIO_RUNTIME=1 FIO_SIZE=4m FIO_BS_LIST="4k" FIO_RW_LIST="read write" META_OPS=5 \
  scripts/docker-kernel-mount-test.sh scripts/fio-over-nfs.sh
```
