# SlateFS Performance Harness

Phase 6 performance work is measured through a real kernel NFS client, not an
in-process shortcut. The fio sweep lives in:

```sh
scripts/fio-over-nfs.sh
```

Run it through the existing privileged Docker harness:

```sh
SKIP_SMOKE=1 \
FIO_RUNTIME=30 \
FIO_SIZE=1g \
FIO_JOBS=4 \
scripts/docker-kernel-mount-test.sh scripts/fio-over-nfs.sh
```

The script emits a markdown table with the Phase 6 matrix:

- sequential read and write;
- random read and write;
- block sizes 4 KiB, 128 KiB, and 1 MiB;
- a simple create/stat/unlink metadata ops/s smoke.

For a quick local smoke, lower `FIO_RUNTIME`, `FIO_SIZE`, and `META_OPS`.
Bench numbers are only comparable when the object store, cache settings,
kernel NFS client, host CPU, and Docker/VM environment are held fixed.
Slow environments can raise `FIO_CMD_TIMEOUT`; the default is 600 seconds per
fio/prefill command. Read-source prefill uses `FIO_PREFILL_BS` (default 1 MiB)
so the 4 KiB read row does not spend the setup phase issuing tiny writes. The
fio harness also defaults to a longer kernel NFS soft-mount timeout
(`FIO_NFS_TIMEO=600`, `FIO_NFS_RETRANS=3`) so slow setup I/O does not collapse
into client-side `EIO`.

## Failover Timing

The failover drill can run a fio workload against the primary NFS mount while
the takeover daemon fences it:

```sh
SKIP_SMOKE=1 \
FAILOVER_LOAD_MODE=fio \
FAILOVER_FIO_RUNTIME=30 \
FAILOVER_FIO_SIZE=256m \
FAILOVER_MAX_SECONDS=10 \
FAILOVER_FSX_OPS=50000 \
scripts/docker-kernel-mount-test.sh scripts/nfs-failover-drill.sh
```

The script measures from takeover daemon start to the first verified durable
write on the remounted takeover export, then fails if the window is above
`FAILOVER_MAX_SECONDS`. When `FAILOVER_FSX_OPS` is set, it also runs `fsx` on
the takeover mount after the failover to catch post-takeover corruption.

## Target Table

The GA target table should be filled from a dedicated bench host. Do not treat
Docker Desktop or laptop file-store results as product targets.
Use the Docker wrapper for functional smoke and regression checks; sustained
1 GiB sweeps can be dominated by the container's local file-store compaction
and NFS soft-mount timeout behavior.

| Workload | Target | Source |
|---|---:|---|
| Warm 128 KiB read p99 | <= 1 ms | Phase 3 local read-latency baseline plus NFS overhead budget |
| Cold read p99 | object-store latency + decode | DD-4 cache model |
| Failover under client load | < 10 s | Phase 6 acceptance criteria |
| Metadata create/stat/unlink | bench-host baseline | fio harness metadata smoke |

## Local Docker Smoke Evidence

On 2026-06-14, the privileged Docker wrapper completed a compact functional
fio sweep with `FIO_RUNTIME=1`, `FIO_SIZE=64m`, `FIO_JOBS=1`, and
`META_OPS=5`. It also completed an isolated 1 GiB, 30 second, 4 KiB random-write
run with four fio jobs after the NFS request backpressure fix. Treat these as
regression evidence only.

The full 1 GiB Phase 6 fio matrix should run on a dedicated Linux bench host.
Local Docker completed the early rows but then hit container local file-store
compaction/backpressure and kernel NFS soft-mount retransmit behavior during
later prefill work.

## Multi-Volume Overhead

DD-1 calls for measuring one-DB-per-volume overhead at 100 idle volumes plus 20
hot volumes. Run the harness through the same privileged Docker wrapper:

```sh
SKIP_SMOKE=1 \
scripts/docker-kernel-mount-test.sh scripts/multi-volume-overhead.sh
```

The script creates `MULTI_IDLE_VOLUMES` idle volumes and `MULTI_HOT_VOLUMES` hot
volumes, starts a one-export baseline daemon, then starts a daemon with all
exports open. It mounts the hot subset through kernel NFS, writes and stats test
files concurrently, and emits a markdown report with:

- baseline/all-export/after-workload daemon RSS;
- approximate KiB per additional open volume;
- object-store/cache-related Prometheus metric deltas and per-second rates.

The 2026-06-14 Docker run completed the default DD-1 shape:

| sample | open volumes | daemon RSS MiB | delta vs baseline MiB | approx KiB/additional volume |
|---|---:|---:|---:|---:|
| baseline | 1 | 29.8 | 0.0 | 0.0 |
| all exports idle | 120 | 37.3 | 7.6 | 65.2 |
| after hot workload | 120 | 122.0 | 92.3 | 793.9 |

For a quick local smoke:

```sh
SKIP_SMOKE=1 \
MULTI_IDLE_VOLUMES=2 \
MULTI_HOT_VOLUMES=1 \
MULTI_OPS_PER_VOLUME=2 \
MULTI_FILE_KIB=4 \
scripts/docker-kernel-mount-test.sh scripts/multi-volume-overhead.sh
```
