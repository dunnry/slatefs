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

## Failover Timing

The failover drill can run a fio workload against the primary NFS mount while
the takeover daemon fences it:

```sh
SKIP_SMOKE=1 \
FAILOVER_LOAD_MODE=fio \
FAILOVER_FIO_RUNTIME=30 \
FAILOVER_FIO_SIZE=256m \
FAILOVER_MAX_SECONDS=10 \
scripts/docker-kernel-mount-test.sh scripts/nfs-failover-drill.sh
```

The script measures from takeover daemon start to the first verified durable
write on the remounted takeover export, then fails if the window is above
`FAILOVER_MAX_SECONDS`.

## Target Table

The GA target table should be filled from a dedicated bench host. Do not treat
Docker Desktop or laptop file-store results as product targets.

| Workload | Target | Source |
|---|---:|---|
| Warm 128 KiB read p99 | <= 1 ms | Phase 3 local read-latency baseline plus NFS overhead budget |
| Cold read p99 | object-store latency + decode | DD-4 cache model |
| Failover under client load | < 10 s | Phase 6 acceptance criteria |
| Metadata create/stat/unlink | bench-host baseline | fio harness metadata smoke |
