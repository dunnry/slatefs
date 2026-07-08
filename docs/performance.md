# SlateFS Performance Harness

Phase 6 performance work is measured through a real kernel NFS client, not an
in-process shortcut. The fio sweep lives in:

```sh
scripts/fio-over-nfs.sh
```

For the production-like Azure Blob path, use:

```sh
AZURE_SUBSCRIPTION_ID=0a1ca07f-76d3-4739-b946-58d39524082f \
scripts/azure-prodtest.sh all
```

That harness creates a fresh East US 2 rig by default: one Blob-backed storage
account, one kernel-NFS client VM, two daemon VMs, local Prometheus/Grafana
through an SSH metrics tunnel, and then deallocates all VMs at the end of the
run. It leaves the resource group, storage account, and collected artifacts in
place for inspection. Use `AZURE_PRODTEST_FIO_RUNTIME`,
`AZURE_PRODTEST_FIO_SIZE`, and `AZURE_PRODTEST_FIO_JOBS` to scale the fio
matrix.

For a quota-friendly harness smoke, skip the unused takeover VM and use a
smaller VM size:

```sh
AZURE_PRODTEST_CREATE_DAEMON2=0 \
AZURE_PRODTEST_VM_SIZE=Standard_D2ds_v5 \
AZURE_PRODTEST_FIO_RUNTIME=1 \
AZURE_PRODTEST_FIO_SIZE=16m \
AZURE_PRODTEST_FIO_BS_LIST=4k \
AZURE_PRODTEST_FIO_RW_LIST=write \
AZURE_PRODTEST_META_OPS=1 \
scripts/azure-prodtest.sh all
```

Run it through the existing privileged Docker harness:

```sh
SKIP_SMOKE=1 \
BIN_OVERRIDE=release \
FIO_RUNTIME=30 \
FIO_SIZE=1g \
FIO_JOBS=4 \
scripts/docker-kernel-mount-test.sh scripts/fio-over-nfs.sh
```

`BIN_OVERRIDE=release` makes the Docker wrapper build release binaries and makes
the fio script run them from the shared Cargo target directory. The Docker
wrapper also writes a bounded `[slatedb]` section for the generated test config:
16 MiB L0 SSTs, 256 MiB max unflushed bytes, 64 total L0 SSTs, 16 overlapping
L0 SSTs per key, two L0 flush workers, and two compaction workers/fetch tasks.
Override the `SLATEDB_*` environment variables in
[scripts/docker-kernel-mount-test.sh](../scripts/docker-kernel-mount-test.sh)
for larger bench hosts. The script emits a markdown table with the Phase 6
matrix:

- sequential read and write;
- random read and write;
- block sizes 4 KiB, 128 KiB, and 1 MiB;
- a simple create/stat/unlink metadata ops/s smoke.

For a quick local smoke, lower `FIO_RUNTIME`, `FIO_SIZE`, and `META_OPS`.
Bench numbers are only comparable when the object store, cache settings,
kernel NFS client, host CPU, and Docker/VM environment are held fixed.
Slow environments can raise `FIO_CMD_TIMEOUT`; the default is 600 seconds per
fio/prefill command. Read-source prefill uses `FIO_PREFILL_BS` (default 4 KiB);
larger values can speed setup on stronger clients but may stress kernel NFS
writeback on small VMs. Prefill defaults to `FIO_PREFILL_FSYNC=0` because the
write workload rows already exercise durable `end_fsync=1`; forcing an extra
durable prefill can dominate the read rows on small NFS clients. The fio harness
also defaults to a longer kernel NFS soft-mount timeout
(`FIO_NFS_TIMEO=600`, `FIO_NFS_RETRANS=3`) so slow setup I/O does not collapse
into client-side `EIO`.

For direct host runs outside the Docker wrapper, add an explicit `[slatedb]`
section to the config used by `SLATEFS_CONFIG` when running write-heavy fio:

```toml
[slatedb]
l0_sst_size_bytes = 16777216
max_unflushed_bytes = 268435456
l0_max_ssts = 64
l0_max_ssts_per_key = 16
l0_flush_parallelism = 2
compaction_max_sst_size_bytes = 67108864
compaction_max_concurrent = 2
compaction_max_fetch_tasks = 2
```

## NBD

Phase B3 block-device fio work should run through a real kernel NBD attach, not
the in-process NBD client. The functional/crash fixture is:

```sh
SKIP_SMOKE=1 \
BIN_OVERRIDE=release \
FIO_RUNTIME=30 \
FIO_SIZE=1g \
FIO_JOBS=4 \
FIO_BS=64k \
FIO_RW=randwrite \
scripts/docker-kernel-mount-test.sh scripts/nbd-kernel-attach-test.sh
```

Set any `FIO_*` variable to make the crash-recovery drill use fio instead of
the default dd loop. Sweep `FIO_RW` over `read write randread randwrite` and
`FIO_BS` over `4k 64k 1m` for the B3 matrix; keep `FIO_RUNTIME`, `FIO_SIZE`,
and `FIO_JOBS` fixed for comparable rows. The Docker wrapper is privileged and
passes the NBD knobs through, but the kernel module must exist in the host/VM
kernel. Docker Desktop may report `SLATEFS_NBD_KERNEL_TEST_SKIPPED`; run the
matrix on Linux CI or a Linux bench host where `modprobe nbd` succeeds.

### Nested VM NBD Chunk-Size Evidence

On 2026-07-07, `nested-vm` ran the NBD chunk-size matrix through the Linux
kernel NBD client against raw `/dev/nbd0` devices, with no filesystem layered on
top. The host was a 2 vCPU / 3.8 GiB Ubuntu Azure VM, kernel
`6.8.0-1052-azure`, `fio-3.28`, `nbd-client` 3.23, and `nbd.ko`. Each chunk
size ran in its own fresh `slatefsd` process and local `file://` object store
under `/mnt`, then the store was removed after result capture. The local-disk
backend makes absolute throughput optimistic versus S3/Azure Blob, but the
relative chunk-size comparison is still valid because the backend and SlateDB
settings were held fixed.

The initial target was 1 GiB and 30 seconds per cell, but an all-volume run
filled the available `/mnt` local disk and a second all-volume run exceeded the
small VM's memory during background compaction. The completed matrix therefore
used one isolated daemon/store per chunk size, 1 GiB virtual block volumes,
`FIO_SIZE=256m`, `FIO_RUNTIME=20`, `numjobs=1`, and `iodepth=8`. The first
4 KiB `randwrite` row for each chunk size ran before prefill on a sparse volume
so `allocated_bytes` growth could be measured; the read rows were preceded by a
256 MiB raw-device prefill.

Attach command, with `b32`, `b64`, `b128`, and `b256` substituted per chunk:

```sh
sudo nbd-client 127.0.0.1 22200 /dev/nbd0 \
  -N /t1/b<chunk-kib> -b 4096 -timeout 60 -C 2
```

Prefill command before read rows:

```sh
sudo fio --name=c<chunk-kib>-prefill --filename=/dev/nbd0 \
  --rw=write --bs=1m --size=256m --ioengine=libaio --iodepth=8 \
  --numjobs=1 --direct=1 --group_reporting=1 --fallocate=none \
  --end_fsync=1 --eta=never --output-format=json --output=<json>
```

Read and write matrix commands:

```sh
sudo fio --name=c<chunk-kib>-<rw>-<bs> --filename=/dev/nbd0 \
  --rw=<read|write|randread|randwrite> --bs=<4k|64k|1m> \
  --size=256m --runtime=20 --time_based=1 --ioengine=libaio \
  --iodepth=8 --numjobs=1 --direct=1 --group_reporting=1 \
  --fallocate=none --eta=never --output-format=json --output=<json>
```

Write and mixed rows also used `--end_fsync=1`. The mixed row used:

```sh
sudo fio --name=c<chunk-kib>-randrw70-4k --filename=/dev/nbd0 \
  --rw=randrw --rwmixread=70 --bs=4k --size=256m --runtime=20 \
  --time_based=1 --ioengine=libaio --iodepth=8 --numjobs=1 \
  --direct=1 --group_reporting=1 --fallocate=none --end_fsync=1 \
  --eta=never --output-format=json --output=<json>
```

| chunk | workload | block | IOPS | MiB/s | mean ms | p99 ms |
|---:|---|---:|---:|---:|---:|---:|
| 32 KiB | randwrite | 4k | 1580 | 6.2 | 5.037 | 6.586 |
| 32 KiB | read | 4k | 20901 | 81.6 | 0.374 | 0.971 |
| 32 KiB | write | 4k | 2410 | 9.4 | 3.291 | 49.021 |
| 32 KiB | randread | 4k | 11988 | 46.8 | 0.649 | 2.245 |
| 32 KiB | read | 64k | 7006 | 437.9 | 1.117 | 3.064 |
| 32 KiB | write | 64k | 904 | 56.5 | 8.790 | 76.022 |
| 32 KiB | randread | 64k | 5808 | 363.0 | 1.351 | 3.228 |
| 32 KiB | randwrite | 64k | 253 | 15.8 | 31.537 | 110.625 |
| 32 KiB | read | 1m | 348 | 348.1 | 22.808 | 221.250 |
| 32 KiB | write | 1m | 32 | 32.1 | 246.219 | 8153.727 |
| 32 KiB | randread | 1m | 430 | 429.8 | 18.441 | 96.993 |
| 32 KiB | randwrite | 1m | 21 | 21.5 | 371.360 | 7818.183 |
| 32 KiB | randrw70read | 4k | 1551 | 6.1 | 2.674 | 7.438 |
| 32 KiB | randrw30write | 4k | 663 | 2.6 | 5.713 | 8.847 |
| 64 KiB | randwrite | 4k | 800 | 3.1 | 9.970 | 12.911 |
| 64 KiB | read | 4k | 24262 | 94.8 | 0.322 | 0.872 |
| 64 KiB | write | 4k | 1106 | 4.3 | 7.205 | 69.730 |
| 64 KiB | randread | 4k | 12709 | 49.6 | 0.613 | 2.056 |
| 64 KiB | read | 64k | 10622 | 663.9 | 0.732 | 2.212 |
| 64 KiB | write | 64k | 1033 | 64.5 | 7.689 | 84.410 |
| 64 KiB | randread | 64k | 6700 | 418.7 | 1.172 | 3.097 |
| 64 KiB | randwrite | 64k | 277 | 17.3 | 28.826 | 81.265 |
| 64 KiB | read | 1m | 536 | 535.8 | 14.767 | 87.556 |
| 64 KiB | write | 1m | 57 | 57.4 | 138.411 | 2004.877 |
| 64 KiB | randread | 1m | 609 | 609.0 | 12.986 | 49.545 |
| 64 KiB | randwrite | 1m | 16 | 15.8 | 504.816 | 10804.527 |
| 64 KiB | randrw70read | 4k | 481 | 1.9 | 3.072 | 72.876 |
| 64 KiB | randrw30write | 4k | 207 | 0.8 | 31.445 | 183.501 |
| 128 KiB | randwrite | 4k | 409 | 1.6 | 19.507 | 20.316 |
| 128 KiB | read | 4k | 25862 | 101.0 | 0.302 | 0.856 |
| 128 KiB | write | 4k | 607 | 2.4 | 13.145 | 109.576 |
| 128 KiB | randread | 4k | 12919 | 50.5 | 0.602 | 1.892 |
| 128 KiB | read | 64k | 11169 | 698.1 | 0.696 | 1.794 |
| 128 KiB | write | 64k | 471 | 29.5 | 16.901 | 158.335 |
| 128 KiB | randread | 64k | 7214 | 450.9 | 1.084 | 2.834 |
| 128 KiB | randwrite | 64k | 124 | 7.7 | 64.459 | 244.318 |
| 128 KiB | read | 1m | 637 | 636.8 | 12.398 | 92.799 |
| 128 KiB | write | 1m | 71 | 71.5 | 110.921 | 1044.382 |
| 128 KiB | randread | 1m | 839 | 838.8 | 9.362 | 29.229 |
| 128 KiB | randwrite | 1m | 15 | 14.9 | 535.816 | 9730.785 |
| 128 KiB | randrw70read | 4k | 110 | 0.4 | 2.356 | 61.604 |
| 128 KiB | randrw30write | 4k | 49 | 0.2 | 157.328 | 8657.043 |
| 256 KiB | randwrite | 4k | 226 | 0.9 | 35.273 | 89.653 |
| 256 KiB | read | 4k | 25762 | 100.6 | 0.302 | 0.954 |
| 256 KiB | write | 4k | 284 | 1.1 | 28.136 | 379.585 |
| 256 KiB | randread | 4k | 13294 | 51.9 | 0.585 | 1.630 |
| 256 KiB | read | 64k | 11985 | 749.0 | 0.647 | 1.729 |
| 256 KiB | write | 64k | 302 | 18.9 | 26.412 | 227.541 |
| 256 KiB | randread | 64k | 8481 | 530.1 | 0.919 | 2.671 |
| 256 KiB | randwrite | 64k | 52 | 3.2 | 154.680 | 599.785 |
| 256 KiB | read | 1m | 574 | 573.9 | 13.785 | 66.322 |
| 256 KiB | write | 1m | 33 | 32.7 | 242.799 | 784.335 |
| 256 KiB | randread | 1m | 898 | 897.5 | 8.738 | 19.005 |
| 256 KiB | randwrite | 1m | 10 | 9.8 | 818.236 | 16844.325 |
| 256 KiB | randrw70read | 4k | 45 | 0.2 | 1.466 | 6.980 |
| 256 KiB | randrw30write | 4k | 19 | 0.1 | 411.673 | 9059.697 |

For the sparse 4 KiB randwrite cell, SlateFS-side allocation growth and NBD
write metrics were:

| chunk | fio write bytes | allocated delta | alloc amp | NBD written bytes | NBD write reqs |
|---:|---:|---:|---:|---:|---:|
| 32 KiB | 147558400 | 233500672 | 1.58x | 147558400 | 36025 |
| 64 KiB | 77205504 | 221093888 | 2.86x | 77205504 | 18849 |
| 128 KiB | 39481344 | 216031232 | 5.47x | 39481344 | 9639 |
| 256 KiB | 19959808 | 214708224 | 10.76x | 19959808 | 4873 |

Conclusion: change the block-volume default from 64 KiB to 32 KiB. The 64 KiB
chunk size remained competitive for 64 KiB and 1 MiB rows, but the product
default is meant to protect guest filesystem 4-64 KiB write behavior. In the
decision rows, 32 KiB delivered 2.0x the sparse 4 KiB randwrite IOPS of 64 KiB
with lower p99 latency, 3.2x the mixed 70/30 4 KiB write IOPS, and materially
lower allocation amplification (1.58x versus 2.86x).

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

## Nested VM Release Evidence

On 2026-06-14, a 2 vCPU / 3.8 GiB Ubuntu Azure VM (`nested-vm`) completed the
full release fio matrix through the kernel NFSv3 client with `FIO_RUNTIME=30`,
`FIO_SIZE=1g`, `FIO_JOBS=4`, `FIO_PREFILL_BS=4k`,
`FIO_PREFILL_FSYNC=0`, and the bounded `[slatedb]` settings above. Sequential
read rows are kernel-client-visible measurements and can include Linux NFS page
cache effects; use colder read modes for future object-store read-latency
targets.

| workload | block | IOPS | MiB/s | mean ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| read | 4k | 309584 | 1209.3 | 0.012 | 0.510 |
| write | 4k | 99254 | 387.7 | 0.035 | 0.010 |
| randread | 4k | 12887 | 50.3 | 0.308 | 1.253 |
| randwrite | 4k | 1194 | 4.7 | 2.522 | 0.009 |
| read | 128k | 7849 | 981.2 | 0.498 | 2.310 |
| write | 128k | 128 | 16.0 | 30.959 | 6.062 |
| randread | 128k | 8741 | 1092.6 | 0.447 | 2.834 |
| randwrite | 128k | 254 | 31.8 | 15.304 | 379.585 |
| read | 1m | 1359 | 1359.3 | 2.863 | 8.978 |
| write | 1m | 83 | 83.1 | 47.606 | 952.107 |
| randread | 1m | 1048 | 1047.6 | 3.747 | 13.959 |
| randwrite | 1m | 29 | 28.6 | 135.589 | 3808.428 |

The same run completed the metadata smoke with 1500 create/stat/unlink cycles
in 57.798 seconds (26.0 ops/s).

## Azure Blob Cross-VM Evidence

On 2026-06-14, a three-VM East US 2 Azure rig completed the cross-VM fio matrix
against Azure Blob storage. The rig used a dedicated client VM mounting NFSv3
from a dedicated daemon VM over the private VNet, with `FIO_RUNTIME=30`,
`FIO_SIZE=512m`, `FIO_JOBS=4`, `FIO_PREFILL_BS=4k`,
`FIO_PREFILL_FSYNC=0`, the bounded `[slatedb]` settings above, and the disk
cache open-file cap at 256. The storage account was Standard LRS block blob;
premium block blobs were not used. Sequential read rows are
kernel-client-visible measurements and can include Linux NFS page cache
effects.

The run first exposed two production-like bugs: an empty SlateDB scan range in
sequential read-ahead and unbounded disk-cache file handles under Blob-backed
write load. Both fixes landed before the final matrix below.

| workload | block | IOPS | MiB/s | mean ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| read | 4k | 563364 | 2200.6 | 0.007 | 0.253 |
| write | 4k | 70511 | 275.4 | 0.040 | 0.012 |
| randread | 4k | 38653 | 151.0 | 0.102 | 0.494 |
| randwrite | 4k | 13391 | 52.3 | 0.252 | 0.013 |
| read | 128k | 13368 | 1671.0 | 0.292 | 1.253 |
| write | 128k | 925 | 115.6 | 4.220 | 5.276 |
| randread | 128k | 23213 | 2901.6 | 0.161 | 0.799 |
| randwrite | 128k | 491 | 61.4 | 7.146 | 0.100 |
| read | 1m | 3895 | 3895.1 | 1.015 | 3.424 |
| write | 1m | 109 | 109.3 | 33.970 | 189.792 |
| randread | 1m | 4311 | 4311.5 | 0.841 | 4.293 |
| randwrite | 1m | 89 | 89.1 | 36.530 | 19.268 |

The same run completed the metadata smoke with 1500 create/stat/unlink cycles
in 101.142 seconds (14.8 ops/s). The Azure VMs were deallocated after artifact
collection.

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
