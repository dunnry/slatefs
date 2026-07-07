#!/usr/bin/env bash
# Run the kernel NFS mount test inside a privileged Linux container — a real
# kernel NFS client without needing a Linux host or root on the host (the
# mount lives in the Docker VM; a hang can't wedge the host, just kill the
# container).
#
# NBD extra scripts use the Docker host/VM kernel too. On Linux hosts this
# wrapper bind-mounts /lib/modules when present so modprobe can load nbd.ko;
# Docker Desktop's LinuxKit VM may still lack nbd.ko, in which case the NBD
# script reports SLATEFS_NBD_KERNEL_TEST_SKIPPED and exits 0.
#
# Usage: scripts/docker-kernel-mount-test.sh [extra-script]
#   extra-script: optional path (relative to repo root) run inside the
#                 container after the smoke test, with the same env.
set -euo pipefail

cd "$(dirname "$0")/.."
EXTRA="${1:-}"

# Separate target dir for the Linux build; named volumes cache the registry
# and build artifacts across runs.
docker volume create slatefs-cargo-registry >/dev/null
docker volume create slatefs-target-linux >/dev/null

KERNEL_MODULE_ARGS=()
if [ -d /lib/modules ]; then
    KERNEL_MODULE_ARGS=(-v /lib/modules:/lib/modules:ro)
fi

docker run --rm --privileged \
    "${KERNEL_MODULE_ARGS[@]}" \
    -e PJD_TESTS -e PJD_PROVE_ARGS -e PJD_TIMEOUT -e SKIP_SMOKE \
    -e BIN_OVERRIDE \
    -e FSX_OPS -e FSSTRESS_OPS -e FSSTRESS_PROCS -e RESTARTS \
    -e FAILOVER_PRIMARY_PORT -e FAILOVER_TAKEOVER_PORT \
    -e FAILOVER_PRIMARY_METRICS_PORT -e FAILOVER_TAKEOVER_METRICS_PORT \
    -e FAILOVER_LOAD_MODE -e FAILOVER_LOAD_WARMUP -e FAILOVER_MAX_SECONDS \
    -e FAILOVER_FIO_RUNTIME -e FAILOVER_FIO_SIZE -e FAILOVER_FIO_JOBS \
    -e FAILOVER_FIO_BS -e FAILOVER_FIO_RW \
    -e FAILOVER_FSX_OPS -e FAILOVER_FSX_SEED -e FAILOVER_FSX_TIMEOUT \
    -e PERF_NFS_PORT -e PERF_METRICS_PORT -e FIO_RUNTIME -e FIO_SIZE \
    -e FIO_JOBS -e FIO_BS_LIST -e FIO_RW_LIST -e FIO_PREFILL_BS \
    -e FIO_PREFILL_FSYNC -e META_OPS -e FIO_CMD_TIMEOUT \
    -e FIO_NFS_TIMEO -e FIO_NFS_RETRANS -e PERF_REPORT \
    -e SLATEDB_L0_SST_SIZE_BYTES -e SLATEDB_MAX_UNFLUSHED_BYTES \
    -e SLATEDB_L0_MAX_SSTS -e SLATEDB_L0_MAX_SSTS_PER_KEY \
    -e SLATEDB_L0_FLUSH_PARALLELISM -e SLATEDB_COMPACTION_MAX_SST_SIZE_BYTES \
    -e SLATEDB_COMPACTION_MAX_CONCURRENT -e SLATEDB_COMPACTION_MAX_FETCH_TASKS \
    -e MULTI_TENANT -e MULTI_IDLE_VOLUMES -e MULTI_HOT_VOLUMES \
    -e MULTI_PORT_BASE -e MULTI_METRICS_PORT -e MULTI_OPS_PER_VOLUME \
    -e MULTI_FILE_KIB -e MULTI_SETTLE_SECONDS -e MULTI_REPORT \
    -e LIVE_SNAPSHOT_PORT -e LIVE_SNAPSHOT_ADMIN_PORT -e LIVE_SNAPSHOT_SNAPSHOT_PORT \
    -e LIVE_SNAPSHOT_CLONE_PORT -e LIVE_SNAPSHOT_CLONE_VOLUME -e LIVE_SNAPSHOT_METRICS_PORT \
    -e QEMU_BIN -e QEMU_KERNEL -e QEMU_TIMEOUT -e QEMU_INSTALL_DEPS \
    -e BUSYBOX -e SLATEFS_P9_PORT -e SLATEFS_P9_TOKEN -e SLATEFS_P9_ANAME \
    -e SLATEFS_NBD_TENANT -e SLATEFS_NBD_VOLUME -e SLATEFS_NBD_SIZE_BYTES \
    -e SLATEFS_NBD_CHUNK_SIZE \
    -e SLATEFS_NBD_PORT -e SLATEFS_NBD_ADMIN_PORT -e SLATEFS_NBD_CLIENT_TIMEOUT \
    -e SLATEFS_NBD_CRASH_WARMUP -e SLATEFS_NBD_OP_TIMEOUT \
    -e SLATEFS_NBD_LONG_TIMEOUT -e SLATEFS_NBD_DEVICES -e SLATEFS_NBD_TRIM_MIB \
    -e SLATEFS_NBD_DD_LOAD_TIMEOUT -e SLATEFS_NBD_DD_LOAD_MIB \
    -e SLATEFS_QEMU_NBD_TENANT -e SLATEFS_QEMU_NBD_VOLUME \
    -e SLATEFS_QEMU_NBD_SIZE_MIB -e SLATEFS_QEMU_NBD_SIZE_BYTES \
    -e SLATEFS_QEMU_NBD_CHUNK_SIZE -e SLATEFS_QEMU_NBD_PORT \
    -e SLATEFS_QEMU_NBD_ADMIN_PORT -e SLATEFS_QEMU_NBD_OP_TIMEOUT \
    -e SLATEFS_QEMU_NBD_LONG_TIMEOUT -e SLATEFS_QEMU_NBD_BENCH_COUNT \
    -e SLATEFS_QEMU_NBD_BENCH_DEPTH -e SLATEFS_QEMU_NBD_INSTALL_DEPS \
    -e SLATEFS_QEMU_NBD_URI \
    -e SLATEFS_ZFS_NBD_TENANT -e SLATEFS_ZFS_NBD_VOLUME \
    -e SLATEFS_ZFS_NBD_SIZE_BYTES -e SLATEFS_ZFS_NBD_CHUNK_SIZE \
    -e SLATEFS_ZFS_NBD_PORT -e SLATEFS_ZFS_NBD_ADMIN_PORT \
    -e SLATEFS_ZFS_NBD_CLIENT_TIMEOUT -e SLATEFS_ZFS_NBD_PAYLOAD_MIB \
    -e SLATEFS_ZFS_NBD_OP_TIMEOUT -e SLATEFS_ZFS_NBD_LONG_TIMEOUT \
    -e SLATEFS_ZFS_NBD_POOL -e SLATEFS_ZFS_NBD_DEVICES \
    -v "$PWD":/src:ro \
    -v slatefs-cargo-registry:/usr/local/cargo/registry \
    -v slatefs-target-linux:/target \
    -e CARGO_TARGET_DIR=/target \
    -w /src \
    rust:1 bash -ceu '
        # Snapshot the harness scripts: /src is a live bind mount and a host
        # edit mid-run would corrupt a script bash is still reading.
        cp -r /src/scripts /tmp/scripts
        apt-get update -qq >/dev/null && apt-get install -y -qq nfs-common attr >/dev/null
        build_args=()
        case "${BIN_OVERRIDE:-debug}" in
            debug) ;;
            release) build_args+=(--release) ;;
            *) echo "unsupported BIN_OVERRIDE=${BIN_OVERRIDE}; expected debug or release" >&2; exit 1 ;;
        esac
        cargo build -q "${build_args[@]}" -p slatefs-daemon -p slatefs-cli
        BIN="/target/${BIN_OVERRIDE:-debug}"

        STORE=$(mktemp -d)
        cat > /tmp/slatefs.toml <<EOF
[object_store]
url = "file://$STORE"
[kms]
provider = "static"
key_hex = "0000000000000000000000000000000000000000000000000000000000000001"
[slatedb]
l0_sst_size_bytes = ${SLATEDB_L0_SST_SIZE_BYTES:-16777216}
max_unflushed_bytes = ${SLATEDB_MAX_UNFLUSHED_BYTES:-268435456}
l0_max_ssts = ${SLATEDB_L0_MAX_SSTS:-64}
l0_max_ssts_per_key = ${SLATEDB_L0_MAX_SSTS_PER_KEY:-16}
l0_flush_parallelism = ${SLATEDB_L0_FLUSH_PARALLELISM:-2}
compaction_max_sst_size_bytes = ${SLATEDB_COMPACTION_MAX_SST_SIZE_BYTES:-67108864}
compaction_max_concurrent = ${SLATEDB_COMPACTION_MAX_CONCURRENT:-2}
compaction_max_fetch_tasks = ${SLATEDB_COMPACTION_MAX_FETCH_TASKS:-2}
[[exports]]
tenant = "t1"
volume = "v1"
listen = "127.0.0.1:12049"
squash = "none"
[[exports]]
tenant = "t1"
volume = "v1"
listen = "127.0.0.1:12050"
protocol = "p9"
p9_token = "sekrit"
EOF
        "$BIN/slatefs" -c /tmp/slatefs.toml tenant create t1
        "$BIN/slatefs" -c /tmp/slatefs.toml volume create t1 v1

        export SLATEFS_CONFIG=/tmp/slatefs.toml
        [ -n "${SKIP_SMOKE:-}" ] || /tmp/scripts/nfs-kernel-mount-test.sh
        '"${EXTRA:+/tmp/$EXTRA}"'
    '
