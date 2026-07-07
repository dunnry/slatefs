#!/usr/bin/env bash
# ZFS-on-NBD showcase smoke against slatefsd's block export.
#
# Requires a Linux kernel with nbd.ko and zfs.ko available. Missing ZFS support
# is reported as:
#   SLATEFS_ZFS_NBD_SMOKE_SKIPPED no-zfs ...
# and exits 0 so CI/local Docker can distinguish SKIP from PASS.
#
# Run through the Docker harness:
#   SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/zfs-over-nbd-smoke.sh
# shellcheck disable=SC2086
set -euo pipefail

export PATH="/usr/sbin:/sbin:$PATH"

if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="${SUDO:-sudo}"; fi

TENANT="${SLATEFS_ZFS_NBD_TENANT:-${SLATEFS_NBD_TENANT:-t1}}"
VOLUME="${SLATEFS_ZFS_NBD_VOLUME:-zfs-b1}"
SIZE_BYTES="${SLATEFS_ZFS_NBD_SIZE_BYTES:-536870912}"
CHUNK_SIZE="${SLATEFS_ZFS_NBD_CHUNK_SIZE:-${SLATEFS_NBD_CHUNK_SIZE:-4096}}"
PORT="${SLATEFS_ZFS_NBD_PORT:-12062}"
ADMIN_PORT="${SLATEFS_ZFS_NBD_ADMIN_PORT:-13062}"
NBD_CLIENT_TIMEOUT="${SLATEFS_ZFS_NBD_CLIENT_TIMEOUT:-60}"
PAYLOAD_MIB="${SLATEFS_ZFS_NBD_PAYLOAD_MIB:-16}"
OP_TIMEOUT="${SLATEFS_ZFS_NBD_OP_TIMEOUT:-60}"
LONG_TIMEOUT="${SLATEFS_ZFS_NBD_LONG_TIMEOUT:-240}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"
CLI="$BIN/slatefs"
DAEMON="$BIN/slatefsd"
EXPORT_NAME="/$TENANT/$VOLUME"

WORK="$(mktemp -d)"
BASE_CONFIG="${SLATEFS_CONFIG:-}"
CONFIG="$WORK/zfs-nbd.toml"
LOG="$WORK/slatefsd-zfs-nbd.log"
MNT="$WORK/zfs"
POOL="${SLATEFS_ZFS_NBD_POOL:-slatefsnbd$$}"
NBD_DEV=""
DAEMON_PID=""
NBD_ATTACHED=0
POOL_CREATED=0

mkdir -p "$MNT"

cleanup() {
    local status=$?
    set +e
    if [ "$POOL_CREATED" -eq 1 ]; then
        timeout 60 $SUDO zpool destroy "$POOL" >/dev/null 2>&1 || true
    fi
    if [ "$NBD_ATTACHED" -eq 1 ] && [ -n "$NBD_DEV" ]; then
        timeout 20 $SUDO nbd-client -d "$NBD_DEV" >/dev/null 2>&1 || true
    fi
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
    [ -n "${DAEMON_PID:-}" ] && wait "$DAEMON_PID" 2>/dev/null
    if [ "$status" -ne 0 ] && [ -s "$LOG" ]; then
        echo "== slatefsd log tail (exit $status)"
        tail -120 "$LOG" | sed 's/\x1b\[[0-9;]*m//g' || true
    fi
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

run() {
    timeout "$OP_TIMEOUT" "$@"
}

run_long() {
    timeout "$LONG_TIMEOUT" "$@"
}

skip_zfs() {
    echo "SLATEFS_ZFS_NBD_SMOKE_SKIPPED no-zfs: $*"
    exit 0
}

skip_no_nbd() {
    echo "SLATEFS_ZFS_NBD_SMOKE_SKIPPED no-nbd.ko: $*"
    exit 0
}

ensure_binaries() {
    if [ -x "$CLI" ] && [ -x "$DAEMON" ]; then
        return 0
    fi
    command -v cargo >/dev/null 2>&1 || {
        echo "missing $CLI or $DAEMON and cargo is not available"
        exit 1
    }
    local build_args=()
    case "${BIN_OVERRIDE:-debug}" in
        debug) ;;
        release) build_args+=(--release) ;;
        *) echo "unsupported BIN_OVERRIDE=${BIN_OVERRIDE}; expected debug or release" >&2; exit 1 ;;
    esac
    echo "== building slatefsd + slatefs CLI"
    cargo build -q "${build_args[@]}" -p slatefs-daemon -p slatefs-cli
}

install_missing_tools() {
    local missing=()
    for cmd in timeout nbd-client modprobe blockdev sha256sum lsmod; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        command -v apt-get >/dev/null 2>&1 || {
            echo "missing tools: ${missing[*]}; install nbd-client kmod util-linux coreutils"
            exit 1
        }
        echo "== installing NBD/ZFS smoke base tools: ${missing[*]}"
        $SUDO apt-get update -qq >/dev/null
        DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq \
            nbd-client kmod util-linux coreutils procps >/dev/null
    fi

    if ! command -v zpool >/dev/null 2>&1 || ! command -v zfs >/dev/null 2>&1; then
        command -v apt-get >/dev/null 2>&1 || skip_zfs "zpool/zfs tools are unavailable"
        echo "== installing zfsutils-linux if available"
        $SUDO apt-get update -qq >/dev/null
        DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq zfsutils-linux >/dev/null || \
            skip_zfs "apt-get install zfsutils-linux failed"
    fi
    command -v zpool >/dev/null 2>&1 || skip_zfs "zpool is unavailable"
    command -v zfs >/dev/null 2>&1 || skip_zfs "zfs is unavailable"
}

base_config() {
    awk '
        /^\[\[exports\]\]/ { exit }
        /^\[admin\]/ { skip = 1; next }
        /^\[metrics\]/ { skip = 1; next }
        /^\[/ && skip { skip = 0 }
        !skip { print }
    ' "$BASE_CONFIG"
}

write_default_base_config() {
    local store="$WORK/store"
    mkdir -p "$store"
    BASE_CONFIG="$WORK/base.toml"
    cat > "$BASE_CONFIG" <<EOF
[object_store]
url = "file://$store"
[kms]
provider = "static"
key_hex = "0000000000000000000000000000000000000000000000000000000000000001"
EOF
}

write_zfs_nbd_config() {
    if [ -z "$BASE_CONFIG" ]; then
        write_default_base_config
    fi
    [ -f "$BASE_CONFIG" ] || {
        echo "SLATEFS_CONFIG does not point at a file: $BASE_CONFIG"
        exit 1
    }
    base_config > "$CONFIG"
    cat >> "$CONFIG" <<EOF

[admin]
listen = "127.0.0.1:$ADMIN_PORT"

[[exports]]
tenant = "$TENANT"
volume = "$VOLUME"
listen = "127.0.0.1:$PORT"
protocol = "nbd"
read_only = false
sync = "strict"
EOF
}

tenant_exists() {
    "$CLI" -c "$CONFIG" tenant list | awk '{ print $1 }' | grep -Fx "$TENANT" >/dev/null
}

volume_exists() {
    "$CLI" -c "$CONFIG" volume list "$TENANT" | awk '{ print $1 }' | grep -Fx "$TENANT/$VOLUME" >/dev/null
}

ensure_block_volume() {
    echo "== creating tenant and block volume if needed"
    if ! tenant_exists; then
        "$CLI" -c "$CONFIG" tenant create "$TENANT"
    fi
    if volume_exists; then
        local info
        info="$("$CLI" -c "$CONFIG" volume info "$TENANT" "$VOLUME")"
        grep -q '^kind:[[:space:]]*block$' <<<"$info" || {
            echo "existing volume $TENANT/$VOLUME is not a block volume"
            exit 1
        }
        grep -q "^size_bytes:[[:space:]]*$SIZE_BYTES$" <<<"$info" || {
            echo "existing block volume $TENANT/$VOLUME does not match size_bytes=$SIZE_BYTES"
            echo "$info"
            exit 1
        }
    else
        "$CLI" -c "$CONFIG" volume create "$TENANT" "$VOLUME" \
            --kind block \
            --size "$SIZE_BYTES" \
            --chunk-size "$CHUNK_SIZE"
    fi
}

port_open() {
    local port="$1"
    timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null
}

wait_port() {
    local port="$1"
    for _ in $(seq 1 75); do
        port_open "$port" && return 0
        sleep 0.2
    done
    echo "port $port never opened"
    tail -120 "$LOG" 2>/dev/null || true
    return 1
}

start_daemon() {
    echo "== starting slatefsd on NBD $PORT admin $ADMIN_PORT"
    "$DAEMON" -c "$CONFIG" >>"$LOG" 2>&1 &
    DAEMON_PID=$!
    wait_port "$PORT"
    wait_port "$ADMIN_PORT"
}

ensure_nbd_nodes() {
    local sys name major_minor major minor
    for sys in /sys/block/nbd*; do
        [ -e "$sys/dev" ] || continue
        name="${sys##*/}"
        [ -e "/dev/$name" ] && continue
        major_minor="$(cat "$sys/dev")"
        major="${major_minor%:*}"
        minor="${major_minor#*:}"
        $SUDO mknod "/dev/$name" b "$major" "$minor" 2>/dev/null || true
    done
}

ensure_nbd_kernel() {
    if [ -e /dev/nbd0 ] || [ -d /sys/block/nbd0 ]; then
        ensure_nbd_nodes
        return 0
    fi
    if ! $SUDO modprobe nbd max_part=8 nbds_max="${SLATEFS_ZFS_NBD_DEVICES:-16}" >/dev/null 2>&1; then
        skip_no_nbd "modprobe nbd failed; the host/VM kernel likely lacks nbd.ko"
    fi
    sleep 0.2
    ensure_nbd_nodes
    [ -e /dev/nbd0 ] || skip_no_nbd "modprobe succeeded but /dev/nbd0 was not created"
}

ensure_zfs_kernel() {
    if lsmod | awk '{ print $1 }' | grep -Fx zfs >/dev/null; then
        return 0
    fi
    if ! $SUDO modprobe zfs >/dev/null 2>&1; then
        skip_zfs "modprobe zfs failed; the host/VM kernel likely lacks zfs.ko"
    fi
}

select_free_nbd() {
    local sys name sectors
    for sys in /sys/block/nbd*; do
        [ -e "$sys/size" ] || continue
        name="${sys##*/}"
        [ -e "/dev/$name" ] || continue
        sectors="$(cat "$sys/size")"
        if [ "$sectors" = "0" ]; then
            NBD_DEV="/dev/$name"
            return 0
        fi
    done
    echo "no free /dev/nbd* device found"
    return 1
}

wait_device_size() {
    local size
    for _ in $(seq 1 50); do
        size="$($SUDO blockdev --getsize64 "$NBD_DEV" 2>/dev/null || echo 0)"
        [ "$size" = "$SIZE_BYTES" ] && return 0
        sleep 0.2
    done
    size="$($SUDO blockdev --getsize64 "$NBD_DEV" 2>/dev/null || echo 0)"
    echo "NBD device size mismatch: $NBD_DEV size=$size expected=$SIZE_BYTES"
    return 1
}

attach_nbd() {
    select_free_nbd
    echo "== attaching $EXPORT_NAME to $NBD_DEV"
    local common_args=(127.0.0.1 "$PORT" "$NBD_DEV" -N "$EXPORT_NAME" -persist off -timeout "$NBD_CLIENT_TIMEOUT")
    if $SUDO nbd-client "${common_args[@]}" >/tmp/zfs-nbd-client-attach.log 2>&1; then
        NBD_ATTACHED=1
        wait_device_size
        return 0
    fi
    echo "nbd-client attach with -persist off failed; retrying without -persist off"
    cat /tmp/zfs-nbd-client-attach.log || true
    local fallback_args=(127.0.0.1 "$PORT" "$NBD_DEV" -N "$EXPORT_NAME" -timeout "$NBD_CLIENT_TIMEOUT")
    $SUDO nbd-client "${fallback_args[@]}" >/tmp/zfs-nbd-client-attach.log 2>&1 || {
        cat /tmp/zfs-nbd-client-attach.log || true
        return 1
    }
    NBD_ATTACHED=1
    wait_device_size
}

wait_scrub_done() {
    for _ in $(seq 1 120); do
        if ! $SUDO zpool status "$POOL" | grep -q "scrub in progress"; then
            return 0
        fi
        sleep 1
    done
    echo "zpool scrub did not finish within timeout"
    $SUDO zpool status "$POOL" || true
    return 1
}

exercise_zfs() {
    echo "== zpool create $POOL on $NBD_DEV"
    run_long $SUDO zpool create -f -m "$MNT" -O atime=off "$POOL" "$NBD_DEV"
    POOL_CREATED=1

    echo "== write payload through ZFS"
    run_long $SUDO dd if=/dev/urandom of="$MNT/payload.bin" bs=1M count="$PAYLOAD_MIB" conv=fsync status=none
    local expected actual
    expected="$(run $SUDO sha256sum "$MNT/payload.bin" | awk '{ print $1 }')"

    echo "== zfs snapshot"
    run $SUDO zfs snapshot "$POOL@smoke"

    echo "== zpool scrub"
    run $SUDO zpool scrub "$POOL"
    wait_scrub_done
    $SUDO zpool status "$POOL"
    $SUDO zpool status -x "$POOL" | tee "$WORK/zpool-status-x.txt"
    grep -Eq "is healthy|all pools are healthy" "$WORK/zpool-status-x.txt" || {
        echo "zpool status -x did not report healthy"
        exit 1
    }

    actual="$(run $SUDO sha256sum "$MNT/payload.bin" | awk '{ print $1 }')"
    [ "$actual" = "$expected" ] || {
        echo "ZFS payload checksum mismatch after scrub: $actual != $expected"
        exit 1
    }

    echo "== destroy zpool"
    run_long $SUDO zpool destroy "$POOL"
    POOL_CREATED=0
}

install_missing_tools
ensure_zfs_kernel
ensure_binaries
write_zfs_nbd_config
ensure_block_volume
start_daemon
ensure_nbd_kernel
attach_nbd
exercise_zfs

timeout 20 $SUDO nbd-client -d "$NBD_DEV" >/dev/null 2>&1 || true
NBD_ATTACHED=0
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
echo "SLATEFS_ZFS_NBD_SMOKE_PASSED"
