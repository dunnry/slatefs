#!/usr/bin/env bash
# QEMU userspace NBD smoke against slatefsd's block export. This does not use
# the Linux nbd.ko kernel module; it exercises QEMU/qemu-img's NBD client.
#
# Run directly on Linux/macOS with qemu-img installed, or through:
#   SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/qemu-nbd-smoke.sh
#
# Optional env:
#   SLATEFS_CONFIG                  base config to copy object_store/kms/slatedb from
#   SLATEFS_QEMU_NBD_TENANT         tenant name (default: SLATEFS_NBD_TENANT or t1)
#   SLATEFS_QEMU_NBD_VOLUME         block volume name (default: qemu-b1)
#   SLATEFS_QEMU_NBD_SIZE_MIB       virtual/image size in MiB (default: 32)
#   SLATEFS_QEMU_NBD_PORT           NBD listen port (default: 12061)
#   SLATEFS_QEMU_NBD_ADMIN_PORT     admin listen port (default: 13061)
#   SLATEFS_QEMU_NBD_INSTALL_DEPS   apt-install qemu-utils if missing (default: 1)
set -euo pipefail

export PATH="/usr/sbin:/sbin:$PATH"

if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="${SUDO:-sudo}"; fi

TENANT="${SLATEFS_QEMU_NBD_TENANT:-${SLATEFS_NBD_TENANT:-t1}}"
VOLUME="${SLATEFS_QEMU_NBD_VOLUME:-qemu-b1}"
SIZE_MIB="${SLATEFS_QEMU_NBD_SIZE_MIB:-32}"
SIZE_BYTES="${SLATEFS_QEMU_NBD_SIZE_BYTES:-$((SIZE_MIB * 1024 * 1024))}"
CHUNK_SIZE="${SLATEFS_QEMU_NBD_CHUNK_SIZE:-${SLATEFS_NBD_CHUNK_SIZE:-4096}}"
PORT="${SLATEFS_QEMU_NBD_PORT:-12061}"
ADMIN_PORT="${SLATEFS_QEMU_NBD_ADMIN_PORT:-13061}"
OP_TIMEOUT="${SLATEFS_QEMU_NBD_OP_TIMEOUT:-60}"
LONG_TIMEOUT="${SLATEFS_QEMU_NBD_LONG_TIMEOUT:-180}"
BENCH_COUNT="${SLATEFS_QEMU_NBD_BENCH_COUNT:-64}"
BENCH_DEPTH="${SLATEFS_QEMU_NBD_BENCH_DEPTH:-4}"
INSTALL_DEPS="${SLATEFS_QEMU_NBD_INSTALL_DEPS:-1}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"
CLI="$BIN/slatefs"
DAEMON="$BIN/slatefsd"
EXPORT_NAME="/$TENANT/$VOLUME"
NBD_URI="${SLATEFS_QEMU_NBD_URI:-nbd://127.0.0.1:$PORT/$EXPORT_NAME}"

WORK="$(mktemp -d)"
BASE_CONFIG="${SLATEFS_CONFIG:-}"
CONFIG="$WORK/qemu-nbd.toml"
LOG="$WORK/slatefsd-qemu-nbd.log"
SRC="$WORK/source.raw"
ROUNDTRIP="$WORK/roundtrip.raw"
DAEMON_PID=""

cleanup() {
    local status=$?
    set +e
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

skip_qemu_img() {
    echo "SLATEFS_QEMU_NBD_SMOKE_SKIPPED no-qemu-img: $*"
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

ensure_qemu_img() {
    if command -v qemu-img >/dev/null 2>&1; then
        return 0
    fi
    if [ "$INSTALL_DEPS" = "1" ] && command -v apt-get >/dev/null 2>&1; then
        echo "== installing qemu-img (qemu-utils)"
        $SUDO apt-get update -qq >/dev/null
        DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq qemu-utils coreutils >/dev/null || \
            skip_qemu_img "apt-get install qemu-utils failed"
    fi
    command -v qemu-img >/dev/null 2>&1 || skip_qemu_img "qemu-img is unavailable"
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

write_qemu_nbd_config() {
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

write_source_image() {
    echo "== writing $SIZE_BYTES byte raw source image"
    run_long head -c "$SIZE_BYTES" /dev/urandom > "$SRC"
}

exercise_qemu_img() {
    echo "== qemu-img info $NBD_URI"
    run qemu-img info "$NBD_URI"

    write_source_image
    local expected actual
    expected="$(sha256sum "$SRC" | awk '{ print $1 }')"

    echo "== qemu-img convert raw image to NBD export"
    run_long qemu-img convert -f raw -O raw -n "$SRC" "$NBD_URI"

    echo "== qemu-img convert NBD export back to raw"
    run_long qemu-img convert -f raw -O raw "$NBD_URI" "$ROUNDTRIP"
    actual="$(sha256sum "$ROUNDTRIP" | awk '{ print $1 }')"
    [ "$actual" = "$expected" ] || {
        echo "qemu-img round-trip checksum mismatch: $actual != $expected"
        exit 1
    }

    echo "== qemu-img bench read smoke"
    run_long qemu-img bench -f raw -c "$BENCH_COUNT" -d "$BENCH_DEPTH" "$NBD_URI"
}

ensure_qemu_img
ensure_binaries
write_qemu_nbd_config
ensure_block_volume
start_daemon
exercise_qemu_img

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
echo "SLATEFS_QEMU_NBD_SMOKE_PASSED"
