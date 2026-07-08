#!/usr/bin/env bash
# NBD failover drill against two slatefsd instances sharing one block volume.
#
# Runs inside the privileged container from docker-kernel-mount-test.sh or on a
# Linux host with nbd.ko. The primary daemon serves a block volume through the
# kernel NBD client, a raw-device load runs, the primary is killed, and the
# takeover daemon binds the same endpoint. The default gate measures the
# practical scripted recovery path: detach the failed kernel NBD session,
# reattach the same /dev/nbdX to the same endpoint, and verify the durable
# marker written before kill. Set SLATEFS_NBD_FAILOVER_PERSIST_PROBE=1 to also
# try transparent nbd-client -persist reconnect on a second volume.
# shellcheck disable=SC2086
set -euo pipefail

export PATH="/usr/sbin:/sbin:$PATH"

if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="${SUDO:-sudo}"; fi

TENANT="${SLATEFS_NBD_FAILOVER_TENANT:-${SLATEFS_NBD_TENANT:-${SLATEFS_TENANT:-t1}}}"
VOLUME="${SLATEFS_NBD_FAILOVER_VOLUME:-nbd-failover-b1}"
SIZE_BYTES="${SLATEFS_NBD_FAILOVER_SIZE_BYTES:-268435456}"
CHUNK_SIZE="${SLATEFS_NBD_FAILOVER_CHUNK_SIZE:-${SLATEFS_NBD_CHUNK_SIZE:-32768}}"
NBD_BLOCK_SIZE="${SLATEFS_NBD_FAILOVER_BLOCK_SIZE:-${SLATEFS_NBD_BLOCK_SIZE:-4096}}"
PORT="${SLATEFS_NBD_FAILOVER_PORT:-12064}"
PRIMARY_ADMIN_PORT="${SLATEFS_NBD_FAILOVER_PRIMARY_ADMIN_PORT:-13064}"
TAKEOVER_ADMIN_PORT="${SLATEFS_NBD_FAILOVER_TAKEOVER_ADMIN_PORT:-13065}"
PRIMARY_METRICS_PORT="${SLATEFS_NBD_FAILOVER_PRIMARY_METRICS_PORT:-14064}"
TAKEOVER_METRICS_PORT="${SLATEFS_NBD_FAILOVER_TAKEOVER_METRICS_PORT:-14065}"
NBD_CLIENT_TIMEOUT="${SLATEFS_NBD_FAILOVER_CLIENT_TIMEOUT:-10}"
LOAD_MODE="${SLATEFS_NBD_FAILOVER_LOAD_MODE:-auto}"
LOAD_WARMUP="${SLATEFS_NBD_FAILOVER_LOAD_WARMUP:-1}"
MAX_FAILOVER_SECONDS="${SLATEFS_NBD_FAILOVER_MAX_SECONDS:-10}"
OP_TIMEOUT="${SLATEFS_NBD_FAILOVER_OP_TIMEOUT:-30}"
LONG_TIMEOUT="${SLATEFS_NBD_FAILOVER_LONG_TIMEOUT:-180}"
FIO_RUNTIME="${SLATEFS_NBD_FAILOVER_FIO_RUNTIME:-${FIO_RUNTIME:-30}}"
FIO_SIZE="${SLATEFS_NBD_FAILOVER_FIO_SIZE:-${FIO_SIZE:-64m}}"
FIO_JOBS="${SLATEFS_NBD_FAILOVER_FIO_JOBS:-${FIO_JOBS:-1}}"
FIO_BS="${SLATEFS_NBD_FAILOVER_FIO_BS:-${FIO_BS:-128k}}"
FIO_RW="${SLATEFS_NBD_FAILOVER_FIO_RW:-${FIO_RW:-randwrite}}"
PERSIST_PROBE="${SLATEFS_NBD_FAILOVER_PERSIST_PROBE:-0}"
PERSIST_REQUIRED="${SLATEFS_NBD_FAILOVER_PERSIST_REQUIRED:-0}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"
CLI="$BIN/slatefs"
DAEMON="$BIN/slatefsd"

BASE_CONFIG="${SLATEFS_CONFIG:-}"
WORK="$(mktemp -d)"
MANUAL_CONFIG_PRIMARY="$WORK/manual-primary.toml"
MANUAL_CONFIG_TAKEOVER="$WORK/manual-takeover.toml"
PERSIST_CONFIG_PRIMARY="$WORK/persist-primary.toml"
PERSIST_CONFIG_TAKEOVER="$WORK/persist-takeover.toml"
BASE_CONFIG_GENERATED="$WORK/base.toml"
PRIMARY_LOG="$WORK/primary.log"
TAKEOVER_LOG="$WORK/takeover.log"
FIO_LOG="$WORK/fio-load.log"
PAYLOAD="$WORK/payload.bin"
READBACK="$WORK/readback.bin"
NBD_DEV=""
PRIMARY_PID=""
TAKEOVER_PID=""
LOAD_PID=""
NBD_ATTACHED=0
CURRENT_CONFIG=""
CURRENT_VOLUME=""
CURRENT_PRIMARY_ADMIN_PORT=""
CURRENT_TAKEOVER_ADMIN_PORT=""
CURRENT_PRIMARY_METRICS_PORT=""
CURRENT_TAKEOVER_METRICS_PORT=""

cleanup() {
    local status=$?
    set +e
    [ -n "${LOAD_PID:-}" ] && kill "$LOAD_PID" 2>/dev/null
    detach_nbd
    stop_load
    [ -n "${PRIMARY_PID:-}" ] && kill "$PRIMARY_PID" 2>/dev/null
    [ -n "${PRIMARY_PID:-}" ] && wait "$PRIMARY_PID" 2>/dev/null
    [ -n "${TAKEOVER_PID:-}" ] && kill "$TAKEOVER_PID" 2>/dev/null
    [ -n "${TAKEOVER_PID:-}" ] && wait "$TAKEOVER_PID" 2>/dev/null
    if [ "$status" -ne 0 ]; then
        for log in "$PRIMARY_LOG" "$TAKEOVER_LOG"; do
            if [ -s "$log" ]; then
                echo "== $(basename "$log") tail (exit $status)"
                tail -120 "$log" | sed 's/\x1b\[[0-9;]*m//g' || true
            fi
        done
        [ -s "$FIO_LOG" ] && tail -80 "$FIO_LOG" || true
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

skip_no_nbd() {
    echo "SLATEFS_NBD_FAILOVER_SKIPPED no-nbd.ko: $*"
    exit 0
}

now_ns() {
    date +%s%N
}

elapsed_seconds() {
    awk -v start="$1" -v end="$2" 'BEGIN { printf "%.3f", (end - start) / 1000000000 }'
}

assert_failover_target() {
    local elapsed="$1"
    awk -v elapsed="$elapsed" -v max="$MAX_FAILOVER_SECONDS" 'BEGIN { exit !(elapsed <= max) }' || {
        echo "failover took ${elapsed}s, exceeding ${MAX_FAILOVER_SECONDS}s target"
        exit 1
    }
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
    for cmd in timeout nbd-client modprobe blockdev sha256sum cmp pkill awk; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        return 0
    fi
    command -v apt-get >/dev/null 2>&1 || {
        echo "missing tools: ${missing[*]}; install nbd-client kmod util-linux coreutils procps"
        exit 1
    }
    echo "== installing NBD failover tools: ${missing[*]}"
    $SUDO apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq \
        nbd-client kmod util-linux coreutils procps >/dev/null
}

fio_requested() {
    env | grep -Eq '^(FIO_|SLATEFS_NBD_FAILOVER_FIO_)'
}

ensure_fio() {
    if command -v fio >/dev/null 2>&1; then
        return 0
    fi
    command -v apt-get >/dev/null 2>&1 || {
        echo "fio load requested but fio is unavailable"
        exit 1
    }
    echo "== installing fio"
    $SUDO apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq fio >/dev/null
}

write_default_base_config() {
    local store="$WORK/store"
    mkdir -p "$store"
    BASE_CONFIG="$BASE_CONFIG_GENERATED"
    cat > "$BASE_CONFIG" <<EOF
[object_store]
url = "file://$store"
[kms]
provider = "static"
key_hex = "0000000000000000000000000000000000000000000000000000000000000001"
EOF
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

write_config() {
    local out="$1"
    local volume="$2"
    local admin_port="$3"
    local metrics_port="$4"
    base_config > "$out"
    cat >> "$out" <<EOF

[admin]
listen = "127.0.0.1:$admin_port"

[metrics]
listen = "127.0.0.1:$metrics_port"

[[exports]]
tenant = "$TENANT"
volume = "$volume"
listen = "127.0.0.1:$PORT"
protocol = "nbd"
read_only = false
sync = "strict"
EOF
}

prepare_configs() {
    if [ -z "$BASE_CONFIG" ]; then
        write_default_base_config
    fi
    [ -f "$BASE_CONFIG" ] || {
        echo "SLATEFS_CONFIG does not point at a file: $BASE_CONFIG"
        exit 1
    }
    write_config "$MANUAL_CONFIG_PRIMARY" "$VOLUME" "$PRIMARY_ADMIN_PORT" "$PRIMARY_METRICS_PORT"
    write_config "$MANUAL_CONFIG_TAKEOVER" "$VOLUME" "$TAKEOVER_ADMIN_PORT" "$TAKEOVER_METRICS_PORT"
    write_config "$PERSIST_CONFIG_PRIMARY" "$VOLUME-persist" "$((PRIMARY_ADMIN_PORT + 10))" "$((PRIMARY_METRICS_PORT + 10))"
    write_config "$PERSIST_CONFIG_TAKEOVER" "$VOLUME-persist" "$((TAKEOVER_ADMIN_PORT + 10))" "$((TAKEOVER_METRICS_PORT + 10))"
}

tenant_exists() {
    "$CLI" -c "$CURRENT_CONFIG" tenant list | awk '{ print $1 }' | grep -Fx "$TENANT" >/dev/null
}

volume_exists() {
    "$CLI" -c "$CURRENT_CONFIG" volume list "$TENANT" | awk '{ print $1 }' | grep -Fx "$TENANT/$CURRENT_VOLUME" >/dev/null
}

ensure_block_volume() {
    echo "== creating tenant and block volume $TENANT/$CURRENT_VOLUME if needed"
    if ! tenant_exists; then
        "$CLI" -c "$CURRENT_CONFIG" tenant create "$TENANT"
    fi
    if volume_exists; then
        local info
        info="$("$CLI" -c "$CURRENT_CONFIG" volume info "$TENANT" "$CURRENT_VOLUME")"
        grep -q '^kind:[[:space:]]*block$' <<<"$info" || {
            echo "existing volume $TENANT/$CURRENT_VOLUME is not a block volume"
            exit 1
        }
        grep -q "^size_bytes:[[:space:]]*$SIZE_BYTES$" <<<"$info" || {
            echo "existing block volume $TENANT/$CURRENT_VOLUME does not match size_bytes=$SIZE_BYTES"
            echo "$info"
            exit 1
        }
        grep -q "^chunk_size:[[:space:]]*$CHUNK_SIZE$" <<<"$info" || {
            echo "existing block volume $TENANT/$CURRENT_VOLUME does not match chunk_size=$CHUNK_SIZE"
            echo "$info"
            exit 1
        }
    else
        "$CLI" -c "$CURRENT_CONFIG" volume create "$TENANT" "$CURRENT_VOLUME" \
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
    local log="$2"
    for _ in $(seq 1 75); do
        port_open "$port" && return 0
        sleep 0.2
    done
    echo "port $port never opened"
    tail -120 "$log" 2>/dev/null || true
    return 1
}

wait_port_closed() {
    local port="$1"
    for _ in $(seq 1 50); do
        port_open "$port" || return 0
        sleep 0.1
    done
    echo "port $port stayed open after primary death"
    return 1
}

start_primary() {
    echo "== starting primary slatefsd on NBD $PORT admin $CURRENT_PRIMARY_ADMIN_PORT metrics $CURRENT_PRIMARY_METRICS_PORT"
    : > "$PRIMARY_LOG"
    "$DAEMON" -c "$CURRENT_CONFIG" >>"$PRIMARY_LOG" 2>&1 &
    PRIMARY_PID=$!
    wait_port "$PORT" "$PRIMARY_LOG"
    wait_port "$CURRENT_PRIMARY_ADMIN_PORT" "$PRIMARY_LOG"
    wait_port "$CURRENT_PRIMARY_METRICS_PORT" "$PRIMARY_LOG"
}

start_takeover() {
    echo "== starting takeover slatefsd on same NBD endpoint $PORT admin $CURRENT_TAKEOVER_ADMIN_PORT metrics $CURRENT_TAKEOVER_METRICS_PORT"
    : > "$TAKEOVER_LOG"
    "$DAEMON" -c "$CURRENT_CONFIG" >>"$TAKEOVER_LOG" 2>&1 &
    TAKEOVER_PID=$!
    wait_port "$PORT" "$TAKEOVER_LOG"
    wait_port "$CURRENT_TAKEOVER_ADMIN_PORT" "$TAKEOVER_LOG"
    wait_port "$CURRENT_TAKEOVER_METRICS_PORT" "$TAKEOVER_LOG"
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
    if ! command -v modprobe >/dev/null 2>&1; then
        skip_no_nbd "modprobe is unavailable"
    fi
    if ! $SUDO modprobe nbd max_part=8 nbds_max="${SLATEFS_NBD_FAILOVER_DEVICES:-16}" >/dev/null 2>&1; then
        skip_no_nbd "modprobe nbd failed; the host/VM kernel likely lacks nbd.ko"
    fi
    sleep 0.2
    ensure_nbd_nodes
    [ -e /dev/nbd0 ] || skip_no_nbd "modprobe succeeded but /dev/nbd0 was not created"
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

attach_nbd_common() {
    local persist_arg="$1"
    local export_name="/$TENANT/$CURRENT_VOLUME"
    case "$NBD_BLOCK_SIZE" in
        512|1024|2048|4096) ;;
        *) echo "unsupported SLATEFS_NBD_FAILOVER_BLOCK_SIZE=$NBD_BLOCK_SIZE; nbd-client accepts 512, 1024, 2048, or 4096" >&2; exit 1 ;;
    esac
    local common_args=(127.0.0.1 "$PORT" "$NBD_DEV" -N "$export_name" -b "$NBD_BLOCK_SIZE" -timeout "$NBD_CLIENT_TIMEOUT")
    echo "== attaching $export_name to $NBD_DEV block_size=$NBD_BLOCK_SIZE $persist_arg"
    if [ "$persist_arg" = "off" ]; then
        $SUDO nbd-client "${common_args[@]}" >/tmp/nbd-failover-client-attach.log 2>&1 || {
            cat /tmp/nbd-failover-client-attach.log || true
            return 1
        }
        NBD_ATTACHED=1
        wait_device_size
        return 0
    fi
    $SUDO nbd-client "${common_args[@]}" -persist >/tmp/nbd-failover-client-attach.log 2>&1 || {
        cat /tmp/nbd-failover-client-attach.log || true
        return 1
    }
    NBD_ATTACHED=1
    wait_device_size
}

attach_nbd() {
    local persist_arg="${1:-off}"
    if [ -z "$NBD_DEV" ]; then
        select_free_nbd
    fi
    attach_nbd_common "$persist_arg"
}

detach_nbd() {
    if [ "$NBD_ATTACHED" -eq 1 ] && [ -n "$NBD_DEV" ]; then
        timeout 20 $SUDO nbd-client -d "$NBD_DEV" >/dev/null 2>&1 || true
    fi
    NBD_ATTACHED=0
}

block_index_for_offset() {
    local offset="$1"
    echo $((offset / NBD_BLOCK_SIZE))
}

write_pattern_file() {
    local label="$1"
    local sequence="$2"
    run dd if=/dev/zero of="$PAYLOAD" bs="$NBD_BLOCK_SIZE" count=1 status=none
    printf "slatefs-nbd-failover:%s:%s:%s\n" "$CURRENT_VOLUME" "$label" "$sequence" |
        dd of="$PAYLOAD" bs=1 conv=notrunc status=none
}

write_block() {
    local offset="$1"
    local label="$2"
    local sequence="$3"
    local block
    block="$(block_index_for_offset "$offset")"
    write_pattern_file "$label" "$sequence"
    timeout "$OP_TIMEOUT" $SUDO dd if="$PAYLOAD" of="$NBD_DEV" bs="$NBD_BLOCK_SIZE" count=1 seek="$block" \
        oflag=direct conv=notrunc,fsync status=none
}

read_block() {
    local offset="$1"
    local block
    block="$(block_index_for_offset "$offset")"
    timeout "$OP_TIMEOUT" $SUDO dd if="$NBD_DEV" of="$READBACK" bs="$NBD_BLOCK_SIZE" count=1 skip="$block" \
        iflag=direct status=none
}

verify_block() {
    local offset="$1"
    local label="$2"
    local sequence="$3"
    write_pattern_file "$label" "$sequence"
    read_block "$offset"
    run cmp "$PAYLOAD" "$READBACK"
}

flush_device() {
    timeout "$OP_TIMEOUT" $SUDO blockdev --flushbufs "$NBD_DEV"
}

stop_load() {
    if [ -n "${LOAD_PID:-}" ]; then
        if command -v pkill >/dev/null 2>&1; then
            pkill -TERM -P "$LOAD_PID" 2>/dev/null || true
        fi
        kill "$LOAD_PID" 2>/dev/null || true
        for _ in $(seq 1 15); do
            kill -0 "$LOAD_PID" 2>/dev/null || break
            sleep 0.2
        done
        if command -v pkill >/dev/null 2>&1; then
            pkill -KILL -P "$LOAD_PID" 2>/dev/null || true
        fi
        kill -9 "$LOAD_PID" 2>/dev/null || true
        sleep 0.2
        if kill -0 "$LOAD_PID" 2>/dev/null; then
            echo "load process $LOAD_PID did not exit after signal; detach cleanup will continue"
        else
            wait "$LOAD_PID" 2>/dev/null || true
        fi
        LOAD_PID=""
    fi
}

start_loop_load() {
    echo "== starting verified raw-device load loop"
    (
        i=0
        while :; do
            offset=$((16 * 1024 * 1024 + (i % 256) * NBD_BLOCK_SIZE))
            write_block "$offset" "load" "$i" || exit 0
            verify_block "$offset" "load" "$i" || exit 1
            i=$((i + 1))
        done
    ) &
    LOAD_PID=$!
}

start_fio_load() {
    ensure_fio
    echo "== starting fio raw-device load: rw=$FIO_RW bs=$FIO_BS size=$FIO_SIZE jobs=$FIO_JOBS"
    $SUDO fio \
        --name=nbd-failover-load \
        --filename="$NBD_DEV" \
        --rw="$FIO_RW" \
        --bs="$FIO_BS" \
        --size="$FIO_SIZE" \
        --offset=32m \
        --runtime="$FIO_RUNTIME" \
        --time_based=1 \
        --ioengine=sync \
        --direct=1 \
        --numjobs="$FIO_JOBS" \
        --group_reporting=1 \
        --verify=crc32c \
        --verify_fatal=1 \
        --verify_backlog=1024 \
        --verify_backlog_batch=128 \
        --output="$FIO_LOG" \
        >/dev/null 2>&1 &
    LOAD_PID=$!
}

start_load() {
    case "$LOAD_MODE" in
        none)
            echo "== client load disabled"
            return 0
            ;;
        loop)
            start_loop_load
            ;;
        fio)
            start_fio_load
            ;;
        auto)
            if fio_requested; then
                start_fio_load
            else
                start_loop_load
            fi
            ;;
        *)
            echo "unknown SLATEFS_NBD_FAILOVER_LOAD_MODE=$LOAD_MODE (none|loop|fio|auto)"
            exit 1
            ;;
    esac
    sleep "$LOAD_WARMUP"
}

scrape_metrics() {
    local port="$1"
    timeout 5 bash -c "
        exec 3<>/dev/tcp/127.0.0.1/$port
        printf 'GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3
        cat <&3
    "
}

nbd_request_count() {
    local port="$1"
    local cmd="$2"
    scrape_metrics "$port" | awk -v tenant="$TENANT" -v volume="$CURRENT_VOLUME" -v cmd="$cmd" '
        $1 ~ /^slatefs_nbd_requests_total\{/ &&
            index($0, "tenant=\"" tenant "\"") &&
            index($0, "volume=\"" volume "\"") &&
            index($0, "cmd=\"" cmd "\"") {
                print int($2)
                found = 1
            }
        END {
            if (!found) {
                print 0
            }
        }
    '
}

assert_takeover_live() {
    scrape_metrics "$CURRENT_TAKEOVER_METRICS_PORT" |
        grep -q "slatefs_volume_dead{tenant=\"$TENANT\",volume=\"$CURRENT_VOLUME\"} 0" || {
            echo "takeover metrics did not report a live block volume"
            scrape_metrics "$CURRENT_TAKEOVER_METRICS_PORT" || true
            exit 1
        }
}

stop_daemon() {
    local which="$1"
    local pid
    case "$which" in
        primary) pid="$PRIMARY_PID"; PRIMARY_PID="" ;;
        takeover) pid="$TAKEOVER_PID"; TAKEOVER_PID="" ;;
        *) echo "unknown daemon role: $which"; exit 1 ;;
    esac
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

run_offline_fsck() {
    echo "== offline block fsck"
    "$CLI" -c "$CURRENT_CONFIG" volume fsck "$TENANT" "$CURRENT_VOLUME"
}

manual_failover_drill() {
    CURRENT_VOLUME="$VOLUME"
    CURRENT_CONFIG="$MANUAL_CONFIG_PRIMARY"
    CURRENT_PRIMARY_ADMIN_PORT="$PRIMARY_ADMIN_PORT"
    CURRENT_PRIMARY_METRICS_PORT="$PRIMARY_METRICS_PORT"
    CURRENT_TAKEOVER_ADMIN_PORT="$TAKEOVER_ADMIN_PORT"
    CURRENT_TAKEOVER_METRICS_PORT="$TAKEOVER_METRICS_PORT"
    ensure_block_volume
    start_primary
    ensure_nbd_kernel
    select_free_nbd
    attach_nbd off

    echo "== writing durable FLUSH/FUA marker before failover"
    write_block 0 "durable-before-failover" 1
    flush_device
    local flush_count
    flush_count="$(nbd_request_count "$CURRENT_PRIMARY_METRICS_PORT" flush)"
    if [ "$flush_count" -lt 1 ]; then
        echo "primary did not observe an NBD FLUSH for the durable marker"
        exit 1
    fi
    verify_block 0 "durable-before-failover" 1
    start_load

    echo "== kill -9 primary under load"
    local kill_start kill_done detach_done takeover_done attach_done io_done
    kill_start="$(now_ns)"
    kill -9 "$PRIMARY_PID"
    wait "$PRIMARY_PID" 2>/dev/null || true
    PRIMARY_PID=""
    kill_done="$(now_ns)"
    wait_port_closed "$PORT"
    echo "== scripted detach from failed primary"
    detach_nbd
    stop_load
    detach_done="$(now_ns)"

    CURRENT_CONFIG="$MANUAL_CONFIG_TAKEOVER"
    start_takeover
    takeover_done="$(now_ns)"

    echo "== scripted reattach to takeover on same endpoint"
    attach_nbd off
    attach_done="$(now_ns)"

    echo "== verifying durable marker through takeover"
    verify_block 0 "durable-before-failover" 1
    io_done="$(now_ns)"
    local failover_seconds
    failover_seconds="$(elapsed_seconds "$kill_start" "$io_done")"
    echo "== failover breakdown: kill_wait=$(elapsed_seconds "$kill_start" "$kill_done")s detach=$(elapsed_seconds "$kill_done" "$detach_done")s takeover_open=$(elapsed_seconds "$detach_done" "$takeover_done")s reattach=$(elapsed_seconds "$takeover_done" "$attach_done")s first_io=$(elapsed_seconds "$attach_done" "$io_done")s total=${failover_seconds}s"
    echo "== failover window: ${failover_seconds}s (target <= ${MAX_FAILOVER_SECONDS}s)"
    assert_failover_target "$failover_seconds"

    echo "== verifying takeover writes and liveness"
    write_block "$NBD_BLOCK_SIZE" "after-failover" 1
    flush_device
    verify_block "$NBD_BLOCK_SIZE" "after-failover" 1
    assert_takeover_live

    echo "== clean detach and fsck"
    detach_nbd
    stop_daemon takeover
    run_offline_fsck
    echo "SLATEFS_NBD_FAILOVER_MANUAL_PASSED ${failover_seconds}s"
}

persist_reconnect_probe() {
    CURRENT_VOLUME="$VOLUME-persist"
    CURRENT_CONFIG="$PERSIST_CONFIG_PRIMARY"
    CURRENT_PRIMARY_ADMIN_PORT="$((PRIMARY_ADMIN_PORT + 10))"
    CURRENT_PRIMARY_METRICS_PORT="$((PRIMARY_METRICS_PORT + 10))"
    CURRENT_TAKEOVER_ADMIN_PORT="$((TAKEOVER_ADMIN_PORT + 10))"
    CURRENT_TAKEOVER_METRICS_PORT="$((TAKEOVER_METRICS_PORT + 10))"
    PRIMARY_LOG="$WORK/persist-primary.log"
    TAKEOVER_LOG="$WORK/persist-takeover.log"
    NBD_DEV=""
    ensure_block_volume
    start_primary
    select_free_nbd
    if ! attach_nbd on; then
        echo "SLATEFS_NBD_FAILOVER_PERSIST_SKIPPED attach-failed"
        [ "$PERSIST_REQUIRED" = "0" ] || exit 1
        stop_daemon primary
        return 0
    fi

    echo "== writing durable marker before persist probe"
    write_block 0 "persist-durable-before-failover" 1
    flush_device
    verify_block 0 "persist-durable-before-failover" 1

    echo "== kill -9 primary for persist probe"
    local kill_start kill_done takeover_done io_done status
    kill_start="$(now_ns)"
    kill -9 "$PRIMARY_PID"
    wait "$PRIMARY_PID" 2>/dev/null || true
    PRIMARY_PID=""
    kill_done="$(now_ns)"
    wait_port_closed "$PORT"
    CURRENT_CONFIG="$PERSIST_CONFIG_TAKEOVER"
    start_takeover
    takeover_done="$(now_ns)"

    set +e
    timeout "$MAX_FAILOVER_SECONDS" bash -c '
        while :; do
            if '"$SUDO"' dd if="'"$NBD_DEV"'" of="'"$READBACK"'" bs="'"$NBD_BLOCK_SIZE"'" count=1 iflag=direct status=none 2>/dev/null; then
                exit 0
            fi
            sleep 0.1
        done
    '
    status=$?
    set -e
    if [ "$status" -ne 0 ]; then
        echo "SLATEFS_NBD_FAILOVER_PERSIST_SKIPPED reconnect-timeout"
        [ "$PERSIST_REQUIRED" = "0" ] || exit 1
        detach_nbd
        stop_daemon takeover
        return 0
    fi
    verify_block 0 "persist-durable-before-failover" 1
    io_done="$(now_ns)"
    local failover_seconds
    failover_seconds="$(elapsed_seconds "$kill_start" "$io_done")"
    echo "== persist breakdown: kill_wait=$(elapsed_seconds "$kill_start" "$kill_done")s takeover_open=$(elapsed_seconds "$kill_done" "$takeover_done")s first_io=$(elapsed_seconds "$takeover_done" "$io_done")s total=${failover_seconds}s"
    assert_failover_target "$failover_seconds"
    detach_nbd
    stop_daemon takeover
    run_offline_fsck
    echo "SLATEFS_NBD_FAILOVER_PERSIST_PASSED ${failover_seconds}s"
}

ensure_binaries
install_missing_tools
prepare_configs
manual_failover_drill
if [ "$PERSIST_PROBE" != "0" ]; then
    persist_reconnect_probe
fi
echo "SLATEFS_NBD_FAILOVER_PASSED"
