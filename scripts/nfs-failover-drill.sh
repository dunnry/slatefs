#!/usr/bin/env bash
# NFS failover drill against two slatefsd instances sharing one object store.
#
# Runs inside the privileged container from docker-kernel-mount-test.sh. The
# first daemon owns the live volume, a kernel NFS client writes durable data,
# then a configurable client load runs while a second daemon opens the same
# volume on another port and fences the stale writer. The client remounts to
# the takeover daemon and verifies the durable marker, takeover time, live
# metrics, and read-only scrub.
set -euo pipefail

CONFIG="${SLATEFS_CONFIG:?set SLATEFS_CONFIG}"
TENANT="${SLATEFS_TENANT:-t1}"
VOLUME="${SLATEFS_VOLUME:-v1}"
PRIMARY_PORT="${FAILOVER_PRIMARY_PORT:-12052}"
TAKEOVER_PORT="${FAILOVER_TAKEOVER_PORT:-12053}"
PRIMARY_METRICS_PORT="${FAILOVER_PRIMARY_METRICS_PORT:-13052}"
TAKEOVER_METRICS_PORT="${FAILOVER_TAKEOVER_METRICS_PORT:-13053}"
LOAD_MODE="${FAILOVER_LOAD_MODE:-loop}"
LOAD_WARMUP="${FAILOVER_LOAD_WARMUP:-1}"
MAX_FAILOVER_SECONDS="${FAILOVER_MAX_SECONDS:-10}"
FIO_RUNTIME="${FAILOVER_FIO_RUNTIME:-30}"
FIO_SIZE="${FAILOVER_FIO_SIZE:-64m}"
FIO_JOBS="${FAILOVER_FIO_JOBS:-1}"
FIO_BS="${FAILOVER_FIO_BS:-128k}"
FIO_RW="${FAILOVER_FIO_RW:-randwrite}"
FSX_OPS="${FAILOVER_FSX_OPS:-0}"
FSX_SEED="${FAILOVER_FSX_SEED:-13}"
FSX_TIMEOUT="${FAILOVER_FSX_TIMEOUT:-120}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"

if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="${SUDO:-sudo}"; fi

WORK="$(mktemp -d)"
PRIMARY_CONFIG="$WORK/primary.toml"
TAKEOVER_CONFIG="$WORK/takeover.toml"
PRIMARY_LOG="$WORK/primary.log"
TAKEOVER_LOG="$WORK/takeover.log"
FIO_LOG="$WORK/fio-load.log"
PRIMARY_MNT="$WORK/mnt-primary"
TAKEOVER_MNT="$WORK/mnt-takeover"
PRIMARY_PID=""
TAKEOVER_PID=""
LOAD_PID=""

mkdir -p "$PRIMARY_MNT" "$TAKEOVER_MNT"

cleanup() {
    set +e
    [ -n "${LOAD_PID:-}" ] && kill "$LOAD_PID" 2>/dev/null
    [ -n "${LOAD_PID:-}" ] && wait "$LOAD_PID" 2>/dev/null
    $SUDO umount -f "$PRIMARY_MNT" 2>/dev/null
    $SUDO umount -f "$TAKEOVER_MNT" 2>/dev/null
    [ -n "${PRIMARY_PID:-}" ] && kill "$PRIMARY_PID" 2>/dev/null
    [ -n "${TAKEOVER_PID:-}" ] && kill "$TAKEOVER_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

base_config() {
    # Copy non-export config from the harness config. Drop any existing
    # metrics section so each generated daemon gets its own listener.
    awk '
        /^\[\[exports\]\]/ { exit }
        /^\[metrics\]/ { skip = 1; next }
        /^\[/ && skip { skip = 0 }
        !skip { print }
    ' "$CONFIG"
}

write_config() {
    local out="$1"
    local port="$2"
    local metrics_port="$3"
    base_config > "$out"
    cat >> "$out" <<EOF

[metrics]
listen = "127.0.0.1:$metrics_port"

[[exports]]
tenant = "$TENANT"
volume = "$VOLUME"
listen = "127.0.0.1:$port"
squash = "none"
EOF
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
    tail -100 "$log" || true
    return 1
}

wait_exit() {
    local pid="$1"
    local log="$2"
    for _ in $(seq 1 75); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        sleep 0.2
    done
    echo "process $pid did not exit after being fenced"
    tail -100 "$log" || true
    return 1
}

run() {
    timeout 30 "$@"
}

write_file() {
    local path="$1"
    local contents="$2"
    printf "%s\n" "$contents" | timeout 30 $SUDO tee "$path" >/dev/null
}

scrape_metrics() {
    local port="$1"
    timeout 5 bash -c "
        exec 3<>/dev/tcp/127.0.0.1/$port
        printf 'GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3
        cat <&3
    "
}

ensure_fio() {
    if [ -x /usr/bin/fio ]; then
        return 0
    fi
    $SUDO apt-get update -qq >/dev/null
    $SUDO apt-get install -y -qq fio >/dev/null
}

fio_bin() {
    if [ -x /usr/bin/fio ]; then
        echo /usr/bin/fio
    else
        command -v fio
    fi
}

ensure_fsx() {
    if [ -x /tmp/xfstests/ltp/fsx ]; then
        return 0
    fi
    echo "== building fsx verifier (xfstests)"
    $SUDO apt-get update -qq >/dev/null
    $SUDO apt-get install -y -qq git autoconf automake gcc make libtool pkg-config \
        libacl1-dev libattr1-dev libaio-dev uuid-dev xfslibs-dev >/dev/null
    rm -rf /tmp/xfstests
    git clone -q --depth 1 https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git /tmp/xfstests
    (cd /tmp/xfstests && make -j"$(nproc)" >/dev/null 2>&1) || true
    [ -x /tmp/xfstests/ltp/fsx ] || {
        echo "fsx failed to build"
        exit 1
    }
}

run_post_failover_fsx() {
    if [ "$FSX_OPS" -le 0 ]; then
        return 0
    fi
    ensure_fsx
    echo "== fsx post-failover verifier: $FSX_OPS ops"
    timeout "$FSX_TIMEOUT" $SUDO /tmp/xfstests/ltp/fsx \
        -q \
        -S "$FSX_SEED" \
        -N "$FSX_OPS" \
        "$TAKEOVER_MNT/fsx-post-failover" || {
            echo "FSX FAILED after failover"
            exit 1
        }
}

start_load() {
    case "$LOAD_MODE" in
        none)
            echo "== client load disabled"
            return 0
            ;;
        loop)
            echo "== starting small client write load"
            run $SUDO mkdir -p "$PRIMARY_MNT/live-load"
            (
                i=0
                while :; do
                    printf "load-%06d\n" "$i" |
                        timeout 5 $SUDO tee "$PRIMARY_MNT/live-load/$i.txt" >/dev/null ||
                        exit 0
                    i=$((i + 1))
                    sleep 0.05
                done
            ) &
            LOAD_PID=$!
            ;;
        fio)
            ensure_fio
            local fio
            fio="$(fio_bin)"
            echo "== starting fio client load: rw=$FIO_RW bs=$FIO_BS size=$FIO_SIZE jobs=$FIO_JOBS"
            run $SUDO mkdir -p "$PRIMARY_MNT/fio-load"
            $SUDO "$fio" \
                --name=failover-load \
                --directory="$PRIMARY_MNT/fio-load" \
                --filename=load.dat \
                --rw="$FIO_RW" \
                --bs="$FIO_BS" \
                --size="$FIO_SIZE" \
                --runtime="$FIO_RUNTIME" \
                --time_based=1 \
                --ioengine=sync \
                --numjobs="$FIO_JOBS" \
                --group_reporting=1 \
                --fallocate=none \
                --end_fsync=1 \
                --output="$FIO_LOG" \
                >/dev/null 2>&1 &
            LOAD_PID=$!
            ;;
        *)
            echo "unknown FAILOVER_LOAD_MODE=$LOAD_MODE (none|loop|fio)"
            exit 1
            ;;
    esac
    sleep "$LOAD_WARMUP"
}

stop_load() {
    if [ -n "${LOAD_PID:-}" ]; then
        kill "$LOAD_PID" 2>/dev/null || true
        wait "$LOAD_PID" 2>/dev/null || true
        LOAD_PID=""
    fi
}

signal_load_stop() {
    if [ -n "${LOAD_PID:-}" ]; then
        kill "$LOAD_PID" 2>/dev/null || true
    fi
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
        [ -s "$FIO_LOG" ] && tail -60 "$FIO_LOG" || true
        exit 1
    }
}

write_config "$PRIMARY_CONFIG" "$PRIMARY_PORT" "$PRIMARY_METRICS_PORT"
write_config "$TAKEOVER_CONFIG" "$TAKEOVER_PORT" "$TAKEOVER_METRICS_PORT"

echo "== starting primary slatefsd on $PRIMARY_PORT"
"$BIN/slatefsd" -c "$PRIMARY_CONFIG" >>"$PRIMARY_LOG" 2>&1 &
PRIMARY_PID=$!
wait_port "$PRIMARY_PORT" "$PRIMARY_LOG"

echo "== mounting primary export"
$SUDO mount -t nfs \
    -o "vers=3,tcp,nolock,soft,timeo=20,retrans=3,port=$PRIMARY_PORT,mountport=$PRIMARY_PORT" \
    127.0.0.1:/ "$PRIMARY_MNT"

echo "== writing durable marker on primary"
write_file "$PRIMARY_MNT/durable-before-failover.txt" "durable-before-failover"
run sync "$PRIMARY_MNT/durable-before-failover.txt"
start_load

echo "== starting takeover slatefsd on $TAKEOVER_PORT"
FAILOVER_START_NS="$(now_ns)"
"$BIN/slatefsd" -c "$TAKEOVER_CONFIG" >>"$TAKEOVER_LOG" 2>&1 &
TAKEOVER_PID=$!
wait_port "$TAKEOVER_PORT" "$TAKEOVER_LOG"

echo "== forcing stale writer to observe fencing"
set +e
write_file "$PRIMARY_MNT/stale-writer-should-fail.txt" "stale-writer"
STALE_STATUS=$?
set -e
[ "$STALE_STATUS" -ne 0 ] || {
    echo "stale writer unexpectedly accepted a write after takeover"
    exit 1
}

wait_exit "$PRIMARY_PID" "$PRIMARY_LOG"
signal_load_stop
grep -q "volume fenced; dropping daemon exports" "$PRIMARY_LOG" || {
    echo "primary daemon did not log the fencing transition"
    tail -100 "$PRIMARY_LOG" || true
    exit 1
}

echo "== remounting against takeover"
$SUDO umount -f "$PRIMARY_MNT" 2>/dev/null || true
$SUDO mount -t nfs \
    -o "vers=3,tcp,nolock,soft,timeo=20,retrans=3,port=$TAKEOVER_PORT,mountport=$TAKEOVER_PORT" \
    127.0.0.1:/ "$TAKEOVER_MNT"

echo "== verifying durable data and takeover writes"
run cmp <(printf "durable-before-failover\n") "$TAKEOVER_MNT/durable-before-failover.txt"
write_file "$TAKEOVER_MNT/after-failover.txt" "after-failover"
run sync "$TAKEOVER_MNT/after-failover.txt"
run cmp <(printf "after-failover\n") "$TAKEOVER_MNT/after-failover.txt"
FAILOVER_END_NS="$(now_ns)"
FAILOVER_SECONDS="$(elapsed_seconds "$FAILOVER_START_NS" "$FAILOVER_END_NS")"
echo "== failover window: ${FAILOVER_SECONDS}s (target <= ${MAX_FAILOVER_SECONDS}s)"
assert_failover_target "$FAILOVER_SECONDS"
stop_load

echo "== verifying takeover metrics and scrub"
wait_port "$TAKEOVER_METRICS_PORT" "$TAKEOVER_LOG"
scrape_metrics "$TAKEOVER_METRICS_PORT" |
    grep -q "slatefs_volume_dead{tenant=\"$TENANT\",volume=\"$VOLUME\"} 0" || {
        echo "takeover metrics did not report a live volume"
        scrape_metrics "$TAKEOVER_METRICS_PORT" || true
        exit 1
    }
"$BIN/slatefs" -c "$TAKEOVER_CONFIG" volume scrub "$TENANT" "$VOLUME"
run_post_failover_fsx

echo "== unmount"
$SUDO umount "$TAKEOVER_MNT"
TAKEOVER_MNT=""
echo "nfs failover drill PASSED"
