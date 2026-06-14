#!/usr/bin/env bash
# Live snapshot drill over real kernel NFS.
#
# Runs inside the privileged container from docker-kernel-mount-test.sh. A
# live slatefsd writer serves a kernel NFS mount, the CLI creates a checkpoint
# through the daemon admin endpoint, then a second daemon serves that checkpoint
# as a read-only snapshot export while writes continue on the live mount.
set -euo pipefail

CONFIG="${SLATEFS_CONFIG:?set SLATEFS_CONFIG}"
TENANT="${SLATEFS_TENANT:-t1}"
VOLUME="${SLATEFS_VOLUME:-v1}"
LIVE_PORT="${LIVE_SNAPSHOT_PORT:-12056}"
ADMIN_PORT="${LIVE_SNAPSHOT_ADMIN_PORT:-13056}"
SNAPSHOT_PORT="${LIVE_SNAPSHOT_SNAPSHOT_PORT:-12057}"
METRICS_PORT="${LIVE_SNAPSHOT_METRICS_PORT:-13057}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"

if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="${SUDO:-sudo}"; fi

WORK="$(mktemp -d)"
LIVE_CONFIG="$WORK/live.toml"
SNAPSHOT_CONFIG="$WORK/snapshot.toml"
LIVE_LOG="$WORK/live.log"
SNAPSHOT_LOG="$WORK/snapshot.log"
LIVE_MNT="$WORK/mnt-live"
SNAPSHOT_MNT="$WORK/mnt-snapshot"
LIVE_PID=""
SNAPSHOT_PID=""
SNAPSHOT_ID=""

mkdir -p "$LIVE_MNT" "$SNAPSHOT_MNT"

cleanup() {
    set +e
    $SUDO umount -f "$LIVE_MNT" 2>/dev/null
    $SUDO umount -f "$SNAPSHOT_MNT" 2>/dev/null
    [ -n "${LIVE_PID:-}" ] && kill "$LIVE_PID" 2>/dev/null
    [ -n "${SNAPSHOT_PID:-}" ] && kill "$SNAPSHOT_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

base_config() {
    awk '
        /^\[\[exports\]\]/ { exit }
        /^\[metrics\]/ { skip = 1; next }
        /^\[admin\]/ { skip = 1; next }
        /^\[/ && skip { skip = 0 }
        !skip { print }
    ' "$CONFIG"
}

write_live_config() {
    base_config > "$LIVE_CONFIG"
    cat >> "$LIVE_CONFIG" <<EOF

[admin]
listen = "127.0.0.1:$ADMIN_PORT"

[[exports]]
tenant = "$TENANT"
volume = "$VOLUME"
listen = "127.0.0.1:$LIVE_PORT"
squash = "none"
EOF
}

write_snapshot_config() {
    base_config > "$SNAPSHOT_CONFIG"
    cat >> "$SNAPSHOT_CONFIG" <<EOF

[metrics]
listen = "127.0.0.1:$METRICS_PORT"

[[exports]]
tenant = "$TENANT"
volume = "$VOLUME"
snapshot = "$SNAPSHOT_ID"
listen = "127.0.0.1:$SNAPSHOT_PORT"
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

write_live_config

echo "== starting live slatefsd on $LIVE_PORT with admin $ADMIN_PORT"
"$BIN/slatefsd" -c "$LIVE_CONFIG" >>"$LIVE_LOG" 2>&1 &
LIVE_PID=$!
wait_port "$LIVE_PORT" "$LIVE_LOG"
wait_port "$ADMIN_PORT" "$LIVE_LOG"

echo "== mounting live export"
$SUDO mount -t nfs \
    -o "vers=3,tcp,nolock,soft,timeo=20,retrans=3,port=$LIVE_PORT,mountport=$LIVE_PORT" \
    127.0.0.1:/ "$LIVE_MNT"

echo "== writing baseline over live mount"
write_file "$LIVE_MNT/live.txt" "baseline"
run sync "$LIVE_MNT/live.txt"

echo "== creating live snapshot through CLI/admin endpoint"
SNAPSHOT_ID="$("$BIN/slatefs" -c "$LIVE_CONFIG" snapshot create --live "$TENANT" "$VOLUME" --name "kernel live snapshot" | awk 'NR == 1 { print $1 }')"
[ -n "$SNAPSHOT_ID" ] || {
    echo "snapshot id was empty"
    exit 1
}
echo "snapshot id: $SNAPSHOT_ID"

echo "== mutating live mount after snapshot"
write_file "$LIVE_MNT/live.txt" "latest"
write_file "$LIVE_MNT/live-only.txt" "live-only"
run sync "$LIVE_MNT/live.txt"
run sync "$LIVE_MNT/live-only.txt"

write_snapshot_config

echo "== starting snapshot slatefsd on $SNAPSHOT_PORT"
"$BIN/slatefsd" -c "$SNAPSHOT_CONFIG" >>"$SNAPSHOT_LOG" 2>&1 &
SNAPSHOT_PID=$!
wait_port "$SNAPSHOT_PORT" "$SNAPSHOT_LOG"

echo "== mounting snapshot export"
$SUDO mount -t nfs \
    -o "vers=3,tcp,nolock,soft,timeo=20,retrans=3,port=$SNAPSHOT_PORT,mountport=$SNAPSHOT_PORT" \
    127.0.0.1:/ "$SNAPSHOT_MNT"

echo "== verifying snapshot is point-in-time and read-only"
run cmp <(printf "baseline\n") "$SNAPSHOT_MNT/live.txt"
run test ! -e "$SNAPSHOT_MNT/live-only.txt"
set +e
write_file "$SNAPSHOT_MNT/should-fail.txt" "should-fail"
WRITE_STATUS=$?
set -e
[ "$WRITE_STATUS" -ne 0 ] || {
    echo "snapshot export unexpectedly accepted a write"
    exit 1
}

echo "== verifying live export kept moving"
run cmp <(printf "latest\n") "$LIVE_MNT/live.txt"
run cmp <(printf "live-only\n") "$LIVE_MNT/live-only.txt"

echo "== verifying snapshot metrics"
wait_port "$METRICS_PORT" "$SNAPSHOT_LOG"
scrape_metrics "$METRICS_PORT" |
    grep -q "slatefs_block_decode_failures_total{tenant=\"$TENANT\",volume=\"$VOLUME\",snapshot=\"$SNAPSHOT_ID\"} 0" || {
        echo "snapshot metrics did not include decode-failure counter"
        scrape_metrics "$METRICS_PORT" || true
        exit 1
    }

echo "== unmount"
$SUDO umount "$SNAPSHOT_MNT"
$SUDO umount "$LIVE_MNT"
echo "live snapshot over NFS PASSED"
