#!/usr/bin/env bash
# DD-1 overhead harness: open many SlateFS volumes in one daemon, drive a hot
# subset through real kernel NFS mounts, and report daemon RSS plus object-store
# related Prometheus metric deltas.
#
# Defaults match the Phase 6 DD-1 target: 100 idle volumes and 20 hot volumes.
# Lower MULTI_IDLE_VOLUMES/MULTI_HOT_VOLUMES/MULTI_OPS_PER_VOLUME for a quick
# local smoke.
set -euo pipefail

CONFIG="${SLATEFS_CONFIG:?set SLATEFS_CONFIG}"
TENANT="${MULTI_TENANT:-dd1}"
IDLE_VOLUMES="${MULTI_IDLE_VOLUMES:-100}"
HOT_VOLUMES="${MULTI_HOT_VOLUMES:-20}"
PORT_BASE="${MULTI_PORT_BASE:-12100}"
METRICS_PORT="${MULTI_METRICS_PORT:-13100}"
OPS_PER_VOLUME="${MULTI_OPS_PER_VOLUME:-25}"
FILE_KIB="${MULTI_FILE_KIB:-64}"
SETTLE_SECONDS="${MULTI_SETTLE_SECONDS:-2}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"

if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="${SUDO:-sudo}"; fi

WORK="$(mktemp -d)"
BASE_CONFIG="$WORK/base.toml"
BASELINE_CONFIG="$WORK/baseline.toml"
FULL_CONFIG="$WORK/full.toml"
BASELINE_LOG="$WORK/baseline.log"
FULL_LOG="$WORK/full.log"
METRICS_BEFORE="$WORK/metrics-before.prom"
METRICS_AFTER="$WORK/metrics-after.prom"
METRICS_TSV="$WORK/metrics-delta.tsv"
REPORT="${MULTI_REPORT:-$WORK/multi-volume-overhead.md}"
DAEMON_PID=""
MOUNTS=()

cleanup() {
    set +e
    for mountpoint in "${MOUNTS[@]}"; do
        $SUDO umount -f "$mountpoint" 2>/dev/null
    done
    if [ -n "${DAEMON_PID:-}" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

base_config() {
    awk '
        /^\[\[exports\]\]/ { exit }
        /^\[metrics\]/ { skip = 1; next }
        /^\[/ && skip { skip = 0 }
        !skip { print }
    ' "$CONFIG"
}

volume_name() {
    local kind="$1"
    local index="$2"
    printf "%s%03d" "$kind" "$index"
}

port_for_hot() {
    local index="$1"
    echo $((PORT_BASE + index - 1))
}

port_open() {
    timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null
}

wait_port() {
    local port="$1"
    local log="$2"
    for _ in $(seq 1 100); do
        port_open "$port" && return 0
        sleep 0.2
    done
    echo "port $port never opened"
    tail -120 "$log" || true
    return 1
}

run() {
    timeout 180 "$@"
}

rss_kib() {
    awk '/VmRSS:/ { print $2; found = 1 } END { if (!found) print 0 }' "/proc/$DAEMON_PID/status"
}

scrape_metrics() {
    local port="$1"
    local output="$2"
    {
        printf 'GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3
        cat <&3
    } 3<>"/dev/tcp/127.0.0.1/$port" |
        awk 'body { print } /^\r?$/ { body = 1 }' > "$output"
}

start_daemon() {
    local config="$1"
    local log="$2"
    local ready_port="$3"
    "$BIN/slatefsd" -c "$config" >>"$log" 2>&1 &
    DAEMON_PID=$!
    wait_port "$ready_port" "$log"
    sleep "$SETTLE_SECONDS"
}

stop_daemon() {
    if [ -n "${DAEMON_PID:-}" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null || true
        DAEMON_PID=""
    fi
}

emit_export() {
    local volume="$1"
    local port="$2"
    cat <<EOF

[[exports]]
tenant = "$TENANT"
volume = "$volume"
listen = "127.0.0.1:$port"
squash = "none"
EOF
}

write_full_config() {
    cp "$BASE_CONFIG" "$FULL_CONFIG"
    cat >> "$FULL_CONFIG" <<EOF

[metrics]
listen = "127.0.0.1:$METRICS_PORT"
EOF
    for i in $(seq 1 "$HOT_VOLUMES"); do
        emit_export "$(volume_name hot "$i")" "$(port_for_hot "$i")" >> "$FULL_CONFIG"
    done
    for i in $(seq 1 "$IDLE_VOLUMES"); do
        emit_export "$(volume_name idle "$i")" "$((PORT_BASE + HOT_VOLUMES + i - 1))" >> "$FULL_CONFIG"
    done
}

ensure_control_state() {
    "$BIN/slatefs" -c "$BASE_CONFIG" tenant create "$TENANT" >/dev/null 2>&1 || true
    for i in $(seq 1 "$HOT_VOLUMES"); do
        local volume
        volume="$(volume_name hot "$i")"
        if ! "$BIN/slatefs" -c "$BASE_CONFIG" volume info "$TENANT" "$volume" >/dev/null 2>&1; then
            "$BIN/slatefs" -c "$BASE_CONFIG" volume create "$TENANT" "$volume" >/dev/null
        fi
    done
    for i in $(seq 1 "$IDLE_VOLUMES"); do
        local volume
        volume="$(volume_name idle "$i")"
        if ! "$BIN/slatefs" -c "$BASE_CONFIG" volume info "$TENANT" "$volume" >/dev/null 2>&1; then
            "$BIN/slatefs" -c "$BASE_CONFIG" volume create "$TENANT" "$volume" >/dev/null
        fi
    done
}

mount_hot_volumes() {
    for i in $(seq 1 "$HOT_VOLUMES"); do
        local port mountpoint
        port="$(port_for_hot "$i")"
        mountpoint="$WORK/mnt-hot-$i"
        mkdir -p "$mountpoint"
        $SUDO mount -t nfs \
            -o "vers=3,tcp,nolock,soft,timeo=20,retrans=3,port=$port,mountport=$port" \
            127.0.0.1:/ "$mountpoint"
        MOUNTS+=("$mountpoint")
    done
}

drive_hot_volume() {
    local mountpoint="$1"
    local index="$2"
    local payload="$WORK/payload-$index.bin"
    local dir="$mountpoint/hot"
    dd if=/dev/urandom of="$payload" bs=1024 count="$FILE_KIB" status=none
    run $SUDO mkdir -p "$dir"
    for op in $(seq 1 "$OPS_PER_VOLUME"); do
        run $SUDO cp "$payload" "$dir/file-$op.bin"
        run $SUDO stat "$dir/file-$op.bin" >/dev/null
    done
    run sync "$dir"
}

run_hot_workload() {
    local pids=()
    for i in $(seq 1 "$HOT_VOLUMES"); do
        drive_hot_volume "$WORK/mnt-hot-$i" "$i" &
        pids+=("$!")
    done
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
}

metrics_delta_table() {
    awk -v before="$METRICS_BEFORE" -v after="$METRICS_AFTER" -v secs="$1" '
        function load(file, arr,    line, value, key) {
            while ((getline line < file) > 0) {
                if (line == "" || line ~ /^#/) {
                    continue
                }
                value = line
                sub(/^.* /, "", value)
                key = line
                sub(/[[:space:]][^[:space:]]+$/, "", key)
                arr[key] = value + 0
            }
            close(file)
        }
        BEGIN {
            load(before, b)
            load(after, a)
            for (key in a) {
                delta = a[key] - b[key]
                if (delta == 0) {
                    continue
                }
                if (key !~ /object_store|cache|request|get|put|list|head|write|read/) {
                    continue
                }
                printf "%s\t%.3f\t%.3f\n", key, delta, delta / secs
            }
        }
    ' | sort > "$METRICS_TSV"
}

render_report() {
    local baseline_rss="$1"
    local idle_rss="$2"
    local hot_rss="$3"
    local workload_seconds="$4"
    local total_volumes="$((IDLE_VOLUMES + HOT_VOLUMES))"
    local extra_volumes="$((total_volumes - 1))"
    {
        echo "# SlateFS Multi-Volume Overhead Report"
        echo
        echo "- idle volumes: $IDLE_VOLUMES"
        echo "- hot volumes: $HOT_VOLUMES"
        echo "- operations per hot volume: $OPS_PER_VOLUME writes + $OPS_PER_VOLUME stats"
        echo "- payload per write: ${FILE_KIB} KiB"
        echo "- workload seconds: $workload_seconds"
        echo
        echo "| sample | open volumes | daemon RSS MiB | delta vs baseline MiB | approx KiB/additional volume |"
        echo "|---|---:|---:|---:|---:|"
        awk -v base="$baseline_rss" -v idle="$idle_rss" -v hot="$hot_rss" -v total="$total_volumes" -v extra="$extra_volumes" '
            BEGIN {
                printf "| baseline | 1 | %.1f | 0.0 | 0.0 |\n", base / 1024
                delta = idle - base
                per = extra > 0 ? delta / extra : 0
                printf "| all exports idle | %d | %.1f | %.1f | %.1f |\n", total, idle / 1024, delta / 1024, per
                delta = hot - base
                per = extra > 0 ? delta / extra : 0
                printf "| after hot workload | %d | %.1f | %.1f | %.1f |\n", total, hot / 1024, delta / 1024, per
            }
        '
        echo
        echo "## Object-Store And Cache Metric Deltas"
        echo
        if [ -s "$METRICS_TSV" ]; then
            echo "| metric | delta | per second |"
            echo "|---|---:|---:|"
            awk -F '\t' '{ printf "| `%s` | %.3f | %.3f |\n", $1, $2, $3 }' "$METRICS_TSV"
        else
            echo "No object-store/cache-related metric deltas were emitted by this run."
        fi
    } | tee "$REPORT"
}

if [ "$HOT_VOLUMES" -lt 1 ]; then
    echo "MULTI_HOT_VOLUMES must be >= 1" >&2
    exit 1
fi
if [ "$IDLE_VOLUMES" -lt 0 ]; then
    echo "MULTI_IDLE_VOLUMES must be >= 0" >&2
    exit 1
fi

base_config > "$BASE_CONFIG"
ensure_control_state

first_hot="$(volume_name hot 1)"
cp "$BASE_CONFIG" "$BASELINE_CONFIG"
emit_export "$first_hot" "$PORT_BASE" >> "$BASELINE_CONFIG"
write_full_config

echo "== baseline daemon with one open volume"
start_daemon "$BASELINE_CONFIG" "$BASELINE_LOG" "$PORT_BASE"
baseline_rss="$(rss_kib)"
stop_daemon

echo "== full daemon with $IDLE_VOLUMES idle and $HOT_VOLUMES hot exports"
start_daemon "$FULL_CONFIG" "$FULL_LOG" "$PORT_BASE"
idle_rss="$(rss_kib)"
wait_port "$METRICS_PORT" "$FULL_LOG"
for i in $(seq 1 "$HOT_VOLUMES"); do
    wait_port "$(port_for_hot "$i")" "$FULL_LOG"
done

echo "== mounting $HOT_VOLUMES hot exports"
mount_hot_volumes
scrape_metrics "$METRICS_PORT" "$METRICS_BEFORE"

echo "== driving hot workload"
start_ns="$(date +%s%N)"
run_hot_workload
end_ns="$(date +%s%N)"
workload_seconds="$(awk -v start="$start_ns" -v end="$end_ns" 'BEGIN { printf "%.3f", (end - start) / 1000000000 }')"
hot_rss="$(rss_kib)"
scrape_metrics "$METRICS_PORT" "$METRICS_AFTER"
metrics_delta_table "$workload_seconds"

render_report "$baseline_rss" "$idle_rss" "$hot_rss" "$workload_seconds"
echo "multi-volume overhead drill PASSED"
