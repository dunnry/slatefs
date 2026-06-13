#!/usr/bin/env bash
# fio performance sweep over a real kernel NFS mount of slatefsd.
#
# Runs inside the privileged container from docker-kernel-mount-test.sh. The
# defaults are a quick local smoke; raise FIO_RUNTIME/FIO_SIZE/FIO_JOBS in CI or
# on a bench host for stable numbers.
set -euo pipefail

CONFIG="${SLATEFS_CONFIG:?set SLATEFS_CONFIG}"
TENANT="${SLATEFS_TENANT:-t1}"
VOLUME="${SLATEFS_VOLUME:-v1}"
PORT="${PERF_NFS_PORT:-12054}"
METRICS_PORT="${PERF_METRICS_PORT:-13054}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"
FIO_RUNTIME="${FIO_RUNTIME:-10}"
FIO_SIZE="${FIO_SIZE:-64m}"
FIO_JOBS="${FIO_JOBS:-1}"
FIO_BS_LIST="${FIO_BS_LIST:-4k 128k 1m}"
FIO_RW_LIST="${FIO_RW_LIST:-read write randread randwrite}"
META_OPS="${META_OPS:-500}"

if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="${SUDO:-sudo}"; fi

WORK="$(mktemp -d)"
PERF_CONFIG="$WORK/perf.toml"
LOG="$WORK/slatefsd.log"
MNT="$WORK/mnt"
BENCH_DIR="$MNT/fio"
RESULTS_TSV="$WORK/fio-results.tsv"
REPORT="${PERF_REPORT:-$WORK/fio-report.md}"
DAEMON_PID=""

mkdir -p "$MNT"

cleanup() {
    set +e
    $SUDO umount -f "$MNT" 2>/dev/null
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
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

base_config > "$PERF_CONFIG"
cat >> "$PERF_CONFIG" <<EOF

[metrics]
listen = "127.0.0.1:$METRICS_PORT"

[[exports]]
tenant = "$TENANT"
volume = "$VOLUME"
listen = "127.0.0.1:$PORT"
squash = "none"
EOF

port_open() {
    timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null
}

wait_port() {
    for _ in $(seq 1 75); do
        port_open "$1" && return 0
        sleep 0.2
    done
    echo "port $1 never opened"
    tail -100 "$LOG" || true
    return 1
}

run() {
    timeout 120 "$@"
}

ensure_tools() {
    if ! command -v /usr/bin/fio >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        $SUDO apt-get update -qq >/dev/null
        $SUDO apt-get install -y -qq fio jq >/dev/null
    fi
}

fio_bin() {
    if [ -x /usr/bin/fio ]; then
        echo /usr/bin/fio
    else
        command -v fio
    fi
}

metric_kind() {
    case "$1" in
        read|randread) echo read ;;
        write|randwrite) echo write ;;
        *) echo "unknown fio rw mode: $1" >&2; exit 1 ;;
    esac
}

emit_result() {
    local rw="$1"
    local bs="$2"
    local json="$3"
    local op
    op="$(metric_kind "$rw")"
    jq -r --arg rw "$rw" --arg bs "$bs" --arg op "$op" '
        .jobs[0][$op] as $m |
        [
            $rw,
            $bs,
            ($m.iops // 0),
            (($m.bw_bytes // 0) / 1048576),
            (($m.clat_ns.mean // 0) / 1000000),
            (($m.clat_ns.percentile["99.000000"] // 0) / 1000000)
        ] | @tsv
    ' "$json" >> "$RESULTS_TSV"
}

render_report() {
    {
        echo "# SlateFS NFS fio Report"
        echo
        echo "- runtime: ${FIO_RUNTIME}s"
        echo "- size per job: $FIO_SIZE"
        echo "- jobs: $FIO_JOBS"
        echo "- mount: kernel NFSv3, soft,timeo=20,retrans=3"
        echo
        echo "| workload | block | IOPS | MiB/s | mean ms | p99 ms |"
        echo "|---|---:|---:|---:|---:|---:|"
        awk -F '\t' '{
            printf "| %s | %s | %.0f | %.1f | %.3f | %.3f |\n", $1, $2, $3, $4, $5, $6
        }' "$RESULTS_TSV"
        echo
        echo "## Metadata Smoke"
        echo
        cat "$WORK/meta-report.txt"
    } | tee "$REPORT"
}

ensure_tools
FIO="$(fio_bin)"

echo "== starting slatefsd on $PORT"
"$BIN/slatefsd" -c "$PERF_CONFIG" >>"$LOG" 2>&1 &
DAEMON_PID=$!
wait_port "$PORT"

echo "== mounting NFS export"
$SUDO mount -t nfs \
    -o "vers=3,tcp,nolock,soft,timeo=20,retrans=3,port=$PORT,mountport=$PORT" \
    127.0.0.1:/ "$MNT"
run $SUDO mkdir -p "$BENCH_DIR"

: > "$RESULTS_TSV"

for bs in $FIO_BS_LIST; do
    prep="$BENCH_DIR/prep-$bs.dat"
    echo "== prefill $bs read source"
    run "$FIO" \
        --name="prep-$bs" \
        --filename="$prep" \
        --rw=write \
        --bs="$bs" \
        --size="$FIO_SIZE" \
        --ioengine=sync \
        --numjobs=1 \
        --fallocate=none \
        --end_fsync=1 \
        --output=/dev/null

    for rw in $FIO_RW_LIST; do
        json="$WORK/$rw-$bs.json"
        if [ "$(metric_kind "$rw")" = "read" ]; then
            file="$prep"
        else
            file="$BENCH_DIR/$rw-$bs.dat"
        fi
        echo "== fio $rw bs=$bs runtime=${FIO_RUNTIME}s size=$FIO_SIZE jobs=$FIO_JOBS"
        run "$FIO" \
            --name="$rw-$bs" \
            --filename="$file" \
            --rw="$rw" \
            --bs="$bs" \
            --size="$FIO_SIZE" \
            --runtime="$FIO_RUNTIME" \
            --time_based=1 \
            --ioengine=sync \
            --numjobs="$FIO_JOBS" \
            --group_reporting=1 \
            --fallocate=none \
            --end_fsync=1 \
            --output-format=json \
            --output="$json"
        emit_result "$rw" "$bs" "$json"
    done
done

echo "== metadata create/stat/unlink smoke: $META_OPS files"
meta_dir="$BENCH_DIR/meta"
run $SUDO mkdir -p "$meta_dir"
start_ns="$(date +%s%N)"
for i in $(seq 1 "$META_OPS"); do
    run $SUDO touch "$meta_dir/f$i"
done
for i in $(seq 1 "$META_OPS"); do
    run $SUDO stat "$meta_dir/f$i" >/dev/null
done
for i in $(seq 1 "$META_OPS"); do
    run $SUDO rm "$meta_dir/f$i"
done
end_ns="$(date +%s%N)"
awk -v ops="$((META_OPS * 3))" -v start="$start_ns" -v end="$end_ns" '
    BEGIN {
        secs = (end - start) / 1000000000;
        printf "- create/stat/unlink ops: %d\n", ops;
        printf "- elapsed seconds: %.3f\n", secs;
        printf "- metadata ops/s: %.1f\n", ops / secs;
    }
' > "$WORK/meta-report.txt"

render_report

echo "== unmount"
$SUDO umount "$MNT"
echo "fio-over-nfs PASSED; report written to $REPORT"
