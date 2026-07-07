#!/usr/bin/env bash
# Kernel NBD client integration test against slatefsd's block export.
#
# This needs root on a Linux kernel with nbd.ko available in the host/VM
# kernel. In Docker, the container uses the Docker host/VM kernel; Docker
# Desktop's LinuxKit VM may not ship nbd.ko. That is reported as:
#   SLATEFS_NBD_KERNEL_TEST_SKIPPED no-nbd.ko ...
# and exits 0 so local Docker smoke can distinguish SKIP from PASS. CI on
# Ubuntu treats that marker as a failure because nbd.ko is expected there.
#
# Optional base env:
#   SLATEFS_CONFIG          base config to copy object_store/kms/slatedb from
#   SLATEFS_NBD_TENANT      tenant name (default: SLATEFS_TENANT or t1)
#   SLATEFS_NBD_VOLUME      block volume name (default: b1)
#   SLATEFS_NBD_SIZE_BYTES  virtual size (default: 536870912, 512 MiB)
#   SLATEFS_NBD_CHUNK_SIZE  block volume chunk size (default: 4096)
#   SLATEFS_NBD_PORT        NBD listen port (default: 12059)
#   SLATEFS_NBD_ADMIN_PORT  admin listen port for allocated_bytes (default: 13059)
#   SLATEFS_NBD_TRIM_MIB    file size for TRIM proof in MiB (default: 32)
#   FSSTRESS_*              if set, build/run a small fsstress pass
#   FIO_*                   if set, use fio for the crash-drill load
# shellcheck disable=SC2086
set -euo pipefail

export PATH="/usr/sbin:/sbin:$PATH"

if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="${SUDO:-sudo}"; fi

TENANT="${SLATEFS_NBD_TENANT:-${SLATEFS_TENANT:-t1}}"
VOLUME="${SLATEFS_NBD_VOLUME:-b1}"
SIZE_BYTES="${SLATEFS_NBD_SIZE_BYTES:-536870912}"
CHUNK_SIZE="${SLATEFS_NBD_CHUNK_SIZE:-4096}"
PORT="${SLATEFS_NBD_PORT:-12059}"
ADMIN_PORT="${SLATEFS_NBD_ADMIN_PORT:-13059}"
NBD_CLIENT_TIMEOUT="${SLATEFS_NBD_CLIENT_TIMEOUT:-60}"
TRIM_MIB="${SLATEFS_NBD_TRIM_MIB:-32}"
CRASH_WARMUP="${SLATEFS_NBD_CRASH_WARMUP:-2}"
OP_TIMEOUT="${SLATEFS_NBD_OP_TIMEOUT:-60}"
LONG_TIMEOUT="${SLATEFS_NBD_LONG_TIMEOUT:-180}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"
CLI="$BIN/slatefs"
DAEMON="$BIN/slatefsd"
EXPORT_NAME="/$TENANT/$VOLUME"

WORK="$(mktemp -d)"
BASE_CONFIG="${SLATEFS_CONFIG:-}"
CONFIG="$WORK/nbd.toml"
LOG="$WORK/slatefsd.log"
MNT="$WORK/mnt"
PAYLOAD="$WORK/payload.bin"
NBD_DEV=""
DAEMON_PID=""
LOAD_PID=""
NBD_ATTACHED=0

mkdir -p "$MNT"

cleanup_mount_lazy() {
    if findmnt -rn "$MNT" >/dev/null 2>&1; then
        timeout 20 $SUDO umount "$MNT" 2>/dev/null ||
            timeout 20 $SUDO umount -f "$MNT" 2>/dev/null ||
            timeout 20 $SUDO umount -l "$MNT" 2>/dev/null ||
            true
    fi
}

detach_nbd() {
    if [ "$NBD_ATTACHED" -eq 1 ] && [ -n "$NBD_DEV" ]; then
        timeout 20 $SUDO nbd-client -d "$NBD_DEV" >/dev/null 2>&1 || true
    fi
    NBD_ATTACHED=0
}

stop_load() {
    if [ -n "${LOAD_PID:-}" ]; then
        if command -v pkill >/dev/null 2>&1; then
            pkill -TERM -P "$LOAD_PID" 2>/dev/null || true
        fi
        kill "$LOAD_PID" 2>/dev/null || true
        for _ in $(seq 1 25); do
            kill -0 "$LOAD_PID" 2>/dev/null || break
            sleep 0.2
        done
        if command -v pkill >/dev/null 2>&1; then
            pkill -KILL -P "$LOAD_PID" 2>/dev/null || true
        fi
        kill -9 "$LOAD_PID" 2>/dev/null || true
        wait "$LOAD_PID" 2>/dev/null || true
        LOAD_PID=""
    fi
}

cleanup() {
    local status=$?
    set +e
    stop_load
    cleanup_mount_lazy
    detach_nbd
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

skip_no_nbd() {
    echo "SLATEFS_NBD_KERNEL_TEST_SKIPPED no-nbd.ko: $*"
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
    for cmd in timeout nbd-client modprobe mkfs.ext4 e2fsck blockdev fstrim findmnt jq curl sha256sum pkill; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        return 0
    fi
    command -v apt-get >/dev/null 2>&1 || {
        echo "missing tools: ${missing[*]}; install nbd-client kmod e2fsprogs util-linux jq coreutils"
        exit 1
    }
    echo "== installing NBD/ext4 test tools: ${missing[*]}"
    $SUDO apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq \
        nbd-client kmod e2fsprogs util-linux jq curl coreutils procps >/dev/null
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

write_nbd_config() {
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
        grep -q "^chunk_size:[[:space:]]*$CHUNK_SIZE$" <<<"$info" || {
            echo "existing block volume $TENANT/$VOLUME does not match chunk_size=$CHUNK_SIZE"
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

    if ! command -v modprobe >/dev/null 2>&1; then
        skip_no_nbd "modprobe is unavailable"
    fi
    if ! $SUDO modprobe nbd max_part=8 nbds_max="${SLATEFS_NBD_DEVICES:-16}" >/dev/null 2>&1; then
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

nbd_client_help() {
    nbd-client -h 2>&1 || true
}

nbd_client_supports_c() {
    nbd_client_help | grep -Eq -- '(^|[[:space:],])-C([[:space:],]|$)'
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
    if nbd_client_supports_c; then
        if $SUDO nbd-client "${common_args[@]}" -C 2 >/tmp/nbd-client-attach.log 2>&1; then
            NBD_ATTACHED=1
            wait_device_size
            echo "attached with nbd-client -C 2"
            return 0
        fi
        echo "nbd-client -C 2 attach failed; retrying single connection"
        cat /tmp/nbd-client-attach.log || true
        timeout 20 $SUDO nbd-client -d "$NBD_DEV" >/dev/null 2>&1 || true
    fi
    if $SUDO nbd-client "${common_args[@]}" >/tmp/nbd-client-attach.log 2>&1; then
        NBD_ATTACHED=1
        wait_device_size
        echo "attached with single NBD connection"
        return 0
    fi
    echo "nbd-client attach with -persist off failed; retrying without -persist off"
    cat /tmp/nbd-client-attach.log || true
    local fallback_args=(127.0.0.1 "$PORT" "$NBD_DEV" -N "$EXPORT_NAME" -timeout "$NBD_CLIENT_TIMEOUT")
    $SUDO nbd-client "${fallback_args[@]}" >/tmp/nbd-client-attach.log 2>&1 || {
        cat /tmp/nbd-client-attach.log || true
        return 1
    }
    NBD_ATTACHED=1
    wait_device_size
}

mount_ext4() {
    echo "== mounting ext4 on $NBD_DEV"
    run $SUDO mount -t ext4 -o noatime "$NBD_DEV" "$MNT"
}

unmount_ext4_strict() {
    if findmnt -rn "$MNT" >/dev/null 2>&1; then
        timeout 30 $SUDO umount "$MNT" ||
            { sleep 1; timeout 30 $SUDO umount "$MNT"; } ||
            timeout 30 $SUDO umount -f "$MNT"
    fi
}

unmount_ext4_after_crash() {
    if ! findmnt -rn "$MNT" >/dev/null 2>&1; then
        return 0
    fi
    for _ in $(seq 1 30); do
        timeout 5 $SUDO umount "$MNT" && return 0
        sleep 1
    done
    timeout 10 $SUDO umount -f "$MNT" && return 0
    echo "regular crash unmount stayed busy; using lazy unmount"
    timeout 10 $SUDO umount -l "$MNT"
}

write_file() {
    local path="$1"
    local contents="$2"
    printf "%s\n" "$contents" | timeout "$OP_TIMEOUT" $SUDO tee "$path" >/dev/null
}

mounted_sha256() {
    local path="$1"
    timeout "$OP_TIMEOUT" $SUDO sha256sum "$path" | awk '{ print $1 }'
}

file_extents() {
    local path="$1"
    local block_size
    block_size="$(stat -fc '%S' "$MNT")"
    $SUDO filefrag -b"$block_size" -v "$path" | awk -v block_size="$block_size" '
        /^[[:space:]]*[0-9]+:/ {
            physical = $4
            ext_len = $6
            gsub(/:/, "", physical)
            gsub(/:/, "", ext_len)
            split(physical, p, /\.\./)
            if (p[1] ~ /^[0-9]+$/ && ext_len ~ /^[0-9]+$/) {
                print p[1] * block_size, ext_len * block_size
            }
        }
    '
}

admin_get_volume() {
    local path="/admin/v1/tenants/$TENANT/volumes/$VOLUME"
    curl -fsS --max-time 15 "http://127.0.0.1:$ADMIN_PORT$path"
}

allocated_bytes() {
    local body value
    body="$(admin_get_volume)"
    value="$(printf '%s\n' "$body" | jq -r '.volume.allocated_bytes // empty')"
    [[ "$value" =~ ^-?[0-9]+$ ]] || {
        echo "admin allocated_bytes was not numeric" >&2
        printf '%s\n' "$body" >&2
        return 1
    }
    printf '%s\n' "$value"
}

wait_allocated_drop() {
    local before="$1"
    local after err="$WORK/allocated-bytes.err"
    for _ in $(seq 1 40); do
        if after="$(allocated_bytes 2>"$err")"; then
            if [ "$after" -lt "$before" ]; then
                echo "$after"
                return 0
            fi
        else
            cat "$err" >&2 || true
        fi
        sleep 0.5
    done
    after="$(allocated_bytes 2>"$err")" || {
        cat "$err" >&2 || true
        after="unavailable"
    }
    echo "allocated_bytes did not drop after TRIM: before=$before after=$after"
    return 1
}

fsstress_requested() {
    [ -n "${FSSTRESS_OPS+x}" ] || [ -n "${FSSTRESS_PROCS+x}" ] || [ -n "${FSSTRESS_TIMEOUT+x}" ]
}

ensure_fsstress() {
    if [ -x /tmp/xfstests/ltp/fsstress ]; then
        return 0
    fi
    echo "== building fsstress (xfstests)"
    $SUDO apt-get update -qq >/dev/null
    $SUDO apt-get install -y -qq git autoconf automake gcc make libtool pkg-config \
        libacl1-dev libattr1-dev libaio-dev uuid-dev xfslibs-dev >/dev/null
    rm -rf /tmp/xfstests
    git clone -q --depth 1 https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git /tmp/xfstests
    (cd /tmp/xfstests && make -j"$(nproc)" >/dev/null 2>&1) || true
    [ -x /tmp/xfstests/ltp/fsstress ] || {
        echo "fsstress failed to build"
        exit 1
    }
}

directory_churn() {
    echo "== directory churn"
    if fsstress_requested; then
        ensure_fsstress
        local ops="${FSSTRESS_OPS:-200}"
        local procs="${FSSTRESS_PROCS:-2}"
        local fsstress_timeout="${FSSTRESS_TIMEOUT:-120}"
        run $SUDO mkdir -p "$MNT/fsstress"
        timeout "$fsstress_timeout" $SUDO /tmp/xfstests/ltp/fsstress \
            -d "$MNT/fsstress" -n "$ops" -p "$procs" -S t -s 42 >/dev/null
        run $SUDO rm -rf "$MNT/fsstress"
    else
        run $SUDO mkdir -p "$MNT/churn/a" "$MNT/churn/b"
        for i in $(seq 1 100); do
            write_file "$MNT/churn/a/f$i" "file-$i"
            run $SUDO mv "$MNT/churn/a/f$i" "$MNT/churn/b/g$i"
            run $SUDO ln "$MNT/churn/b/g$i" "$MNT/churn/a/h$i"
        done
        local count
        count="$(run $SUDO find "$MNT/churn" -type f | wc -l)"
        [ "$count" -eq 200 ] || { echo "directory churn count mismatch: $count != 200"; exit 1; }
        run $SUDO rm -rf "$MNT/churn"
    fi
}

exercise_filesystem() {
    echo "== mkfs.ext4"
    run_long $SUDO mkfs.ext4 -F "$NBD_DEV" >/dev/null
    mount_ext4

    echo "== write/read checksum round-trip"
    run dd if=/dev/urandom of="$PAYLOAD" bs=1M count=16 status=none
    local expected actual
    expected="$(sha256sum "$PAYLOAD" | awk '{ print $1 }')"
    run $SUDO cp "$PAYLOAD" "$MNT/payload.bin"
    write_file "$MNT/hello.txt" "hello kernel nbd"
    run sync
    actual="$(mounted_sha256 "$MNT/payload.bin")"
    [ "$actual" = "$expected" ] || {
        echo "payload checksum mismatch: $actual != $expected"
        exit 1
    }
    run cmp <(printf "hello kernel nbd\n") "$MNT/hello.txt"

    directory_churn

    echo "== unmount/remount verify"
    unmount_ext4_strict
    mount_ext4
    actual="$(mounted_sha256 "$MNT/payload.bin")"
    [ "$actual" = "$expected" ] || {
        echo "payload checksum mismatch after remount: $actual != $expected"
        exit 1
    }
    run cmp <(printf "hello kernel nbd\n") "$MNT/hello.txt"
}

trim_proof() {
    echo "== TRIM allocated_bytes proof"
    local trim_file="$MNT/trim-proof.bin"
    run_long $SUDO dd if=/dev/urandom of="$trim_file" bs=1M count="$TRIM_MIB" conv=fsync status=none
    run sync
    local extents=()
    mapfile -t extents < <(file_extents "$trim_file")
    [ "${#extents[@]}" -gt 0 ] || {
        echo "filefrag did not report extents for $trim_file"
        exit 1
    }
    local before after
    before="$(allocated_bytes)"
    echo "allocated_bytes before delete: $before"
    run $SUDO rm "$trim_file"
    run sync
    run_long $SUDO fstrim -v "$MNT"
    run sync
    if ! after="$(wait_allocated_drop "$before")"; then
        echo "$after"
        echo "SLATEFS_NBD_FSTRIM_NO_ALLOC_DROP fstrim did not release the deleted file extents; issuing blkdiscard fallback"
        unmount_ext4_strict
        local extent offset length
        for extent in "${extents[@]}"; do
            read -r offset length <<<"$extent"
            run $SUDO blkdiscard --force -o "$offset" -l "$length" "$NBD_DEV"
        done
        mount_ext4
        after="$(wait_allocated_drop "$before")"
        echo "allocated_bytes after blkdiscard fallback: $after"
        return 0
    fi
    echo "allocated_bytes after fstrim: $after"
}

fio_requested() {
    env | grep -q '^FIO_'
}

ensure_fio() {
    if command -v fio >/dev/null 2>&1; then
        return 0
    fi
    echo "== installing fio"
    $SUDO apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq fio >/dev/null
}

start_crash_load() {
    run $SUDO mkdir -p "$MNT/crash-load"
    if fio_requested; then
        ensure_fio
        local fio_runtime="${FIO_RUNTIME:-20}"
        local fio_size="${FIO_SIZE:-64m}"
        local fio_jobs="${FIO_JOBS:-1}"
        local fio_bs="${FIO_BS:-128k}"
        local fio_rw="${FIO_RW:-randwrite}"
        echo "== starting fio crash load rw=$fio_rw bs=$fio_bs size=$fio_size jobs=$fio_jobs"
        $SUDO fio \
            --name=nbd-crash-load \
            --filename="$MNT/crash-load/fio.dat" \
            --rw="$fio_rw" \
            --bs="$fio_bs" \
            --size="$fio_size" \
            --runtime="$fio_runtime" \
            --time_based=1 \
            --ioengine=sync \
            --numjobs="$fio_jobs" \
            --group_reporting=1 \
            --fallocate=none \
            --end_fsync=1 \
            --output="$WORK/fio-crash-load.log" \
            >/dev/null 2>&1 &
        LOAD_PID=$!
    else
        echo "== starting dd crash load"
        timeout "${SLATEFS_NBD_DD_LOAD_TIMEOUT:-300}" $SUDO dd \
            if=/dev/urandom \
            of="$MNT/crash-load/load.bin" \
            bs=1M \
            count="${SLATEFS_NBD_DD_LOAD_MIB:-128}" \
            conv=fsync \
            status=none &
        LOAD_PID=$!
    fi
}

crash_recovery_drill() {
    echo "== crash-recovery drill"
    write_file "$MNT/durable-before-crash.txt" "durable-before-crash"
    run sync "$MNT/durable-before-crash.txt"
    start_crash_load
    sleep "$CRASH_WARMUP"

    echo "== kill -9 slatefsd mid-load"
    kill -9 "$DAEMON_PID"
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=""
    stop_load

    echo "== unmount after daemon crash"
    unmount_ext4_after_crash
    detach_nbd

    start_daemon
    attach_nbd

    echo "== mount after restart for journal replay"
    mount_ext4
    run cmp <(printf "durable-before-crash\n") "$MNT/durable-before-crash.txt"
    unmount_ext4_strict

    echo "== e2fsck -f -p must be clean"
    set +e
    timeout 120 $SUDO e2fsck -f -p "$NBD_DEV" >/tmp/nbd-e2fsck.log 2>&1
    local fsck_status=$?
    set -e
    cat /tmp/nbd-e2fsck.log
    [ "$fsck_status" -eq 0 ] || {
        echo "e2fsck exited $fsck_status; expected 0 (repairs are failures in this drill)"
        exit 1
    }

    mount_ext4
    run cmp <(printf "durable-before-crash\n") "$MNT/durable-before-crash.txt"
}

ensure_binaries
install_missing_tools
write_nbd_config
ensure_block_volume
start_daemon
ensure_nbd_kernel
attach_nbd
exercise_filesystem
trim_proof
crash_recovery_drill

echo "== clean detach"
unmount_ext4_strict
detach_nbd
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
echo "SLATEFS_NBD_KERNEL_TEST_PASSED"
