#!/usr/bin/env bash
# Boot a tiny QEMU guest and mount slatefsd's 9P2000.L TCP export from inside
# the VM. This covers the VM/client path for SlateFS's actual 9P transport.
#
# Run through the Docker harness for reproducible Linux tooling:
#   SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/qemu-p9-tcp-smoke.sh
set -euo pipefail

CONFIG="${SLATEFS_CONFIG:?set SLATEFS_CONFIG}"
PORT="${SLATEFS_P9_PORT:-12050}"
TOKEN="${SLATEFS_P9_TOKEN:-sekrit}"
ANAME="${SLATEFS_P9_ANAME:-/t1/v1}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"
HOST_ARCH="$(uname -m)"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-180}"
QEMU_INSTALL_DEPS="${QEMU_INSTALL_DEPS:-1}"

case "$HOST_ARCH" in
    x86_64|amd64)
        DEFAULT_QEMU_BIN="qemu-system-x86_64"
        QEMU_PACKAGE="qemu-system-x86"
        KERNEL_PACKAGE="linux-image-amd64"
        DEFAULT_NET_MODULES="e1000"
        ;;
    aarch64|arm64)
        DEFAULT_QEMU_BIN="qemu-system-aarch64"
        QEMU_PACKAGE="qemu-system-arm"
        KERNEL_PACKAGE="linux-image-arm64"
        DEFAULT_NET_MODULES="virtio_mmio virtio_net"
        ;;
    *)
        echo "unsupported QEMU smoke host architecture: $HOST_ARCH" >&2
        exit 1
        ;;
esac

QEMU_BIN="${QEMU_BIN:-$DEFAULT_QEMU_BIN}"
QEMU_NET_MODULES="${QEMU_NET_MODULES:-$DEFAULT_NET_MODULES}"

WORK="$(mktemp -d)"
INITRD_ROOT="$WORK/initrd"
INITRD_IMG="$WORK/initramfs.cpio.gz"
DAEMON_LOG="$WORK/slatefsd-9p.log"
QEMU_LOG="$WORK/qemu.log"
DAEMON_PID=""

cleanup() {
    set +e
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

install_deps() {
    [ "$QEMU_INSTALL_DEPS" = "1" ] || return 0
    if command -v apt-get >/dev/null 2>&1; then
        if ! command -v "$QEMU_BIN" >/dev/null 2>&1 || ! ls /boot/vmlinuz-* >/dev/null 2>&1; then
            apt-get update -qq >/dev/null
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                "$QEMU_PACKAGE" "$KERNEL_PACKAGE" busybox-static cpio kmod xz-utils zstd \
                >/dev/null
        fi
    fi
}

find_kernel() {
    if [ -n "${QEMU_KERNEL:-}" ]; then
        echo "$QEMU_KERNEL"
        return
    fi
    ls -1 /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1
}

kernel_version() {
    local kernel="$1"
    basename "$kernel" | sed 's/^vmlinuz-//'
}

busybox_path() {
    if [ -n "${BUSYBOX:-}" ]; then
        echo "$BUSYBOX"
    elif [ -x /bin/busybox ]; then
        echo /bin/busybox
    else
        command -v busybox
    fi
}

decompress_module() {
    local src="$1"
    local out="$2"
    case "$src" in
        *.ko) cp "$src" "$out" ;;
        *.ko.xz) xz -dc "$src" > "$out" ;;
        *.ko.zst) zstd -dc "$src" > "$out" ;;
        *.ko.gz) gzip -dc "$src" > "$out" ;;
        *) echo "unsupported kernel module compression: $src" >&2; return 1 ;;
    esac
}

copy_module_deps() {
    local kver="$1"
    local module="$2"
    local dep
    if command -v modprobe >/dev/null 2>&1; then
        modprobe --set-version "$kver" --show-depends "$module" 2>/dev/null |
            awk '/^insmod / { print $2 }'
    else
        find "/lib/modules/$kver" -name "$module.ko*" 2>/dev/null
    fi |
        while read -r dep; do
            [ -n "$dep" ] || continue
            local base out
            base="$(basename "$dep")"
            base="${base%.xz}"
            base="${base%.zst}"
            base="${base%.gz}"
            out="$INITRD_ROOT/modules/$base"
            if [ ! -f "$out" ]; then
                decompress_module "$dep" "$out"
                echo "$base" >> "$INITRD_ROOT/modules.load"
            fi
        done
}

write_initramfs() {
    local kernel="$1"
    local kver="$2"
    local busybox="$3"

    mkdir -p "$INITRD_ROOT"/{bin,dev,mnt,modules,proc,sys,tmp}
    cp "$busybox" "$INITRD_ROOT/bin/busybox"
    for applet in sh mount umount mkdir rmdir cat echo touch rm ls wc sync dd cmp stat poweroff sleep ip udhcpc insmod; do
        ln -sf busybox "$INITRD_ROOT/bin/$applet"
    done
    : > "$INITRD_ROOT/modules.load"

    for module in $QEMU_NET_MODULES; do
        copy_module_deps "$kver" "$module"
    done
    copy_module_deps "$kver" 9pnet_fd
    copy_module_deps "$kver" 9p

    cat > "$INITRD_ROOT/expected.txt" <<'EOF'
hello from qemu guest
EOF
    cat > "$INITRD_ROOT/init" <<EOF
#!/bin/sh
set -eu
export PATH=/bin

fail() {
    echo "QEMU 9P TCP SMOKE FAILED: \$*"
    poweroff -f || exit 1
}

mount -t proc proc /proc || true
mount -t sysfs sysfs /sys || true
mount -t devtmpfs devtmpfs /dev || true

if [ -s /modules.load ]; then
    while read module; do
        [ -n "\$module" ] || continue
        insmod "/modules/\$module" 2>/dev/null || true
    done < /modules.load
fi

ip link set lo up || true
ip link set eth0 up || fail "eth0 did not appear"
udhcpc -i eth0 -q -n -t 5 2>/dev/null || true
ip addr flush dev eth0 2>/dev/null || true
ip addr add 10.0.2.15/24 dev eth0 || fail "failed to configure eth0"
ip route add default via 10.0.2.2 dev eth0 2>/dev/null || true
ip addr show dev eth0
ip route show

mkdir -p /mnt
mount -t 9p -o "trans=tcp,port=$PORT,version=9p2000.L,msize=1048576,uname=$TOKEN,aname=$ANAME,access=user" \
    10.0.2.2 /mnt || fail "mount failed"

cat /expected.txt > /mnt/qemu-guest.txt
sync
cmp /expected.txt /mnt/qemu-guest.txt || fail "file roundtrip mismatch"
mkdir /mnt/qemu-dir
touch /mnt/qemu-dir/a /mnt/qemu-dir/b
test "\$(ls /mnt/qemu-dir | wc -l)" = "2" || fail "readdir mismatch"
rm /mnt/qemu-dir/a /mnt/qemu-dir/b
rmdir /mnt/qemu-dir
rm /mnt/qemu-guest.txt
umount /mnt || fail "umount failed"

echo "QEMU 9P TCP SMOKE PASSED"
poweroff -f || exit 0
EOF
    chmod +x "$INITRD_ROOT/init"

    (
        cd "$INITRD_ROOT"
        find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "$INITRD_IMG"
    )
}

port_open() {
    timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null
}

install_deps
KERNEL="$(find_kernel)"
[ -n "$KERNEL" ] && [ -f "$KERNEL" ] || {
    echo "no QEMU kernel found; set QEMU_KERNEL or run with QEMU_INSTALL_DEPS=1 on Debian/Ubuntu"
    exit 1
}
KVER="$(kernel_version "$KERNEL")"
BUSYBOX_PATH="$(busybox_path)"
[ -x "$BUSYBOX_PATH" ] || { echo "busybox not found; install busybox-static or set BUSYBOX"; exit 1; }
write_initramfs "$KERNEL" "$KVER" "$BUSYBOX_PATH"

echo "== starting slatefsd 9P export on $PORT"
RUST_LOG=info "$BIN/slatefsd" -c "$CONFIG" >>"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 75); do port_open && break; sleep 0.2; done
port_open || { echo "daemon never opened port $PORT"; cat "$DAEMON_LOG"; exit 1; }

echo "== booting QEMU guest for 9P TCP smoke"
set +e
QEMU_STATUS=0
if [ "$HOST_ARCH" = "x86_64" ] || [ "$HOST_ARCH" = "amd64" ]; then
    timeout "$QEMU_TIMEOUT" "$QEMU_BIN" \
        -m 256M \
        -nodefaults \
        -no-reboot \
        -nographic \
        -serial mon:stdio \
        -kernel "$KERNEL" \
        -initrd "$INITRD_IMG" \
        -append "console=ttyS0 panic=1 init=/init" \
        -netdev user,id=net0 \
        -device e1000,netdev=net0 \
        2>&1 | tee "$QEMU_LOG"
    QEMU_STATUS=${PIPESTATUS[0]}
else
    timeout "$QEMU_TIMEOUT" "$QEMU_BIN" \
        -M virt \
        -cpu max \
        -m 512M \
        -no-reboot \
        -nographic \
        -serial mon:stdio \
        -kernel "$KERNEL" \
        -initrd "$INITRD_IMG" \
        -append "console=ttyAMA0 panic=1 init=/init" \
        -netdev user,id=net0 \
        -device virtio-net-device,netdev=net0 \
        2>&1 | tee "$QEMU_LOG"
    QEMU_STATUS=${PIPESTATUS[0]}
fi
set -e

if [ "$QEMU_STATUS" -ne 0 ]; then
    echo "QEMU exited with status $QEMU_STATUS"
    exit "$QEMU_STATUS"
fi
grep -q "QEMU 9P TCP SMOKE PASSED" "$QEMU_LOG" || {
    echo "guest did not report success"
    exit 1
}
echo "qemu 9p tcp smoke PASSED"
