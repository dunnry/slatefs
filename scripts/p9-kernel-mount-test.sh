#!/usr/bin/env bash
# Kernel v9fs client smoke test against slatefsd's 9P export (plan §14
# Phase 4). Runs inside the privileged container (root, SLATEFS_CONFIG
# exported with a p9 export on 127.0.0.1:12050, binaries built).
set -euo pipefail

CONFIG="${SLATEFS_CONFIG:?set SLATEFS_CONFIG}"
PORT="${SLATEFS_P9_PORT:-12050}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"
MNT="$(mktemp -d)"

echo "== starting slatefsd"
RUST_LOG=info,rs9p=debug,slatefs_9p=debug "$BIN/slatefsd" -c "$CONFIG" >>/tmp/slatefsd-9p.log 2>&1 &
DAEMON_PID=$!
cleanup() {
    status=$?
    umount -f "$MNT" 2>/dev/null || true
    kill "$DAEMON_PID" 2>/dev/null || true
    if [ "$status" -ne 0 ]; then
        echo "== daemon log tail (exit $status)"
        tail -40 /tmp/slatefsd-9p.log | sed 's/\x1b\[[0-9;]*m//g'
    fi
}
trap cleanup EXIT
port_open() { timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; }
for _ in $(seq 1 50); do port_open && break; sleep 0.2; done
port_open || { echo "daemon never opened port $PORT"; cat /tmp/slatefsd-9p.log; exit 1; }

echo "== kernel v9fs mount"
mount -t 9p -o "trans=tcp,port=$PORT,version=9p2000.L,msize=1048576,uname=sekrit,aname=/t1/v1,access=user" \
    127.0.0.1 "$MNT"

run() { timeout 30 "$@"; }

echo "== exercise"
run ls -la "$MNT"
echo "hello 9p kernel" > "$MNT/hello.txt"
run cmp <(echo "hello 9p kernel") "$MNT/hello.txt"
run dd if=/dev/urandom of=/tmp/p9payload bs=64K count=32 status=none
run cp /tmp/p9payload "$MNT/payload.bin"
run sync
run cmp /tmp/p9payload "$MNT/payload.bin"

run mkdir "$MNT/dir"
run mv "$MNT/hello.txt" "$MNT/dir/renamed.txt"
run cmp <(echo "hello 9p kernel") "$MNT/dir/renamed.txt"
for i in $(seq 1 30); do run touch "$MNT/dir/f$i"; done
count=$(run ls "$MNT/dir" | wc -l)
[ "$count" -eq 31 ] || { echo "readdir count mismatch: $count != 31"; exit 1; }

run ln -s dir/renamed.txt "$MNT/link"
[ "$(run readlink "$MNT/link")" = "dir/renamed.txt" ]
run ln "$MNT/dir/renamed.txt" "$MNT/hard"
[ "$(run stat -c %h "$MNT/hard")" = "2" ]
run truncate -s 100 "$MNT/payload.bin"
[ "$(run stat -c %s "$MNT/payload.bin")" -eq 100 ]

# xattrs over 9P2000.L
run setfattr -n user.color -v blue "$MNT/hard" 2>/dev/null || echo "(setfattr unavailable; skipping xattr check)"
if command -v getfattr >/dev/null; then
    [ "$(run getfattr --only-values -n user.color "$MNT/hard")" = "blue" ]
fi

run rm "$MNT/link" "$MNT/hard" "$MNT/payload.bin"
run rm -r "$MNT/dir"
run df "$MNT" >/dev/null

echo "== unmount"
umount "$MNT"
echo "9p kernel mount test PASSED"
