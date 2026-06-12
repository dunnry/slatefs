#!/usr/bin/env bash
# Kernel NFS client smoke test against slatefsd (plan §14 Phase 2).
#
# Runs on Linux (CI: ubuntu runner with passwordless sudo). Mounts the
# export with the kernel NFS client and exercises real file I/O.
#
# Mount discipline (learned the hard way): ALWAYS soft+timeo so a server
# bug yields EIO instead of an unkillable D-state wedge, and bound every
# command that touches the mountpoint with `timeout`.
#
# Required env: SLATEFS_CONFIG pointing at a config whose [[exports]]
# serves tenant t1 / volume v1 on 127.0.0.1:12049.
set -euo pipefail

CONFIG="${SLATEFS_CONFIG:?set SLATEFS_CONFIG}"
PORT="${SLATEFS_NFS_PORT:-12049}"
MNT="$(mktemp -d)"
BIN="${CARGO_TARGET_DIR:-target}/debug"

cleanup() {
    sudo umount -f "$MNT" 2>/dev/null || true
    kill "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "== starting slatefsd"
"$BIN/slatefsd" -c "$CONFIG" &
DAEMON_PID=$!
for _ in $(seq 1 50); do
    nc -z 127.0.0.1 "$PORT" 2>/dev/null && break
    sleep 0.2
done
nc -z 127.0.0.1 "$PORT" || { echo "daemon never opened port $PORT"; exit 1; }

echo "== kernel mount"
sudo mount -t nfs \
    -o "vers=3,tcp,nolock,soft,timeo=20,retrans=3,port=$PORT,mountport=$PORT" \
    127.0.0.1:/ "$MNT"
trap 'sudo umount -f "$MNT" 2>/dev/null || true; kill $DAEMON_PID 2>/dev/null || true' EXIT

run() { timeout 30 "$@"; }

echo "== exercise"
run ls -la "$MNT"

# Write/read round-trip, including a multi-chunk file.
echo "hello kernel nfs" | run sudo tee "$MNT/hello.txt" >/dev/null
run cmp <(echo "hello kernel nfs") "$MNT/hello.txt"
run sudo dd if=/dev/urandom of=/tmp/payload bs=64K count=64 status=none
run sudo cp /tmp/payload "$MNT/payload.bin"
run sync
run cmp /tmp/payload "$MNT/payload.bin"

# Directory ops + rename + readdir.
run sudo mkdir "$MNT/dir"
run sudo mv "$MNT/hello.txt" "$MNT/dir/renamed.txt"
run cmp <(echo "hello kernel nfs") "$MNT/dir/renamed.txt"
for i in $(seq 1 50); do
    run sudo touch "$MNT/dir/f$i"
done
count=$(run ls "$MNT/dir" | wc -l)
[ "$count" -eq 51 ] || { echo "readdir count mismatch: $count != 51"; exit 1; }

# Symlink + remove + truncate.
run sudo ln -s dir/renamed.txt "$MNT/link"
[ "$(run readlink "$MNT/link")" = "dir/renamed.txt" ]
run sudo truncate -s 100 "$MNT/payload.bin"
[ "$(run stat -c %s "$MNT/payload.bin")" -eq 100 ]
run sudo rm "$MNT/link" "$MNT/payload.bin"
run sudo rm -r "$MNT/dir"

# Server restart mid-mount: handles must survive (plan §5/§13).
echo "== restart server under live mount"
echo "before restart" | run sudo tee "$MNT/survivor.txt" >/dev/null
run sync
kill "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
"$BIN/slatefsd" -c "$CONFIG" &
DAEMON_PID=$!
for _ in $(seq 1 50); do
    nc -z 127.0.0.1 "$PORT" 2>/dev/null && break
    sleep 0.2
done
run cmp <(echo "before restart") "$MNT/survivor.txt"
run sudo rm "$MNT/survivor.txt"

echo "== unmount"
sudo umount "$MNT"
echo "kernel mount test PASSED"
