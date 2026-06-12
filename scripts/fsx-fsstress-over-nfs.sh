#!/usr/bin/env bash
# fsx + fsstress + restart-under-load over a kernel NFS mount of slatefsd
# (plan §14 Phase 2 AC: "fsx 10M ops clean; fsstress 1h clean; restart
# server mid-workload → clients recover, no acknowledged-fsync data lost").
#
# Runs inside the privileged container from docker-kernel-mount-test.sh.
# Scale knobs (defaults are a quick local pass; nightly CI raises them):
#   FSX_OPS       fsx operations            (default 50000; AC 10M)
#   FSSTRESS_OPS  fsstress ops per process  (default 2000)
#   FSSTRESS_PROCS  parallel fsstress procs (default 4)
#   RESTARTS      server restarts under load (default 3; 0 disables)
set -euo pipefail

CONFIG="${SLATEFS_CONFIG:?set SLATEFS_CONFIG}"
PORT="${SLATEFS_NFS_PORT:-12049}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"
MNT="$(mktemp -d)"
FSX_OPS="${FSX_OPS:-50000}"
FSSTRESS_OPS="${FSSTRESS_OPS:-2000}"
FSSTRESS_PROCS="${FSSTRESS_PROCS:-4}"
RESTARTS="${RESTARTS:-3}"

echo "== building fsx + fsstress (xfstests)"
apt-get install -y -qq git autoconf automake gcc make libtool pkg-config \
    libacl1-dev libattr1-dev libaio-dev uuid-dev xfslibs-dev >/dev/null
if [ ! -x /tmp/xfstests/ltp/fsx ]; then
    rm -rf /tmp/xfstests
    git clone -q --depth 1 https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git /tmp/xfstests
    (cd /tmp/xfstests && make -j"$(nproc)" >/dev/null 2>&1) || true
fi
[ -x /tmp/xfstests/ltp/fsx ] || { echo "fsx failed to build"; exit 1; }
[ -x /tmp/xfstests/ltp/fsstress ] || { echo "fsstress failed to build"; exit 1; }
FSX=/tmp/xfstests/ltp/fsx
FSSTRESS=/tmp/xfstests/ltp/fsstress

start_daemon() {
    "$BIN/slatefsd" -c "$CONFIG" >>/tmp/slatefsd.log 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 50); do port_open && return 0; sleep 0.2; done
    echo "daemon never opened port $PORT"
    return 1
}
port_open() { timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; }
cleanup() {
    umount -f "$MNT" 2>/dev/null || true
    kill "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "== starting slatefsd + kernel mount"
start_daemon
# hard mount: the restart drill needs in-flight ops to retry across the
# server gap rather than EIO. Safe here — worst case kill the container.
mount -t nfs -o "vers=3,tcp,nolock,hard,timeo=20,retrans=10,port=$PORT,mountport=$PORT" \
    127.0.0.1:/ "$MNT"

echo "== fsx: $FSX_OPS ops"
# NFSv3 has no fallocate-family support; fsx probes most but pin the flags
# for determinism: -W/-R keep mmap I/O on (page cache exercises commit).
time "$FSX" -q -S 1 -N "$FSX_OPS" "$MNT/fsx-file" || { echo "FSX FAILED"; exit 1; }

echo "== fsstress: $FSSTRESS_PROCS procs x $FSSTRESS_OPS ops"
mkdir -p "$MNT/stress"
"$FSSTRESS" -d "$MNT/stress" -n "$FSSTRESS_OPS" -p "$FSSTRESS_PROCS" -S t -s 42 \
    -f resvsp=0 -f unresvsp=0 -f fallocate=0 -f punch=0 -f zero=0 \
    -f collapse=0 -f insert=0 -f clonerange=0 -f deduperange=0 \
    -f copyrange=0 -f exchangerange=0 -f setxattr=0 -f attr_set=0 \
    -f attr_remove=0 -f getfattr=0 -f listfattr=0 -f removefattr=0 -f setfattr=0 \
    >/dev/null || { echo "FSSTRESS FAILED"; exit 1; }
rm -rf "$MNT/stress"

if [ "$RESTARTS" -gt 0 ]; then
    echo "== restart drill: fsx under $RESTARTS server restarts"
    # Acked-fsync durability marker before each restart; fsx keeps running
    # through the gaps (hard mount + per-instance writeverf -> client
    # retransmits uncommitted writes).
    "$FSX" -q -S 7 -N "$((FSX_OPS * 2))" "$MNT/fsx-restart" &
    FSX_PID=$!
    for i in $(seq 1 "$RESTARTS"); do
        sleep 5
        echo "durable-$i" > "$MNT/marker-$i"
        sync "$MNT/marker-$i"
        kill "$DAEMON_PID"
        wait "$DAEMON_PID" 2>/dev/null || true
        sleep 1
        start_daemon
        cmp <(echo "durable-$i") "$MNT/marker-$i" || { echo "MARKER $i LOST"; kill $FSX_PID; exit 1; }
    done
    if ! wait "$FSX_PID"; then
        echo "FSX FAILED under restarts"
        exit 1
    fi
fi

echo "== unmount"
umount "$MNT"
echo "fsx/fsstress/restart drill PASSED"
