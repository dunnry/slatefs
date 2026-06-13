#!/usr/bin/env bash
# pjdfstest over a kernel v9fs (9P2000.L) mount of slatefsd (plan §14
# Phase 4 AC). Designed to run inside the privileged Linux container set
# up by scripts/docker-kernel-mount-test.sh (root, SLATEFS_CONFIG exported
# with a p9 export on 127.0.0.1:12050, binaries in $CARGO_TARGET_DIR).
#
# access=user makes v9fs re-attach per uid, so pjdfstest's uid switches
# carry real credentials — the 9P analogue of AUTH_UNIX + squash=none.
set -euo pipefail

CONFIG="${SLATEFS_CONFIG:?set SLATEFS_CONFIG}"
PORT="${SLATEFS_P9_PORT:-12050}"
TOKEN="${SLATEFS_P9_TOKEN:-sekrit}"
ANAME="${SLATEFS_P9_ANAME:-/t1/v1}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"
MNT="$(mktemp -d)"
RESULTS=/tmp/pjdfstest-9p-results.txt
# Cap the whole prove run; partial results still print a summary.
PJD_TIMEOUT="${PJD_TIMEOUT:-3600}"

echo "== building pjdfstest"
apt-get install -y -qq git autoconf automake gcc make libtool pkg-config perl >/dev/null
if [ ! -x /tmp/pjdfstest/pjdfstest ]; then
    rm -rf /tmp/pjdfstest
    git clone -q --depth 1 https://github.com/pjd/pjdfstest /tmp/pjdfstest
    (cd /tmp/pjdfstest && autoreconf -ifs >/dev/null 2>&1 && ./configure >/dev/null && make >/dev/null)
fi

echo "== starting slatefsd"
RUST_LOG=info "$BIN/slatefsd" -c "$CONFIG" >>/tmp/slatefsd-9p-pjd.log 2>&1 &
DAEMON_PID=$!
cleanup() {
    status=$?
    umount -f "$MNT" 2>/dev/null || true
    kill "$DAEMON_PID" 2>/dev/null || true
    if [ "$status" -ne 0 ] && [ ! -s "$RESULTS" ]; then
        echo "== daemon log tail (exit $status)"
        tail -40 /tmp/slatefsd-9p-pjd.log | sed 's/\x1b\[[0-9;]*m//g'
    fi
}
trap cleanup EXIT
port_open() { timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; }
for _ in $(seq 1 50); do port_open && break; sleep 0.2; done
port_open || { echo "daemon never opened port $PORT"; exit 1; }

echo "== kernel v9fs mount"
mount -t 9p \
    -o "trans=tcp,port=$PORT,version=9p2000.L,msize=1048576,uname=$TOKEN,aname=$ANAME,access=user" \
    127.0.0.1 "$MNT"

# PJD_TESTS: space-separated test paths relative to the pjdfstest tests dir
# (default: everything). PJD_PROVE_ARGS: extra prove flags (e.g. -v).
PJD_TESTS="${PJD_TESTS:-}"
PJD_PROVE_ARGS="${PJD_PROVE_ARGS:--rQ}"
targets=()
if [ -n "$PJD_TESTS" ]; then
    for t in $PJD_TESTS; do targets+=("/tmp/pjdfstest/tests/$t"); done
else
    targets=(/tmp/pjdfstest/tests)
fi

echo "== running pjdfstest (timeout ${PJD_TIMEOUT}s)"
cd "$MNT"
set +e
# shellcheck disable=SC2086
timeout "$PJD_TIMEOUT" prove $PJD_PROVE_ARGS "${targets[@]}" 2>&1 | tee "$RESULTS" | tail -40
status=$?
set -e
cd /
echo "== prove exit: $status"
echo "== failure summary"
grep -E '^/tmp/pjdfstest/tests.*\(Wstat' "$RESULTS" | head -40 || echo "(no failing test files)"
echo "== failing assertions (verbose runs)"
grep -E '^not ok' "$RESULTS" | head -60 || echo "(none captured)"
exit "$status"
