#!/usr/bin/env bash
# pjdfstest over a kernel NFS mount of slatefsd (plan §14 Phase 2 AC).
# Designed to run inside the privileged Linux container set up by
# scripts/docker-kernel-mount-test.sh (root, nfs-common present,
# SLATEFS_CONFIG exported, binaries in $CARGO_TARGET_DIR/debug).
#
# The export must use squash = "none": pjdfstest switches uids to test
# permission semantics, which requires honoring AUTH_UNIX identities.
set -euo pipefail

CONFIG="${SLATEFS_CONFIG:?set SLATEFS_CONFIG}"
PORT="${SLATEFS_NFS_PORT:-12049}"
BIN="${CARGO_TARGET_DIR:-target}/${BIN_OVERRIDE:-debug}"
MNT="$(mktemp -d)"
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
"$BIN/slatefsd" -c "$CONFIG" &
DAEMON_PID=$!
cleanup() {
    umount -f "$MNT" 2>/dev/null || true
    kill "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT
port_open() { timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; }
for _ in $(seq 1 50); do port_open && break; sleep 0.2; done
port_open || { echo "daemon never opened port $PORT"; exit 1; }

echo "== kernel mount"
mount -t nfs \
    -o "vers=3,tcp,nolock,soft,timeo=50,retrans=5,port=$PORT,mountport=$PORT" \
    127.0.0.1:/ "$MNT"

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
timeout "$PJD_TIMEOUT" prove $PJD_PROVE_ARGS "${targets[@]}" 2>&1 | tee /tmp/pjdfstest-results.txt | tail -40
status=$?
set -e
cd /
echo "== prove exit: $status"
echo "== failure summary"
grep -E '^/tmp/pjdfstest/tests.*\(Wstat' /tmp/pjdfstest-results.txt | head -40 || echo "(no failing test files)"
echo "== failing assertions (verbose runs)"
grep -E '^not ok' /tmp/pjdfstest-results.txt | head -60 || echo "(none captured)"
exit "$status"
