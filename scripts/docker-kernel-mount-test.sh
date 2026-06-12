#!/usr/bin/env bash
# Run the kernel NFS mount test inside a privileged Linux container — a real
# kernel NFS client without needing a Linux host or root on the host (the
# mount lives in the Docker VM; a hang can't wedge the host, just kill the
# container).
#
# Usage: scripts/docker-kernel-mount-test.sh [extra-script]
#   extra-script: optional path (relative to repo root) run inside the
#                 container after the smoke test, with the same env.
set -euo pipefail

cd "$(dirname "$0")/.."
EXTRA="${1:-}"

# Separate target dir for the Linux build; named volumes cache the registry
# and build artifacts across runs.
docker volume create slatefs-cargo-registry >/dev/null
docker volume create slatefs-target-linux >/dev/null

docker run --rm --privileged \
    -e PJD_TESTS -e PJD_PROVE_ARGS -e PJD_TIMEOUT -e SKIP_SMOKE \
    -e FSX_OPS -e FSSTRESS_OPS -e FSSTRESS_PROCS -e RESTARTS \
    -v "$PWD":/src:ro \
    -v slatefs-cargo-registry:/usr/local/cargo/registry \
    -v slatefs-target-linux:/target \
    -e CARGO_TARGET_DIR=/target \
    -w /src \
    rust:1 bash -ceu '
        # Snapshot the harness scripts: /src is a live bind mount and a host
        # edit mid-run would corrupt a script bash is still reading.
        cp -r /src/scripts /tmp/scripts
        apt-get update -qq >/dev/null && apt-get install -y -qq nfs-common >/dev/null
        cargo build -q -p slatefs-daemon -p slatefs-cli

        STORE=$(mktemp -d)
        cat > /tmp/slatefs.toml <<EOF
[object_store]
url = "file://$STORE"
[kms]
provider = "static"
key_hex = "0000000000000000000000000000000000000000000000000000000000000001"
[[exports]]
tenant = "t1"
volume = "v1"
listen = "127.0.0.1:12049"
squash = "none"
EOF
        /target/debug/slatefs -c /tmp/slatefs.toml tenant create t1
        /target/debug/slatefs -c /tmp/slatefs.toml volume create t1 v1

        export SLATEFS_CONFIG=/tmp/slatefs.toml
        [ -n "${SKIP_SMOKE:-}" ] || /tmp/scripts/nfs-kernel-mount-test.sh
        '"${EXTRA:+/tmp/$EXTRA}"'
    '
