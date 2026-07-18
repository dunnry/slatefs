#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DEMO_ROOT="$ROOT"
# shellcheck source=scripts/web-demo-package-manager.sh
source "$ROOT/scripts/web-demo-package-manager.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
WORKSPACE="$TMP/repository with spaces/web"
mkdir -p "$WORKSPACE"
ORIGINAL_PATH="$PATH"

fail() { printf 'test-web-demo-package-manager: %s\n' "$*" >&2; exit 1; }
assert_log() {
  local expected="$1"
  [[ "$(<"$TMP/invocations")" == "$expected" ]] || \
    fail "expected invocation '$expected', got '$(<"$TMP/invocations")'"
}

# A global pnpm is preferred and receives arguments without word splitting.
mkdir "$TMP/global"
# These single-quoted lines are the literal shim script body.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/bash' 'printf '\''pnpm cwd=%s args='\'' "$PWD" >"$TEST_LOG"' \
  'printf '\''<%s>'\'' "$@" >>"$TEST_LOG"' >"$TMP/global/pnpm"
chmod +x "$TMP/global/pnpm"
TEST_LOG="$TMP/invocations" PATH="$TMP/global" resolve_pnpm "$WORKSPACE" pnpm@11.7.0
TEST_LOG="$TMP/invocations" PATH="$TMP/global" run_pnpm --filter '@scope/name with spaces' build
assert_log "pnpm cwd=$WORKSPACE args=<--filter><@scope/name with spaces><build>"

# With no pnpm, Corepack is called directly and resolves the declared version.
mkdir "$TMP/corepack"
# These single-quoted lines are the literal shim script body.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/bash' \
  'if [[ "$*" == "pnpm --version" ]]; then printf '\''11.7.0\n'\''; exit 0; fi' \
  'printf '\''corepack cwd=%s args='\'' "$PWD" >"$TEST_LOG"' \
  'printf '\''<%s>'\'' "$@" >>"$TEST_LOG"' >"$TMP/corepack/corepack"
chmod +x "$TMP/corepack/corepack"
TEST_LOG="$TMP/invocations" PATH="$TMP/corepack" resolve_pnpm "$WORKSPACE" pnpm@11.7.0
TEST_LOG="$TMP/invocations" PATH="$TMP/corepack" run_pnpm --filter '@scope/name with spaces' build
assert_log "corepack cwd=$WORKSPACE args=<pnpm><--filter><@scope/name with spaces><build>"

# No provider fails with both exact supported remediation paths.
mkdir "$TMP/empty"
if PATH="$TMP/empty" resolve_pnpm "$WORKSPACE" pnpm@11.7.0 2>"$TMP/error"; then
  fail "resolution unexpectedly succeeded without pnpm or Corepack"
fi
grep -F 'npm install --global pnpm@11.7.0' "$TMP/error" >/dev/null || fail "missing direct-install help"
grep -F 'corepack prepare pnpm@11.7.0 --activate' "$TMP/error" >/dev/null || fail "missing Corepack help"

PATH="$ORIGINAL_PATH"

# The launcher must refresh the browser bundle (including workspace
# dependencies) before compiling the BFF that serves it.
demo_build_line="$(grep -nF "run_pnpm --filter '@slatefs/demo...' build" "$ROOT/scripts/web-demo.sh" | cut -d: -f1)"
server_build_line="$(grep -nF 'run_pnpm --filter @slatefs/demo-server build' "$ROOT/scripts/web-demo.sh" | cut -d: -f1)"
[[ -n "$demo_build_line" && -n "$server_build_line" && "$demo_build_line" -lt "$server_build_line" ]] || \
  fail "web-demo must build the demo and dependencies before the BFF"

printf 'web-demo package-manager resolution tests passed\n'
