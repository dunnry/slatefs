#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf 'acme-token\n' >"$WORK/acme.token"
printf 'globex-token\n' >"$WORK/globex.token"

run_dry_run() {
  env SLATEFS_ACME_TOKEN_FILE="$WORK/acme.token" \
    SLATEFS_GLOBEX_TOKEN_FILE="$WORK/globex.token" \
    "$@" "$ROOT/scripts/web-demo-seed.sh" dry-run
}

output="$(run_dry_run)"
grep -F 'scope: acme/acme-demo-documents globex/globex-demo-documents' <<<"$output" >/dev/null
grep -F 'actions: delete only root children' <<<"$output" >/dev/null
grep -F 'demo-review-v1' "$ROOT/scripts/web-demo-seed.sh" >/dev/null
grep -F 'review_commit' "$ROOT/scripts/web-demo-seed.sh" >/dev/null

if run_dry_run env SLATEFS_DEMO_REQUEST_TIMEOUT_SECS=0 >"$WORK/invalid.out" 2>&1; then
  printf 'expected a zero request timeout to fail\n' >&2
  exit 1
fi
grep -F 'SLATEFS_DEMO_REQUEST_TIMEOUT_SECS must be a positive integer' \
  "$WORK/invalid.out" >/dev/null

printf 'web-demo seed tests passed\n'
