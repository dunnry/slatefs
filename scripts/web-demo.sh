#!/usr/bin/env bash
# Local one-writer SlateFS daemon + demo BFF lifecycle harness.
set -euo pipefail

ACTION="${1:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DEMO_ROOT="$ROOT"
# shellcheck source=scripts/web-demo-package-manager.sh
source "$ROOT/scripts/web-demo-package-manager.sh"
WORK="${SLATEFS_DEMO_WORKDIR:-/tmp/slatefs-web-demo}"
CONFIG="$WORK/slatefs.toml"
DAEMON_PID="$WORK/slatefsd.pid"
BFF_PID="$WORK/demo-bff.pid"
ADMIN_PORT="${SLATEFS_DEMO_ADMIN_PORT:-9400}"
CONSUMER_PORT="${SLATEFS_DEMO_CONSUMER_PORT:-9410}"
BFF_PORT="${SLATEFS_DEMO_PORT:-4174}"
ACME_VOLUME="acme-demo-documents"
GLOBEX_VOLUME="globex-demo-documents"

die() { printf 'web-demo: %s\n' "$*" >&2; exit 1; }
running() { [[ -f "$1" ]] && kill -0 "$(<"$1")" 2>/dev/null; }
managed_running() {
  local pid_file="$1" expected="$2" command
  running "$pid_file" || return 1
  command="$(ps -p "$(<"$pid_file")" -o command= 2>/dev/null || true)"
  [[ "$command" == *"$expected"* ]]
}
discard_stale_pid() {
  local pid_file="$1" expected="$2"
  if running "$pid_file" && ! managed_running "$pid_file" "$expected"; then
    printf 'web-demo: ignoring stale pid file %s; it does not identify this demo\n' "$pid_file" >&2
    rm -f "$pid_file"
  elif ! running "$pid_file"; then
    rm -f "$pid_file"
  fi
}
stop_managed() {
  local pid_file="$1" expected="$2" signal="$3" label="$4" pid
  if ! running "$pid_file"; then rm -f "$pid_file"; return 0; fi
  if ! managed_running "$pid_file" "$expected"; then
    printf 'web-demo: refusing to signal unrelated process from stale %s\n' "$pid_file" >&2
    rm -f "$pid_file"
    return 0
  fi
  pid="$(<"$pid_file")"
  kill "-$signal" "$pid"
  for _ in {1..200}; do
    kill -0 "$pid" 2>/dev/null || { rm -f "$pid_file"; return 0; }
    sleep 0.1
  done
  die "$label process $pid did not stop within 20 seconds"
}
wait_http() {
  local url="$1" token="${2:-}"
  for _ in {1..100}; do
    if [[ -n "$token" ]]; then
      curl -fsS -H "Authorization: Bearer $token" "$url" >/dev/null 2>&1 && return 0
    else
      curl -fsS "$url" >/dev/null 2>&1 && return 0
    fi
    sleep 0.1
  done
  return 1
}

port_in_use() {
  local port="$1"
  if command -v lsof >/dev/null; then
    lsof -nP -iTCP@127.0.0.1:"$port" -sTCP:LISTEN -t 2>/dev/null | grep -q .
    return
  fi
  node -e '
    const net = require("node:net");
    const server = net.createServer();
    server.once("error", error => process.exit(error.code === "EADDRINUSE" ? 0 : 2));
    server.listen(Number(process.argv[1]), "127.0.0.1", () => server.close(() => process.exit(1)));
  ' "$port"
}

require_free_demo_ports() {
  local label port status
  for label in admin consumer BFF; do
    case "$label" in
      admin) port="$ADMIN_PORT" ;;
      consumer) port="$CONSUMER_PORT" ;;
      BFF) port="$BFF_PORT" ;;
    esac
    if port_in_use "$port"; then
      die "$label port 127.0.0.1:$port is already in use; stop the existing stack before opening demo writers"
    else
      status="$?"
      [[ "$status" == 1 ]] || die "could not test whether $label port 127.0.0.1:$port is available"
    fi
  done
}

write_config() {
  local kms_key
  kms_key="$(openssl rand -hex 32)"
  cat >"$CONFIG" <<EOF
[object_store]
url = "file://$WORK/store"
[kms]
provider = "static"
key_hex = "$kms_key"
[volume_defaults]
chunk_size = 4096
compression = "lz4"
cipher = "aes256_gcm"
[admin]
listen = "127.0.0.1:$ADMIN_PORT"
[admin.tenant_token_files]
acme = "$WORK/acme.token"
globex = "$WORK/globex.token"
[consumer]
listen = "127.0.0.1:$CONSUMER_PORT"
historical_view_cache_entries = 2
[consumer.tenant_identities.acme]
uid = 1000
gid = 1000
[consumer.tenant_identities.globex]
uid = 1000
gid = 1000
[export_control]
poll_interval_secs = 1
EOF
  chmod 600 "$CONFIG"
}

init_store() {
  local cli="$ROOT/target/debug/slatefs" tenant volume
  for tenant in acme globex; do
    "$cli" -c "$CONFIG" tenant create "$tenant" >/dev/null 2>&1 || \
      "$cli" -c "$CONFIG" tenant list | awk '{print $1}' | grep -Fx "$tenant" >/dev/null
  done
  for tenant in acme globex; do
    if [[ "$tenant" == acme ]]; then volume="$ACME_VOLUME"; else volume="$GLOBEX_VOLUME"; fi
    "$cli" -c "$CONFIG" volume info "$tenant" "$volume" >/dev/null 2>&1 || \
      "$cli" -c "$CONFIG" volume create "$tenant" "$volume" --note "consumer demo only" >/dev/null
  done
}

case "$ACTION" in
  up)
    discard_stale_pid "$DAEMON_PID" "target/debug/slatefsd -c $CONFIG"
    discard_stale_pid "$BFF_PID" "web/apps/demo-server/dist/src/main.js"
    managed_running "$DAEMON_PID" "target/debug/slatefsd -c $CONFIG" && die "daemon already running in $WORK"
    managed_running "$BFF_PID" "web/apps/demo-server/dist/src/main.js" && die "BFF already running in $WORK"
    command -v cargo >/dev/null || die "cargo is required"
    command -v node >/dev/null || die "Node.js 22 or newer is required (install Node.js, then use pnpm or Corepack as described in docs/web-demo-local.md)"
    node_major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null)" || \
      die "could not determine the Node.js version; Node.js 22 or newer is required"
    [[ "$node_major" =~ ^[0-9]+$ && "$node_major" -ge 22 ]] || \
      die "Node.js 22 or newer is required (found $(node --version 2>/dev/null || printf unknown))"
    # Opening the CLI or daemon against a live store creates newer SlateDB
    # writers and fences the existing stack. Reject occupied listeners before
    # init_store performs any control- or volume-writer operation.
    require_free_demo_ports
    package_manager="$(node -p 'require(process.argv[1]).packageManager || ""' "$ROOT/web/package.json")" || \
      die "could not read packageManager from $ROOT/web/package.json"
    [[ -n "$package_manager" ]] || die "web/package.json must declare packageManager"
    resolve_pnpm "$ROOT/web" "$package_manager" || exit 1
    command -v curl >/dev/null || die "curl is required"
    command -v jq >/dev/null || die "jq is required"
    command -v openssl >/dev/null || die "openssl is required"
    mkdir -p "$WORK/store"
    [[ -f "$CONFIG" ]] || write_config
    [[ -s "$WORK/acme.token" ]] || openssl rand -hex 32 >"$WORK/acme.token"
    [[ -s "$WORK/globex.token" ]] || openssl rand -hex 32 >"$WORK/globex.token"
    chmod 600 "$WORK/acme.token" "$WORK/globex.token"
    cargo build --manifest-path "$ROOT/Cargo.toml" -p slatefs-cli -p slatefs-daemon
    init_store
    # The BFF serves demo/dist, so build the demo and its workspace
    # dependencies before compiling and starting the server. Building only the
    # BFF can silently serve a stale browser client.
    run_pnpm --filter '@slatefs/demo...' build
    run_pnpm --filter @slatefs/demo-server build
    nohup env RUST_MIN_STACK="${RUST_MIN_STACK:-8388608}" \
      "$ROOT/target/debug/slatefsd" -c "$CONFIG" \
      >"$WORK/slatefsd.log" 2>&1 </dev/null &
    printf '%s\n' "$!" >"$DAEMON_PID"
    acme_token="$(tr -d '\r\n' <"$WORK/acme.token")"
    wait_http "http://127.0.0.1:$CONSUMER_PORT/consumer/v1/capabilities" "$acme_token" || {
      tail -n 80 "$WORK/slatefsd.log" >&2; die "slatefsd did not become ready";
    }
    nohup env SLATEFS_ACME_TOKEN_FILE="$WORK/acme.token" \
      SLATEFS_GLOBEX_TOKEN_FILE="$WORK/globex.token" \
      SLATEFS_CONSUMER_BASE_URL="http://127.0.0.1:$CONSUMER_PORT" \
      SLATEFS_ADMIN_BASE_URL="http://127.0.0.1:$ADMIN_PORT" \
      SLATEFS_DEMO_PORT="$BFF_PORT" SLATEFS_DEMO_STATIC_DIR="$ROOT/web/apps/demo/dist" \
      node "$ROOT/web/apps/demo-server/dist/src/main.js" \
      >"$WORK/demo-bff.log" 2>&1 </dev/null &
    printf '%s\n' "$!" >"$BFF_PID"
    wait_http "http://127.0.0.1:$BFF_PORT/healthz" || {
      tail -n 80 "$WORK/demo-bff.log" >&2; die "demo BFF did not become ready";
    }
    printf 'ready: BFF http://127.0.0.1:%s daemon consumer :%s admin :%s workdir %s\n' \
      "$BFF_PORT" "$CONSUMER_PORT" "$ADMIN_PORT" "$WORK"
    ;;
  seed|reset|dry-run)
    managed_running "$DAEMON_PID" "target/debug/slatefsd -c $CONFIG" || die "run '$0 up' first"
    export SLATEFS_ACME_TOKEN_FILE="$WORK/acme.token"
    export SLATEFS_GLOBEX_TOKEN_FILE="$WORK/globex.token"
    export SLATEFS_CONSUMER_BASE_URL="http://127.0.0.1:$CONSUMER_PORT"
    export SLATEFS_ADMIN_BASE_URL="http://127.0.0.1:$ADMIN_PORT"
    export SLATEFS_ACME_DEMO_VOLUME="$ACME_VOLUME"
    export SLATEFS_GLOBEX_DEMO_VOLUME="$GLOBEX_VOLUME"
    "$ROOT/scripts/web-demo-seed.sh" "$ACTION"
    ;;
  smoke)
    managed_running "$DAEMON_PID" "target/debug/slatefsd -c $CONFIG" || die "run '$0 up' first"
    managed_running "$BFF_PID" "web/apps/demo-server/dist/src/main.js" || die "demo BFF is not running"
    command -v timeout >/dev/null || die "timeout is required for the bounded smoke run"
    export SLATEFS_DEMO_BFF_URL="http://127.0.0.1:$BFF_PORT"
    export SLATEFS_ACME_DEMO_VOLUME="$ACME_VOLUME"
    export SLATEFS_GLOBEX_DEMO_VOLUME="$GLOBEX_VOLUME"
    timeout "${SLATEFS_DEMO_SMOKE_TIMEOUT:-120s}" "$ROOT/scripts/web-demo-smoke.sh"
    ;;
  down)
    stop_managed "$BFF_PID" "web/apps/demo-server/dist/src/main.js" TERM BFF
    stop_managed "$DAEMON_PID" "target/debug/slatefsd -c $CONFIG" INT daemon
    printf 'stopped; demo-scoped data remains in %s (remove that directory for teardown)\n' "$WORK"
    ;;
  status)
    managed_running "$DAEMON_PID" "target/debug/slatefsd -c $CONFIG" && daemon=running || daemon=stopped
    managed_running "$BFF_PID" "web/apps/demo-server/dist/src/main.js" && bff=running || bff=stopped
    printf 'daemon=%s bff=%s workdir=%s\n' "$daemon" "$bff" "$WORK"
    ;;
  *) die "usage: $0 {up|seed|reset|dry-run|smoke|status|down}" ;;
esac
