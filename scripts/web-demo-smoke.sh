#!/usr/bin/env bash
# Bounded socket-level acceptance smoke for an already running, seeded demo.
set -euo pipefail

BFF_URL="${SLATEFS_DEMO_BFF_URL:-http://127.0.0.1:${SLATEFS_DEMO_PORT:-4174}}"
ACME_VOLUME="${SLATEFS_ACME_DEMO_VOLUME:-acme-demo-documents}"
GLOBEX_VOLUME="${SLATEFS_GLOBEX_DEMO_VOLUME:-globex-demo-documents}"
ORIGIN="$BFF_URL"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

die() { printf 'web-demo-smoke: %s\n' "$*" >&2; exit 1; }
for command in curl jq node; do command -v "$command" >/dev/null || die "$command is required"; done

# The production BFF must serve a freshly compiled same-origin browser client,
# never a bundle configured to bypass the session facade for daemon ports.
index="$(curl --silent --show-error --fail-with-body "$BFF_URL/")"
asset="$(sed -n 's#.*src="\(/assets/[^"?]*\.js\)[^"]*".*#\1#p' <<<"$index" | head -n 1)"
[[ -n "$asset" ]] || die "demo index does not reference a compiled JavaScript asset"
bundle="$(curl --silent --show-error --fail-with-body "$BFF_URL$asset")"
grep -F 'baseUrl:"/api"' <<<"$bundle" >/dev/null || \
  die "compiled demo client is not configured for the same-origin /api facade"
if grep -Eq 'https?://[^"[:space:]]+:(9400|9410)' <<<"$bundle"; then
  die "compiled demo client contains a hard-coded SlateFS daemon origin"
fi

login() {
  local user="$1" jar="$2" session csrf status
  session="$(curl --silent --show-error --fail-with-body -c "$jar" -b "$jar" "$BFF_URL/api/v1/session")"
  csrf="$(jq -r '.csrfToken' <<<"$session")"
  status="$(curl --silent --show-error -o "$TMP/login-$user.json" -w '%{http_code}' \
    -c "$jar" -b "$jar" -X POST -H "Origin: $ORIGIN" -H "X-CSRF-Token: $csrf" \
    -H 'Content-Type: application/json' --data "{\"username\":\"$user\",\"password\":\"slatefs\"}" \
    "$BFF_URL/api/v1/login")"
  [[ "$status" == 200 ]] || { cat "$TMP/login-$user.json" >&2; die "$user login returned $status"; }
  jq -er '.csrfToken' "$TMP/login-$user.json"
}

request() {
  local jar="$1" csrf="$2" method="$3" path="$4" expected="$5" body="${6:-}" status
  local args=(-c "$jar" -b "$jar" -X "$method" -H "Origin: $ORIGIN")
  if [[ "$method" != GET && "$method" != HEAD ]]; then args+=(-H "X-CSRF-Token: $csrf"); fi
  if [[ -n "$body" ]]; then args+=(-H 'Content-Type: application/json' --data "$body"); fi
  status="$(curl --silent --show-error -D "$TMP/headers" -o "$TMP/body" -w '%{http_code}' "${args[@]}" "$BFF_URL$path")"
  [[ "$status" == "$expected" ]] || { cat "$TMP/body" >&2; die "$method $path returned $status, expected $expected"; }
}

alice_jar="$TMP/alice.cookies"; bob_jar="$TMP/bob.cookies"
alice_csrf="$(login alice "$alice_jar")"; bob_csrf="$(login bob "$bob_jar")"

# Session and tenant isolation, including guessed cross-tenant volume names.
request "$alice_jar" "$alice_csrf" GET /api/v1/session 200
jq -e '.user.username == "alice"' "$TMP/body" >/dev/null
request "$bob_jar" "$bob_csrf" GET /api/v1/session 200
jq -e '.user.username == "bob"' "$TMP/body" >/dev/null
request "$alice_jar" "$alice_csrf" GET /api/consumer/v1/volumes 200
jq -e --arg own "$ACME_VOLUME" --arg other "$GLOBEX_VOLUME" \
  '.volumes | any(.name == $own) and all(.name != $other)' "$TMP/body" >/dev/null
request "$alice_jar" "$alice_csrf" GET "/api/consumer/v1/volumes/$GLOBEX_VOLUME/entries?path=" 404
request "$bob_jar" "$bob_csrf" GET "/api/consumer/v1/volumes/$ACME_VOLUME/entries?path=" 404

# Live browse, staged upload, byte range, and delete through the BFF.
# Match the exact root-list query emitted by the browser client.
request "$alice_jar" "$alice_csrf" GET "/api/consumer/v1/volumes/$ACME_VOLUME/entries?path=&view=live&limit=200" 200
root_id="$(jq -r '.entry.entry_id|@uri' "$TMP/body")"
status="$(curl --silent --show-error -D "$TMP/headers" -o "$TMP/body" -w '%{http_code}' \
  -c "$alice_jar" -b "$alice_jar" -X PUT -H "Origin: $ORIGIN" -H "X-CSRF-Token: $alice_csrf" \
  -H 'Content-Type: application/octet-stream' --data-binary 'acceptance-range-body' \
  "$BFF_URL/api/consumer/v1/volumes/$ACME_VOLUME/content?parent_entry_id=$root_id&name=acceptance.txt")"
[[ "$status" == 201 ]] || { cat "$TMP/body" >&2; die "upload returned $status"; }
upload_id="$(jq -r '.entry_id|@uri' "$TMP/body")"
status="$(curl --silent --show-error -D "$TMP/headers" -o "$TMP/body" -w '%{http_code}' \
  -c "$alice_jar" -b "$alice_jar" -H 'Range: bytes=11-15' \
  "$BFF_URL/api/consumer/v1/volumes/$ACME_VOLUME/content?entry_id=$upload_id")"
[[ "$status" == 206 && "$(<"$TMP/body")" == range ]] || die "range read did not return expected bytes"
request "$alice_jar" "$alice_csrf" DELETE "/api/consumer/v1/volumes/$ACME_VOLUME/entries?entry_id=$upload_id&recursive=false" 204

# Snapshot create/list and immutable historical browse.
request "$alice_jar" "$alice_csrf" POST "/api/v1/volumes/$ACME_VOLUME/snapshots" 200 '{"name":"acceptance-smoke"}'
smoke_snapshot="$(jq -r '.snapshot.id' "$TMP/body")"
request "$alice_jar" "$alice_csrf" GET "/api/v1/volumes/$ACME_VOLUME/snapshots" 200
jq -e --arg id "$smoke_snapshot" '.snapshots | any(.id == $id)' "$TMP/body" >/dev/null
request "$alice_jar" "$alice_csrf" GET "/api/consumer/v1/volumes/$ACME_VOLUME/entries?path=&view=snapshot&ref=$smoke_snapshot&limit=1" 200
snapshot_page="$(jq -r '.next_page_token // empty|@uri' "$TMP/body")"

# Version history, diff, exact and symbolic reads, and exact-view token binding.
request "$alice_jar" "$alice_csrf" GET "/api/v1/volumes/$ACME_VOLUME/versioning/commits?limit=100" 200
first="$(jq -r '.commits[-1].id' "$TMP/body")"; second="$(jq -r '.commits[0].id' "$TMP/body")"
[[ ${#first} == 64 && ${#second} == 64 && "$first" != "$second" ]] || die "seeded commit history is incomplete"
request "$alice_jar" "$alice_csrf" GET "/api/v1/volumes/$ACME_VOLUME/versioning/diff?from=$first&to=$second&limit=100" 200
jq -e '.changes | length > 0' "$TMP/body" >/dev/null
request "$alice_jar" "$alice_csrf" GET "/api/consumer/v1/volumes/$ACME_VOLUME/content?path=versioned.txt&view=version&ref=$first" 200
[[ "$(<"$TMP/body")" == 'Alice version one\n' ]] || die "exact historical read returned unexpected bytes"
request "$alice_jar" "$alice_csrf" GET "/api/consumer/v1/volumes/$ACME_VOLUME/content?path=versioned.txt&view=version&ref=main" 200
resolved="$(awk 'BEGIN{IGNORECASE=1} /^x-slatefs-resolved-commit:/ {gsub("\\r",""); print $2}' "$TMP/headers")"
[[ "$resolved" == "$second" ]] || die "symbolic historical read did not expose the resolved commit"
request "$alice_jar" "$alice_csrf" GET "/api/consumer/v1/volumes/$ACME_VOLUME/entries?path=&view=version&ref=$first&limit=1" 200
version_entry="$(jq -r '.entry.entry_id|@uri' "$TMP/body")"
version_page="$(jq -r '.next_page_token // empty|@uri' "$TMP/body")"
request "$alice_jar" "$alice_csrf" GET "/api/consumer/v1/volumes/$ACME_VOLUME/entries?entry_id=$version_entry&view=version&ref=$second" 412
if [[ -n "$version_page" ]]; then
  request "$alice_jar" "$alice_csrf" GET "/api/consumer/v1/volumes/$ACME_VOLUME/entries?path=&view=version&ref=$second&limit=1&page_token=$version_page" 412
fi
if [[ -n "$snapshot_page" ]]; then
  request "$alice_jar" "$alice_csrf" GET "/api/consumer/v1/volumes/$ACME_VOLUME/entries?path=&view=version&ref=$first&limit=1&page_token=$snapshot_page" 412
fi

# Tag/branch inventory, restore preview, atomic expected-head enforcement.
request "$alice_jar" "$alice_csrf" GET "/api/v1/volumes/$ACME_VOLUME/versioning/tags" 200
jq -e '.tags | any(.name == "demo-baseline")' "$TMP/body" >/dev/null
request "$alice_jar" "$alice_csrf" GET "/api/v1/volumes/$ACME_VOLUME/versioning/branches" 200
main_head="$(jq -r '.branches[]|select(.name=="main")|.commit' "$TMP/body")"
review_head="$(jq -r '.branches[]|select(.name=="demo-review")|.commit' "$TMP/body")"
request "$alice_jar" "$alice_csrf" POST "/api/v1/volumes/$ACME_VOLUME/versioning/restore-preview" 200 \
  "{\"commit\":\"$first\",\"path\":\"/versioned.txt\",\"mode\":\"overlay\"}"
jq -e '.preview.token | length > 0' "$TMP/body" >/dev/null
zeros="$(printf '%064d' 0)"
request "$alice_jar" "$alice_csrf" POST "/api/v1/volumes/$ACME_VOLUME/versioning/branches/demo-review/merge" 409 \
  "{\"source\":\"main\",\"expected_source\":\"$zeros\",\"expected_target\":\"$review_head\",\"conflict_strategy\":\"fail\"}"
request "$alice_jar" "$alice_csrf" POST "/api/v1/volumes/$ACME_VOLUME/versioning/branches/main/cherry-pick" 200 \
  "{\"source\":\"demo-review\",\"expected_target\":\"$main_head\",\"idempotency_key\":\"acceptance-review-cherry\"}"
jq -e '.cherry_pick.applied == true and (.cherry_pick.commit | length > 0)' "$TMP/body" >/dev/null
picked_main_head="$(jq -r '.cherry_pick.commit' "$TMP/body")"
request "$alice_jar" "$alice_csrf" POST "/api/v1/volumes/$ACME_VOLUME/versioning/branches/demo-review/merge" 200 \
  "{\"source\":\"main\",\"expected_source\":\"$picked_main_head\",\"expected_target\":\"$review_head\",\"conflict_strategy\":\"fail\"}"
jq -e '.merge.commit | length > 0' "$TMP/body" >/dev/null
request "$alice_jar" "$alice_csrf" POST "/api/v1/volumes/$ACME_VOLUME/versioning/branches/demo-review/cherry-pick" 409 \
  "{\"source\":\"$first\",\"expected_target\":\"$review_head\",\"idempotency_key\":\"acceptance-stale\"}"

SLATEFS_DEMO_BFF_URL="$BFF_URL" \
SLATEFS_ACME_DEMO_VOLUME="$ACME_VOLUME" \
SLATEFS_GLOBEX_DEMO_VOLUME="$GLOBEX_VOLUME" \
  node "$ROOT/scripts/web-demo-blob-upload.mjs"

printf 'web-demo-smoke: PASS (Alice/Bob isolation, live I/O and native Blob upload/upsert/preconditions/collisions, snapshots, history/diff, pinned views, token binding, restore preview, clean review cherry-pick, merge, stale heads)\n'
