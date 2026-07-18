#!/usr/bin/env bash
# Deterministic, daemon-aware SlateFS consumer demo seed/reset.
set -euo pipefail
shopt -s inherit_errexit

MODE="${1:-seed}"
CONSUMER_URL="${SLATEFS_CONSUMER_BASE_URL:-http://127.0.0.1:9410}"
ADMIN_URL="${SLATEFS_ADMIN_BASE_URL:-http://127.0.0.1:9400}"
ACME_TOKEN_FILE="${SLATEFS_ACME_TOKEN_FILE:-}"
GLOBEX_TOKEN_FILE="${SLATEFS_GLOBEX_TOKEN_FILE:-}"
ACME_VOLUME="${SLATEFS_ACME_DEMO_VOLUME:-acme-demo-documents}"
GLOBEX_VOLUME="${SLATEFS_GLOBEX_DEMO_VOLUME:-globex-demo-documents}"
REQUEST_TIMEOUT_SECS="${SLATEFS_DEMO_REQUEST_TIMEOUT_SECS:-120}"

die() { printf 'web-demo-seed: %s\n' "$*" >&2; exit 1; }
for command in curl jq; do command -v "$command" >/dev/null || die "$command is required"; done
[[ "$MODE" == seed || "$MODE" == reset || "$MODE" == dry-run ]] || die "usage: $0 [seed|reset|dry-run]"
[[ "$ACME_VOLUME" == acme-demo-* ]] || die "acme volume must start with acme-demo-"
[[ "$GLOBEX_VOLUME" == globex-demo-* ]] || die "globex volume must start with globex-demo-"
[[ -r "$ACME_TOKEN_FILE" && -r "$GLOBEX_TOKEN_FILE" ]] || die "set readable SLATEFS_ACME_TOKEN_FILE and SLATEFS_GLOBEX_TOKEN_FILE"
[[ "$REQUEST_TIMEOUT_SECS" =~ ^[1-9][0-9]*$ ]] || die "SLATEFS_DEMO_REQUEST_TIMEOUT_SECS must be a positive integer"

acme_token="$(tr -d '\r\n' < "$ACME_TOKEN_FILE")"
globex_token="$(tr -d '\r\n' < "$GLOBEX_TOKEN_FILE")"
[[ -n "$acme_token" && -n "$globex_token" ]] || die "tenant token files must not be empty"

if [[ "$MODE" == dry-run ]]; then
  printf 'scope: acme/%s globex/%s\n' "$ACME_VOLUME" "$GLOBEX_VOLUME"
  printf 'endpoints: consumer=%s admin=%s\n' "$CONSUMER_URL" "$ADMIN_URL"
  printf 'actions: delete only root children, snapshots, and version history in those two volumes; then seed files, snapshots, commits, tag, and branch\n'
  exit 0
fi

timed_curl() {
  local label="$1" started status elapsed; shift
  started="$SECONDS"
  printf 'request start: %s (timeout=%ss)\n' "$label" "$REQUEST_TIMEOUT_SECS" >&2
  if curl --connect-timeout 5 --max-time "$REQUEST_TIMEOUT_SECS" "$@"; then
    status=0
  else
    status="$?"
  fi
  elapsed="$((SECONDS - started))"
  printf 'request complete: %s elapsed=%ss curl_status=%s\n' "$label" "$elapsed" "$status" >&2
  return "$status"
}

consumer() {
  local token="$1" method="$2" path="$3"; shift 3
  timed_curl "$method consumer$path" --silent --show-error --fail-with-body -X "$method" \
    -H "Authorization: Bearer $token" -H "X-Request-Id: demo-seed-$RANDOM" \
    "$CONSUMER_URL$path" "$@"
}
admin() {
  local token="$1" method="$2" path="$3"; shift 3
  timed_curl "$method admin$path" --silent --show-error --fail-with-body -X "$method" \
    -H "Authorization: Bearer $token" -H "X-Request-Id: demo-seed-$RANDOM" \
    "$ADMIN_URL$path" "$@"
}

root_entry() {
  consumer "$1" GET "/consumer/v1/volumes/$2/entries?path=" | jq -r '.entry.entry_id'
}

reset_volume() {
  local tenant="$1" volume="$2" token="$3" listing id snapshot remaining
  printf 'resetting %s/%s through daemon APIs\n' "$tenant" "$volume"
  # Always delete the first bounded page and re-list. Directory mutation can
  # invalidate continuation cookies, while repeated first-page deletion is
  # complete for any number of demo entries.
  while :; do
    listing="$(consumer "$token" GET "/consumer/v1/volumes/$volume/entries?path=&limit=500")"
    remaining="$(jq '.entries | length' <<<"$listing")"
    [[ "$remaining" -gt 0 ]] || break
    while IFS= read -r id; do
      [[ -n "$id" ]] || continue
      timed_curl "DELETE consumer entries ($tenant/$volume)" \
        --silent --show-error --fail-with-body -X DELETE \
        -H "Authorization: Bearer $token" -H "X-Request-Id: demo-reset-$RANDOM" \
        --get --data-urlencode "entry_id=$id" --data-urlencode "recursive=true" \
        "$CONSUMER_URL/consumer/v1/volumes/$volume/entries" >/dev/null
    done < <(jq -r '.entries[].entry_id' <<<"$listing")
  done

  while IFS= read -r snapshot; do
    [[ -n "$snapshot" ]] || continue
    admin "$token" DELETE "/admin/v1/tenants/$tenant/volumes/$volume/snapshots/$snapshot" >/dev/null
  done < <(admin "$token" GET "/admin/v1/tenants/$tenant/volumes/$volume/snapshots?limit=500" | jq -r '.snapshots[].id')

  # A missing repository is an expected first-run condition (404). Any other
  # response must succeed so reset cannot silently leave mixed history behind.
  local status body
  body="$(mktemp)"
  status="$(timed_curl "DELETE admin version history ($tenant/$volume)" \
    --silent --show-error -o "$body" -w '%{http_code}' -X DELETE \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    --data '{"confirm":true}' \
    "$ADMIN_URL/admin/v1/tenants/$tenant/volumes/$volume/versioning/history")"
  if [[ "$status" != 200 && "$status" != 404 ]]; then
    cat "$body" >&2; rm -f "$body"; die "history reset failed for $tenant/$volume (HTTP $status)"
  fi
  rm -f "$body"
}

write_new() {
  local token="$1" volume="$2" parent="$3" name="$4" content="$5" parent_q name_q
  parent_q="$(jq -rn --arg value "$parent" '$value|@uri')"
  name_q="$(jq -rn --arg value "$name" '$value|@uri')"
  timed_curl "PUT consumer content ($volume/$name)" \
    --silent --show-error --fail-with-body -X PUT \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/octet-stream' \
    --data-binary "$content" \
    "$CONSUMER_URL/consumer/v1/volumes/$volume/content?parent_entry_id=$parent_q&name=$name_q"
}

replace_path() {
  local token="$1" volume="$2" path="$3" content="$4" entry id etag id_q
  entry="$(timed_curl "GET consumer entry ($volume/$path)" \
    --silent --show-error --fail-with-body -G \
    -H "Authorization: Bearer $token" --data-urlencode "path=$path" \
    "$CONSUMER_URL/consumer/v1/volumes/$volume/entries")"
  id="$(jq -r '.entry.entry_id' <<<"$entry")"; etag="$(jq -r '.entry.etag' <<<"$entry")"
  id_q="$(jq -rn --arg value "$id" '$value|@uri')"
  timed_curl "PUT consumer content ($volume/$path)" \
    --silent --show-error --fail-with-body -X PUT \
    -H "Authorization: Bearer $token" -H "If-Match: $etag" \
    -H 'Content-Type: application/octet-stream' --data-binary "$content" \
    "$CONSUMER_URL/consumer/v1/volumes/$volume/content?entry_id=$id_q"
}

seed_volume() {
  local tenant="$1" volume="$2" token="$3" label="$4" root first review second snapshot first_path review_path
  admin "$token" PATCH "/admin/v1/tenants/$tenant/volumes/$volume/consumer-root" \
    -H 'Content-Type: application/json' --data '{"mode":493,"uid":1000,"gid":1000}' >/dev/null
  root="$(root_entry "$token" "$volume")"
  write_new "$token" "$volume" "$root" "${label,,}-only.txt" "$label private demo data\n" >/dev/null
  write_new "$token" "$volume" "$root" versioned.txt "$label version one\n" >/dev/null

  snapshot="$(admin "$token" POST "/admin/v1/tenants/$tenant/volumes/$volume/snapshot?name=demo-baseline" | jq -r '.snapshot.id')"
  admin "$token" PATCH "/admin/v1/tenants/$tenant/volumes/$volume/versioning" \
    -H 'Content-Type: application/json' --data '{"enabled":true}' >/dev/null
  first="$(admin "$token" POST "/admin/v1/tenants/$tenant/volumes/$volume/versioning/commits" \
    -H 'Content-Type: application/json' \
    --data "{\"paths\":[\"/versioned.txt\",\"/${label,,}-only.txt\"],\"message\":\"$label demo baseline\",\"author\":\"$label\",\"idempotency_key\":\"demo-baseline-v1\"}" | jq -r '.commit.id')"
  admin "$token" POST "/admin/v1/tenants/$tenant/volumes/$volume/versioning/tags" \
    -H 'Content-Type: application/json' --data "{\"name\":\"demo-baseline\",\"commit\":\"$first\"}" >/dev/null
  admin "$token" POST "/admin/v1/tenants/$tenant/volumes/$volume/versioning/branches" \
    -H 'Content-Type: application/json' --data "{\"name\":\"demo-review\",\"commit\":\"$first\"}" >/dev/null

  # Give demo-review its own commit so cherry-picking it onto main demonstrates
  # a real branch transfer instead of trying to replay main's older ancestor.
  review_path="/${label,,}-review.txt"
  write_new "$token" "$volume" "$root" "${label,,}-review.txt" "$label review branch candidate\n" >/dev/null
  review="$(admin "$token" POST "/admin/v1/tenants/$tenant/volumes/$volume/versioning/commits" \
    -H 'Content-Type: application/json' \
    --data "{\"paths\":[\"$review_path\"],\"message\":\"$label demo review change\",\"author\":\"$label\",\"branch\":\"demo-review\",\"idempotency_key\":\"demo-review-v1\"}" | jq -r '.commit.id')"

  replace_path "$token" "$volume" versioned.txt "$label version two\n" >/dev/null
  first_path="/${label,,}-only.txt"
  second="$(admin "$token" POST "/admin/v1/tenants/$tenant/volumes/$volume/versioning/commits" \
    -H 'Content-Type: application/json' \
    --data "{\"paths\":[\"/versioned.txt\",\"$first_path\"],\"message\":\"$label demo second revision\",\"author\":\"$label\",\"idempotency_key\":\"demo-second-v1\"}" | jq -r '.commit.id')"
  # Leave live content ahead of history so restore/status previews are useful.
  replace_path "$token" "$volume" versioned.txt "$label uncommitted restore candidate\n" >/dev/null
  jq -n --arg tenant "$tenant" --arg volume "$volume" --arg snapshot "$snapshot" \
    --arg first "$first" --arg review "$review" --arg second "$second" \
    '{tenant:$tenant,volume:$volume,snapshot:$snapshot,first_commit:$first,review_commit:$review,second_commit:$second,tag:"demo-baseline",branch:"demo-review"}'
}

reset_volume acme "$ACME_VOLUME" "$acme_token"
reset_volume globex "$GLOBEX_VOLUME" "$globex_token"
[[ "$MODE" == reset ]] && exit 0

acme="$(seed_volume acme "$ACME_VOLUME" "$acme_token" Alice)"
globex="$(seed_volume globex "$GLOBEX_VOLUME" "$globex_token" Bob)"
jq -n --argjson acme "$acme" --argjson globex "$globex" '{acme:$acme,globex:$globex}'
