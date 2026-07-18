#!/usr/bin/env bash

# Package-manager resolution shared by the local web demo lifecycle script.
# The caller must set WEB_DEMO_ROOT to the repository root.

PNPM_COMMAND=()
PNPM_WORKSPACE=""

package_manager_help() {
  local required="$1" detail="${2:-}"
  [[ -z "$detail" ]] || printf 'web-demo: %s\n' "$detail" >&2
  printf 'web-demo: no usable pnpm provider was found; this repository requires %s\n' "$required" >&2
  printf 'web-demo: either install it directly:\n' >&2
  printf '  npm install --global %s\n' "$required" >&2
  printf 'web-demo: or install/enable Corepack and activate the checked-in version:\n' >&2
  printf '  npm install --global corepack\n' >&2
  printf '  corepack enable\n' >&2
  printf '  corepack prepare %s --activate\n' "$required" >&2
}

resolve_pnpm() {
  local workspace="$1" required="$2" corepack_version

  if [[ ! "$required" =~ ^pnpm@[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
    printf 'web-demo: invalid packageManager declaration %q in %s/web/package.json\n' \
      "$required" "$WEB_DEMO_ROOT" >&2
    return 1
  fi

  PNPM_WORKSPACE="$workspace"
  if command -v pnpm >/dev/null 2>&1; then
    PNPM_COMMAND=(pnpm)
    return 0
  fi

  if ! command -v corepack >/dev/null 2>&1; then
    package_manager_help "$required"
    return 1
  fi

  if ! corepack_version="$(cd "$workspace" && corepack pnpm --version 2>&1)"; then
    package_manager_help "$required" \
      "Corepack is installed, but 'corepack pnpm' could not activate $required: $corepack_version"
    return 1
  fi
  if [[ "$corepack_version" != "${required#pnpm@}" ]]; then
    package_manager_help "$required" \
      "Corepack resolved pnpm $corepack_version instead of the checked-in ${required#pnpm@}"
    return 1
  fi

  PNPM_COMMAND=(corepack pnpm)
}

run_pnpm() {
  (cd "$PNPM_WORKSPACE" && "${PNPM_COMMAND[@]}" "$@")
}
