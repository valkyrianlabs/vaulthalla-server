#!/usr/bin/env bash

# Source this file from the repository root to load the E2E/test environment.
# It intentionally does not enable strict mode because callers source it.

_vh_e2e_loader_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_vh_e2e_repo_root="$(cd "${_vh_e2e_loader_dir}/../.." && pwd)"

VH_E2E_ENV_FILES=(
  "$HOME/.bashrc"
  "${_vh_e2e_repo_root}/.bashrc"
  "${_vh_e2e_repo_root}/deploy/bashrc"
  "${_vh_e2e_repo_root}/deploy/vaulthalla.env"
  # TEST-ONLY S3/R2 provider credentials (operator-managed; see tools/lab/providers.env.example).
  "${VH_TEST_PROVIDERS_ENV:-/etc/vaulthalla/testing/providers.env}"
)
VH_E2E_ENV_SOURCED_FILES=()
VH_E2E_ENV_MISSING_FILES=()
VH_E2E_ENV_FAILED_FILES=()

_vh_e2e_file_in_list() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

_vh_e2e_source_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    VH_E2E_ENV_MISSING_FILES+=("$file")
    return 0
  fi

  local shell_flags="$-"
  local had_errexit=0
  local had_nounset=0
  local had_allexport=0
  [[ "$shell_flags" == *e* ]] && had_errexit=1
  [[ "$shell_flags" == *u* ]] && had_nounset=1
  [[ "$shell_flags" == *a* ]] && had_allexport=1

  set +e +u
  set -a
  # shellcheck disable=SC1090
  source "$file" >/dev/null 2>&1
  local status=$?
  if [[ "$had_allexport" == "1" ]]; then set -a; else set +a; fi
  if [[ "$had_nounset" == "1" ]]; then set -u; else set +u; fi
  if [[ "$had_errexit" == "1" ]]; then set -e; else set +e; fi

  if [[ "$status" == "0" ]]; then
    VH_E2E_ENV_SOURCED_FILES+=("$file")
  else
    VH_E2E_ENV_FAILED_FILES+=("$file")
  fi
  return 0
}

for _vh_e2e_env_file in "${VH_E2E_ENV_FILES[@]}"; do
  _vh_e2e_source_file "$_vh_e2e_env_file"
done
unset _vh_e2e_env_file

vh_e2e_repo_root() {
  printf '%s\n' "$_vh_e2e_repo_root"
}

_vh_e2e_source_status() {
  local file="$1"
  if _vh_e2e_file_in_list "$file" "${VH_E2E_ENV_SOURCED_FILES[@]}"; then
    printf 'sourced'
  elif _vh_e2e_file_in_list "$file" "${VH_E2E_ENV_FAILED_FILES[@]}"; then
    printf 'failed'
  else
    printf 'missing'
  fi
}

_vh_e2e_var_status() {
  local name="$1"
  if [[ -n "${!name:-}" ]]; then
    printf 'set'
  else
    printf 'missing'
  fi
}

vh_e2e_redacted_env_report() {
  local file name
  printf 'E2E env sources:\n'
  for file in "${VH_E2E_ENV_FILES[@]}"; do
    printf '  %s: %s\n' "$file" "$(_vh_e2e_source_status "$file")"
  done
  printf 'E2E env values:\n'
  for name in \
    VH_TEST_DB_USER \
    VH_TEST_DB_PASS \
    VH_TEST_DB_HOST \
    VH_TEST_DB_PORT \
    VH_TEST_DB_NAME \
    S3_GATEWAY_SMOKE_UPSTREAM_ACCESS_KEY \
    S3_GATEWAY_SMOKE_UPSTREAM_SECRET_KEY \
    S3_GATEWAY_SMOKE_UPSTREAM_ENDPOINT \
    S3_GATEWAY_SMOKE_UPSTREAM_BUCKET \
    VAULTHALLA_E2E_USER \
    VAULTHALLA_E2E_PASSWORD
  do
    printf '  %s: %s\n' "$name" "$(_vh_e2e_var_status "$name")"
  done
}

vh_e2e_require_test_db_env() {
  local missing=()
  local name
  for name in VH_TEST_DB_USER VH_TEST_DB_PASS VH_TEST_DB_HOST VH_TEST_DB_PORT VH_TEST_DB_NAME; do
    [[ -n "${!name:-}" ]] || missing+=("$name")
  done

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return 0
  fi

  printf 'Missing test DB environment after loading known E2E env files: %s\n' "${missing[*]}" >&2
  vh_e2e_redacted_env_report >&2
  return 1
}

# The remote (R2) gateway smoke's upstream: an existing vh-test-* bucket the operator names explicitly. No script
# creates buckets (testing.md, "Live provider tests").
vh_e2e_has_r2_env() {
  [[ -n "${S3_GATEWAY_SMOKE_UPSTREAM_BUCKET:-}" &&
     -n "${S3_GATEWAY_SMOKE_UPSTREAM_ACCESS_KEY:-}" &&
     -n "${S3_GATEWAY_SMOKE_UPSTREAM_SECRET_KEY:-}" &&
     -n "${S3_GATEWAY_SMOKE_UPSTREAM_ENDPOINT:-}" ]]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  vh_e2e_redacted_env_report
fi
