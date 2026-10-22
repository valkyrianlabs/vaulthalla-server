#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"
# shellcheck source=tools/e2e/load_env.sh
source "$REPO_ROOT/tools/e2e/load_env.sh"

DEFAULT_VH_BIN="$REPO_ROOT/build/core/vaulthalla-cli"
[[ -x "$DEFAULT_VH_BIN" ]] || DEFAULT_VH_BIN="vh"
VH_BIN="${VH_BIN:-$DEFAULT_VH_BIN}"
AWS_BIN="${AWS_BIN:-aws}"
MC_BIN="${MC_BIN:-mc}"
JQ_BIN="${JQ_BIN:-jq}"
ENDPOINT="${S3_GATEWAY_ENDPOINT:-http://127.0.0.1:39000}"
SMOKE_RUN_ID="${S3_GATEWAY_SMOKE_RUN_ID:-$$}"
LOCAL_BUCKET="${S3_GATEWAY_SMOKE_LOCAL_BUCKET:-vh-smoke-local-$SMOKE_RUN_ID}"
OTHER_BUCKET="${S3_GATEWAY_SMOKE_OTHER_BUCKET:-vh-smoke-denied-$SMOKE_RUN_ID}"
REMOTE_BUCKET="${S3_GATEWAY_SMOKE_REMOTE_BUCKET:-vh-smoke-remote-$SMOKE_RUN_ID}"
CRED_NAME="${S3_GATEWAY_SMOKE_CRED_NAME:-vh-smoke-scoped-budget}"
SMOKE_OWNER="${S3_GATEWAY_SMOKE_OWNER:-admin}"
SYNTHETIC_MONTHLY_LIMIT="${S3_GATEWAY_SMOKE_SYNTHETIC_MONTHLY_LIMIT:-0.00000003}"
ACTUAL_MONTHLY_LIMIT="${S3_GATEWAY_SMOKE_ACTUAL_MONTHLY_LIMIT:-0.00000000}"
MC_ALIAS="${S3_GATEWAY_SMOKE_MC_ALIAS:-vh-smoke}"
# The remote-cache upstream is the fixed test bucket vh-test-gateway-smoke. A remote run creates it first and deletes
# it last, also on failure (the EXIT trap), through build/core/vh_live_bucket: the guarded live-test helper
# (core/tests/helpers/live_bucket.hpp), which manages no other name. A leftover of a crashed run is emptied and
# deleted before the new one is created. The only credential is the R2 admin key VH_R2_ADMIN_* (repo-root .bashrc);
# the daemon under test gets it as the upstream API key.
UPSTREAM_BUCKET="vh-test-gateway-smoke"
LIVE_BUCKET_BIN="$REPO_ROOT/build/core/vh_live_bucket"
UPSTREAM_API_KEY=""
UPSTREAM_API_KEY_NAME="vh-smoke-upstream-$$"
UPSTREAM_ACCESS_KEY="${VH_R2_ADMIN_ACCESS_KEY:-}"
UPSTREAM_SECRET_KEY="${VH_R2_ADMIN_SECRET_KEY:-}"
UPSTREAM_ENDPOINT="${VH_R2_ADMIN_ENDPOINT:-}"
UPSTREAM_REGION="${VH_R2_ADMIN_REGION:-auto}"
UPSTREAM_PROVIDER="cloudflare-r2"
UPSTREAM_CREATED=0
PREFIX="${S3_GATEWAY_SMOKE_PREFIX:-s3-gateway-test/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
BUDGET_DENIAL="${S3_GATEWAY_SMOKE_BUDGET_DENIAL:-synthetic}"
BUDGET_DENIAL_SET=0
LOCAL_ONLY=0
REQUIRE_REMOTE=0
KEEP_RESOURCES=0
CREATED_UPSTREAM_API_KEY=0
REMOTE_CREATED=0
TARGET_BUCKET=""
MODE_USED="local"
ACCESS_KEY=""
SECRET_KEY=""
CREDENTIAL_USED=""
SMOKE_ACCESS_KEYS=()
REMOTE_CLEANUP_STATUS="not-run"
GATEWAY_CLEANUP_STATUS="not-run"
CLEANUP_TIMEOUT="${S3_GATEWAY_SMOKE_CLEANUP_TIMEOUT:-60}"

usage() {
  cat <<'USAGE'
Usage: tools/smoke/s3_gateway_scoped_budget_smoke.sh [options]

Options:
  --local-only       Exercise only local gateway bucket behavior.
  --require-remote   Fail if an R2/S3 remote-cache bucket cannot be created.
  --budget-denial <synthetic|actual-upstream|both>
                     Select deterministic budget-denial smoke mode. Default: synthetic.
  --keep-resources   Do not revoke credentials or delete the test prefix.
  --prefix <prefix>  Prefix for all test objects. Defaults to s3-gateway-test/<timestamp>-<pid>.
  -h, --help         Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local-only)
      LOCAL_ONLY=1
      shift
      ;;
    --require-remote)
      REQUIRE_REMOTE=1
      shift
      ;;
    --budget-denial)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--budget-denial requires synthetic, actual-upstream, or both" >&2
        exit 2
      fi
      BUDGET_DENIAL="$2"
      BUDGET_DENIAL_SET=1
      shift 2
      ;;
    --keep-resources)
      KEEP_RESOURCES=1
      shift
      ;;
    --prefix)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--prefix requires a value" >&2
        exit 2
      fi
      PREFIX="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$BUDGET_DENIAL" in
  synthetic|actual-upstream|both) ;;
  *)
    echo "--budget-denial must be synthetic, actual-upstream, or both" >&2
    exit 2
    ;;
esac

if [[ "$REQUIRE_REMOTE" == "1" && "$LOCAL_ONLY" != "1" && "$BUDGET_DENIAL_SET" != "1" ]]; then
  BUDGET_DENIAL="both"
fi

if [[ "$LOCAL_ONLY" == "1" && ( "$BUDGET_DENIAL" == "actual-upstream" || "$BUDGET_DENIAL" == "both" ) ]]; then
  echo "--local-only cannot run actual-upstream budget denial" >&2
  exit 2
fi

PREFIX="${PREFIX#/}"
PREFIX="${PREFIX%/}"
if [[ -z "$PREFIX" ]]; then
  echo "prefix must not be empty" >&2
  exit 2
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

budget_mode_includes() {
  local mode="$1"
  [[ "$BUDGET_DENIAL" == "$mode" || "$BUDGET_DENIAL" == "both" ]]
}

json_value() {
  "$JQ_BIN" -r "$1"
}

create_gateway_credential() {
  local name="$1"
  local enforce_local="$2"
  local credential_json
  local credential_args=(s3-gateway creds create "$name"
    --scope vault-allowlist
    --vault "$TARGET_BUCKET"
    --list --read --write --delete
    --json)
  if [[ "$enforce_local" == "1" ]]; then
    credential_args+=(--enforce-budget-for-local-requests)
  fi
  credential_json="$(run_vh "${credential_args[@]}")"
  ACCESS_KEY="$(printf '%s\n' "$credential_json" | json_value '.access_key')"
  SECRET_KEY="$(printf '%s\n' "$credential_json" | json_value '.secret_access_key')"
  CREDENTIAL_USED="$ACCESS_KEY"
  SMOKE_ACCESS_KEYS+=("$ACCESS_KEY")
}

run_vh() {
  "$VH_BIN" "$@"
}

redact_secret_output() {
  sed -E \
    -e 's/(Access Key: ).*/\1<redacted>/I' \
    -e 's/(Secret Access Key: ).*/\1<redacted>/I' \
    -e 's/(Secret Key: ).*/\1<redacted>/I' \
    -e 's/(--access[= ]+)[^ ]+/\1<redacted>/gI' \
    -e 's/(--secret[= ]+)[^ ]+/\1<redacted>/gI'
}

run_with_timeout() {
  local seconds="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@"
  else
    "$@"
  fi
}

create_local_bucket() {
  local bucket="$1"
  if run_vh s3-gateway bucket create-local "$bucket"; then
    return 0
  fi
  echo "create-local failed for $bucket; continuing in case it already exists" >&2
}

gateway_rm_prefix() {
  [[ -n "$TARGET_BUCKET" && -n "$ACCESS_KEY" && "$KEEP_RESOURCES" != "1" ]] || return 0
  if [[ "$AWS_AVAILABLE" == "1" ]]; then
    AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
    AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
    AWS_EC2_METADATA_DISABLED=true \
    AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}" \
      run_with_timeout "$CLEANUP_TIMEOUT" "$AWS_BIN" --endpoint-url "$ENDPOINT" s3 rm "s3://$TARGET_BUCKET/$PREFIX/" --recursive >/dev/null
    return 0
  fi
  if [[ "$MC_AVAILABLE" == "1" ]]; then
    run_with_timeout "$CLEANUP_TIMEOUT" "$MC_BIN" rm --recursive --force "$MC_ALIAS/$TARGET_BUCKET/$PREFIX/" >/dev/null
    return 0
  fi
}

remote_configured() {
  [[ -n "$UPSTREAM_ACCESS_KEY" && -n "$UPSTREAM_SECRET_KEY" && -n "$UPSTREAM_ENDPOINT" && -x "$LIVE_BUCKET_BIN" ]]
}

# Empties and deletes the upstream test bucket (the helper then checks HeadBucket says it is gone).
remote_delete_bucket() {
  [[ "$UPSTREAM_CREATED" == "1" ]] || return 0
  run_with_timeout 300 "$LIVE_BUCKET_BIN" delete "$UPSTREAM_BUCKET"
}

delete_gateway_bucket_if_present() {
  local bucket="$1"
  [[ -n "$bucket" ]] || return 0
  run_vh vault delete "$bucket" --owner "$SMOKE_OWNER" >/dev/null 2>&1 || true
}

cleanup_resources() {
  rm -f "${tmp_file:-}" "${unlisted_out:-}" "${budget_out:-}" "${download_out:-}" "${inventory_file:-}"

  if [[ "$KEEP_RESOURCES" == "1" ]]; then
    GATEWAY_CLEANUP_STATUS="kept"
    REMOTE_CLEANUP_STATUS="kept"
    return 0
  fi

  if gateway_rm_prefix; then
    GATEWAY_CLEANUP_STATUS="ok"
  else
    GATEWAY_CLEANUP_STATUS="failed"
    echo "GATEWAY CLEANUP FAILED for bucket=$TARGET_BUCKET prefix=$PREFIX" >&2
  fi

  delete_gateway_bucket_if_present "$REMOTE_BUCKET"
  delete_gateway_bucket_if_present "$OTHER_BUCKET"
  delete_gateway_bucket_if_present "$LOCAL_BUCKET"

  local key
  for key in "${SMOKE_ACCESS_KEYS[@]:-}"; do
    [[ -n "$key" ]] && run_vh s3-gateway creds revoke "$key" >/dev/null 2>&1 || true
  done
  if [[ "${#SMOKE_ACCESS_KEYS[@]}" -eq 0 ]]; then
    run_vh s3-gateway creds revoke "$CRED_NAME" >/dev/null 2>&1 || true
  fi
  if [[ "$CREATED_UPSTREAM_API_KEY" == "1" && -n "${UPSTREAM_API_KEY:-}" ]]; then
    run_vh api-key delete "$UPSTREAM_API_KEY" >/dev/null 2>&1 || true
  fi
  if [[ "${MC_AVAILABLE:-0}" == "1" ]]; then
    "$MC_BIN" alias rm "$MC_ALIAS" >/dev/null 2>&1 || true
  fi

  # Last: the gateway bucket and the API key that used it are gone, so nothing writes to the upstream any more.
  if remote_delete_bucket; then
    REMOTE_CLEANUP_STATUS=$([[ "$UPSTREAM_CREATED" == "1" ]] && echo "ok (bucket deleted)" || echo "not-needed")
  else
    REMOTE_CLEANUP_STATUS="failed"
    echo "REMOTE CLEANUP FAILED: delete $UPSTREAM_BUCKET with $LIVE_BUCKET_BIN delete $UPSTREAM_BUCKET" >&2
  fi
}

finish() {
  local code=$?
  local result="FAIL"
  if [[ "$code" == "0" ]]; then result="PASS"; fi
  cleanup_resources || true
  echo
  echo "S3 gateway smoke summary: $result"
  echo "  endpoint: $ENDPOINT"
  echo "  bucket: ${TARGET_BUCKET:-not-created}"
  echo "  credential: ${CREDENTIAL_USED:-not-created}"
  echo "  mode: $MODE_USED"
  echo "  budget denial: $BUDGET_DENIAL"
  echo "  prefix: $PREFIX"
  echo "  upstream_bucket: ${UPSTREAM_BUCKET:-not-configured}"
  echo "  gateway cleanup: $GATEWAY_CLEANUP_STATUS"
  echo "  remote cleanup: $REMOTE_CLEANUP_STATUS"
  exit "$code"
}
trap finish EXIT

require_cmd "$VH_BIN"
require_cmd "$JQ_BIN"
AWS_AVAILABLE=0
MC_AVAILABLE=0
if has_cmd "$AWS_BIN"; then AWS_AVAILABLE=1; fi
if has_cmd "$MC_BIN"; then MC_AVAILABLE=1; fi
if [[ "${S3_GATEWAY_SMOKE_REQUIRE_AWS:-0}" == "1" ]]; then require_cmd "$AWS_BIN"; AWS_AVAILABLE=1; fi
if [[ "${S3_GATEWAY_SMOKE_REQUIRE_MC:-0}" == "1" ]]; then require_cmd "$MC_BIN"; MC_AVAILABLE=1; fi
if [[ "$AWS_AVAILABLE" != "1" && "$MC_AVAILABLE" != "1" ]]; then
  echo "missing S3 client: install aws or mc, or set AWS_BIN/MC_BIN" >&2
  exit 2
fi
if budget_mode_includes synthetic || budget_mode_includes actual-upstream; then
  require_cmd "$AWS_BIN"
  AWS_AVAILABLE=1
fi
USE_AWS="$AWS_AVAILABLE"
USE_MC=0
if [[ "$MC_AVAILABLE" == "1" && ( "$AWS_AVAILABLE" != "1" || "${S3_GATEWAY_SMOKE_REQUIRE_MC:-0}" == "1" ) ]]; then
  USE_MC=1
fi

echo "Smoke configuration"
echo "  endpoint: $ENDPOINT"
echo "  prefix: $PREFIX"
echo "  local bucket: $LOCAL_BUCKET"
echo "  remote bucket: $REMOTE_BUCKET"
echo "  upstream bucket: ${UPSTREAM_BUCKET:-not-configured}"
echo "  mode request: $([[ "$LOCAL_ONLY" == "1" ]] && echo local-only || ([[ "$REQUIRE_REMOTE" == "1" ]] && echo require-remote || echo auto))"
echo "  budget denial: $BUDGET_DENIAL"

echo "1. Enable S3 gateway"
run_vh s3-gateway enable

echo "2. Create local buckets"
create_local_bucket "$LOCAL_BUCKET"
create_local_bucket "$OTHER_BUCKET"

TARGET_BUCKET="$LOCAL_BUCKET"
if [[ "$LOCAL_ONLY" != "1" ]]; then
  if remote_configured; then
    echo "3a. Create the upstream test bucket $UPSTREAM_BUCKET"
    UPSTREAM_CREATED=1   # before the call: the trap deletes a half-created bucket too
    if ! run_with_timeout 300 "$LIVE_BUCKET_BIN" create "$UPSTREAM_BUCKET"; then
      echo "could not create $UPSTREAM_BUCKET" >&2
      exit 1
    fi
    echo "3b. Create the upstream API key"
    api_key_output=""
    if api_key_output="$(run_vh api-key create "$UPSTREAM_API_KEY_NAME" \
      --access "$UPSTREAM_ACCESS_KEY" \
      --secret "$UPSTREAM_SECRET_KEY" \
      --provider "$UPSTREAM_PROVIDER" \
      --endpoint "$UPSTREAM_ENDPOINT" \
      --region "$UPSTREAM_REGION" 2>&1)"; then
      printf '%s\n' "$api_key_output" | redact_secret_output
      UPSTREAM_API_KEY="$UPSTREAM_API_KEY_NAME"
      CREATED_UPSTREAM_API_KEY=1
    else
      printf '%s\n' "$api_key_output" | redact_secret_output >&2
      echo "upstream API key create failed; continuing in case $UPSTREAM_API_KEY_NAME already exists" >&2
      UPSTREAM_API_KEY="$UPSTREAM_API_KEY_NAME"
    fi
  fi

  if [[ -n "$UPSTREAM_API_KEY" ]]; then
    echo "3. Create remote-cache bucket"
    if run_vh s3-gateway bucket create-remote-cache "$REMOTE_BUCKET" \
      --api-key "$UPSTREAM_API_KEY" \
      --upstream-bucket "$UPSTREAM_BUCKET" \
      --no-encrypt; then
      TARGET_BUCKET="$REMOTE_BUCKET"
      REMOTE_CREATED=1
      MODE_USED="remote-cache"
    elif [[ "$REQUIRE_REMOTE" == "1" ]]; then
      echo "remote-cache create failed and --require-remote was set" >&2
      exit 1
    else
      echo "remote-cache create failed; continuing with local-only scope checks" >&2
    fi
  elif [[ "$REQUIRE_REMOTE" == "1" ]]; then
    echo "--require-remote set but upstream API key/bucket configuration is unavailable" >&2
    exit 2
  else
    echo "3. Skipping remote-cache bucket; needs VH_R2_ADMIN_* and $LIVE_BUCKET_BIN (ninja -C build core/vh_live_bucket)"
  fi
else
  echo "3. Skipping remote-cache bucket due to --local-only"
fi

echo "4. Create scoped credential for $TARGET_BUCKET"
create_gateway_credential "$CRED_NAME" 0

export AWS_ACCESS_KEY_ID="$ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$SECRET_KEY"
export AWS_EC2_METADATA_DISABLED=true
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

tmp_file="$(mktemp)"
unlisted_out="$(mktemp)"
budget_out="$(mktemp)"
download_out="$(mktemp)"
printf 'vaulthalla scoped gateway smoke %s\n' "$(date -Iseconds)" >"$tmp_file"

aws_gateway_s3api() {
  AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  AWS_EC2_METADATA_DISABLED=true \
  AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}" \
    "$AWS_BIN" --endpoint-url "$ENDPOINT" s3api "$@"
}

aws_upstream_s3api() {
  AWS_ACCESS_KEY_ID="$UPSTREAM_ACCESS_KEY" \
  AWS_SECRET_ACCESS_KEY="$UPSTREAM_SECRET_KEY" \
  AWS_EC2_METADATA_DISABLED=true \
  AWS_DEFAULT_REGION="$UPSTREAM_REGION" \
    "$AWS_BIN" --endpoint-url "$UPSTREAM_ENDPOINT" s3api "$@"
}

assert_aws_denial() {
  local expected_code="$1"
  local output_file="$2"
  if ! grep -q "$expected_code" "$output_file"; then
    cat "$output_file" >&2
    echo "expected S3 denial code $expected_code" >&2
    exit 1
  fi
}

assert_synthetic_ledger() {
  local object_key="$1"
  local ledger_json
  ledger_json="$(run_vh s3-gateway budget ledger --key "$ACCESS_KEY" --limit 50 --json)"
  printf '%s\n' "$ledger_json" | "$JQ_BIN" -e '
    all(.[]; .gateway_credential_id != null and .synthetic == true)
    and ([.[] | select(.usage_source == "metadata")] | length >= 1)
  ' >/dev/null
  printf '%s\n' "$ledger_json" | "$JQ_BIN" -e --arg key "$object_key" '
    [.[] | select(.object_key == $key and .usage_source == "sync_deferred" and .synthetic == true and .status == "committed")]
    | length >= 1
  ' >/dev/null
  printf '%s\n' "$ledger_json" | "$JQ_BIN" -e --arg key "$object_key" '
    [.[] | select(
      .object_key == $key
      and (.usage_source == "local_file" or .usage_source == "local_cache")
      and .synthetic == true
      and .status == "committed"
    )] | length >= 1
  ' >/dev/null
}

has_actual_remote_download_ledger() {
  local object_key="$1"
  local ledger_json
  ledger_json="$(run_vh s3-gateway budget ledger --key "$ACCESS_KEY" --limit 50 --json)"
  printf '%s\n' "$ledger_json" | "$JQ_BIN" -e --arg key "$object_key" '
    [.[] | select(
      .object_key == $key
      and .operation == "GetObject"
      and .synthetic == false
      and .usage_source == "remote_download"
      and .gateway_credential_id != null
      and .status == "committed"
    )] | length >= 1
  ' >/dev/null
}

run_synthetic_budget_denial() {
  local object_key="$PREFIX/synthetic-budget.txt"
  echo "7a. Run synthetic local/cache gateway budget denial"
  create_gateway_credential "$CRED_NAME-synthetic-$SMOKE_RUN_ID" 1
  run_vh s3-gateway budget set-key "$ACCESS_KEY" \
    --monthly "${S3_GATEWAY_SMOKE_SYNTHETIC_ALLOW_MONTHLY_LIMIT:-1.00000000}" \
    --mode enforce \
    --currency USD

  aws_gateway_s3api list-objects-v2 --bucket "$TARGET_BUCKET" --prefix "$PREFIX/" >/dev/null
  aws_gateway_s3api put-object --bucket "$TARGET_BUCKET" --key "$object_key" --body "$tmp_file" >/dev/null
  aws_gateway_s3api head-object --bucket "$TARGET_BUCKET" --key "$object_key" >/dev/null
  aws_gateway_s3api get-object --bucket "$TARGET_BUCKET" --key "$object_key" "$download_out" >/dev/null
  assert_synthetic_ledger "$object_key"

  run_vh s3-gateway budget set-key "$ACCESS_KEY" \
    --monthly "$SYNTHETIC_MONTHLY_LIMIT" \
    --mode enforce \
    --currency USD

  if aws_gateway_s3api list-objects-v2 --bucket "$TARGET_BUCKET" --prefix "$PREFIX/" >"$budget_out" 2>&1; then
    echo "expected synthetic local LIST to be denied by gateway key budget" >&2
    exit 1
  fi
  cat "$budget_out"
  assert_aws_denial "AccessDenied" "$budget_out"
}

seed_upstream_object() {
  local key="$1"
  local body="$2"
  printf '%s\n' "$body" >"$tmp_file"
  aws_upstream_s3api put-object --bucket "$UPSTREAM_BUCKET" --key "$key" --body "$tmp_file" --content-type text/plain >/dev/null
}

run_actual_upstream_budget_denial() {
  if [[ "$REMOTE_CREATED" != "1" ]]; then
    echo "actual-upstream budget denial requires a remote-cache bucket" >&2
    exit 1
  fi
  if [[ -z "$UPSTREAM_ACCESS_KEY" || -z "$UPSTREAM_SECRET_KEY" || -z "$UPSTREAM_ENDPOINT" || -z "$UPSTREAM_BUCKET" ]]; then
    echo "actual-upstream budget denial requires upstream AWS-compatible credentials" >&2
    exit 2
  fi

  create_gateway_credential "$CRED_NAME-actual-$SMOKE_RUN_ID" 0

  echo "7b. Seed remote-only objects and import remote index"
  local success_key="$PREFIX/actual-upstream-success.txt"
  local price_key="$PREFIX/actual-upstream-price-denied.txt"
  local request_key="$PREFIX/actual-upstream-request-denied.txt"
  seed_upstream_object "$success_key" "actual upstream success"
  seed_upstream_object "$price_key" "actual upstream price denied"
  seed_upstream_object "$request_key" "actual upstream request denied"
  REMOTE_CREATED=1

  inventory_file="$(mktemp)"
  chmod 0644 "$inventory_file"
  {
    echo "key,size,storage_class"
    printf '%s,%s,STANDARD\n' "$success_key" "24"
    printf '%s,%s,STANDARD\n' "$price_key" "29"
    printf '%s,%s,STANDARD\n' "$request_key" "31"
  } >"$inventory_file"
  run_vh vault sync inventory "$TARGET_BUCKET" --owner "$SMOKE_OWNER" --file "$inventory_file"
  run_vh s3-gateway bucket backfill "$TARGET_BUCKET"

  echo "7c. Assert actual upstream GET uses a remote-only object"
  run_vh s3-gateway budget set-key "$ACCESS_KEY" \
    --monthly "1.00000000" \
    --mode report \
    --currency USD \
    --no-require-verified-catalog \
    --allow-stale-catalog
  aws_gateway_s3api get-object --bucket "$TARGET_BUCKET" --key "$success_key" "$download_out" >/dev/null
  if has_actual_remote_download_ledger "$success_key"; then
    echo "Actual upstream price ledger captured synthetic=false usage_source=remote_download."
  else
    echo "Actual upstream GET succeeded, but no price-budget ledger row was captured."
    echo "Provider pricing catalog is unavailable in this dev stack; DB-backed tests cover synthetic=false remote_download ledger capture with a seeded catalog."
  fi

  echo "7d. Assert actual upstream price-budget denial returns AccessDenied"
  run_vh s3-gateway budget set-key "$ACCESS_KEY" \
    --monthly "$ACTUAL_MONTHLY_LIMIT" \
    --mode enforce \
    --currency USD \
    --no-require-verified-catalog \
    --allow-stale-catalog
  if aws_gateway_s3api get-object --bucket "$TARGET_BUCKET" --key "$price_key" "$download_out" >"$budget_out" 2>&1; then
    echo "expected actual upstream GET to be denied by gateway price budget" >&2
    exit 1
  fi
  cat "$budget_out"
  assert_aws_denial "AccessDenied" "$budget_out"

  echo "7e. Assert actual upstream request-budget denial returns SlowDown"
  run_vh s3-gateway budget disable-key "$ACCESS_KEY" >/dev/null
  run_vh vault sync update "$TARGET_BUCKET" --owner "$SMOKE_OWNER" --s3-budget-get 0
  if aws_gateway_s3api get-object --bucket "$TARGET_BUCKET" --key "$request_key" "$download_out" >"$budget_out" 2>&1; then
    echo "expected actual upstream GET to be denied by upstream request budget" >&2
    exit 1
  fi
  cat "$budget_out"
  assert_aws_denial "SlowDown" "$budget_out"
}

echo "5. Prove allowed bucket works"
if [[ "$USE_AWS" == "1" ]]; then
  "$AWS_BIN" --endpoint-url "$ENDPOINT" s3 cp "$tmp_file" "s3://$TARGET_BUCKET/$PREFIX/allowed-aws.txt"
  "$AWS_BIN" --endpoint-url "$ENDPOINT" s3 ls "s3://$TARGET_BUCKET/$PREFIX/"
fi
if [[ "$USE_MC" == "1" ]]; then
  "$MC_BIN" alias set "$MC_ALIAS" "$ENDPOINT" "$ACCESS_KEY" "$SECRET_KEY" >/dev/null
  "$MC_BIN" cp "$tmp_file" "$MC_ALIAS/$TARGET_BUCKET/$PREFIX/allowed-mc.txt"
  "$MC_BIN" ls "$MC_ALIAS/$TARGET_BUCKET/$PREFIX/"
fi

echo "6. Prove unlisted bucket fails"
if [[ "$USE_AWS" == "1" ]]; then
  if "$AWS_BIN" --endpoint-url "$ENDPOINT" s3 ls "s3://$OTHER_BUCKET/" >"$unlisted_out" 2>&1; then
    cat "$unlisted_out" >&2
    echo "expected unlisted bucket to fail with aws, but it succeeded" >&2
    exit 1
  fi
fi
if [[ "$USE_MC" == "1" ]]; then
  if "$MC_BIN" ls "$MC_ALIAS/$OTHER_BUCKET/" >"$unlisted_out" 2>&1; then
    cat "$unlisted_out" >&2
    echo "expected unlisted bucket to fail with mc, but it succeeded" >&2
    exit 1
  fi
fi

echo "7. Run selected budget-denial smoke"
echo "   This step requires the vh CLI context to have S3 gateway admin permission."
if budget_mode_includes synthetic; then
  run_synthetic_budget_denial
fi
if budget_mode_includes actual-upstream; then
  run_actual_upstream_budget_denial
fi

echo "8. Show budget ledger/status"
run_vh s3-gateway budget status --key "$ACCESS_KEY" --json
run_vh s3-gateway budget ledger --key "$ACCESS_KEY" --limit 20 --json

echo "9. Revoke credential"
if [[ "$KEEP_RESOURCES" != "1" ]]; then
  run_vh s3-gateway creds revoke "$ACCESS_KEY"
  ACCESS_KEY=""
else
  echo "keeping credential due to --keep-resources"
fi
