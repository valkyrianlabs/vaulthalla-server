#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"
# shellcheck source=tools/e2e/load_env.sh
source "$REPO_ROOT/tools/e2e/load_env.sh"

RESULT_DIR="${VAULTHALLA_E2E_RESULT_DIR:-$REPO_ROOT/test-results/s3-gateway-e2e}"
PRIVATE_ENV_FILE="${VAULTHALLA_E2E_ENV_FILE:-$RESULT_DIR/e2e.env}"
E2E_USER_DEFAULT="e2e_s3_gateway_admin"
E2E_USER_FROM_ENV="${VAULTHALLA_E2E_USER:-}"
E2E_USER="${E2E_USER_FROM_ENV:-$E2E_USER_DEFAULT}"
E2E_EMAIL="${VAULTHALLA_E2E_EMAIL:-}"
VH_BIN="${VH_BIN:-vh}"
PRINT_EXPORTS=0
FORCE_PROVISION="${VAULTHALLA_E2E_FORCE_PROVISION:-0}"
FRESH_USER="${VAULTHALLA_E2E_FRESH_USER:-0}"
SETUP_COMMAND_RUN="not-run"
TMP_FILES=()
LOCAL_DEV_DB_NAME=""

cleanup_tmp_files() {
  local file
  for file in "${TMP_FILES[@]}"; do
    if [[ -n "$file" ]]; then
      rm -f "$file"
    fi
  done
  return 0
}
trap cleanup_tmp_files EXIT

usage() {
  cat <<'USAGE'
Usage: tools/e2e/provision_e2e_user.sh [options]

Options:
  --force          Seed a fresh E2E password even if credentials already exist.
  --fresh-user     Generate a new E2E username, ignoring configured E2E credentials.
  --print-exports  Print shell exports for wrapper eval.
  -h, --help       Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE_PROVISION=1
      shift
      ;;
    --fresh-user)
      FORCE_PROVISION=1
      FRESH_USER=1
      shift
      ;;
    --print-exports)
      PRINT_EXPORTS=1
      shift
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

if [[ "$FRESH_USER" == "1" ]]; then
  E2E_USER_FROM_ENV=""
  E2E_USER="e2e_s3gw_$(date -u +%Y%m%d%H%M%S)_$$"
  E2E_EMAIL=""
elif [[ "$FORCE_PROVISION" == "1" && -z "$E2E_USER_FROM_ENV" ]]; then
  E2E_USER="e2e_s3gw_$(date -u +%Y%m%d%H%M%S)_$$"
fi
if [[ -z "$E2E_EMAIL" ]]; then
  E2E_EMAIL="$E2E_USER@localhost.invalid"
fi

shell_export() {
  local key="$1"
  local value="$2"
  printf 'export %s=%q\n' "$key" "$value"
}

emit_exports() {
  shell_export VAULTHALLA_E2E_USER "$VAULTHALLA_E2E_USER"
  shell_export VAULTHALLA_E2E_PASSWORD "$VAULTHALLA_E2E_PASSWORD"
}

write_private_env() {
  install -d -m 0700 "$RESULT_DIR"
  local tmp
  tmp="$(mktemp "$RESULT_DIR/e2e.env.XXXXXX")"
  chmod 0600 "$tmp"
  {
    shell_export VAULTHALLA_E2E_USER "$VAULTHALLA_E2E_USER"
    shell_export VAULTHALLA_E2E_PASSWORD "$VAULTHALLA_E2E_PASSWORD"
  } >"$tmp"
  mv "$tmp" "$PRIVATE_ENV_FILE"
  chmod 0600 "$PRIVATE_ENV_FILE"
}

load_private_env_if_present() {
  [[ -f "$PRIVATE_ENV_FILE" ]] || return 1
  local shell_flags="$-"
  set +u
  set -a
  # shellcheck disable=SC1090
  source "$PRIVATE_ENV_FILE"
  set +a
  [[ "$shell_flags" == *u* ]] && set -u
  [[ -n "${VAULTHALLA_E2E_USER:-}" && -n "${VAULTHALLA_E2E_PASSWORD:-}" ]]
}

finish_with_existing_credentials() {
  echo "E2E credentials loaded for user '${VAULTHALLA_E2E_USER}' with password redacted." >&2
  if [[ "$PRINT_EXPORTS" == "1" ]]; then
    emit_exports
  fi
  return 0
}

reload_known_env() {
  # Re-source through the common loader after setup scripts update deploy/bashrc
  # or deploy/vaulthalla.env.
  # shellcheck source=tools/e2e/load_env.sh
  source "$REPO_ROOT/tools/e2e/load_env.sh"
}

ensure_test_db_env() {
  if vh_e2e_require_test_db_env >/dev/null 2>&1; then
    return 0
  fi

  # The shared test role (and the script that rotated its password into the repo's env files) is gone; nothing here
  # creates or rewrites credentials. Point VH_TEST_DB_* at the install the E2E run targets, explicitly.
  echo "VH_TEST_DB_* is incomplete: export VH_TEST_DB_{USER,PASS,HOST,PORT,NAME} for the database of the install" >&2
  echo "under test (see tools/e2e/load_env.sh); E2E no longer provisions a shared test role." >&2
  return 1
}

guard_test_db_target() {
  if [[ "${VAULTHALLA_E2E_ALLOW_NON_TEST_DB:-0}" == "1" ]]; then
    return 0
  fi

  case "${VH_TEST_DB_NAME:-}:${VH_TEST_DB_USER:-}" in
    *test*:*) return 0 ;;
    *:vaulthalla_test) return 0 ;;
  esac

  echo "Refusing direct E2E DB seed because VH_TEST_DB_* does not look like a test database." >&2
  echo "Set VAULTHALLA_E2E_ALLOW_NON_TEST_DB=1 only for an explicitly approved non-production target." >&2
  vh_e2e_redacted_env_report >&2
  return 1
}

hash_password_with_existing_format() {
  local password_file="$1"
  python3 - "$password_file" <<'PY'
import ctypes
import ctypes.util
import pathlib
import sys

password = pathlib.Path(sys.argv[1]).read_bytes()
libname = ctypes.util.find_library("sodium") or "libsodium.so"
sodium = ctypes.cdll.LoadLibrary(libname)

if sodium.sodium_init() < 0:
    raise SystemExit("libsodium initialization failed")

sodium.crypto_pwhash_str.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulonglong,
    ctypes.c_ulonglong,
    ctypes.c_size_t,
]
sodium.crypto_pwhash_str.restype = ctypes.c_int

try:
    sodium.crypto_pwhash_opslimit_moderate.restype = ctypes.c_size_t
    sodium.crypto_pwhash_memlimit_moderate.restype = ctypes.c_size_t
    opslimit = sodium.crypto_pwhash_opslimit_moderate()
    memlimit = sodium.crypto_pwhash_memlimit_moderate()
except AttributeError:
    opslimit = 3
    memlimit = 268435456

buf = ctypes.create_string_buffer(128)
if sodium.crypto_pwhash_str(buf, password, len(password), opslimit, memlimit) != 0:
    raise SystemExit("password hashing failed")

print(buf.value.decode("utf-8"))
PY
}

psql_test_db() {
  PGPASSWORD="$VH_TEST_DB_PASS" psql \
    --host "$VH_TEST_DB_HOST" \
    --port "$VH_TEST_DB_PORT" \
    --username "$VH_TEST_DB_USER" \
    --dbname "$VH_TEST_DB_NAME" \
    --set ON_ERROR_STOP=1 \
    "$@"
}

config_database_value() {
  local key="$1"
  local config_path="${VH_PATH_TO_CONFIG:-$REPO_ROOT/deploy/config/config.yaml}"
  [[ -f "$config_path" ]] || return 1
  awk -v key="$key" '
    /^database:/ { in_db = 1; next }
    in_db && /^[^[:space:]]/ { in_db = 0 }
    in_db {
      sub(/[[:space:]]*#.*/, "")
      if ($0 ~ "^[[:space:]]*" key "[[:space:]]*:") {
        sub("^[[:space:]]*" key "[[:space:]]*:[[:space:]]*", "")
        gsub(/^["'\'']|["'\'']$/, "")
        print
        exit
      }
    }
  ' "$config_path"
}

local_dev_db_seed_allowed() {
  if [[ "${VAULTHALLA_E2E_ALLOW_LOCAL_DEV_DB_SEED:-0}" == "1" ]]; then
    return 0
  fi

  case "${VH_BUILD_MODE:-}" in
    dev|debug|test) ;;
    *) return 1 ;;
  esac

  local host db_name db_user
  host="$(config_database_value host || true)"
  db_name="$(config_database_value name || true)"
  db_user="$(config_database_value user || true)"

  case "$host" in
    localhost|127.0.0.1|"") ;;
    *) return 1 ;;
  esac

  [[ "$db_name" == "vaulthalla" || "$db_name" == *dev* || "$db_name" == *test* ]] || return 1
  [[ "$db_user" == "vaulthalla" || "$db_user" == *test* ]] || return 1
  LOCAL_DEV_DB_NAME="$db_name"
  return 0
}

psql_local_dev_db() {
  [[ -n "$LOCAL_DEV_DB_NAME" ]] || return 1
  sudo -n -u postgres psql \
    --dbname "$LOCAL_DEV_DB_NAME" \
    --set ON_ERROR_STOP=1 \
    "$@"
}

ensure_required_admin_permissions() {
  local role_name
  if ! local_dev_db_seed_allowed; then
    return 0
  fi

  command -v sudo >/dev/null 2>&1 || return 0
  command -v psql >/dev/null 2>&1 || return 0
  if ! sudo -n -u postgres psql --dbname "$LOCAL_DEV_DB_NAME" --tuples-only --no-align --command "SELECT 1" >/dev/null 2>&1; then
    return 0
  fi

  role_name="$(
    psql_local_dev_db --quiet --tuples-only --no-align --set "e2e_user=$E2E_USER" <<'SQL'
WITH target_user AS (
  SELECT id
  FROM users
  WHERE name = :'e2e_user'
),
required_role AS (
  SELECT id
  FROM admin_role
  WHERE name = 'super_admin'
),
upsert_assignment AS (
  INSERT INTO admin_role_assignments (user_id, role_id)
  SELECT target_user.id, required_role.id
  FROM target_user, required_role
  ON CONFLICT (user_id) DO UPDATE SET
    role_id = EXCLUDED.role_id,
    assigned_at = CURRENT_TIMESTAMP
  RETURNING role_id
),
activate_user AS (
  UPDATE users
  SET is_active = TRUE,
      updated_at = NOW()
  WHERE id IN (SELECT id FROM target_user)
  RETURNING id
)
SELECT admin_role.name
FROM users
JOIN admin_role_assignments ON admin_role_assignments.user_id = users.id
JOIN admin_role ON admin_role.id = admin_role_assignments.role_id
WHERE users.name = :'e2e_user'
  AND EXISTS (SELECT 1 FROM activate_user)
  AND EXISTS (SELECT 1 FROM upsert_assignment);
SQL
  )"

  if ! printf '%s\n' "$role_name" | grep -qx 'super_admin'; then
    echo "Unable to verify required E2E admin permissions for '$E2E_USER' in local dev DB." >&2
    return 1
  fi

  echo "Verified E2E user '$E2E_USER' has required admin permissions in local dev DB." >&2
}

provision_with_cli() {
  command -v "$VH_BIN" >/dev/null 2>&1 || return 1

  local output password
  if output="$("$VH_BIN" user create "$E2E_USER" --role admin --email "$E2E_EMAIL" 2>&1)"; then
    password="$(printf '%s\n' "$output" | sed -n 's/^Password: //p' | tail -n 1)"
    if [[ -z "$password" ]]; then
      echo "vh user create succeeded but did not return a parseable password." >&2
      return 1
    fi
    export VAULTHALLA_E2E_USER="$E2E_USER"
    export VAULTHALLA_E2E_PASSWORD="$password"
    ensure_required_admin_permissions
    write_private_env
    echo "Provisioned E2E admin user with vh CLI; password stored in $PRIVATE_ENV_FILE (0600)." >&2
    return 0
  fi

  echo "vh CLI provisioning did not complete; falling back if a safe DB seed is available." >&2
  return 1
}

write_seed_sql() {
  local sql_file="$1"
  cat >"$sql_file" <<'SQL'
WITH admin_role_row AS (
  SELECT id
  FROM admin_role
  WHERE name = 'super_admin'
),
upserted_user AS (
  INSERT INTO users (name, email, password_hash, is_active)
  SELECT :'e2e_user', :'e2e_email', :'password_hash', TRUE
  WHERE EXISTS (SELECT 1 FROM admin_role_row)
  ON CONFLICT (name) DO UPDATE SET
    email = COALESCE(users.email, EXCLUDED.email),
    password_hash = EXCLUDED.password_hash,
    is_active = TRUE,
    updated_at = NOW()
  RETURNING id
)
INSERT INTO admin_role_assignments (user_id, role_id)
SELECT upserted_user.id, admin_role_row.id
FROM upserted_user, admin_role_row
ON CONFLICT (user_id) DO UPDATE SET
  role_id = EXCLUDED.role_id,
  assigned_at = CURRENT_TIMESTAMP;
SQL
}

new_e2e_password_hash() {
  local password_file="$1"
  local password password_hash
  password="$(openssl rand -base64 48 | tr -d '\n')"
  chmod 0600 "$password_file"
  printf '%s' "$password" >"$password_file"
  password_hash="$(hash_password_with_existing_format "$password_file")"
  printf '%s\n' "$password"
  printf '%s\n' "$password_hash"
}

provision_with_local_dev_db() {
  local_dev_db_seed_allowed || return 1
  command -v sudo >/dev/null 2>&1 || return 1
  command -v psql >/dev/null 2>&1 || return 1
  if ! sudo -n -u postgres psql --dbname "$LOCAL_DEV_DB_NAME" --tuples-only --no-align --command "SELECT 1" >/dev/null 2>&1; then
    return 1
  fi

  local password password_file password_hash sql_file
  local generated=()
  password_file="$(mktemp "$RESULT_DIR/e2e.password.XXXXXX")"
  sql_file="$(mktemp "$RESULT_DIR/e2e.seed.XXXXXX.sql")"
  TMP_FILES+=("$password_file" "$sql_file")
  chmod 0600 "$password_file" "$sql_file"
  mapfile -t generated < <(new_e2e_password_hash "$password_file")
  password="${generated[0]}"
  password_hash="${generated[1]}"
  write_seed_sql "$sql_file"

  psql_local_dev_db \
    --quiet \
    --variable "e2e_user=$E2E_USER" \
    --variable "e2e_email=$E2E_EMAIL" \
    --variable "password_hash=$password_hash" \
    <"$sql_file" >/dev/null

  export VAULTHALLA_E2E_USER="$E2E_USER"
  export VAULTHALLA_E2E_PASSWORD="$password"
  write_private_env
  echo "Provisioned E2E admin user in local dev DB '$LOCAL_DEV_DB_NAME'; password stored in $PRIVATE_ENV_FILE (0600)." >&2
}

provision_with_test_db() {
  ensure_test_db_env
  guard_test_db_target
  command -v psql >/dev/null 2>&1 || {
    echo "psql is required for direct test DB E2E user provisioning." >&2
    return 1
  }

  local password password_file password_hash sql_file
  local generated=()
  password_file="$(mktemp "$RESULT_DIR/e2e.password.XXXXXX")"
  sql_file="$(mktemp "$RESULT_DIR/e2e.seed.XXXXXX.sql")"
  TMP_FILES+=("$password_file" "$sql_file")
  chmod 0600 "$password_file" "$sql_file"
  mapfile -t generated < <(new_e2e_password_hash "$password_file")
  password="${generated[0]}"
  password_hash="${generated[1]}"
  write_seed_sql "$sql_file"

  psql_test_db \
    --quiet \
    --variable "e2e_user=$E2E_USER" \
    --variable "e2e_email=$E2E_EMAIL" \
    --variable "password_hash=$password_hash" \
    --file "$sql_file" >/dev/null

  export VAULTHALLA_E2E_USER="$E2E_USER"
  export VAULTHALLA_E2E_PASSWORD="$password"
  write_private_env
  echo "Provisioned E2E admin user in VH_TEST_DB_*; password stored in $PRIVATE_ENV_FILE (0600)." >&2
}

install -d -m 0700 "$RESULT_DIR"

if [[ "$FORCE_PROVISION" != "1" && -n "${VAULTHALLA_E2E_USER:-}" && -n "${VAULTHALLA_E2E_PASSWORD:-}" ]]; then
  ensure_required_admin_permissions
  finish_with_existing_credentials
  exit 0
fi

if [[ "$FORCE_PROVISION" != "1" ]] && load_private_env_if_present; then
  ensure_required_admin_permissions
  finish_with_existing_credentials
  exit 0
fi

if [[ "$FORCE_PROVISION" == "1" ]] && provision_with_local_dev_db; then
  finish_with_existing_credentials
  exit 0
fi

if ! provision_with_cli; then
  if ! provision_with_local_dev_db; then
    provision_with_test_db
  fi
fi

finish_with_existing_credentials
