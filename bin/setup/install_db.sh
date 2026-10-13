#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$ROOT_DIR/bin/lib/dev_mode.sh"
source "$ROOT_DIR/bin/lib/platform.sh"
vh_instance_layout "$(vh_selected_instance)"

echo "🔐 Creating PostgreSQL user and database..."

DB_NAME="$VH_DB_NAME"
DB_ROLE="$VH_DB_ROLE"
PENDING_DB_PASS_FILE="$VH_RUNTIME_DIR/db_password"

DEV_MODE=false
vh_is_dev_mode && DEV_MODE=true

# ── macOS: the instance's own PostgreSQL 16 cluster ───────────────────────────────────────────────────────────────
# Homebrew's postgresql@16 binaries, a cluster owned by the instance's service account in its support dir, a
# LaunchDaemon (<label prefix>.postgres) so it starts at boot without a login, 127.0.0.1:5432+offset only, scram
# everywhere. The superuser password and the role's password live in 0600 files of the service account and only ever
# travel file -> file (psql reads them itself); nothing secret reaches a command line or the terminal.
darwin_cluster() {
  local pgbin="${VH_PG_BIN:-$(brew --prefix postgresql@16 2>/dev/null || true)/bin}"
  local data="$VH_PG_DIR/data" superpw="$VH_PG_DIR/superuser.pw" pgpass="$VH_PG_DIR/pgpass"
  local plist="/Library/LaunchDaemons/$VH_PG_LABEL.plist" acct="$VH_ACCOUNT"
  [ -x "$pgbin/initdb" ] || vh_dry_run || vh_die "postgresql@16 is not installed (brew bundle --file tools/macos/Brewfile)"
  as_svc() { vh_as "$acct" "$@"; }

  vh_priv install -d -m 0700 -o "$acct" -g "$acct" "$VH_PG_DIR"
  if vh_dry_run || ! vh_priv test -f "$data/PG_VERSION"; then
    echo "🐘 initdb $data (owner $acct, 127.0.0.1:$VH_PG_PORT)"
    openssl rand -hex 24 | vh_priv_write "$superpw" 0600 "$acct:$acct"
    as_svc "$pgbin/initdb" -D "$data" -U postgres -E UTF8 --locale=C --auth-local=scram-sha-256 \
      --auth-host=scram-sha-256 --pwfile="$superpw" >/dev/null
    printf "\n# bin/setup/install_db.sh: the %s instance's private cluster\nlisten_addresses = '127.0.0.1'\nport = %s\nunix_socket_directories = '%s'\n" \
      "$VH_INSTANCE" "$VH_PG_PORT" "$VH_PG_DIR" | as_svc tee -a "$data/postgresql.conf" >/dev/null
  else
    echo "🐘 keeping the existing cluster in $data"
  fi
  # libpq's password file for the superuser, built by root from the 0600 file (the password stays off argv).
  vh_priv sh -c 'umask 077; printf "127.0.0.1:%s:*:postgres:%s\n" "$1" "$(cat "$2")" > "$3"; chown "$4:$4" "$3"' \
    sh "$VH_PG_PORT" "$superpw" "$pgpass" "$acct"

  cat <<EOF | vh_priv_write "$plist" 0644 root:wheel
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- The $VH_INSTANCE instance's private PostgreSQL (bin/setup/install_db.sh): starts at boot, no login needed. -->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$VH_PG_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$pgbin/postgres</string>
        <string>-D</string>
        <string>$data</string>
    </array>
    <key>UserName</key>
    <string>$acct</string>
    <key>GroupName</key>
    <string>$acct</string>
    <key>WorkingDirectory</key>
    <string>$VH_PG_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>$VH_LOG_DIR/postgres.log</string>
</dict>
</plist>
EOF
  vh_dry_run || plutil -lint "$plist" >/dev/null
  if launchctl print "system/$VH_PG_LABEL" >/dev/null 2>&1; then
    vh_priv launchctl kickstart -k "system/$VH_PG_LABEL"
  else
    vh_priv launchctl bootstrap system "$plist"
  fi
  if ! vh_dry_run; then
    local i=0
    until "$pgbin/pg_isready" -q -h 127.0.0.1 -p "$VH_PG_PORT"; do
      i=$((i + 1)); [ "$i" -lt 60 ] || vh_die "PostgreSQL did not come up on 127.0.0.1:$VH_PG_PORT ($VH_LOG_DIR/postgres.log)"
      sleep 1
    done
  fi

  # The role's password: a fresh one in the daemon's handoff file (it seals it on start and deletes the file), set
  # on the role by psql reading that same file.
  openssl rand -hex 24 | vh_priv_write "$PENDING_DB_PASS_FILE" 0600 "$acct:$acct"
  as_svc env PGPASSFILE="$pgpass" "$pgbin/psql" -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$VH_PG_PORT" -U postgres \
    -d postgres -v role="$DB_ROLE" -v pwfile="$PENDING_DB_PASS_FILE" >/dev/null <<'SQL'
\set pw `cat :'pwfile'`
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE', :'role')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'role', :'pw') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'role', :'role')
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'role') \gexec
SQL
  echo "✅ $DB_ROLE@127.0.0.1:$VH_PG_PORT/$DB_NAME ready; password handed over in $PENDING_DB_PASS_FILE"
  vh_priv launchctl kickstart -k "system/$VH_LABEL_PREFIX.server"
}

if [[ "$(vh_os)" == darwin ]]; then
  [ -n "$VH_INSTANCE" ] || vh_die "macOS production installs come from the package or the Homebrew cask"
  darwin_cluster
  exit 0
fi

# ── Linux: the host's PostgreSQL (production's database, or the instance's own role and database beside it) ───────

ROLE_CREATED=false
PASSWORD_READY=false
VAUL_PG_PASS="$(openssl rand -base64 32 | tr -d '\n')"

if sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_ROLE}'" | grep -q 1; then
  echo "ℹ️ PostgreSQL role '${DB_ROLE}' already exists."
  if [[ "$DEV_MODE" == true ]]; then
    sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -c "ALTER ROLE ${DB_ROLE} WITH LOGIN PASSWORD '${VAUL_PG_PASS}';"
    PASSWORD_READY=true
    echo "✅ Reset PostgreSQL password for existing dev role '${DB_ROLE}'."
  fi
else
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -c "CREATE USER ${DB_ROLE} WITH PASSWORD '${VAUL_PG_PASS}';"
  ROLE_CREATED=true
  PASSWORD_READY=true
  echo "✅ Created PostgreSQL role '${DB_ROLE}'."
fi

if sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -c "ALTER DATABASE ${DB_NAME} OWNER TO ${DB_ROLE};"
else
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_ROLE};"
fi

sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_ROLE};"
sudo -u postgres psql -v ON_ERROR_STOP=1 -d "${DB_NAME}" -c "GRANT USAGE, CREATE ON SCHEMA public TO ${DB_ROLE};"

# === Seed DB Password (for runtime TPM sealing) ===
if [[ "$PASSWORD_READY" == true ]]; then
  echo "🔐 Seeding PostgreSQL password for Vaulthalla user (pending runtime init)..."
  vh_priv install -d -m 0755 "$(dirname "$PENDING_DB_PASS_FILE")"
  echo "$VAUL_PG_PASS" | vh_priv_write "$PENDING_DB_PASS_FILE" 600 "$VH_USER:$VH_GROUP"
  echo "✅ Wrote DB password seed to $PENDING_DB_PASS_FILE"
elif [[ "$ROLE_CREATED" == false ]]; then
  echo "ℹ️ Role existed already outside dev mode; leaving DB password seed state unchanged."
fi
