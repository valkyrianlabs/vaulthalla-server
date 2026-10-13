#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/../lib/dev_mode.sh"

vh_require_dev_mode

source "$(dirname "$0")/../lib/platform.sh"
# make dev runs this for the dev instance: its own database and role (vaulthalla_dev), never production's.
vh_instance_layout "$(vh_selected_instance)"
DB_NAME="$VH_DB_NAME"
DB_ROLE="$VH_DB_ROLE"

if ! command -v psql >/dev/null 2>&1 || ! id -u postgres >/dev/null 2>&1; then
    echo "🛡️  PostgreSQL client not installed or 'postgres' user missing. Skipping database cleanup."
    exit 0
fi

pg_server_ready() {
    if command -v pg_isready >/dev/null 2>&1; then
        sudo -u postgres pg_isready -q
        return $?
    fi

    sudo -u postgres psql -d postgres -Atqc 'SELECT 1;' >/dev/null 2>&1
}

if ! pg_server_ready; then
    echo "🛡️  PostgreSQL server is not accepting local connections. Skipping database cleanup."
    exit 0
fi

role_exists() {
    sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -Atqc \
        "SELECT 1 FROM pg_roles WHERE rolname = '$DB_ROLE';" | grep -q 1
}

drop_role_owned_objects() {
    local db
    while IFS= read -r db; do
        [[ -z "$db" ]] && continue
        sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$db" -c "DROP OWNED BY $DB_ROLE;"
    done < <(
        sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -Atqc \
            "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname;"
    )
}

if vh_confirm "⚠️  Drop PostgreSQL database and user '$DB_ROLE'?" "N" "Y"; then
    if vh_is_dev_mode; then
        echo "⚠️  [DEV_MODE] Dropping PostgreSQL DB and user '$DB_ROLE'..."
    else
        echo "🧨 Dropping PostgreSQL DB and user..."
    fi

    sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres <<EOF
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND (datname = '$DB_NAME' OR usename = '$DB_ROLE');
DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE);
EOF
    if role_exists; then
        drop_role_owned_objects
    fi
    sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -c "DROP ROLE IF EXISTS $DB_ROLE;"
else
    echo "🛡️  Skipping database deletion. You can do it manually with psql if needed."
fi
