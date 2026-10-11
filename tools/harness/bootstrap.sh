#!/usr/bin/env bash
# One-time (idempotent) setup for the integration engine on a dev/CI host. Never run it on vh-storage.
#
#   sudo tools/harness/bootstrap.sh            # venv, harness DB role, CLI actor accounts
#   sudo tools/harness/bootstrap.sh --remove   # remove the actor accounts and the harness role
#
# - .venv with tools/harness/requirements.txt
# - PostgreSQL role `vh_harness` (LOGIN, no CREATEDB, no superuser) whose settings live in the root-only file
#   /var/lib/vaulthalla-harness/db.env. Per-run databases are created by postgres and owned by this role, and dropped
#   after each run. It is separate from the `vaulthalla_test` role that `make test` rotates and tears down.
# - CLI actor accounts `vhh-actor-01..N`: system users with no home and no login shell, in the `vaulthalla` group.
#   The daemon identifies CLI callers by their Linux uid and checks the caller's group through the passwd database,
#   so CLI sessions need real accounts. Nothing can log in as them; the engine (root) starts processes as them.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR=/var/lib/vaulthalla-harness
ACTORS="${VHH_ACTORS:-16}"
ROLE=vh_harness

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
case "$(hostname -s)" in vh-storage*) echo "refusing to bootstrap the harness on vh-storage" >&2; exit 1;; esac

if [[ "${1:-}" == "--remove" ]]; then
    for i in $(seq -f "%02g" 1 "$ACTORS"); do
        id "vhh-actor-$i" &>/dev/null && userdel "vhh-actor-$i"
    done
    runuser -u postgres -- psql -qXtAc "DROP ROLE IF EXISTS $ROLE" || true
    rm -f "$STATE_DIR/db.env"
    echo "removed harness actors and role"
    exit 0
fi

getent group vaulthalla >/dev/null || { echo "group 'vaulthalla' missing (install the dev environment first)" >&2; exit 1; }

# venv (owned by the invoking user so they can pip install into it)
OWNER="${SUDO_USER:-root}"
if [[ ! -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
    runuser -u "$OWNER" -- python3 -m venv "$SCRIPT_DIR/.venv"
fi
runuser -u "$OWNER" -- "$SCRIPT_DIR/.venv/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt"

# harness DB role
install -d -m 0700 -o root -g root "$STATE_DIR"
if [[ ! -s "$STATE_DIR/db.env" ]]; then
    PW="$(openssl rand -hex 24)"
    runuser -u postgres -- psql -qXtAc \
        "DO \$\$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='$ROLE') THEN CREATE ROLE $ROLE LOGIN; END IF; END\$\$;"
    runuser -u postgres -- psql -qXtAc "ALTER ROLE $ROLE PASSWORD '$PW'" >/dev/null
    umask 077
    printf 'VH_TEST_DB_USER=%s\nVH_TEST_DB_PASS=%s\nVH_TEST_DB_HOST=localhost\nVH_TEST_DB_PORT=5432\n' "$ROLE" "$PW" \
        > "$STATE_DIR/db.env"
    unset PW
fi
chmod 0600 "$STATE_DIR/db.env"

# CLI actor accounts
for i in $(seq -f "%02g" 1 "$ACTORS"); do
    name="vhh-actor-$i"
    if ! id "$name" &>/dev/null; then
        useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
                --user-group --groups vaulthalla "$name"
    elif ! id -nG "$name" | grep -qw vaulthalla; then
        usermod -aG vaulthalla "$name"
    fi
done

echo "harness bootstrap ok: venv $SCRIPT_DIR/.venv, role $ROLE, $ACTORS CLI actors"
