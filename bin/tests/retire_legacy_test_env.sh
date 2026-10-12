#!/usr/bin/env bash
# One-time, explicit retirement of the old shared `make run_test` environment (it no longer exists in the Makefile):
#   - drops the vh_cli_test database and the vaulthalla_test role (only if the role owns nothing elsewhere; otherwise
#     it reports where, and leaves the role: no DROP OWNED across the cluster);
#   - removes the VH_TEST_DB_* lines that bin/tests/install_db.sh used to write into deploy/bashrc,
#     deploy/vaulthalla.env and /etc/vaulthalla/vaulthalla.env (the dev daemon's EnvironmentFile), without printing
#     any value;
#   - removes the old fixed /tmp/vh_{mount,backing,runtime,log} paths if nothing is mounted there.
# Nothing here runs automatically. Asks before each part unless --yes.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
YES=false; [[ "${1:-}" == --yes ]] && YES=true
ask() { $YES && return 0; read -r -p "$1 [y/N]: " r; [[ "$r" =~ ^[Yy]$ ]]; }
q() { sudo -n -u postgres psql -XAtq -v ON_ERROR_STOP=1 -d "${2:-postgres}" -c "$1"; }

if ask "Drop database vh_cli_test and role vaulthalla_test?"; then
  q "DROP DATABASE IF EXISTS vh_cli_test WITH (FORCE)"
  if [[ -n "$(q "SELECT 1 FROM pg_roles WHERE rolname = 'vaulthalla_test'")" ]]; then
    owned=""
    for db in $(q "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate"); do
      n="$(q "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner WHERE r.rolname = 'vaulthalla_test'" "$db")"
      [[ "$n" == 0 ]] || owned+=" $db($n)"
    done
    if [[ -n "$owned" ]]; then
      echo "vaulthalla_test still owns objects in:$owned. Left in place; drop those databases or reassign first."
    else
      q "DROP ROLE vaulthalla_test" && echo "dropped role vaulthalla_test"
    fi
  fi
fi

if ask "Remove VH_TEST_DB_* lines from deploy/bashrc, deploy/vaulthalla.env and /etc/vaulthalla/vaulthalla.env?"; then
  for f in "$REPO/deploy/bashrc" "$REPO/deploy/vaulthalla.env" /etc/vaulthalla/vaulthalla.env; do
    sudo -n test -f "$f" || continue
    n="$(sudo -n grep -cE '^(export )?VH_TEST_DB_' "$f" || true)"
    [[ "$n" == 0 ]] && continue
    sudo -n sed -i -E '/^(export )?VH_TEST_DB_/d' "$f"
    echo "removed $n line(s) from $f"
  done
  echo "restart vaulthalla.service to drop them from the running dev daemon's environment"
fi

if ask "Remove /tmp/vh_{mount,backing,runtime,log} (the old fixed test paths)?"; then
  for d in /tmp/vh_mount /tmp/vh_backing /tmp/vh_runtime /tmp/vh_log; do
    [[ -e "$d" ]] || continue
    if grep -qF " $d " /proc/self/mountinfo; then echo "skipping $d: mounted"; continue; fi
    sudo -n rm -rf --one-file-system "$d" && echo "removed $d"
  done
fi
