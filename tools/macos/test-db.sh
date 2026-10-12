#!/bin/bash
# Disposable PostgreSQL 16 cluster for the DB-backed unit tests on macOS.
#
#   eval "$(tools/macos/test-db.sh up)"     # init + start, print the VH_TEST_DB_* exports (stdout; logs go to stderr)
#   tools/macos/test-db.sh env              # print the exports again for a running cluster
#   tools/macos/test-db.sh down             # stop it and delete its directory
#
# Settings (environment): VH_TEST_PG_DIR (default $TMPDIR/vh-macos-test-pg), VH_TEST_PG_PORT (default 54329).
# The cluster lives entirely in VH_TEST_PG_DIR (data, unix socket, log) and listens on 127.0.0.1 only. It uses the
# Homebrew postgresql@16 binaries directly: no `brew services`, no default data dir, no other cluster is touched.
#
# Contract (same as `make test` on Linux, core/src/db/Connection.cpp): test mode takes all five VH_TEST_DB_{HOST,PORT,
# USER,PASS,NAME} from the environment. The role (vh_harness: LOGIN, not superuser, no CREATEDB, scram password) owns
# an empty database vh_harness_unit_macos (names pass runtime::test_instance::isTestDatabaseName); the suites build
# their schema themselves. Local socket connections are trust (the bootstrap superuser), TCP needs the password.
# Bash 3.2 compatible.
set -euo pipefail

PG_DIR="${VH_TEST_PG_DIR:-${TMPDIR:-/tmp}/vh-macos-test-pg}"
PG_DIR="${PG_DIR%/}"
PG_PORT="${VH_TEST_PG_PORT:-54329}"
ROLE=vh_harness
DB=vh_harness_unit_macos
SUPERUSER=vh_test_admin
MARKER=".vaulthalla-macos-test-db"

log() { printf 'test-db: %s\n' "$*" >&2; }
die() { printf 'test-db: error: %s\n' "$*" >&2; exit 1; }

pg_bin() {
  local prefix
  if command -v brew >/dev/null 2>&1 && prefix="$(brew --prefix postgresql@16 2>/dev/null)" && [ -x "$prefix/bin/initdb" ]; then
    printf '%s\n' "$prefix/bin"
  else
    die "postgresql@16 is not installed (brew bundle --file tools/macos/Brewfile)"
  fi
}

quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

print_env() {
  [ -f "$PG_DIR/$MARKER" ] && [ -f "$PG_DIR/password" ] || die "no cluster in $PG_DIR (run: $0 up)"
  printf 'export VH_TEST_DB_HOST=127.0.0.1\n'
  printf 'export VH_TEST_DB_PORT=%s\n' "$(cat "$PG_DIR/port")"
  printf 'export VH_TEST_DB_USER=%s\n' "$ROLE"
  printf 'export VH_TEST_DB_PASS=%s\n' "$(quote "$(cat "$PG_DIR/password")")"
  printf 'export VH_TEST_DB_NAME=%s\n' "$DB"
  printf 'export VH_TEST_PG_DIR=%s\n' "$(quote "$PG_DIR")"
}

psql_admin() { "$BIN/psql" -X -q -v ON_ERROR_STOP=1 -h "$PG_DIR/sock" -p "$PG_PORT" -U "$SUPERUSER" -d postgres "$@"; }

running() { [ -f "$PG_DIR/data/postmaster.pid" ] && "$BIN/pg_ctl" -D "$PG_DIR/data" status >/dev/null 2>&1; }

cmd_up() {
  if [ -f "$PG_DIR/$MARKER" ] && running; then
    log "already running in $PG_DIR"
    print_env
    return
  fi
  if [ -e "$PG_DIR" ]; then
    [ -f "$PG_DIR/$MARKER" ] || die "$PG_DIR exists and is not a test-db.sh cluster; refusing to touch it"
    log "removing stopped cluster in $PG_DIR"
    rm -rf "$PG_DIR"
  fi
  if lsof -nP -iTCP:"$PG_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    die "port $PG_PORT is in use (set VH_TEST_PG_PORT)"
  fi

  mkdir -p "$PG_DIR"
  PG_DIR="$(cd "$PG_DIR" && pwd -P)"
  # Unix socket paths are limited to 103 bytes on macOS.
  [ ${#PG_DIR} -le 80 ] || die "VH_TEST_PG_DIR is too long for a unix socket path: $PG_DIR"
  : > "$PG_DIR/$MARKER"
  mkdir -m 0700 "$PG_DIR/sock"
  printf '%s\n' "$PG_PORT" > "$PG_DIR/port"
  ( umask 077; openssl rand -hex 24 > "$PG_DIR/password" )

  log "initdb $PG_DIR/data"
  "$BIN/initdb" -D "$PG_DIR/data" -U "$SUPERUSER" -E UTF8 --locale=C \
    --auth-local=trust --auth-host=scram-sha-256 >"$PG_DIR/initdb.log" 2>&1 \
    || { cat "$PG_DIR/initdb.log" >&2; die "initdb failed"; }
  cat >> "$PG_DIR/data/postgresql.conf" <<EOF

# tools/macos/test-db.sh: disposable unit-test cluster
listen_addresses = '127.0.0.1'
port = $PG_PORT
unix_socket_directories = '$PG_DIR/sock'
max_connections = 200
fsync = off
synchronous_commit = off
full_page_writes = off
EOF

  log "starting on 127.0.0.1:$PG_PORT"
  "$BIN/pg_ctl" -D "$PG_DIR/data" -l "$PG_DIR/server.log" -w -t 60 start >/dev/null \
    || { tail -n 50 "$PG_DIR/server.log" >&2 || true; die "pg_ctl start failed"; }

  local pass
  pass="$(cat "$PG_DIR/password")"
  psql_admin -c "CREATE ROLE $ROLE LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$pass'" >/dev/null
  psql_admin -c "CREATE DATABASE $DB OWNER $ROLE" >/dev/null

  # Prove the exact path the tests use: TCP + password as the test role.
  PGPASSWORD="$pass" "$BIN/psql" -X -q -At -h 127.0.0.1 -p "$PG_PORT" -U "$ROLE" -d "$DB" -c 'SELECT 1' >/dev/null \
    || die "test role cannot connect over TCP"
  log "ready: $ROLE@127.0.0.1:$PG_PORT/$DB"
  print_env
}

cmd_down() {
  if [ ! -e "$PG_DIR" ]; then log "nothing at $PG_DIR"; return; fi
  [ -f "$PG_DIR/$MARKER" ] || die "$PG_DIR is not a test-db.sh cluster; refusing to touch it"
  if running; then
    log "stopping"
    "$BIN/pg_ctl" -D "$PG_DIR/data" -m fast -w -t 60 stop >/dev/null || log "warning: pg_ctl stop failed"
  fi
  rm -rf "$PG_DIR"
  log "removed $PG_DIR"
}

[ "$(uname -s)" = Darwin ] || die "macOS only (Linux uses bin/tests/run_unit.sh: make test)"
BIN="$(pg_bin)"
case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  env) print_env ;;
  *) die "usage: $0 up|env|down" ;;
esac
