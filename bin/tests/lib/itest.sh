# shellcheck shell=bash
# Shared plumbing for isolated test runs: bin/tests/run_proof.sh (make itest) and bin/tests/run_unit.sh (make test).
#
# Isolation contract: every run gets its own database (cloned from a migrated template, or empty), owned by the
# vh_harness role whose settings live only in the root-only ITEST_DB_ENV file; nothing is installed, nothing on the host
# is changed, no shared role or database is rotated or dropped. One-time host setup is `sudo tools/harness/bootstrap.sh`;
# the run path only checks for it (itest_preflight) and fails with that command.

ITEST_DB_ENV="/var/lib/vaulthalla-harness/db.env"
ITEST_ROLE="vh_harness"
ITEST_TPL_PREFIX="vh_harness_tpl_"
ITEST_LOCK="/var/lib/vaulthalla-harness/template.lock"
# The build every isolated run uses. Not `build/`: switching that one between configurations costs full rebuilds.
ITEST_BUILD_OPTS=(
  -Dbuildtype=debug
  -Dbuild_unit_tests=true
  -Dintegration_tests=true
  -Dinstall_data=false
  -Dmanpage=false
  -Db_sanitize=address,undefined
)
: "${ITEST_TAG:=itest}"

itest_log() { printf '[%s] %s\n' "$ITEST_TAG" "$*"; }
itest_die() { printf '[%s] error: %s\n' "$ITEST_TAG" "$*" >&2; exit 1; }

# itest_abspath PATH: what GNU `realpath -m PATH` prints, in pure bash (BSD/macOS realpath has no -m; bash 3.2 safe):
# absolute and normalized, symlinks resolved component by component while the path exists (so `..` after a symlink
# leaves its target, as in realpath), the rest taken as written; nothing has to exist.
itest_abspath() {
  local path="$1" resolved="" part k=0 hops=0
  local -a todo target
  [[ "$path" == /* ]] || path="$PWD/$path"
  IFS=/ read -r -a todo <<<"$path"
  while [[ $k -lt ${#todo[@]} ]]; do
    part="${todo[$k]}"
    k=$((k + 1))
    case "$part" in
      ''|.) continue ;;
      ..) resolved="${resolved%/*}"; continue ;;
    esac
    if [[ -L "$resolved/$part" && $hops -lt 40 ]]; then
      hops=$((hops + 1))
      path="$(readlink "$resolved/$part")"
      [[ "$path" != /* ]] || resolved=""
      IFS=/ read -r -a target <<<"$path"
      todo=("${target[@]}" "${todo[@]:$k}")
      k=0
      continue
    fi
    resolved="$resolved/$part"
  done
  printf '%s\n' "${resolved:-/}"
}

# Tier A proofs (make itest) run a private instance on a kernel FUSE mount and inspect it through /proc, fusectl and
# sudo; none of that exists on macOS, where the server never mounts (#262). Fails there with what to run instead.
itest_require_linux() {
  [[ "$(uname -s)" == Darwin ]] || return 0
  itest_die "Tier A proofs (make itest) need Linux: a kernel FUSE mount, /proc and sudo for the private instance, \
which macOS doesn't have (the server never mounts there, #262). On this Mac run the DB-backed unit suites instead: make test"
}

# macOS `make test` (bin/tests/run_unit.sh): no vh_harness host setup and no sudo. The build environment comes from
# tools/macos/env.sh (Homebrew openssl@3 first, postgresql@16 on PATH, as .github/workflows/macos.yml builds) and
# the database is a disposable per-run cluster from tools/macos/test-db.sh.
itest_preflight_darwin() {
  local c missing=() hint="brew bundle --file tools/macos/Brewfile (or tools/macos/bootstrap.sh)"
  command -v brew >/dev/null || itest_die "Homebrew (brew) is missing; the macOS build uses its packages ($hint)"
  # shellcheck source=tools/macos/env.sh
  . "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/tools/macos/env.sh" \
    || itest_die "tools/macos/env.sh failed"
  for c in meson ninja initdb pg_ctl psql python3 openssl; do command -v "$c" >/dev/null || missing+=("$c"); done
  [[ ${#missing[@]} -eq 0 ]] || itest_die "missing tools: ${missing[*]} ($hint)"
}

# itest_exec_darwin TIMEOUT_SECS PASS_VARS CONFIG WORKDIR CMD...: the macOS counterpart of run_unit.sh's
# `env -i ... setpriv ... timeout` line. stdin carries the `export VH_TEST_DB_*=...` lines tools/macos/test-db.sh
# printed (so the password never reaches an argv); the command gets a clean environment of PATH, HOME, TMPDIR, LANG,
# VH_PATH_TO_CONFIG=CONFIG, those VH_TEST_DB_*, the variables named in the comma-separated PASS_VARS that are set (the
# caller decides which, usually none), and /dev/null as stdin. Exits 124 on the timeout (TERM, then KILL 30 s later)
# like timeout(1), 128+N on signal N.
itest_exec_darwin() {
  python3 -I -c '
import os, shlex, subprocess, sys

timeout_s, pass_vars, config, workdir, *cmd = sys.argv[1:]
env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR") if os.environ.get(k)}
env["LANG"] = "C.UTF-8"
# libc++ annotates std::vector for ASan; libpqxx (Homebrew, not instrumented) grows pqxx::params vectors the inlined,
# instrumented code also touches, which reports container-overflow on valid accesses. libstdc++ has no such checks
# unless _GLIBCXX_SANITIZE_VECTOR is defined (it is not), so this matches what the Linux run checks.
env["ASAN_OPTIONS"] = "detect_container_overflow=0"
for line in sys.stdin.read().splitlines():
    words = shlex.split(line)
    if len(words) == 2 and words[0] == "export" and words[1].startswith("VH_TEST_DB_") and "=" in words[1]:
        key, _, value = words[1].partition("=")
        env[key] = value
env.update({k: os.environ[k] for k in pass_vars.split(",") if k and os.environ.get(k)})
env["VH_PATH_TO_CONFIG"] = config

proc = subprocess.Popen(cmd, cwd=workdir, env=env, stdin=subprocess.DEVNULL)
try:
    rc = proc.wait(timeout=int(timeout_s))
except subprocess.TimeoutExpired:
    print(f"timeout: {timeout_s}s reached; stopping the test binary", file=sys.stderr)
    proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    sys.exit(124)
except KeyboardInterrupt:
    proc.wait()
    sys.exit(130)
sys.exit(128 - rc if rc < 0 else rc)
' "$@"
}

# Checks the one-time setup without changing anything. $1 = "fuse" when the run mounts FUSE.
itest_preflight() {
  local need_fuse="${1:-}" missing=()
  local hint="run once: sudo tools/harness/bootstrap.sh"
  sudo -n true 2>/dev/null || itest_die "needs passwordless sudo"
  sudo -n test -r "$ITEST_DB_ENV" || itest_die "$ITEST_DB_ENV is missing ($hint)"
  getent group vaulthalla >/dev/null || itest_die "group 'vaulthalla' is missing ($hint)"
  for c in meson ninja psql python3 setpriv timeout flock; do command -v "$c" >/dev/null || missing+=("$c"); done
  [[ ${#missing[@]} -eq 0 ]] || itest_die "missing tools: ${missing[*]} (install them, or $hint)"
  sudo -n -u postgres psql -XAtqc 'SELECT 1' >/dev/null 2>&1 || itest_die "local PostgreSQL is not reachable as postgres"
  if [[ "$need_fuse" == fuse ]]; then
    [[ -c /dev/fuse ]] || itest_die "/dev/fuse is missing"
    command -v fusermount3 >/dev/null || itest_die "fusermount3 is missing (fuse3)"
  fi
}

# itest_ensure_build DIR TARGET... : configure DIR with ITEST_BUILD_OPTS if it has no build.ninja, re-configure only the
# options that differ, then compile just the targets. Never with sudo (root-owned files would break later builds).
itest_ensure_build() {
  local dir="$1" root opt key want have changed=()
  shift
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
  if [[ ! -f "$dir/build.ninja" ]]; then
    itest_log "configuring $dir"
    meson setup "$dir" "$root" "${ITEST_BUILD_OPTS[@]}" >/dev/null
  else
    local current
    current="$(meson introspect "$dir" --buildoptions)"
    for opt in "${ITEST_BUILD_OPTS[@]}"; do
      key="${opt#-D}"; key="${key%%=*}"; want="${opt#*=}"
      have="$(python3 -I -c 'import json,sys
o={x["name"]: x["value"] for x in json.load(sys.stdin)}
v=o.get(sys.argv[1])
print(",".join(v) if isinstance(v, list) else str(v).lower() if isinstance(v, bool) else v)' "$key" <<<"$current")"
      [[ "$have" == "$want" ]] || changed+=("$opt")
    done
    if [[ ${#changed[@]} -gt 0 ]]; then
      itest_log "re-configuring $dir: ${changed[*]}"
      meson configure "$dir" "${changed[@]}" >/dev/null
    fi
  fi
  meson compile -C "$dir" "$@" >/dev/null || meson compile -C "$dir" "$@"
}

# The migrated template for the current deploy/psql, built once per migration set with the daemon's own SqlDeployer
# (vh_migrate) and cloned per run. Prints its name. Older templates are dropped. ITEST_DB_TEMPLATE=0 skips it (the
# runner then starts from an empty database, which keeps the migration path itself covered).
itest_db_template() {
  local migrate="$1" root hash
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
  [[ -x "$migrate" ]] || itest_die "vh_migrate not built: $migrate"
  hash="$(cd "$root/deploy/psql" && for f in $(LC_ALL=C ls ./*.sql); do
            printf '%s %s\n' "${f#./}" "$(sha256sum <"$f" | cut -c1-64)"; done | sha256sum | cut -c1-16)"
  local tpl="${ITEST_TPL_PREFIX}${hash}"
  sudo -n bash -c '
    set -euo pipefail
    env_file="$1" role="$2" tpl="$3" prefix="$4" migrate="$5" dir="$6" lock="$7"
    q() { runuser -u postgres -- psql -XAtq -v ON_ERROR_STOP=1 -d postgres -c "$1"; }
    exec 9>"$lock"
    flock -w 300 9
    if [[ -z "$(q "SELECT 1 FROM pg_database WHERE datname = '\''$tpl'\''")" ]]; then
      building="${tpl}_new"
      runuser -u postgres -- dropdb --force --if-exists "$building"
      runuser -u postgres -- createdb -O "$role" "$building"
      ( set -a; . "$env_file"; set +a; VH_TEST_DB_NAME="$building" "$migrate" "$dir" ) >&2 || {
        runuser -u postgres -- dropdb --force --if-exists "$building"; exit 1; }
      q "ALTER DATABASE \"$building\" RENAME TO \"$tpl\""
      q "ALTER DATABASE \"$tpl\" WITH IS_TEMPLATE true ALLOW_CONNECTIONS false"
    fi
    for old in $(q "SELECT datname FROM pg_database WHERE datname LIKE '\''${prefix}%'\'' AND datname <> '\''$tpl'\''"); do
      q "ALTER DATABASE \"$old\" WITH IS_TEMPLATE false" && runuser -u postgres -- dropdb --force --if-exists "$old" || true
    done
  ' bash "$ITEST_DB_ENV" "$ITEST_ROLE" "$tpl" "$ITEST_TPL_PREFIX" "$migrate" "$root/deploy/psql" "$ITEST_LOCK" \
    || itest_die "could not build the migrated template database"
  printf '%s\n' "$tpl"
}

# itest_create_db NAME [TEMPLATE]
itest_create_db() {
  [[ "$1" =~ ^vh_harness_[a-z0-9_]+$ ]] || itest_die "refusing database name: $1"
  if [[ -n "${2:-}" ]]; then
    sudo -n -u postgres createdb -T "$2" -O "$ITEST_ROLE" "$1"
  else
    sudo -n -u postgres createdb -O "$ITEST_ROLE" "$1"
  fi
}

# itest_drop_db NAME: drops exactly that per-run database (never a template, never anything else).
itest_drop_db() {
  [[ "$1" =~ ^vh_harness_[a-z0-9_]+$ && "$1" != "$ITEST_TPL_PREFIX"* ]] || itest_die "refusing to drop: $1"
  sudo -n -u postgres timeout 60 dropdb --force --if-exists "$1"
}
