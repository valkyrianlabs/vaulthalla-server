#!/bin/bash
# Installs a staged macOS build as the real system service and proves it (roadmap #230). Root, on a Mac you may change.
#
#   sudo tools/macos/install-acceptance.sh --stage DIR --db-port N --db-name NAME --db-user USER \
#        --db-password-file FILE --python PY --report-dir DIR [--client USER] [--phase PHASE] [--db-dir DIR]
#
# Phases (default: all, in this order; each can be rerun on its own):
#   preflight  read-only: every staged file is new (nothing installed is overwritten), no foreign account or
#              directories, the service ports are free. Runs without root.
#   install    copies only the staged paths that don't exist yet (root:wheel, no group/world write); identical
#              existing files are skipped, any differing one stops the run. Records what it created.
#   provision  vaulthalla-provision (the plan is checked: only creations, nothing removed or chmod'ed), then --apply.
#   configure  points the config at the disposable database, hands the DB password over (run dir, 0600), restarts.
#   accept     account + permissions; both LaunchDaemons (status, restart, crash recovery, stop/start); encrypted
#              vault over HTTP with RBAC denial (tools/macos/install_acceptance.py, run as --client); ciphertext at
#              rest; two hidden local test identities: one enrolled in the vaulthalla group (the CLI works), one
#              not (the state, run, log and config paths and the CLI socket are all refused). With --db-dir (a
#              tools/macos/test-db.sh cluster, run by its owner): PostgreSQL stopped under the running service, and
#              the service restarted while it is down (boot before the database), each recovering once it returns.
#   cleanup    removes the two test identities (only if this script created them).
# It never purges, never touches an existing config.yaml beyond the database block of the one provisioning created,
# and never prints secrets: the admin password goes from the state directory to the client on stdin.
set -euo pipefail

SUPPORT="/Library/Application Support/Vaulthalla"
STATE="$SUPPORT/state"
RUN="$SUPPORT/run"
MOUNT="$SUPPORT/mount"
CONFIG="$SUPPORT/config.yaml"
LOGS=/Library/Logs/Vaulthalla
PREFIX=/usr/local
PROV=$PREFIX/lib/vaulthalla/vaulthalla-provision
SERVER=sh.vaulthalla.server
WEB=sh.vaulthalla.web
PORTS="36968 36969 36970"
TEST_MARK="Vaulthalla acceptance test identity"
PROBE=vhtest_probe
CLI_USER=vhtest_cli
REPO="$(cd "$(dirname "$0")/../.." && pwd -P)"

STAGE="" DB_DIR="" DB_PORT="" DB_NAME="" DB_USER="" DB_PW_FILE="" PY="" REPORT="" CLIENT="${SUDO_USER:-}" PHASE=all
while [ $# -gt 0 ]; do
  case "$1" in
    --stage) STAGE="$2"; shift ;;
    --db-port) DB_PORT="$2"; shift ;;
    --db-dir) DB_DIR="$2"; shift ;;
    --db-name) DB_NAME="$2"; shift ;;
    --db-user) DB_USER="$2"; shift ;;
    --db-password-file) DB_PW_FILE="$2"; shift ;;
    --python) PY="$2"; shift ;;
    --report-dir) REPORT="$2"; shift ;;
    --client) CLIENT="$2"; shift ;;
    --phase) PHASE="$2"; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "install-acceptance: unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

failures=0
say() { echo "[acceptance] $*"; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; failures=$((failures + 1)); }
check() { local name="$1"; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }
die() { echo "install-acceptance: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "phase $1 needs root (sudo)"; }

listening() { /usr/bin/nc -z -G 1 127.0.0.1 "$1" >/dev/null 2>&1; }
wait_for() {  # wait_for SECONDS CMD...: polls every 0.5s
  local deadline=$(( $(date +%s) + $1 )); shift
  until "$@"; do [ "$(date +%s)" -lt "$deadline" ] || return 1; sleep 0.5; done
}
not() { ! "$@"; }
pid_of() { { launchctl print "system/$1" 2>/dev/null || true; } | awk '$1 == "pid" && $2 == "=" {print $3}'; }
runs_as_service() { [ "$(ps -o uid= -p "$(pid_of "$1")" | tr -d ' ')" = "$(id -u _vaulthalla)" ]; }
has_pid() { [ -n "$(pid_of "$1")" ]; }
new_pid() { local p; p=$(pid_of "$1"); [ -n "$p" ] && [ "$p" != "$2" ]; }
server_ready() { listening 36969 && listening 36970 && [ -S "$RUN/cli.sock" ]; }
perms() { stat -f '%Sp %Su:%Sg' "$1"; }

client() {  # client seed|verify: the admin password goes from the state dir to the unprivileged client on stdin
  # shellcheck disable=SC2024  # deliberate: root opens the secret, the client only gets the stream
  sudo -u "$CLIENT" -- "$PY" "$REPO/tools/macos/install_acceptance.py" "$1" --state "$REPORT/acceptance.json" \
    --expect-mount-state disabled < "$STATE/super_admin_initial_password"
}

# Paths an earlier run of this script installed (installed-paths.txt): a rerun may update them from a new stage.
ours() {
  local r
  [ -f "$REPORT/installed-paths.txt" ] || return 1
  while IFS= read -r r; do
    case "$1" in "$r"|"$r"/*) return 0 ;; esac
  done < "$REPORT/installed-paths.txt"
  return 1
}

staged_paths() { (cd "$STAGE" && find . -mindepth 1 | LC_ALL=C sort | sed 's|^\.||'); }

phase_preflight() {
  [ -d "$STAGE$PREFIX/bin" ] || die "--stage $STAGE has no $PREFIX/bin"
  local p conflicts=0 new=0 updates=0
  while IFS= read -r p; do
    if { [ -L "$p" ] || [ -e "$p" ]; } && ours "$p"; then
      if [ -f "$STAGE$p" ] && ! cmp -s "$STAGE$p" "$p"; then updates=$((updates + 1)); fi
    elif [ -L "$p" ] || [ -e "$p" ]; then
      if [ -d "$STAGE$p" ] && [ ! -L "$STAGE$p" ]; then
        [ -d "$p" ] && [ ! -L "$p" ] || { say "conflict: $p exists and is not a directory"; conflicts=$((conflicts + 1)); }
      elif [ -L "$STAGE$p" ]; then
        [ "$(readlink "$p" 2>/dev/null)" = "$(readlink "$STAGE$p")" ] || { say "conflict: $p"; conflicts=$((conflicts + 1)); }
      elif ! cmp -s "$STAGE$p" "$p"; then
        say "conflict: $p exists with different content"; conflicts=$((conflicts + 1))
      fi
    else
      new=$((new + 1))
    fi
  done < <(staged_paths)
  [ "$conflicts" = 0 ] || die "$conflicts staged path(s) would overwrite something; nothing installed"
  say "staged paths: $new new, $updates update(s) to files an earlier run installed, $(staged_paths | wc -l | tr -d ' ') total; nothing else would be overwritten"
  # Our own LaunchDaemons (loaded by an earlier run) may hold the ports; anything else is a foreign listener.
  if ! launchctl print "system/$SERVER" >/dev/null 2>&1 && ! launchctl print "system/$WEB" >/dev/null 2>&1; then
    for p in $PORTS; do
      if listening "$p"; then die "port $p is in use by something else"; fi
    done
  fi
  if dscl . -read /Users/_vaulthalla RecordName >/dev/null 2>&1; then say "_vaulthalla exists (provisioning validates it)"
  else say "_vaulthalla does not exist yet"; fi
  for p in "$SUPPORT" "$LOGS" /Library/LaunchDaemons/$SERVER.plist /Library/LaunchDaemons/$WEB.plist; do
    if [ -e "$p" ]; then say "exists: $p"; else say "absent: $p"; fi
  done
}

# Top-most staged paths that don't exist yet: everything this run creates, and nothing else.
new_roots() {
  local p last=""
  while IFS= read -r p; do
    if [ -n "$last" ] && [ "${p#"$last"/}" != "$p" ]; then continue; fi
    if [ ! -e "$p" ] && [ ! -L "$p" ]; then echo "$p"; last="$p"; fi
  done < <(staged_paths)
}

phase_install() {
  need_root install
  phase_preflight >/dev/null
  local p created=()
  while IFS= read -r p; do created+=("$p"); done < <(new_roots)
  for p in ${created[@]+"${created[@]}"}; do
    if [ -L "$STAGE$p" ]; then
      ln -s "$(readlink "$STAGE$p")" "$p"; chown -h root:wheel "$p"
    elif [ -d "$STAGE$p" ]; then
      ditto "$STAGE$p" "$p"; chown -R root:wheel "$p"; chmod -R go-w "$p"
    elif [ -x "$STAGE$p" ]; then
      install -o root -g wheel -m 0755 "$STAGE$p" "$p"
    else
      install -o root -g wheel -m 0644 "$STAGE$p" "$p"
    fi
    say "installed $p"
  done
  # Files an earlier run installed and the new stage changes: replaced in place (same owner and modes).
  local n=0
  while IFS= read -r p; do
    if [ -f "$STAGE$p" ] && [ ! -L "$STAGE$p" ] && [ -f "$p" ] && ours "$p" && ! cmp -s "$STAGE$p" "$p"; then
      if [ -x "$STAGE$p" ]; then install -o root -g wheel -m 0755 "$STAGE$p" "$p"
      else install -o root -g wheel -m 0644 "$STAGE$p" "$p"; fi
      n=$((n + 1))
    fi
  done < <(staged_paths)
  say "$n file(s) an earlier run installed were updated"
  [ "${#created[@]}" -gt 0 ] && printf '%s\n' "${created[@]}" >> "$REPORT/installed-paths.txt"
  say "${#created[@]} path(s) created; list in $REPORT/installed-paths.txt"
}

phase_provision() {
  need_root provision
  [ -x "$PROV" ] || die "$PROV is not installed"
  local plan
  plan=$("$PROV")
  echo "$plan" | tee "$REPORT/provision-plan.txt"
  # A first provisioning only creates: no removal, mode change or bootout may appear in the plan.
  if echo "$plan" | grep 'would run:' | grep -vE "would run: /usr/bin/dscl \. -(create|append) |would run: /usr/bin/install |would run: /bin/launchctl bootstrap system "; then
    die "the plan contains something other than creations (above); not applying"
  fi
  "$PROV" --apply | tee "$REPORT/provision-apply.txt"
  "$PROV" | tee "$REPORT/provision-after.txt" | tail -1
  check "provisioning is idempotent (a second plan has nothing to do)" grep -q "0 change(s) to make" "$REPORT/provision-after.txt"
}

phase_configure() {
  need_root configure
  [ -n "$DB_PORT" ] && [ -n "$DB_NAME" ] && [ -n "$DB_USER" ] && [ -r "$DB_PW_FILE" ] || die "configure needs --db-*"
  # Only the database block; in place, so the file keeps provisioning's owner and mode.
  /usr/bin/python3 - "$CONFIG" "$DB_PORT" "$DB_NAME" "$DB_USER" <<'EOF'
import re, sys
path, port, name, user = sys.argv[1:]
text = open(path).read()
head, sep, rest = text.partition("\ndatabase:\n")
if not sep: sys.exit("no database: block in " + path)
block, nl, tail = rest.partition("\n\n")
for key, value in (("host", "127.0.0.1"), ("port", port), ("name", name), ("user", user)):
    block, n = re.subn(rf"^(\s+{key}:\s*)\S+", rf"\g<1>{value}", block, count=1, flags=re.M)
    if n != 1: sys.exit(f"database.{key} not found")
with open(path, "r+") as f:
    f.seek(0); f.write(head + sep + block + nl + tail); f.truncate()
EOF
  say "config database -> 127.0.0.1:$DB_PORT/$DB_NAME as $DB_USER ($(perms "$CONFIG"))"
  install -o _vaulthalla -g _vaulthalla -m 0600 "$DB_PW_FILE" "$RUN/db_password"
  say "DB password handed over in $RUN/db_password (0600 _vaulthalla)"
  launchctl kickstart -k "system/$SERVER"
  check "server comes up on the configured database" wait_for 120 server_ready
  check "the password handoff was consumed (sealed into the state dir)" wait_for 30 not test -e "$RUN/db_password"
}

phase_accept() {
  need_root accept
  [ -x "$PY" ] || die "--python $PY is not executable"
  local id uid gid out pid t0 took
  say "== account"
  dscl . -read /Users/_vaulthalla RecordName UniqueID PrimaryGroupID UserShell NFSHomeDirectory IsHidden | sed 's/^/  /'
  uid=$(id -u _vaulthalla); gid=$(id -g _vaulthalla)
  check "_vaulthalla is a hidden role account (uid $uid, gid $gid in 200-399, matching)" \
    test "$uid" -ge 200 -a "$uid" -le 399 -a "$uid" = "$gid"
  check "the 'vaulthalla' alias resolves to the same uid" test "$(id -u vaulthalla)" = "$uid"
  check "no human user is in the vaulthalla group" test -z "$(dscl . -read /Groups/_vaulthalla GroupMembership 2>/dev/null | sed 's/^GroupMembership://' | tr -d ' ')"

  say "== directories"
  for p in "$SUPPORT" "$STATE" "$RUN" "$MOUNT" "$LOGS" "$CONFIG" "$RUN/cli.sock" /Library/LaunchDaemons/$SERVER.plist /Library/LaunchDaemons/$WEB.plist; do
    echo "  $(perms "$p")  $p"
  done
  check "support dir root:wheel 0755" test "$(perms "$SUPPORT")" = "drwxr-xr-x root:wheel"
  check "state dir _vaulthalla 0700" test "$(perms "$STATE")" = "drwx------ _vaulthalla:_vaulthalla"
  check "run dir _vaulthalla 0750" test "$(perms "$RUN")" = "drwxr-x--- _vaulthalla:_vaulthalla"
  check "mount dir _vaulthalla 0700" test "$(perms "$MOUNT")" = "drwx------ _vaulthalla:_vaulthalla"
  check "log dir _vaulthalla 0750" test "$(perms "$LOGS")" = "drwxr-x--- _vaulthalla:_vaulthalla"
  check "config root:_vaulthalla 0640" test "$(perms "$CONFIG")" = "-rw-r----- root:_vaulthalla"
  check "CLI socket _vaulthalla 0660" test "$(perms "$RUN/cli.sock")" = "srw-rw---- _vaulthalla:_vaulthalla"

  say "== LaunchDaemons"
  for label in $SERVER $WEB; do
    { launchctl print "system/$label" || true; } | grep -E '^\s+(state|pid|runs|last exit code|username|group) = ' | sed "s/^/  $label /" || true
  done
  check "server running as _vaulthalla" runs_as_service $SERVER
  check "web running as _vaulthalla" runs_as_service $WEB
  check "web answers on 127.0.0.1:36968" wait_for 60 listening 36968
  out=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:36968/ || true)
  check "web console responds over HTTP (got $out)" test "${out:0:1}" = 2 -o "${out:0:1}" = 3

  say "== encrypted vault over HTTP (as $CLIENT)"
  check "seed: vault, uploads, share upload, RBAC denial" client seed
  check "stored bytes are ciphertext (no plaintext copy anywhere in the state dir)" ciphertext_at_rest

  say "== restart (launchctl kickstart -k)"
  pid=$(pid_of $SERVER)
  launchctl kickstart -k "system/$SERVER"
  check "restarted with a new pid" wait_for 60 new_pid $SERVER "$pid"
  check "ready after restart" wait_for 120 server_ready
  check "verify after restart: vault and keys survived" client verify

  say "== crash recovery (SIGKILL; KeepAlive restarts after ThrottleInterval)"
  pid=$(pid_of $SERVER)
  kill -KILL "$pid"
  check "launchd restarted the killed server (new pid)" wait_for 60 new_pid $SERVER "$pid"
  check "ready after crash" wait_for 120 server_ready
  check "verify after crash" client verify

  say "== stop and start (bootout / bootstrap)"
  pid=$(pid_of $SERVER); t0=$(date +%s)
  launchctl bootout "system/$SERVER"
  check "process is gone" wait_for 40 not kill -0 "$pid"
  took=$(( $(date +%s) - t0 ))
  check "stopped gracefully, before launchd's 30s ExitTimeOut (${took}s)" test "$took" -lt 30
  check "ports closed" wait_for 10 not listening 36969
  check "stale CLI socket removed on shutdown" not test -S "$RUN/cli.sock"
  launchctl bootstrap system /Library/LaunchDaemons/$SERVER.plist
  check "bootstrap starts it again" wait_for 120 server_ready
  check "verify after stop/start" client verify
  pid=$(pid_of $WEB)
  launchctl kickstart -k "system/$WEB"
  check "web restarts" wait_for 60 new_pid $WEB "$pid"
  check "web listens after restart" wait_for 60 listening 36968

  if [ -n "$DB_DIR" ]; then accept_db_outage; fi

  say "== local identities: one enrolled for the CLI, one not"
  make_test_user "$PROBE"
  make_test_user "$CLI_USER"
  dseditgroup -o edit -a "$CLI_USER" -t user _vaulthalla
  dscacheutil -flushcache
  check "$CLI_USER is enrolled (dsmemberutil)" sh -c "dsmemberutil checkmembership -U $CLI_USER -G _vaulthalla | grep -q 'is a member'"
  check "$PROBE is not" sh -c "dsmemberutil checkmembership -U $PROBE -G _vaulthalla | grep -q 'not a member'"
  local f victim
  victim=$(find "$STATE" -type f -size +1000k -print -quit)
  for who in "$PROBE" "$CLIENT"; do
    for f in "$STATE" "$RUN" "$MOUNT" "$LOGS"; do
      check "$who can't list $f" not sudo -u "$who" -- /bin/ls "$f"
    done
    check "$who can't read the config" not sudo -u "$who" -- /bin/cat "$CONFIG"
    check "$who can't read a vault backing file by path" not sudo -u "$who" -- /usr/bin/head -c 1 "$victim"
    out=$(sudo -u "$who" -- $PREFIX/bin/vh status 2>&1 || true)
    check "$who is refused by the CLI socket" grep -q "permission denied" <<<"$out"
  done
  # vh status exits 0/1/2 for healthy/degraded/critical: any of them is an answer through the socket.
  id=0; out=$(sudo -u "$CLI_USER" -- $PREFIX/bin/vh status 2>&1) || id=$?
  printf '%s\n' "$out" | sed -n '1,20s/^/  /p'
  check "enrolled $CLI_USER gets an answer from vh status (exit $id)" test "$id" -le 2
  out=$(sudo -u "$CLI_USER" -- $PREFIX/bin/vh vault list 2>&1) || true
  check "enrolled $CLI_USER (bound to admin as the first CLI user) sees the acceptance vault" grep -q install_acceptance <<<"$out"
  if sudo -u "$CLI_USER" -- $PREFIX/bin/vh help fs >/dev/null 2>&1; then accept_vh_fs; fi

  say "== logs"
  { tail -n 5 "$LOGS/server.log" 2>/dev/null || true; } | sed 's/^/  server.log: /'
  check "no secret reached the logs or the report" no_secrets_leaked
  say "accept: $failures failure(s)"
}

ciphertext_at_rest() {  # no stored file is a plaintext copy of an uploaded one; each upload has a sealed-size file
  /usr/bin/python3 - "$STATE" "$REPORT/acceptance.json" <<'EOF'
import hashlib, json, os, sys
state, record = sys.argv[1], json.load(open(sys.argv[2]))
want = {m["sha256"] for m in record["files"].values()}
sizes = {m["size"] for m in record["files"].values()}
plain = sealed = 0
for root, _, names in os.walk(state):
    for n in names:
        p = os.path.join(root, n)
        try: size = os.lstat(p).st_size
        except OSError: continue
        if size in sizes and hashlib.sha256(open(p, "rb").read()).hexdigest() in want: plain += 1
        if size - 16 in sizes: sealed += 1
print(f"  {sealed} sealed-size files, {plain} plaintext copies")
sys.exit(0 if plain == 0 and sealed >= len(want) else 1)
EOF
}

accept_vh_fs() {  # vh fs (#229), when the installed build has it: the bytes through the CLI socket, as the enrolled user
  local vid src got work rc
  say "== vh fs as $CLI_USER"
  vid=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vault_id"])' "$REPORT/acceptance.json")
  src=$(/usr/bin/python3 -c 'import json,sys; print(next(p for p in json.load(open(sys.argv[1]))["files"] if p.startswith("/acceptance-")))' "$REPORT/acceptance.json")
  work=$(mktemp -d /tmp/vh-fs-acceptance.XXXXXX)
  chown "$CLI_USER" "$work"
  check "vh fs ls lists the vault" sh -c "sudo -u $CLI_USER -- $PREFIX/bin/vh fs ls $vid / | grep -q acceptance-"
  check "vh fs get downloads a file uploaded over HTTP" sudo -u "$CLI_USER" -- $PREFIX/bin/vh fs get "$vid" "$src" -o "$work/got.bin"
  got=$(shasum -a 256 "$work/got.bin" 2>/dev/null | awk '{print $1}')
  check "  ...with the bytes the web upload stored" /usr/bin/python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["files"][sys.argv[2]]["sha256"] == sys.argv[3] else 1)' "$REPORT/acceptance.json" "$src" "$got"
  head -c 3000000 /dev/urandom > "$work/up.bin"; chown "$CLI_USER" "$work/up.bin"
  check "vh fs put uploads a 3 MB file" sudo -u "$CLI_USER" -- $PREFIX/bin/vh fs put "$vid" "$work/up.bin" /cli/up.bin
  check "  ...and it reads back identical" sh -c "sudo -u $CLI_USER -- $PREFIX/bin/vh fs get $vid /cli/up.bin -o - | cmp -s - '$work/up.bin'"
  rc=0; sudo -u "$CLI_USER" -- $PREFIX/bin/vh fs put "$vid" "$work/up.bin" /cli/up.bin >/dev/null 2>&1 || rc=$?
  check "vh fs put refuses to replace without --overwrite (exit $rc)" test "$rc" = 73
  check "vh fs put --overwrite replaces it" sudo -u "$CLI_USER" -- $PREFIX/bin/vh fs put "$vid" "$work/up.bin" /cli/up.bin --overwrite
  rc=0; sudo -u "$PROBE" -- $PREFIX/bin/vh fs get "$vid" "$src" -o - >/dev/null 2>&1 || rc=$?
  check "$PROBE can't use vh fs (exit $rc)" test "$rc" = 77
  check "no CLI upload left plaintext staged" test -z "$(find "$STATE/.cli-staging" -name '*.part' 2>/dev/null)"
  rm -rf "$work"
}

pg_ctl_as_owner() {  # pg_ctl_as_owner start|stop: the disposable cluster, as the user who owns it
  local bin owner
  bin="$(dirname "$(readlink -f /opt/homebrew/opt/postgresql@16/bin/pg_ctl)")"
  owner="$(stat -f %Su "$DB_DIR/data")"
  sudo -u "$owner" -- "$bin/pg_ctl" -D "$DB_DIR/data" -l "$DB_DIR/server.log" -w -t 60 -m fast "$1" >/dev/null
}

verify_within() {  # verify_within SECONDS: client verify passes before the deadline (the pool reconnects on its own)
  local deadline=$(( $(date +%s) + $1 ))
  until client verify >/dev/null 2>&1; do [ "$(date +%s)" -lt "$deadline" ] || { client verify; return 1; }; sleep 3; done
}

accept_db_outage() {  # the P0 shape: PostgreSQL goes away under the service, and the service starts before it
  local pid
  say "== database outage under the running server"
  pid=$(pid_of $SERVER)
  pg_ctl_as_owner stop
  sleep 10
  check "server stays up or launchd restarts it while the database is down" wait_for 15 has_pid $SERVER
  pg_ctl_as_owner start
  check "verify within 120s of the database returning (pool recovered)" verify_within 120
  say "  server pid $pid -> $(pid_of $SERVER)"

  say "== server restarted while the database is down (boot before PostgreSQL)"
  pg_ctl_as_owner stop
  pid=$(pid_of $SERVER)
  launchctl kickstart -k "system/$SERVER"
  check "restarted with a new pid" wait_for 60 new_pid $SERVER "$pid"
  sleep 15
  check "still running (or retrying under KeepAlive) without a database" wait_for 15 has_pid $SERVER
  pg_ctl_as_owner start
  check "ready once the database is up" wait_for 120 server_ready
  check "verify within 120s of the database returning" verify_within 120
}

no_secrets_leaked() {
  local s f
  for s in "$STATE/super_admin_initial_password" "$DB_PW_FILE"; do
    [ -r "$s" ] || continue
    for f in "$LOGS"/* "$REPORT"/*; do
      [ -f "$f" ] && grep -qF -- "$(head -1 "$s")" "$f" && { say "a secret appears in $f"; return 1; }
    done
  done
  return 0
}

free_uid() {
  local used id
  used=$(dscl . -list /Users UniqueID | awk '{print $2}')
  # Human-range uids (>= 501): the daemon binds the first CLI user to 'admin' only from there. Hidden, no shell, no
  # password, and high enough to stay clear of real accounts (System Settings counts up from 501).
  for id in $(seq 949 -1 900); do echo "$used" | grep -qx "$id" || { echo "$id"; return; }; done
  return 1
}

make_test_user() {
  if dscl . -read "/Users/$1" RecordName >/dev/null 2>&1; then
    dscl . -read "/Users/$1" RealName | grep -qF "$TEST_MARK" || die "$1 exists and isn't ours; not touching it"
    return 0
  fi
  local id; id=$(free_uid) || die "no free uid in 900-949"
  dscl . -create "/Users/$1"
  dscl . -create "/Users/$1" UniqueID "$id"
  dscl . -create "/Users/$1" PrimaryGroupID 20
  dscl . -create "/Users/$1" RealName "$TEST_MARK"
  dscl . -create "/Users/$1" UserShell /usr/bin/false
  dscl . -create "/Users/$1" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$1" Password '*'
  dscl . -create "/Users/$1" IsHidden 1
  say "created hidden test identity $1 (uid $id, staff, no shell, no password)"
}

phase_cleanup() {
  need_root cleanup
  local u
  for u in "$PROBE" "$CLI_USER"; do
    dscl . -read "/Users/$u" RecordName >/dev/null 2>&1 || continue
    dscl . -read "/Users/$u" RealName | grep -qF "$TEST_MARK" || { say "$u isn't ours; left alone"; continue; }
    dseditgroup -o edit -d "$u" -t user _vaulthalla 2>/dev/null || true
    dscl . -delete "/Users/$u"
    say "removed test identity $u"
  done
}

[ "$(uname -s)" = Darwin ] || die "macOS only"
[ -n "$REPORT" ] || die "--report-dir is required"
[ "$PHASE" = preflight ] || [ "$(id -u)" = 0 ] || die "needs root (sudo) except --phase preflight"
mkdir -p "$REPORT"
# The client half writes its record here as --client.
[ "$(id -u)" = 0 ] && [ -n "$CLIENT" ] && chown "$CLIENT" "$REPORT"
case "$PHASE" in
  preflight) phase_preflight ;;
  install) phase_install ;;
  provision) phase_provision ;;
  configure) phase_configure ;;
  accept) phase_accept ;;
  cleanup) phase_cleanup ;;
  all) phase_preflight; phase_install; phase_provision; phase_configure; phase_accept ;;
  *) die "unknown phase $PHASE" ;;
esac
[ -n "$CLIENT" ] && [ "$(id -u)" = 0 ] && chown -R "$CLIENT" "$REPORT"
echo "install-acceptance ($PHASE): $failures failure(s)"
[ "$failures" = 0 ]
