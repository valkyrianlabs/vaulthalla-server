#!/bin/bash
# Installs the macOS package as the real system service and proves it (roadmap #216/#219/#230). Root, on a Mac you
# may change.
#
#   sudo tools/macos/install-acceptance.sh --pkg FILE --python PY --report-dir DIR [--client USER] [--phase PHASE]
#
# Phases (default: all, in this order; each can be rerun on its own):
#   preflight  read-only: every payload path is new or one this package (or an earlier acceptance run) installed;
#              no foreign account; the service ports are free or held by our own LaunchDaemons. Runs without root.
#   install    `installer -pkg`: its postinstall provisions (account, private dirs, bundled PostgreSQL, LaunchDaemons)
#              and enrolls the console user, who becomes the CLI 'admin'. Then provisioning must be a no-op.
#   accept     account, permissions and the three LaunchDaemons; the web console; an encrypted vault over HTTP with
#              RBAC denial (tools/macos/install_acceptance.py as --client); ciphertext at rest; restart, crash
#              recovery, stop/start; PostgreSQL restarted under the server and the server started before PostgreSQL
#              (each recovers); `vh` and `vh fs` as the enrolled client; a hidden unenrolled identity refused
#              everywhere; `vh setup caddy` on an internal name (HTTPS through the Vaulthalla CA, WebSockets, previews,
#              provisioning still idempotent); the package reinstalled over itself (an upgrade) keeping every byte and
#              bringing Caddy back; then `vh teardown caddy --purge`.
#   cleanup    removes the hidden test identity (only if this script created it).
# It never purges and never prints secrets: the admin password goes from the state directory to the client on stdin.
set -euo pipefail

SUPPORT="/Library/Application Support/Vaulthalla"
STATE="$SUPPORT/state"
RUN="$SUPPORT/run"
MOUNT="$SUPPORT/mount"
PGDIR="$SUPPORT/postgres"
CONFIG="$SUPPORT/config.yaml"
LOGS=/Library/Logs/Vaulthalla
PREFIX=/usr/local
PROV=$PREFIX/lib/vaulthalla/vaulthalla-provision
SERVER=sh.vaulthalla.server
WEB=sh.vaulthalla.web
PG=sh.vaulthalla.postgres
PKG_ID=sh.vaulthalla.server
PORTS="36968 36969 36970 36971"
TEST_MARK="Vaulthalla acceptance test identity"
PROBE=vhtest_probe
CADDY_NAME=acceptance.vaulthalla.test
REPO="$(cd "$(dirname "$0")/../.." && pwd -P)"

PKG="" PY="" REPORT="" CLIENT="${SUDO_USER:-}" PHASE=all
while [ $# -gt 0 ]; do
  case "$1" in
    --pkg) PKG="$2"; shift ;;
    --python) PY="$2"; shift ;;
    --report-dir) REPORT="$2"; shift ;;
    --client) CLIENT="$2"; shift ;;
    --phase) PHASE="$2"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
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
loaded() { launchctl print "system/$1" >/dev/null 2>&1; }
pid_of() { { launchctl print "system/$1" 2>/dev/null || true; } | awk '$1 == "pid" && $2 == "=" {print $3}'; }
runs_as_service() { local p; p=$(pid_of "$1"); [ -n "$p" ] && [ "$(ps -o uid= -p "$p" | tr -d ' ')" = "$(id -u _vaulthalla)" ]; }
has_pid() { [ -n "$(pid_of "$1")" ]; }
new_pid() { local p; p=$(pid_of "$1"); [ -n "$p" ] && [ "$p" != "$2" ]; }
server_ready() { listening 36969 && listening 36970 && [ -S "$RUN/cli.sock" ]; }
pg_ready() { listening 36971; }
perms() { stat -f '%Sp %Su:%Sg' "$1"; }
as_client() { sudo -u "$CLIENT" -- "$@"; }

client() {  # client seed|verify: the admin password goes from the state dir to the unprivileged client on stdin
  # shellcheck disable=SC2024  # deliberate: root opens the secret, the client only gets the stream
  as_client "$PY" "$REPO/tools/macos/install_acceptance.py" "$1" --state "$REPORT/acceptance.json" \
    --expect-mount-state disabled < "$STATE/super_admin_initial_password"
}

verify_within() {  # verify_within SECONDS: client verify passes before the deadline (the pool reconnects on its own)
  local deadline=$(( $(date +%s) + $1 ))
  until client verify >/dev/null 2>&1; do [ "$(date +%s)" -lt "$deadline" ] || { client verify; return 1; }; sleep 3; done
}

payload_dir() {  # the package's payload, expanded once per run
  local d="$REPORT/payload"
  if [ ! -d "$d/root" ]; then
    rm -rf "$d" && mkdir -p "$d"
    pkgutil --expand-full "$PKG" "$d/expanded" >/dev/null
    mv "$d/expanded/component.pkg/Payload" "$d/root"
    rm -rf "$d/expanded"
  fi
  echo "$d/root"
}

phase_preflight() {
  [ -f "$PKG" ] || die "--pkg $PKG: no such package"
  pkgutil --check-signature "$PKG" 2>&1 | sed -n '1,2s/^/  /p' || true
  local root
  root=$(payload_dir)
  # Every payload path must be new, identical, or ours: in this package's receipt or an earlier acceptance install.
  /usr/bin/python3 - "$root" "$REPORT/installed-paths.txt" "$PKG_ID" <<'EOF'
import filecmp, os, subprocess, sys
root, recorded, pkg_id = sys.argv[1:]
owned_roots = [l.strip() for l in open(recorded)] if os.path.exists(recorded) else []
r = subprocess.run(["pkgutil", "--files", pkg_id], capture_output=True, text=True)
receipt = {"/" + l for l in r.stdout.splitlines()} if r.returncode == 0 else set()
def ours(p): return p in receipt or any(p == o or p.startswith(o + "/") for o in owned_roots)
new = same = updates = 0; conflicts = []
for d, dirs, files in os.walk(root):
    for n in dirs + files:
        src = os.path.join(d, n); dst = src[len(root):]
        if not os.path.lexists(dst): new += 1; continue
        if os.path.isdir(src) and not os.path.islink(src):
            if not os.path.isdir(dst) or os.path.islink(dst): conflicts.append(dst)
            continue
        if os.path.islink(src):
            if os.path.islink(dst) and os.readlink(dst) == os.readlink(src): same += 1
            elif ours(dst): updates += 1
            else: conflicts.append(dst)
            continue
        if os.path.isfile(dst) and filecmp.cmp(src, dst, shallow=False): same += 1
        elif ours(dst): updates += 1
        else: conflicts.append(dst)
for c in conflicts[:20]: print(f"[acceptance] conflict: {c} exists and isn't ours")
print(f"[acceptance] payload: {new} new, {same} identical, {updates} update(s) to our own files, {len(conflicts)} conflict(s)")
sys.exit(1 if conflicts else 0)
EOF
  if ! loaded "$SERVER" && ! loaded "$WEB" && ! loaded "$PG"; then
    for p in $PORTS; do
      if listening "$p"; then die "port $p is in use by something else"; fi
    done
  fi
  if dscl . -read /Users/_vaulthalla RecordName >/dev/null 2>&1; then say "_vaulthalla exists (provisioning validates it)"
  else say "_vaulthalla does not exist yet"; fi
  for p in "$SUPPORT" "$LOGS" /Library/LaunchDaemons/$SERVER.plist /Library/LaunchDaemons/$WEB.plist /Library/LaunchDaemons/$PG.plist; do
    if [ -e "$p" ]; then say "exists: $p"; else say "absent: $p"; fi
  done
}

phase_install() {
  need_root install
  phase_preflight
  local log="$REPORT/installer.log"
  say "installing $(basename "$PKG") (console user $(stat -f %Su /dev/console) is enrolled by the postinstall)"
  installer -pkg "$PKG" -target / -verboseR > "$log" 2>&1 || { tail -30 "$log"; die "installer failed (log: $log)"; }
  grep -E '^installer:' "$log" | tail -3 | sed 's/^/  /'
  check "the package receipt is recorded" pkgutil --pkg-info "$PKG_ID"
  "$PROV" | tee "$REPORT/provision-after.txt" | tail -1
  check "provisioning is idempotent after the install (a second plan has nothing to do)" \
    grep -q "0 change(s) to make" "$REPORT/provision-after.txt"
}

phase_accept() {
  need_root accept
  [ -n "$PY" ] && [ -n "$CLIENT" ] || die "accept needs --python and --client (or sudo from your account)"

  say "== account and permissions"
  dscl . -read /Users/_vaulthalla UniqueID PrimaryGroupID UserShell NFSHomeDirectory IsHidden RecordName | sed 's/^/  /'
  check "_vaulthalla uid in 450-499" sh -c 'u=$(id -u _vaulthalla); [ "$u" -ge 450 ] && [ "$u" -le 499 ]'
  check "_vaulthalla is hidden" sh -c 'dscl . -read /Users/_vaulthalla IsHidden | grep -q " 1$"'
  check "support dir root:wheel 0755" test "$(perms "$SUPPORT")" = "drwxr-xr-x root:wheel"
  check "state dir _vaulthalla 0700" test "$(perms "$STATE")" = "drwx------ _vaulthalla:_vaulthalla"
  check "run dir _vaulthalla 0750" test "$(perms "$RUN")" = "drwxr-x--- _vaulthalla:_vaulthalla"
  check "mount dir _vaulthalla 0700" test "$(perms "$MOUNT")" = "drwx------ _vaulthalla:_vaulthalla"
  check "postgres dir _vaulthalla 0700" test "$(perms "$PGDIR")" = "drwx------ _vaulthalla:_vaulthalla"
  check "log dir _vaulthalla 0750" test "$(perms "$LOGS")" = "drwxr-x--- _vaulthalla:_vaulthalla"
  check "config root:_vaulthalla 0640" test "$(perms "$CONFIG")" = "-rw-r----- root:_vaulthalla"
  check "config points at the bundled PostgreSQL" grep -qE '^  port: 36971' "$CONFIG"
  check "CLI socket _vaulthalla 0660" test "$(perms "$RUN/cli.sock")" = "srw-rw---- _vaulthalla:_vaulthalla"
  check "DB password handoff consumed (sealed into the state dir)" not test -e "$RUN/db_password"
  check "uninstaller kept outside the receipt" test -x "$SUPPORT/uninstall.sh"

  say "== LaunchDaemons"
  for label in $PG $SERVER $WEB; do
    { launchctl print "system/$label" || true; } | grep -E '^\s+(state|pid|runs|last exit code) = ' | sed "s/^/  $label /" || true
    check "$label running as _vaulthalla" runs_as_service "$label"
  done
  check "PostgreSQL listens on 127.0.0.1:36971 only" sh -c \
    "lsof -nP -iTCP:36971 -sTCP:LISTEN | awk 'NR>1 {print \$9}' | sort -u | grep -qx '127.0.0.1:36971'"
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
  check "verify after restart: vault and keys survived" verify_within 60

  say "== crash recovery (SIGKILL; KeepAlive restarts after ThrottleInterval)"
  pid=$(pid_of $SERVER)
  kill -KILL "$pid"
  check "launchd restarted the killed server (new pid)" wait_for 60 new_pid $SERVER "$pid"
  check "ready after crash" wait_for 120 server_ready
  check "verify after crash" verify_within 60

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
  check "verify after stop/start" verify_within 60
  pid=$(pid_of $WEB)
  launchctl kickstart -k "system/$WEB"
  check "web restarts" wait_for 60 new_pid $WEB "$pid"
  check "web listens after restart" wait_for 60 listening 36968

  accept_db_outage

  say "== the enrolled client ($CLIENT) and an unenrolled local identity"
  make_test_user "$PROBE"
  check "$CLIENT is enrolled (dsmemberutil)" sh -c "dsmemberutil checkmembership -U $CLIENT -G _vaulthalla | grep -q 'is a member'"
  check "$PROBE is not" sh -c "dsmemberutil checkmembership -U $PROBE -G _vaulthalla | grep -q 'not a member'"
  local f victim
  victim=$(find "$STATE" -type f -size +1000k -print -quit)
  for f in "$STATE" "$MOUNT" "$PGDIR"; do
    check "$CLIENT can't list $f (service-private)" not as_client /bin/ls "$f"
  done
  check "$CLIENT can't read a vault backing file by path" not as_client /usr/bin/head -c 1 "$victim"
  for f in "$STATE" "$RUN" "$MOUNT" "$PGDIR" "$LOGS"; do
    check "$PROBE can't list $f" not sudo -u "$PROBE" -- /bin/ls "$f"
  done
  check "$PROBE can't read the config" not sudo -u "$PROBE" -- /bin/cat "$CONFIG"
  check "$PROBE can't read a vault backing file by path" not sudo -u "$PROBE" -- /usr/bin/head -c 1 "$victim"
  out=$(sudo -u "$PROBE" -- $PREFIX/bin/vh status 2>&1 || true)
  check "$PROBE is refused by the CLI socket" grep -q "permission denied" <<<"$out"
  # vh status exits 0/1/2 for healthy/degraded/critical: any of them is an answer through the socket.
  rc=0; out=$(as_client $PREFIX/bin/vh status 2>&1) || rc=$?
  printf '%s\n' "$out" | sed -n '1,20s/^/  /p'
  check "$CLIENT gets an answer from vh status (exit $rc)" test "$rc" -le 2
  out=$(as_client $PREFIX/bin/vh vault list 2>&1) || true
  check "$CLIENT is bound to 'admin' and sees the acceptance vault" grep -q install_acceptance <<<"$out"
  accept_vh_fs
  accept_caddy

  say "== upgrade: the package installed over itself"
  # installer's exit status, not its wording: a reinstall reports "The upgrade was successful."
  check "reinstall succeeded" installer -pkg "$PKG" -target / > "$REPORT/reinstall.log" 2>&1
  check "ready after the upgrade" wait_for 120 server_ready
  check "verify after the upgrade: every byte kept" verify_within 120
  check "the admin binding survived the upgrade" sh -c "sudo -u $CLIENT -- $PREFIX/bin/vh vault list 2>&1 | grep -q install_acceptance"
  if [ -f "$SUPPORT/caddy/Caddyfile" ]; then
    check "Caddy is back after the upgrade" wait_for 60 caddy_https_ok
    $PREFIX/bin/vh teardown caddy --purge | sed 's/^/  /'
    check "vh teardown caddy --purge removed it" caddy_gone
  fi

  say "== logs"
  { tail -n 5 "$LOGS/server.log" 2>/dev/null || true; } | sed 's/^/  server.log: /'
  check "no secret reached the logs or the report" no_secrets_leaked
  say "accept: $failures failure(s)"
}

accept_db_outage() {  # the P0 shape: PostgreSQL restarts under the server, and the server starts before PostgreSQL
  local pid
  say "== PostgreSQL restarted under the running server"
  pid=$(pid_of $PG)
  launchctl kill SIGINT "system/$PG"  # fast shutdown; KeepAlive brings it back after ThrottleInterval
  check "PostgreSQL went down" wait_for 30 not kill -0 "$pid"
  check "launchd restarted PostgreSQL" wait_for 60 new_pid $PG "$pid"
  check "server stayed up or came back" wait_for 30 has_pid $SERVER
  check "verify within 120s of PostgreSQL returning (pool recovered)" verify_within 120

  say "== server started before PostgreSQL (boot order)"
  launchctl bootout "system/$SERVER"
  launchctl bootout "system/$PG"
  check "PostgreSQL is down" wait_for 60 not pg_ready
  launchctl bootstrap system /Library/LaunchDaemons/$SERVER.plist
  sleep 15
  check "server is running or retrying under KeepAlive without a database" sh -c \
    "launchctl print system/$SERVER | grep -qE 'state = (running|spawn scheduled)'"
  launchctl bootstrap system /Library/LaunchDaemons/$PG.plist
  check "ready once PostgreSQL is up" wait_for 120 server_ready
  check "verify within 120s of PostgreSQL returning" verify_within 120
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

accept_vh_fs() {  # vh fs (#229), when the installed build has it: the bytes through the CLI socket, as the enrolled client
  as_client $PREFIX/bin/vh help fs >/dev/null 2>&1 || { say "vh fs not in this build; skipped"; return 0; }
  local vid src got work rc
  say "== vh fs as $CLIENT"
  vid=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vault_id"])' "$REPORT/acceptance.json")
  src=$(/usr/bin/python3 -c 'import json,sys; print(next(p for p in json.load(open(sys.argv[1]))["files"] if p.startswith("/acceptance-")))' "$REPORT/acceptance.json")
  work=$(mktemp -d /tmp/vh-fs-acceptance.XXXXXX)
  chown "$CLIENT" "$work"
  check "vh fs ls lists the vault" sh -c "sudo -u $CLIENT -- $PREFIX/bin/vh fs ls $vid / | grep -q acceptance-"
  check "vh fs get downloads a file uploaded over HTTP" as_client $PREFIX/bin/vh fs get "$vid" "$src" -o "$work/got.bin"
  got=$(shasum -a 256 "$work/got.bin" 2>/dev/null | awk '{print $1}')
  check "  ...with the bytes the web upload stored" /usr/bin/python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["files"][sys.argv[2]]["sha256"] == sys.argv[3] else 1)' "$REPORT/acceptance.json" "$src" "$got"
  head -c 3000000 /dev/urandom > "$work/up.bin"; chown "$CLIENT" "$work/up.bin"
  check "vh fs put uploads a 3 MB file" as_client $PREFIX/bin/vh fs put "$vid" "$work/up.bin" /cli/up.bin --overwrite
  check "  ...and it reads back identical" sh -c "sudo -u $CLIENT -- $PREFIX/bin/vh fs get $vid /cli/up.bin -o - | cmp -s - '$work/up.bin'"
  rc=0; as_client $PREFIX/bin/vh fs put "$vid" "$work/up.bin" /cli/up.bin >/dev/null 2>&1 || rc=$?
  check "vh fs put refuses to replace without --overwrite (exit $rc)" test "$rc" = 73
  check "vh fs put --overwrite replaces it" as_client $PREFIX/bin/vh fs put "$vid" "$work/up.bin" /cli/up.bin --overwrite
  rc=0; sudo -u "$PROBE" -- $PREFIX/bin/vh fs get "$vid" "$src" -o - >/dev/null 2>&1 || rc=$?
  check "$PROBE can't use vh fs (exit $rc)" test "$rc" = 77
  check "no CLI upload left plaintext staged" test -z "$(find "$STATE/.cli-staging" -name '*.part' 2>/dev/null)"
  rm -rf "$work"
}

caddy_https_ok() {  # the console answers through Caddy, verified against the exported Vaulthalla CA
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$SUPPORT/vaulthalla-local-ca.crt" \
    --resolve "$CADDY_NAME:443:127.0.0.1" "https://$CADDY_NAME/" 2>/dev/null || true)
  case "$code" in 2??|3??) return 0 ;; *) return 1 ;; esac
}
caddy_gone() { ! loaded sh.vaulthalla.caddy && [ ! -e "$SUPPORT/caddy" ] && not listening 443; }
caddy_private() {
  [ "$(stat -f '%Sp %Su' "$SUPPORT/caddy")" = "drwx------ _vaulthalla" ] && [ "$(stat -f '%Lp' "$SUPPORT/caddy/Caddyfile")" = 600 ]
}
ca_constrained() {
  openssl x509 -in "$SUPPORT/vaulthalla-local-ca.crt" -noout -text | grep -A2 'Name Constraints' | grep -q "DNS:$CADDY_NAME"
}
ws_through_caddy() {
  as_client "$PY" - "$SUPPORT/vaulthalla-local-ca.crt" "$CADDY_NAME" <<'WSEOF'
import asyncio, json, ssl, sys
import websockets
async def main():
    ctx = ssl.create_default_context(cafile=sys.argv[1])
    async with websockets.connect(f"wss://{sys.argv[2]}/ws", ssl=ctx, host="127.0.0.1", port=443,
                                  server_hostname=sys.argv[2], open_timeout=10) as ws:
        await ws.send(json.dumps({"command": "auth.isAuthenticated", "requestId": "1", "payload": {}}))
        await asyncio.wait_for(ws.recv(), 10)
asyncio.run(main())
WSEOF
}

accept_caddy() {  # vh setup caddy on an internal name: HTTPS, WebSockets and previews through Caddy as _vaulthalla
  [ -x "$PREFIX/lib/vaulthalla/vaulthalla-caddy" ] || { say "vh setup caddy not in this build; skipped"; return 0; }
  say "== vh setup caddy --domain $CADDY_NAME"
  if listening 443 && ! loaded sh.vaulthalla.caddy; then say "port 443 is in use by something else; skipped"; return 0; fi
  check "vh setup caddy succeeds" sh -c "$PREFIX/bin/vh setup caddy --domain $CADDY_NAME > '$REPORT/caddy-setup.log' 2>&1"
  sed 's/^/  /' "$REPORT/caddy-setup.log" | head -8
  check "Caddy runs as _vaulthalla" runs_as_service sh.vaulthalla.caddy
  check "the caddy directory and Caddyfile are private to it" caddy_private
  check "the CA is name-constrained to $CADDY_NAME" ca_constrained
  check "the console answers over HTTPS, verified against the Vaulthalla CA" wait_for 60 caddy_https_ok
  out=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$SUPPORT/vaulthalla-local-ca.crt" \
    --resolve "$CADDY_NAME:443:127.0.0.1" "https://$CADDY_NAME/preview?vault_id=1&path=/x" || true)
  check "/preview is routed to the HTTP server (got $out without a session)" test "$out" = 401
  check "a WebSocket opens through Caddy and the daemon answers" ws_through_caddy
  "$PROV" > "$REPORT/provision-caddy.txt"
  check "provisioning is still a no-op with Caddy configured" grep -q "0 change(s) to make" "$REPORT/provision-caddy.txt"
}

no_secrets_leaked() {
  local s f
  [ -r "$STATE/super_admin_initial_password" ] || return 0
  s=$(head -1 "$STATE/super_admin_initial_password")
  for f in "$LOGS"/* "$REPORT"/*; do
    [ -f "$f" ] && grep -qF -- "$s" "$f" && { say "a secret appears in $f"; return 1; }
  done
  return 0
}

free_uid() {
  local used id
  used=$(dscl . -list /Users UniqueID | awk '{print $2}')
  # Human-range uids (>= 501), hidden, no shell, no password, and high enough to stay clear of real accounts.
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
  for u in "$PROBE" vhtest_cli; do
    dscl . -read "/Users/$u" RecordName >/dev/null 2>&1 || continue
    dscl . -read "/Users/$u" RealName | grep -qF "$TEST_MARK" || { say "$u isn't ours; left alone"; continue; }
    dseditgroup -o edit -d "$u" -t user _vaulthalla 2>/dev/null || true
    dscl . -delete "/Users/$u"
    say "removed test identity $u"
  done
}

[ "$(uname -s)" = Darwin ] || die "macOS only"
[ -n "$REPORT" ] || die "--report-dir is required"
[ "$PHASE" = preflight ] || [ "$PHASE" = cleanup ] || [ "$(id -u)" = 0 ] || die "needs root (sudo) except --phase preflight"
mkdir -p "$REPORT"
# The client half writes its record here as --client.
[ "$(id -u)" = 0 ] && [ -n "$CLIENT" ] && chown "$CLIENT" "$REPORT"
case "$PHASE" in
  preflight) phase_preflight ;;
  install) phase_install ;;
  accept) phase_accept ;;
  cleanup) phase_cleanup ;;
  all) phase_install; phase_accept ;;
  *) die "unknown phase $PHASE" ;;
esac
[ -n "$CLIENT" ] && [ "$(id -u)" = 0 ] && chown -R "$CLIENT" "$REPORT"
echo "install-acceptance ($PHASE): $failures failure(s)"
[ "$failures" = 0 ]
