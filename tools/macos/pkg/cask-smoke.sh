#!/bin/bash
# The Homebrew path, end to end, on a disposable Mac (CI only: it installs Vaulthalla and then zaps it).
#
#   tools/macos/pkg/cask-smoke.sh PKG
#
# Renders both release casks for PKG into a local tap with file:// URLs, beside the published vaulthalla-desktop cask
# (valkyrianlabs/homebrew-tap), with an empty Homebrew trust store, then:
# - vaulthalla-server, named in full (no `brew trust`): `brew install --cask` (the package's postinstall provisions the
#   service and enrolls the console user as the CLI admin); the three daemons run as _vaulthalla; `vh status` and
#   `vh vault list` answer the console user; the web console answers; the daemon sealed its secrets with the Secure
#   Enclave (on a virtual Mac, whichever backend it reports, `file` if its virtual SEP refuses the daemon) and opens
#   them again after a restart; no Vaulthalla.app is
#   installed; `brew uninstall` stops everything, keeps the data.
# - vaulthalla, the meta cask: refused until the tap is trusted (Homebrew loads dependency casks only from a trusted
#   tap); then it installs vaulthalla-server (the server comes back on the kept data) and vaulthalla-desktop (the
#   published app, signed by the Valkyrian Labs LLC team) and opens Desktop once (its Caskroom marker); uninstalling
#   it leaves both and drops the marker.
# - `brew uninstall --zap` of the two removes the service, its data, the _vaulthalla account and the app.
# Bash 3.2 compatible.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
PKG="$(cd "$(dirname "${1:?usage: cask-smoke.sh PKG}")" && pwd -P)/$(basename "$1")"
SUPPORT="/Library/Application Support/Vaulthalla"
TAP=vaulthalla/smoke
failures=0

die() { echo "::error::cask-smoke: $*" >&2; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "::error::FAIL $*"; failures=$((failures + 1)); }
check() { local name="$1"; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }
wait_for() { local deadline=$(( $(date +%s) + $1 )); shift; until "$@"; do [ "$(date +%s)" -lt "$deadline" ] || return 1; sleep 1; done; }
listening() { /usr/bin/nc -z -G 1 127.0.0.1 "$1" >/dev/null 2>&1; }
pid_of() { sudo launchctl print "system/$1" 2>/dev/null | awk '$1 == "pid" && $2 == "=" {print $3}'; }
running() {  # running LABEL: loaded, with a pid owned by _vaulthalla
  local pid
  pid=$(pid_of "$1")
  [ -n "$pid" ] && [ "$(ps -o user= -p "$pid" | tr -d ' ')" = _vaulthalla ]
}
loaded() { sudo launchctl print "system/$1" >/dev/null 2>&1; }
ready() { listening 36968 && listening 36969 && [ -S "$SUPPORT/run/cli.sock" ]; }
web_ok() { case "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:36968/ || true)" in 2??|3??) return 0 ;; *) return 1 ;; esac; }
CONSOLE=$(stat -f %Su /dev/console)
as_console() { sudo -u "$CONSOLE" -- "$@"; }  # a fresh credential, as a new terminal would have
vh_answers() { local rc=0; as_console /usr/local/bin/vh status >/dev/null 2>&1 || rc=$?; [ "$rc" -le 2 ]; }
admin_bound() { as_console /usr/local/bin/vh vault list >/dev/null 2>&1; }
no_service() { ! loaded sh.vaulthalla.server && ! loaded sh.vaulthalla.web && ! loaded sh.vaulthalla.postgres; }
account_gone() { ! dscl . -read /Users/_vaulthalla >/dev/null 2>&1; }
APP=/Applications/Vaulthalla.app
no_app() { [ ! -e "$APP" ]; }
has_app() { [ -d "$APP" ]; }
OPENED_MARKER="$(brew --caskroom)/vaulthalla/.desktop-opened"
installed() { brew list --cask --versions "${1##*/}" >/dev/null 2>&1; }  # brew list takes the token, not tap/token
nothing_installed() { no_service && no_app; }
status_backend() { as_console /usr/local/bin/vh status 2>/dev/null | awk -F': ' '/secrets backend:/ {print $2; exit}' | awk '{print $1}'; }
VIRTUAL=$(sysctl -n kern.hv_vmm_present 2>/dev/null || echo 0)
backend_expected() {  # secure-enclave on real hardware; a virtual Mac may report file (no usable virtual SEP)
  local b; b=$(status_backend)
  [ "$b" = secure-enclave ] || { [ "$VIRTUAL" = 1 ] && [ "$b" = file ]; }
}
sealed_as_reported() {  # the DB password sealed in the reported backend's format, and no slot left in the other one
  local found ext other
  case "$(status_backend)" in secure-enclave) ext=se other=key ;; file) ext=key other=se ;; *) return 1 ;; esac
  found=$(sudo sh -c "ls '$SUPPORT/state'/.sealed_*.blob/") || return 1
  echo "$found" | grep -qx "psql\.$ext" && ! echo "$found" | grep -q "\.$other\$"
}
same_backend() { [ "$(status_backend)" = "$FIRST_BACKEND" ]; }
restarted() { local pid; pid=$(pid_of sh.vaulthalla.server); [ -n "$pid" ] && [ "$pid" != "$OLD_PID" ] && ready; }
app_signed() { codesign --verify --deep --strict "$APP" && codesign -dv "$APP" 2>&1 | grep -q '^TeamIdentifier=ZG2G6V7GLC$'; }

[ "${CI:-}" = true ] || die "CI only: this installs Vaulthalla and then zaps it, data and account included"
[ -f "$PKG" ] || die "no package at $PKG"

echo "console user: $CONSOLE, running as $(id -un)"

# An empty trust store: only what's named in full may load (Homebrew 7 tap trust).
export XDG_CONFIG_HOME
XDG_CONFIG_HOME="$(mktemp -d)"

# A local tap holding both release casks, pointed at the package on disk, and the published vaulthalla-desktop cask.
brew tap-new --no-git "$TAP" >/dev/null
casks="$(brew --repository)/Library/Taps/vaulthalla/homebrew-smoke/Casks"
mkdir -p "$casks"
"$HERE/render-cask.sh" "$PKG" vaulthalla-server |
  sed -e "s|^  url \".*\"\$|  url \"file://$PKG\"|" > "$casks/vaulthalla-server.rb"
"$HERE/render-cask.sh" "$PKG" vaulthalla |
  sed -e "s|^  url \".*\"\$|  url \"file://$PKG.sha256\"|" \
      -e "s|\"valkyrianlabs/tap/vaulthalla-|\"$TAP/vaulthalla-|" > "$casks/vaulthalla.rb"
curl -fsSL https://raw.githubusercontent.com/valkyrianlabs/homebrew-tap/main/Casks/vaulthalla-desktop.rb \
  -o "$casks/vaulthalla-desktop.rb"
grep -q "file://$PKG\"" "$casks/vaulthalla-server.rb" || die "the rendered vaulthalla-server cask's url wasn't replaced"
grep -q "file://$PKG.sha256\"" "$casks/vaulthalla.rb" || die "the rendered vaulthalla cask's url wasn't replaced"
grep -q "\"$TAP/vaulthalla-desktop\"" "$casks/vaulthalla.rb" || die "the vaulthalla cask's dependencies weren't retargeted"
! grep -q conflicts_with "$casks/vaulthalla-desktop.rb" || die "the published vaulthalla-desktop cask still conflicts"
for cask in vaulthalla vaulthalla-server vaulthalla-desktop; do ruby -c "$casks/$cask.rb" >/dev/null; done
no_app || die "$APP already exists on this runner"

echo "== brew install --cask vaulthalla-server"
brew install --cask "$TAP/vaulthalla-server"
check "the server becomes ready" wait_for 180 ready
for label in sh.vaulthalla.postgres sh.vaulthalla.server sh.vaulthalla.web; do
  check "$label runs as _vaulthalla" running "$label"
done
check "the web console answers on 127.0.0.1:36968" wait_for 60 web_ok
check "vh status answers the console user (enrolled by the postinstall)" wait_for 60 vh_answers
check "the console user is bound to admin (vh vault list)" admin_bound
# Informational: does a session that was open during the install see the new group membership?
rc=0; /usr/local/bin/vh status >/dev/null 2>&1 || rc=$?
if [ "$rc" -le 2 ]; then echo "::notice::an already-open session can use vh right after install (exit $rc)"
else echo "::notice::an already-open session can't use vh yet (exit $rc): a new terminal is needed after install"; fi
check "the initial admin password was generated" sudo test -s "$SUPPORT/state/super_admin_initial_password"
FIRST_BACKEND=$(status_backend)
echo "::notice::secrets backend: $FIRST_BACKEND (virtual machine: $VIRTUAL)"
check "vh status reports the secure-enclave secrets backend (file allowed only on a virtual Mac)" backend_expected
check "the daemon sealed its secrets in the reported backend's format" sealed_as_reported
echo "== restart the daemon (it must unseal what it sealed)"
OLD_PID=$(pid_of sh.vaulthalla.server)
sudo launchctl kickstart -k system/sh.vaulthalla.server
check "the server is ready again after a restart (new pid)" wait_for 180 restarted
check "the sealed DB password opens after a restart (vh vault list)" wait_for 60 admin_bound
check "the uninstaller is kept outside the receipt" test -x "$SUPPORT/uninstall.sh"
check "vaulthalla-server installs no Vaulthalla.app" no_app

echo "== brew uninstall --cask vaulthalla-server (keeps data)"
brew uninstall --cask "$TAP/vaulthalla-server"
check "every daemon is stopped" no_service
check "vault data is kept" sudo test -d "$SUPPORT/state"
check "the package receipt is gone" sh -c '! pkgutil --pkg-info sh.vaulthalla.server >/dev/null 2>&1'

echo "== brew install --cask vaulthalla from an untrusted tap"
check "the meta cask is refused until the tap is trusted" sh -c "! brew install --cask '$TAP/vaulthalla'"
check "nothing was installed" nothing_installed

echo "== brew trust $TAP; brew install --cask vaulthalla"
brew trust --tap "$TAP"
brew install --cask "$TAP/vaulthalla"
check "vaulthalla-server is installed as its own cask" installed "$TAP/vaulthalla-server"
check "vaulthalla-desktop is installed as its own cask" installed "$TAP/vaulthalla-desktop"
check "the server is ready again on the kept data" wait_for 180 ready
check "the admin binding survived" admin_bound
check "the reinstalled server reports the same secrets backend ($FIRST_BACKEND)" same_backend
check "Vaulthalla.app is installed" has_app
check "the app is signed by the Valkyrian Labs LLC team" app_signed
# The meta cask opens Desktop once (it then pairs with this server through vh, no code); upgrades don't reopen it.
check "the meta cask opened Desktop once (its marker is in the Caskroom)" test -e "$OPENED_MARKER"
if pgrep -x Vaulthalla >/dev/null; then echo "::notice::Desktop is running after the meta cask's install"
else echo "::notice::Desktop isn't running after the meta cask's install (no login session for open?)"; fi

echo "== brew uninstall --cask vaulthalla (leaves the server and the app)"
brew uninstall --cask "$TAP/vaulthalla"
check "the server keeps running" ready
check "the app stays" has_app
check "the marker goes with the meta cask" test ! -e "$OPENED_MARKER"
# Quit the Desktop the meta cask opened (by its exact pid) before its cask is zapped.
for pid in $(pgrep -x Vaulthalla || true); do kill "$pid" 2>/dev/null || true; done

echo "== brew uninstall --zap --cask vaulthalla-desktop vaulthalla-server (removes everything)"
brew uninstall --zap --cask "$TAP/vaulthalla-desktop" "$TAP/vaulthalla-server"
check "every daemon is stopped" no_service
check "the support directory is gone" sh -c "[ ! -e '$SUPPORT' ]"
check "the _vaulthalla account is gone" account_gone
check "the app is gone" no_app

brew untap "$TAP" >/dev/null 2>&1 || true
echo "cask-smoke: $failures failure(s)"
[ "$failures" = 0 ]
