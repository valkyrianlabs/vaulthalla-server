#!/bin/bash
# The Homebrew path, end to end, on a disposable Mac (CI only: it installs Vaulthalla and then zaps it).
#
#   tools/macos/pkg/cask-smoke.sh PKG
#
# Renders both release casks for PKG into a local tap with a file:// URL, with an empty Homebrew trust store (a fully
# qualified install must need no `brew trust`), then:
# - vaulthalla-server: `brew install --cask` (the package's postinstall provisions the service and enrolls the console
#   user as the CLI admin); the three daemons run as _vaulthalla; `vh status` and `vh vault list` answer the console
#   user; the web console answers; no Vaulthalla.app is installed; `brew uninstall` stops everything, keeps the data.
# - vaulthalla, over a newer Vaulthalla.app already in /Applications (as Sparkle leaves it): the server comes back on
#   the kept data and the newer app is not replaced; `brew uninstall` removes the app too.
# - vaulthalla again, on a Mac without the app: the bundled app lands, signed by the Valkyrian Labs LLC team.
# - `brew uninstall --zap` removes the service, its data, the _vaulthalla account and the app. Bash 3.2 compatible.
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
running() {  # running LABEL: loaded, with a pid owned by _vaulthalla
  local pid
  pid=$(sudo launchctl print "system/$1" 2>/dev/null | awk '$1 == "pid" && $2 == "=" {print $3}')
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
app_version() { /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$APP/Contents/Info.plist" 2>/dev/null; }
newer_app_kept() { [ "$(app_version)" = 999.0.0 ]; }
bundled_app_installed() { [ "$(app_version)" = "$BUNDLED_VERSION" ]; }
app_signed() { codesign --verify --deep --strict "$APP" && codesign -dv "$APP" 2>&1 | grep -q '^TeamIdentifier=ZG2G6V7GLC$'; }

[ "${CI:-}" = true ] || die "CI only: this installs Vaulthalla and then zaps it, data and account included"
[ -f "$PKG" ] || die "no package at $PKG"

echo "console user: $CONSOLE, running as $(id -un)"

# An empty trust store: only what's named in full may load (Homebrew 7 tap trust).
export XDG_CONFIG_HOME
XDG_CONFIG_HOME="$(mktemp -d)"

# A local tap holding both release casks, pointed at the package on disk.
brew tap-new --no-git "$TAP" >/dev/null
casks="$(brew --repository)/Library/Taps/vaulthalla/homebrew-smoke/Casks"
mkdir -p "$casks"
for cask in vaulthalla vaulthalla-server; do
  "$HERE/render-cask.sh" "$PKG" "$cask" |
    sed -e "s|^  url \".*\"\$|  url \"file://$PKG\"|" > "$casks/$cask.rb"
  grep -q "file://$PKG" "$casks/$cask.rb" || die "the rendered $cask cask's url wasn't replaced"
  ruby -c "$casks/$cask.rb" >/dev/null
done

# The app the package bundles, for the version checks below.
bundled="$(mktemp -d)"
pkgutil --expand-full "$PKG" "$bundled/pkg"
BUNDLED_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" \
  "$bundled/pkg/desktop.pkg/Payload/Vaulthalla.app/Contents/Info.plist")
[ -n "$BUNDLED_VERSION" ] || die "the package bundles no Vaulthalla.app"
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
check "the uninstaller is kept outside the receipt" test -x "$SUPPORT/uninstall.sh"
check "vaulthalla-server installs no Vaulthalla.app" no_app
check "the package's Desktop choice stayed off" sh -c '! pkgutil --pkg-info sh.vaulthalla.desktop >/dev/null 2>&1'

echo "== brew uninstall --cask vaulthalla-server (keeps data)"
brew uninstall --cask "$TAP/vaulthalla-server"
check "every daemon is stopped" no_service
check "vault data is kept" sudo test -d "$SUPPORT/state"
check "the package receipt is gone" sh -c '! pkgutil --pkg-info sh.vaulthalla.server >/dev/null 2>&1'

echo "== brew install --cask vaulthalla over a newer Vaulthalla.app (as Sparkle leaves it)"
sudo ditto "$bundled/pkg/desktop.pkg/Payload/Vaulthalla.app" "$APP"
sudo /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString 999.0.0" -c "Set :CFBundleVersion 999999" \
  "$APP/Contents/Info.plist"
brew install --cask "$TAP/vaulthalla"
check "the server is ready again on the kept data" wait_for 180 ready
check "the admin binding survived" admin_bound
check "the newer app was not replaced by the bundled $BUNDLED_VERSION" newer_app_kept

echo "== brew uninstall --cask vaulthalla (keeps data, removes the app)"
brew uninstall --cask "$TAP/vaulthalla"
check "every daemon is stopped" no_service
check "vault data is kept" sudo test -d "$SUPPORT/state"
check "the app is removed" no_app

echo "== brew install --cask vaulthalla (the bundled app)"
brew install --cask "$TAP/vaulthalla"
check "the server is ready again" wait_for 180 ready
check "Vaulthalla.app $BUNDLED_VERSION is installed" bundled_app_installed
check "the app is signed by the Valkyrian Labs LLC team" app_signed
check "the Desktop component's receipt exists" pkgutil --pkg-info sh.vaulthalla.desktop

echo "== brew uninstall --zap --cask vaulthalla (removes everything)"
brew uninstall --zap --cask "$TAP/vaulthalla"
check "every daemon is stopped" no_service
check "the support directory is gone" sh -c "[ ! -e '$SUPPORT' ]"
check "the _vaulthalla account is gone" account_gone
check "the app is gone" no_app

brew untap "$TAP" >/dev/null 2>&1 || true
rm -rf "$bundled"
echo "cask-smoke: $failures failure(s)"
[ "$failures" = 0 ]
