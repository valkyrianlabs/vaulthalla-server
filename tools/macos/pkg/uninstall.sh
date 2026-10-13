#!/bin/bash
# Removes the Vaulthalla macOS package: stops and unloads its LaunchDaemons and deletes the installed files. Vault
# data, the database, logs, config.yaml and the _vaulthalla account stay unless --purge, which deletes all of them.
#
#   sudo "/Library/Application Support/Vaulthalla/uninstall.sh" [--purge]
set -euo pipefail
SUPPORT="/Library/Application Support/Vaulthalla"
PKG_ID=sh.vaulthalla.server
PURGE=false
case "${1:-}" in --purge) PURGE=true ;; '') ;; *) echo "usage: uninstall.sh [--purge]" >&2; exit 2 ;; esac
[ "$(id -u)" = 0 ] || { echo "uninstall.sh: run it with sudo" >&2; exit 1; }

# --apply: without it the provisioner only prints its plan. If it fails, nothing below runs (set -e): no file is
# deleted while a daemon might still be running.
if [ "$PURGE" = true ]; then "$SUPPORT/vaulthalla-provision" --remove --purge --apply
else "$SUPPORT/vaulthalla-provision" --remove --apply; fi
# bootout returns while launchd still lets a daemon exit (up to its ExitTimeOut: 60 s for PostgreSQL).
for label in sh.vaulthalla.caddy sh.vaulthalla.server sh.vaulthalla.web sh.vaulthalla.postgres; do
  i=0
  while /bin/launchctl print "system/$label" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 75 ]; then echo "uninstall.sh: $label is still loaded; stopping" >&2; exit 1; fi
    sleep 1
  done
done

if /usr/sbin/pkgutil --pkg-info "$PKG_ID" >/dev/null 2>&1; then
  /usr/sbin/pkgutil --only-files --files "$PKG_ID" | while IFS= read -r f; do rm -f "/$f"; done
  # Only directories the package owns outright (a vaulthalla path component); shared ones like usr/local/bin stay.
  /usr/sbin/pkgutil --only-dirs --files "$PKG_ID" | LC_ALL=C sort -r | while IFS= read -r d; do
    case "/$d/" in */vaulthalla/*|*/vaulthalla-web/*) rm -rf "/${d:?}" ;; esac
  done
  /usr/sbin/pkgutil --forget "$PKG_ID" >/dev/null
fi

if [ "$PURGE" = true ]; then
  rm -rf "${SUPPORT:?}"
  echo "Vaulthalla removed, with its data."
else
  echo "Vaulthalla removed. Data kept in $SUPPORT and /Library/Logs/Vaulthalla (uninstall.sh --purge deletes it)."
fi
