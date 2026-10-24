#!/usr/bin/env bash
# Manage the TEST-ONLY provider credential scaffold (/etc/vaulthalla/testing/providers.env).
#   test_providers.sh install [--host <ssh-alias>]   create dir+file from the example if absent (never overwrites)
#   test_providers.sh check   [--host <ssh-alias>]   report per-variable state: set | placeholder | missing
# Values are never printed. Without --host it acts on the local machine (needs sudo).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE="${SCRIPT_DIR}/providers.env.example"
TARGET_DIR="/etc/vaulthalla/testing"
TARGET="${TARGET_DIR}/providers.env"
REQUIRED_VARS=(
  VH_R2_ADMIN_ACCESS_KEY VH_R2_ADMIN_SECRET_KEY VH_R2_ADMIN_ENDPOINT VH_R2_ADMIN_REGION VH_CF_API_TOKEN
)

usage() { sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

cmd="${1:-}"; shift || true
host=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) host="${2:?--host needs a value}"; shift 2 ;;
    *) usage ;;
  esac
done

run_root() {
  # Run a root shell script locally or on --host; the script is passed on stdin. The script is for a Linux lab host
  # (getent, GNU stat, the vaulthalla group): from another OS (a Mac), only --host works.
  if [[ -n "$host" ]]; then ssh -o BatchMode=yes "$host" 'sudo bash -s'; return; fi
  if [[ "$(uname -s)" != Linux ]]; then
    echo "test_providers.sh: the scaffold lives on a Linux lab host; from $(uname -s) pass --host <ssh-alias>" >&2
    exit 2
  fi
  sudo bash -s
}

install_scaffold() {
  local example_b64
  example_b64="$(base64 <"$EXAMPLE" | tr -d '\n')"
  run_root <<REMOTE
set -euo pipefail
group=root
getent group vaulthalla >/dev/null 2>&1 && group=vaulthalla
install -d -m 0750 -o root -g "\$group" "$TARGET_DIR"
if [[ -e "$TARGET" ]]; then
  echo "exists: $TARGET (left unchanged)"
else
  umask 077
  printf '%s' "$example_b64" | base64 -d > "$TARGET"
  echo "created: $TARGET"
fi
chown root:"\$group" "$TARGET"
chmod 0640 "$TARGET"
stat -c '%A %U:%G %n' "$TARGET_DIR" "$TARGET"
REMOTE
}

check_scaffold() {
  local vars="${REQUIRED_VARS[*]}"
  run_root <<REMOTE
set -uo pipefail
if [[ ! -f "$TARGET" ]]; then echo "missing: $TARGET"; exit 1; fi
stat -c '%a %U:%G %n' "$TARGET"
rc=0
for v in $vars; do
  # Evaluate in a subshell with a clean env; print only the state, never the value.
  state=\$(env -i bash -c 'set -a; . "\$1" >/dev/null 2>&1; val="\${!2-}"; if [[ -z "\$val" ]]; then echo missing; elif [[ "\$val" == CHANGE_ME* ]]; then echo placeholder; else echo set; fi' _ "$TARGET" "\$v")
  printf '%-40s %s\n' "\$v" "\$state"
  [[ "\$state" == set ]] || rc=1
done
exit \$rc
REMOTE
}

case "$cmd" in
  install) install_scaffold ;;
  check) check_scaffold ;;
  *) usage ;;
esac
