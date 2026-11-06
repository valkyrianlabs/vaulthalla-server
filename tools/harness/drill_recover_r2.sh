#!/usr/bin/env bash
# The catastrophic restore drill against live Cloudflare R2 (design/encryption/03-metadata-recovery.md §7; #371).
#
#   sudo tools/harness/drill_recover_r2.sh --build build [--files 300] [--env /srv/vaulthalla/.bashrc]
#
# Node A writes an opaque_v1 vault into the fixed test bucket vh-test-recover-drill (vh_live_bucket creates it; a
# leftover of a crashed run is emptied and deleted first), node A is destroyed, node B (its own database, state
# directory and swtpm) restores it from the bucket and the kit, node C restores it again; the bucket is emptied and
# deleted afterwards whatever happened (HeadBucket must say it is gone). The two nodes may be private instances on one
# host (as here) or two hosts: the drill needs nothing from node A but the bucket and the kit.
#
# Credentials: the R2 admin key VH_R2_ADMIN_{ACCESS_KEY,SECRET_KEY,ENDPOINT} (+ optional REGION), read from the env file
# (only those `export` lines) into this process's environment; the drill hands them to the daemons over their sockets,
# never on a command line, and never prints them. Negative drills need the fake bucket's side channel: harness only.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE=/srv/vaulthalla/.bashrc
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) ENV_FILE="$2"; shift 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "drill_recover_r2: needs root (private daemon instances): use sudo" >&2; exit 2; }
[[ -r "$ENV_FILE" ]] || { echo "drill_recover_r2: $ENV_FILE is not readable" >&2; exit 2; }
eval "$(grep -E '^export VH_R2_ADMIN_(ACCESS_KEY|SECRET_KEY|ENDPOINT|REGION)=' "$ENV_FILE")"
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$HERE"
exec python3 -m vhh.drill recover --s3 r2 "${ARGS[@]}"
