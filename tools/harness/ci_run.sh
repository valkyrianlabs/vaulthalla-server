#!/usr/bin/env bash
# Workflow-owned paths only; no installation, bootstrap, service restart or shared cleanup.
set -euo pipefail
: "${VHH_WORK:?}" "${VHH_BUILD:?}" "${VHH_ARTIFACTS:?}" "${PROFILE:?}"
SESSIONS="${SESSIONS:-8}"
ROUNDS="${ROUNDS:-20}"
[[ "$SESSIONS" =~ ^[0-9]+$ && "$SESSIONS" -ge 2 && "$SESSIONS" -le 64 ]] || exit 2
[[ "$ROUNDS" =~ ^[0-9]+$ && "$ROUNDS" -ge 1 && "$ROUNDS" -le 1000 ]] || exit 2
case "$(hostname -s)" in vh-storage*) echo "refusing production host" >&2; exit 2;; esac
seed="$("$VHH_WORK/python/bin/python" -c \
  'import secrets,sys; print(hex(int(sys.argv[1], 0) & (2**64-1)) if sys.argv[1] else hex(secrets.randbits(64)))' "${SEED:-}")"
printf 'harness profile=%s seed=%s sessions=%s\n' "$PROFILE" "$seed" "$SESSIONS"
vhh=(sudo -n env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/tools/harness"
     "$VHH_WORK/python/bin/python" -m vhh)
base=(--target launch --build "$VHH_BUILD" --seed "$seed" --sessions "$SESSIONS" --surfaces "ws,fuse")
case "$PROFILE" in
  smoke) "${vhh[@]}" run "${base[@]}" --ops 25 --schedule lockstep --out "$VHH_ARTIFACTS/smoke"
         "${vhh[@]}" scenario revoke --build "$VHH_BUILD" --out "$VHH_ARTIFACTS/revoke" ;;
  pressure) "${vhh[@]}" run "${base[@]}" --ops 60 --schedule barrier --out "$VHH_ARTIFACTS/pressure"
            "${vhh[@]}" scenario magic --build "$VHH_BUILD" --seed "$seed" --sessions "$SESSIONS" \
              --rounds "$ROUNDS" --out "$VHH_ARTIFACTS/magic" ;;
  assault) "${vhh[@]}" run "${base[@]}" --ops 120 --schedule free --out "$VHH_ARTIFACTS/assault"
           for scenario in revoke hang crash; do
             "${vhh[@]}" scenario "$scenario" --build "$VHH_BUILD" --out "$VHH_ARTIFACTS/$scenario"
           done ;;
  proof) VH_TEST_CONFIG=default VH_TEST_SEED="$seed" bash bin/tests/run_proof.sh --build-dir "$VHH_BUILD" \
           --artifacts "$VHH_ARTIFACTS/proof" ;;
  regress) "${vhh[@]}" regress --build "$VHH_BUILD" --artifacts "$VHH_ARTIFACTS/regress" ;;
  revoke|magic) "${vhh[@]}" scenario "$PROFILE" --build "$VHH_BUILD" --seed "$seed" --sessions "$SESSIONS" \
                  --rounds "$ROUNDS" --out "$VHH_ARTIFACTS/$PROFILE" ;;
  *) echo "unknown profile" >&2; exit 2 ;;
esac
