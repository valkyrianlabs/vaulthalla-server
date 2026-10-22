#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"
# shellcheck source=tools/e2e/load_env.sh
source "$REPO_ROOT/tools/e2e/load_env.sh"

RESULT_DIR="${S3_GATEWAY_E2E_RESULT_DIR:-$REPO_ROOT/test-results/s3-gateway-e2e}"
WEB_LOG="$RESULT_DIR/web.log"
GATEWAY_LOG="$RESULT_DIR/gateway.log"
GATEWAY_SYSTEMD_LOG="$RESULT_DIR/gateway-systemd.log"
ENV_REPORT="$RESULT_DIR/env-report.txt"
DEFAULT_VH_BIN="$REPO_ROOT/build/core/vaulthalla-cli"
[[ -x "$DEFAULT_VH_BIN" ]] || DEFAULT_VH_BIN="vh"
VH_BIN="${VH_BIN:-$DEFAULT_VH_BIN}"

WEB_URL="${VAULTHALLA_E2E_BASE_URL:-http://127.0.0.1:3000}"
GATEWAY_ENDPOINT="${S3_GATEWAY_ENDPOINT:-http://127.0.0.1:39000}"
PREFIX="${S3_GATEWAY_E2E_PREFIX:-s3-gateway-e2e/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
WEB_TIMEOUT=120
GATEWAY_TIMEOUT=90
USE_BUILD_RUNTIME="${S3_GATEWAY_E2E_USE_BUILD_RUNTIME:-0}"
REQUIRE_REMOTE=0
LOCAL_ONLY=0
NO_START_WEB=0
KEEP_PROCESSES=0
WEB_PID=""
RUNTIME_PID=""
WEB_STATUS=not-run
LOCAL_STATUS=not-run
REMOTE_STATUS=not-run
FAILED=0
STOPPED_SYSTEMD_GATEWAY=0

usage() {
  cat <<'USAGE'
Usage: tools/smoke/s3_gateway_e2e.sh [options]

Options:
  --local-only             Exercise web and local gateway smoke only.
  --require-remote         Require the R2/S3-backed smoke pass.
  --prefix <prefix>        Prefix for smoke data. Defaults to s3-gateway-e2e/<timestamp>-<pid>.
  --no-start-web           Do not start the Next dev server if the web URL is unreachable.
  --keep-processes         Keep wrapper-started background processes running after exit.
  --use-build-runtime      Run smoke against build/core/vaulthalla-server and restore systemd afterward.
  --web-timeout <seconds>  Time to wait for a wrapper-started web server. Default: 120.
  -h, --help               Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local-only)
      LOCAL_ONLY=1
      shift
      ;;
    --require-remote)
      REQUIRE_REMOTE=1
      shift
      ;;
    --prefix)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--prefix requires a value" >&2
        exit 2
      fi
      PREFIX="$2"
      shift 2
      ;;
    --no-start-web)
      NO_START_WEB=1
      shift
      ;;
    --keep-processes)
      KEEP_PROCESSES=1
      shift
      ;;
    --use-build-runtime)
      USE_BUILD_RUNTIME=1
      shift
      ;;
    --web-timeout)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
        echo "--web-timeout requires an integer number of seconds" >&2
        exit 2
      fi
      WEB_TIMEOUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$LOCAL_ONLY" == "1" && "$REQUIRE_REMOTE" == "1" ]]; then
  echo "--local-only and --require-remote cannot be combined" >&2
  exit 2
fi

PREFIX="${PREFIX#/}"
PREFIX="${PREFIX%/}"
if [[ -z "$PREFIX" ]]; then
  echo "prefix must not be empty" >&2
  exit 2
fi

install -d -m 0755 "$RESULT_DIR"
vh_e2e_redacted_env_report | tee "$ENV_REPORT"

cleanup() {
  if [[ "$KEEP_PROCESSES" == "1" ]]; then
    return 0
  fi
  if [[ -n "$WEB_PID" ]] && kill -0 "$WEB_PID" >/dev/null 2>&1; then
    kill -- "-$WEB_PID" >/dev/null 2>&1 || kill "$WEB_PID" >/dev/null 2>&1 || true
    wait "$WEB_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$RUNTIME_PID" ]] && kill -0 "$RUNTIME_PID" >/dev/null 2>&1; then
    pkill -TERM -P "$RUNTIME_PID" >/dev/null 2>&1 || true
    kill "$RUNTIME_PID" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      kill -0 "$RUNTIME_PID" >/dev/null 2>&1 || break
      sleep 0.5
    done
    if kill -0 "$RUNTIME_PID" >/dev/null 2>&1; then
      pkill -KILL -P "$RUNTIME_PID" >/dev/null 2>&1 || true
      kill -KILL "$RUNTIME_PID" >/dev/null 2>&1 || true
    fi
    wait "$RUNTIME_PID" >/dev/null 2>&1 || true
  fi
  if [[ "$USE_BUILD_RUNTIME" == "1" ]]; then
    pkill -KILL -u vaulthalla -f "^$REPO_ROOT/build/core/vaulthalla-server( |$)" >/dev/null 2>&1 || true
  fi
  if [[ "$STOPPED_SYSTEMD_GATEWAY" == "1" ]]; then
    run_root systemctl start vaulthalla.service >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

run_root() {
  if [[ "$(id -u)" == "0" ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -n "$@"
  else
    return 1
  fi
}

reachable() {
  local url="$1"
  curl --connect-timeout 3 --max-time 6 -sS -o /dev/null "$url" >/dev/null 2>&1
}

wait_for_url() {
  local url="$1"
  local timeout="$2"
  local label="$3"
  local start
  start="$(date +%s)"
  while (( $(date +%s) - start < timeout )); do
    if reachable "$url"; then
      return 0
    fi
    if [[ "$label" == "web" && -n "$WEB_PID" ]] && ! kill -0 "$WEB_PID" >/dev/null 2>&1; then
      return 1
    fi
    if [[ "$label" == "runtime" && -n "$RUNTIME_PID" ]] && ! kill -0 "$RUNTIME_PID" >/dev/null 2>&1; then
      return 1
    fi
    sleep 2
  done
  return 1
}

url_part() {
  python3 - "$1" "$2" <<'PY'
from urllib.parse import urlparse
import sys
url = urlparse(sys.argv[1])
part = sys.argv[2]
if part == "hostname":
    print(url.hostname or "")
elif part == "port":
    print(url.port or (443 if url.scheme == "https" else 80))
PY
}

is_local_url() {
  local host
  host="$(url_part "$1" hostname)"
  [[ "$host" == "localhost" || "$host" == "127.0.0.1" || "$host" == "::1" ]]
}

remote_configured() {
  [[ -n "${S3_GATEWAY_SMOKE_API_KEY:-}" && -n "${S3_GATEWAY_SMOKE_UPSTREAM_BUCKET:-}" ]] && return 0
  [[ -n "${S3_GATEWAY_SMOKE_UPSTREAM_BUCKET:-}" &&
     -n "${S3_GATEWAY_SMOKE_UPSTREAM_ACCESS_KEY:-}" &&
     -n "${S3_GATEWAY_SMOKE_UPSTREAM_SECRET_KEY:-}" &&
     -n "${S3_GATEWAY_SMOKE_UPSTREAM_ENDPOINT:-}" ]] && return 0
  vh_e2e_has_r2_env
}

start_web_if_needed() {
  if reachable "$WEB_URL"; then
    echo "Web server already reachable at $WEB_URL; reusing it."
    return 0
  fi

  if [[ "$NO_START_WEB" == "1" ]]; then
    echo "web stack is not reachable at $WEB_URL and --no-start-web was set" >&2
    return 1
  fi

  if ! is_local_url "$WEB_URL"; then
    echo "web stack is not reachable at $WEB_URL and the URL is not local; cannot start it from this wrapper" >&2
    return 1
  fi

  local host port bind_host
  host="$(url_part "$WEB_URL" hostname)"
  port="$(url_part "$WEB_URL" port)"
  bind_host="$host"
  [[ "$bind_host" == "localhost" ]] && bind_host="127.0.0.1"

  echo "Starting web dev server for $WEB_URL; log: $WEB_LOG"
  : >"$WEB_LOG"
  NEXT_PUBLIC_VAULTHALLA_WS_ORIGIN="${NEXT_PUBLIC_VAULTHALLA_WS_ORIGIN:-ws://127.0.0.1:36969}" \
  VAULTHALLA_AUTH_ORIGIN="${VAULTHALLA_AUTH_ORIGIN:-http://127.0.0.1:36970}" \
  VAULTHALLA_PREVIEW_ORIGIN="${VAULTHALLA_PREVIEW_ORIGIN:-http://127.0.0.1:36970}" \
  VAULTHALLA_E2E_WEB_HOST="$bind_host" \
  VAULTHALLA_E2E_WEB_PORT="$port" \
    setsid pnpm --dir web run dev:e2e >"$WEB_LOG" 2>&1 &
  WEB_PID=$!

  if wait_for_url "$WEB_URL" "$WEB_TIMEOUT" web; then
    echo "Web server is reachable at $WEB_URL"
    return 0
  fi

  echo "web stack is not reachable at $WEB_URL after startup attempt; last web log lines:" >&2
  tail -n 80 "$WEB_LOG" >&2 || true
  return 1
}

systemd_units() {
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei '^vaulthalla(-swtpm|-cli|-web)?\.service$|^vaulthalla.*\.service$' || true
}

unit_exists() {
  local needle="$1"
  shift
  local unit
  for unit in "$@"; do
    [[ "$unit" == "$needle" ]] && return 0
  done
  return 1
}

systemd_status_logs() {
  local unit="$1"
  {
    echo "===== systemctl status $unit ====="
    run_root systemctl status "$unit" --no-pager --lines=50 || true
    echo
    echo "===== journalctl -u $unit ====="
    run_root journalctl -u "$unit" -n 120 --no-pager || true
  } >>"$GATEWAY_SYSTEMD_LOG" 2>&1
}

start_gateway_with_systemd() {
  mapfile -t units < <(systemd_units)
  [[ "${#units[@]}" -gt 0 ]] || return 1

  {
    echo "Discovered Vaulthalla systemd units:"
    printf '  %s\n' "${units[@]}"
  } >>"$GATEWAY_SYSTEMD_LOG"

  if unit_exists "vaulthalla-swtpm.service" "${units[@]}"; then
    echo "Starting vaulthalla-swtpm.service if needed." | tee -a "$GATEWAY_SYSTEMD_LOG"
    run_root systemctl start vaulthalla-swtpm.service >>"$GATEWAY_SYSTEMD_LOG" 2>&1 || true
    systemd_status_logs "vaulthalla-swtpm.service"
  fi

  if unit_exists "vaulthalla.service" "${units[@]}"; then
    local action="start"
    if systemctl --quiet is-active vaulthalla.service 2>/dev/null; then
      action="restart"
    fi
    echo "Attempting systemctl $action vaulthalla.service." | tee -a "$GATEWAY_SYSTEMD_LOG"
    run_root systemctl "$action" vaulthalla.service >>"$GATEWAY_SYSTEMD_LOG" 2>&1 || true
    systemd_status_logs "vaulthalla.service"
    return 0
  fi

  return 1
}

start_gateway_with_fallback_runtime() {
  : >>"$GATEWAY_LOG"
  if [[ -n "${VAULTHALLA_RUNTIME_CMD:-}" ]]; then
    echo "Starting runtime with VAULTHALLA_RUNTIME_CMD; log: $GATEWAY_LOG"
    bash -lc "$VAULTHALLA_RUNTIME_CMD" >"$GATEWAY_LOG" 2>&1 &
    RUNTIME_PID=$!
    return 0
  fi

  local candidate
  for candidate in "$REPO_ROOT/build/core/vaulthalla" "$REPO_ROOT/build/vaulthalla"; do
    if [[ -x "$candidate" ]]; then
      echo "Starting runtime binary $candidate; log: $GATEWAY_LOG"
      VH_PATH_TO_CONFIG="${VH_PATH_TO_CONFIG:-$REPO_ROOT/deploy/config/config.yaml}" "$candidate" >"$GATEWAY_LOG" 2>&1 &
      RUNTIME_PID=$!
      return 0
    fi
  done

  return 1
}

start_gateway_with_build_runtime() {
  local server="$REPO_ROOT/build/core/vaulthalla-server"
  [[ -x "$server" ]] || {
    echo "build runtime requested but $server is not executable" >&2
    return 1
  }

  : >"$GATEWAY_LOG"
  : >"$GATEWAY_SYSTEMD_LOG"
  echo "Starting branch-built gateway runtime $server; log: $GATEWAY_LOG"
  run_root systemctl stop vaulthalla.service >>"$GATEWAY_SYSTEMD_LOG" 2>&1 || true
  STOPPED_SYSTEMD_GATEWAY=1
  # The log belongs to the caller, not the vaulthalla user: the redirect is meant to run outside sudo.
  # shellcheck disable=SC2024
  sudo -n -u vaulthalla bash -lc \
    'set -a; source /etc/vaulthalla/vaulthalla.env; set +a; cd /var/lib/vaulthalla; exec "$1"' \
    _ "$server" >"$GATEWAY_LOG" 2>&1 &
  RUNTIME_PID=$!
  wait_for_url "$GATEWAY_ENDPOINT" "$GATEWAY_TIMEOUT" runtime
}

gateway_diagnostics() {
  echo "S3 gateway diagnostics:"
  if command -v "$VH_BIN" >/dev/null 2>&1 || [[ -x "$VH_BIN" ]]; then
    "$VH_BIN" s3-gateway status || true
  fi
  if [[ -s "$GATEWAY_SYSTEMD_LOG" ]]; then
    echo "Last systemd diagnostics from $GATEWAY_SYSTEMD_LOG:"
    tail -n 120 "$GATEWAY_SYSTEMD_LOG" || true
  fi
  if [[ -s "$GATEWAY_LOG" ]]; then
    echo "Last fallback runtime log lines from $GATEWAY_LOG:"
    tail -n 120 "$GATEWAY_LOG" || true
  fi
}

start_gateway_if_needed() {
  if [[ "$USE_BUILD_RUNTIME" == "1" ]]; then
    if start_gateway_with_build_runtime; then
      echo "Branch-built S3 gateway is reachable at $GATEWAY_ENDPOINT"
      return 0
    fi
    echo "Branch-built S3 gateway did not become reachable at $GATEWAY_ENDPOINT." >&2
    gateway_diagnostics >&2
    return 1
  fi

  if reachable "$GATEWAY_ENDPOINT"; then
    echo "S3 gateway already reachable at $GATEWAY_ENDPOINT; reusing it."
    return 0
  fi

  : >"$GATEWAY_SYSTEMD_LOG"
  echo "S3 gateway is not reachable at $GATEWAY_ENDPOINT; attempting enable/start."

  if command -v "$VH_BIN" >/dev/null 2>&1 || [[ -x "$VH_BIN" ]]; then
    {
      echo "===== vh s3-gateway status before enable ====="
      "$VH_BIN" s3-gateway status || true
      echo
      echo "===== vh s3-gateway enable ====="
      "$VH_BIN" s3-gateway enable || true
      echo
      echo "===== vh s3-gateway status after enable ====="
      "$VH_BIN" s3-gateway status || true
    } >>"$GATEWAY_LOG" 2>&1
  else
    echo "vh CLI not found; skipping vh s3-gateway enable." >>"$GATEWAY_LOG"
  fi

  start_gateway_with_systemd || start_gateway_with_fallback_runtime || true

  if wait_for_url "$GATEWAY_ENDPOINT" "$GATEWAY_TIMEOUT" runtime; then
    echo "S3 gateway is reachable at $GATEWAY_ENDPOINT"
    return 0
  fi

  echo "S3 gateway is not reachable at $GATEWAY_ENDPOINT after enable/start attempts." >&2
  gateway_diagnostics >&2
  return 1
}

ensure_playwright_chromium() {
  local install_log="$RESULT_DIR/playwright-install.log"
  if pnpm --dir web exec playwright install chromium >"$install_log" 2>&1; then
    return 0
  fi
  if grep -qi "missing dependencies\\|install-deps\\|with-deps" "$install_log"; then
    echo "Installing Playwright Chromium system dependencies; log: $install_log"
    run_root pnpm --dir web exec playwright install-deps chromium >>"$install_log" 2>&1 || true
    pnpm --dir web exec playwright install chromium >>"$install_log" 2>&1
    return 0
  fi
  echo "Playwright Chromium install failed; log: $install_log" >&2
  tail -n 80 "$install_log" >&2 || true
  return 1
}

if ! start_gateway_if_needed; then
  LOCAL_STATUS=unreachable
  FAILED=1
else
  if ! start_web_if_needed; then
    WEB_STATUS=unreachable
    FAILED=1
  else
    if ! ensure_playwright_chromium; then
      WEB_STATUS=browser-install-fail
      FAILED=1
    elif VAULTHALLA_E2E_BASE_URL="$WEB_URL" pnpm --dir web run test:e2e:s3-gateway; then
      WEB_STATUS=pass
    else
      WEB_STATUS=fail
      FAILED=1
    fi
  fi

  if VH_BIN="$VH_BIN" tools/smoke/s3_gateway_scoped_budget_smoke.sh --local-only --budget-denial synthetic --prefix "$PREFIX/local"; then
    LOCAL_STATUS=pass
  else
    LOCAL_STATUS=fail
    FAILED=1
  fi
fi

if [[ "$LOCAL_ONLY" == "1" ]]; then
  REMOTE_STATUS=skipped-local-only
elif [[ "$REQUIRE_REMOTE" == "1" ]] || remote_configured; then
  if VH_BIN="$VH_BIN" tools/smoke/s3_gateway_scoped_budget_smoke.sh --require-remote --budget-denial both --prefix "$PREFIX/remote"; then
    REMOTE_STATUS=pass
  else
    REMOTE_STATUS=fail
    FAILED=1
    echo "REMOTE SMOKE FAILED; check cleanup output for prefix: $PREFIX/remote" >&2
  fi
else
  REMOTE_STATUS=skipped-no-remote-config
fi

echo
if [[ "$FAILED" == "0" ]]; then
  echo "S3 gateway E2E summary: PASS"
else
  echo "S3 gateway E2E summary: FAIL"
fi
echo "  web: $WEB_STATUS ($WEB_URL)"
echo "  local smoke: $LOCAL_STATUS ($GATEWAY_ENDPOINT)"
echo "  remote smoke: $REMOTE_STATUS"
echo "  prefix: $PREFIX"
echo "  env report: $ENV_REPORT"
echo "  web log: $WEB_LOG"
echo "  gateway log: $GATEWAY_LOG"

exit "$FAILED"
