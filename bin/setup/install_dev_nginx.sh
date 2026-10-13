#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$ROOT_DIR/bin/lib/dev_mode.sh"

env_flag_enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

if ! vh_is_dev_mode; then
  exit 0
fi

# `vh setup nginx` (deploy/lifecycle) configures the production install's paths, ports and services, so it never
# runs for the isolated dev instance: the dogfood nginx endpoint belongs to production.
source "$ROOT_DIR/bin/lib/platform.sh"
if [[ -n "$(vh_selected_instance)" ]]; then
  echo "Skipping dev nginx setup: the lifecycle tool targets the production install, not the '$(vh_selected_instance)' instance."
  exit 0
fi

if env_flag_enabled "${VH_SKIP_DEV_NGINX:-}"; then
  echo "Skipping dev nginx setup (VH_SKIP_DEV_NGINX=${VH_SKIP_DEV_NGINX})."
  exit 0
fi

: "${VH_DEV_WEB_DOMAIN:=vaulthalla.dev}"
: "${VH_DEV_S3_DOMAIN:=s3.vaulthalla.dev}"
: "${VH_DEV_CLOUDFLARE_CREDENTIALS_DIR:=/etc/vaulthalla/certbot}"
: "${VH_DEV_CLOUDFLARE_CREDENTIAL_FILENAME:=cloudflare.ini}"
: "${VH_DEV_CLOUDFLARE_CREDENTIALS:=${VH_DEV_CLOUDFLARE_CREDENTIALS_DIR}/${VH_DEV_CLOUDFLARE_CREDENTIAL_FILENAME}}"
: "${SYSTEMD_UNIT_DIR:=/etc/systemd/system}"

WEB_DEV_DROPIN="${VH_WEB_DEV_SYSTEMD_DROPIN:-${SYSTEMD_UNIT_DIR}/vaulthalla-web.service.d/dev-nginx.conf}"

web_unit_exists() {
  systemctl list-unit-files vaulthalla-web.service --no-legend 2>/dev/null | grep -q '^vaulthalla-web\.service' ||
    systemctl status vaulthalla-web.service >/dev/null 2>&1
}

reload_systemd_and_restart_web() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi

  sudo systemctl daemon-reload
  if web_unit_exists; then
    if ! sudo systemctl restart vaulthalla-web.service; then
      echo "Warning: could not restart vaulthalla-web.service after updating dev runtime flags." >&2
    fi
  fi
}

# Older dev installs set VAULTHALLA_WEB_DEV_MODE through a drop-in; it only fed the retired default-password gate.
clear_dev_web_runtime_flags() {
  if [[ ! -f "$WEB_DEV_DROPIN" ]]; then
    return 0
  fi

  echo "Removing dev nginx web runtime flags (${WEB_DEV_DROPIN})."
  sudo rm -f "$WEB_DEV_DROPIN"
  rmdir "$(dirname "$WEB_DEV_DROPIN")" >/dev/null 2>&1 || true
  reload_systemd_and_restart_web
}

if [[ -f "./${VH_DEV_CLOUDFLARE_CREDENTIAL_FILENAME}" ]]; then
  if [[ ! -f "$VH_DEV_CLOUDFLARE_CREDENTIALS" ]] || env_flag_enabled "${VH_DEV_REPLACE_CLOUDFLARE_CREDENTIALS:-}"; then
    sudo mkdir -p "${VH_DEV_CLOUDFLARE_CREDENTIALS_DIR}"
    sudo cp "./${VH_DEV_CLOUDFLARE_CREDENTIAL_FILENAME}" "${VH_DEV_CLOUDFLARE_CREDENTIALS_DIR}"
    sudo chmod 600 "${VH_DEV_CLOUDFLARE_CREDENTIALS}"
  else
    echo "Keeping existing Cloudflare credentials at ${VH_DEV_CLOUDFLARE_CREDENTIALS}."
    sudo chmod 600 "${VH_DEV_CLOUDFLARE_CREDENTIALS}"
  fi
fi

if [[ ! -f "$VH_DEV_CLOUDFLARE_CREDENTIALS" ]]; then
  clear_dev_web_runtime_flags
  cat <<EOF
Skipping dev nginx setup; Cloudflare credentials were not found at:
  $VH_DEV_CLOUDFLARE_CREDENTIALS

The vaulthalla.dev nginx endpoint is optional dogfood infrastructure.
Use the local Caddyfile endpoint for normal development, or add the credentials
and rerun the installer when you want to exercise nginx.
EOF
  exit 0
fi

LIFECYCLE="${VH_LIFECYCLE_BIN:-/usr/lib/vaulthalla/lifecycle}"
if [[ ! -x "$LIFECYCLE" ]]; then
  LIFECYCLE="$ROOT_DIR/deploy/lifecycle/main.py"
fi

echo "Configuring dev nginx for $VH_DEV_WEB_DOMAIN and $VH_DEV_S3_DOMAIN..."
echo "This exposes the web console over HTTPS (optional; skipped without Cloudflare credentials). If the generated"
echo "initial super-admin password is still in use and its file still exists, setup nginx offers to rotate it or"
echo "delete the file first."
"$LIFECYCLE" setup nginx \
  --domain "$VH_DEV_WEB_DOMAIN" \
  --s3-domain "$VH_DEV_S3_DOMAIN" \
  --certbot-dns-cloudflare "$VH_DEV_CLOUDFLARE_CREDENTIALS"

clear_dev_web_runtime_flags
