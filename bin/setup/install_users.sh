#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=bin/lib/platform.sh
source "$ROOT_DIR/bin/lib/platform.sh"
vh_instance_layout "$(vh_selected_instance)"

REAL_USER="${SUDO_USER:-${USER:-}}"
if [[ -z "$REAL_USER" || "$REAL_USER" == "root" ]]; then
    # fallback if script wasn't run via sudo
    REAL_USER="$(logname 2>/dev/null || true)"
fi

if [[ "$(vh_os)" == darwin ]]; then
    # vaulthalla-provision created the hidden account (and never enrolls anyone, #202): enrolling you for the dev
    # instance's CLI is this explicit, dev-only step. Production enrollment stays a deliberate operator action.
    if [[ -n "$REAL_USER" && "$REAL_USER" != "root" ]]; then
        echo "👤 Enrolling '$REAL_USER' in $VH_ACCOUNT (the $VH_INSTANCE instance's CLI group)..."
        vh_priv dseditgroup -o edit -a "$REAL_USER" -t user "$VH_ACCOUNT"
    else
        echo "⚠️ Could not determine a non-root invoking user; skipping CLI enrollment."
    fi
    echo "🔗 $VH_CLI_LINK -> $VH_BINDIR/vaulthalla-cli"
    vh_priv install -d -m 0755 "$(dirname "$VH_CLI_LINK")"
    vh_priv ln -sfn "$VH_BINDIR/vaulthalla-cli" "$VH_CLI_LINK"
    exit 0
fi

# === 1) Create the service group if it doesn't exist ===
if ! getent group "$VH_GROUP" > /dev/null; then
    echo "👥 Creating system group '$VH_GROUP'..."
    vh_priv groupadd --system "$VH_GROUP"
else
    echo "👥 System group '$VH_GROUP' already exists."
fi

# === 2) Create the service user if it doesn't exist ===
if ! id -u "$VH_USER" >/dev/null 2>&1; then
    echo "👤 Creating system user '$VH_USER'..."
    vh_priv useradd \
        --system \
        --gid "$VH_GROUP" \
        --shell /usr/sbin/nologin \
        --no-create-home \
        "$VH_USER"
else
    echo "👤 System user '$VH_USER' already exists."
fi

# === 3) Add invoking user to the service group ===
if [[ -n "$REAL_USER" && "$REAL_USER" != "root" ]]; then
    echo "👤 Adding user '$REAL_USER' to '$VH_GROUP' group..."
    vh_priv usermod -aG "$VH_GROUP" "$REAL_USER"
    echo "ℹ️ Log out and back in for group changes to take effect."
else
    echo "⚠️ Could not determine a non-root invoking user; skipping group addition."
fi

# === 4) Ensure 'tss' group exists and add the service user ===
if ! getent group tss > /dev/null; then
    echo "👥 Creating system group 'tss'..."
    vh_priv groupadd --system tss
fi

echo "🔑 Adding '$VH_USER' user to 'tss' group..."
vh_priv usermod -aG tss "$VH_USER"

# === 5) Ensure TPM device permissions ===
udev_rule_file="/etc/udev/rules.d/60-tpm.rules"

check_perms() {
    local dev=$1
    if [[ -e "$dev" ]]; then
        local perms
        perms=$(stat -c "%a %G" "$dev")
        [[ "$perms" == "660 tss" ]]
    else
        return 0
    fi
}

if ! check_perms /dev/tpm0 || ! check_perms /dev/tpmrm0; then
    echo "🔧 Fixing TPM device permissions via udev rule..."
    cat <<'EOF' | vh_priv_write "$udev_rule_file" 0644
KERNEL=="tpm[0-9]*",   GROUP="tss", MODE="0660"
KERNEL=="tpmrm[0-9]*", GROUP="tss", MODE="0660"
EOF
    vh_priv udevadm control --reload-rules
    vh_priv udevadm trigger
else
    echo "✅ TPM device permissions already correct."
fi
