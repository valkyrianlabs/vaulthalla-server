#!/bin/bash
set -euo pipefail

source "$(dirname "$0")/../lib/dev_mode.sh"

vh_require_dev_mode

REMOVE_BUILD_TOOLS="${REMOVE_BUILD_TOOLS:-false}"

echo "🧹 Vaulthalla uninstall routine starting..."

pkg_installed() {
    local pkg="$1"
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"
}

remove_pkg_if_installed() {
    local pkg="$1"
    local desc="${2:-$1}"

    if pkg_installed "$pkg"; then
        echo "🗑️ Removing $desc..."
        sudo apt remove -y "$pkg" || echo "⚠️ Could not remove $desc"
    else
        echo "✅ $desc not installed."
    fi
}

remove_repo_if_present() {
    local repo_file="/etc/apt/sources.list.d/vaulthalla.list"
    local key_file="/etc/apt/trusted.gpg.d/vaulthalla.gpg"

    echo
    if [[ -f "$repo_file" ]]; then
        echo "🧨 Removing Vaulthalla repository file..."
        sudo rm -f "$repo_file"
    else
        echo "✅ Vaulthalla repository file already absent."
    fi

    if [[ -f "$key_file" ]]; then
        echo "🧨 Removing Vaulthalla public key..."
        sudo rm -f "$key_file"
    else
        echo "✅ Vaulthalla public key already absent."
    fi

    # The Valkyrian Labs repository also serves other tools (vl-release, pmdocs), so its source stays.
    if [[ -f /etc/apt/sources.list.d/valkyrianlabs.list ]]; then
        echo "ℹ️ Keeping /etc/apt/sources.list.d/valkyrianlabs.list (shared Valkyrian Labs repository)."
    fi

    echo "🔄 Refreshing APT package lists..."
    sudo apt update || echo "⚠️ apt update failed after repo removal"
}

echo
echo "⚠️ This script avoids removing common system dependencies unless explicitly requested."
echo "   Vaulthalla-specific packages/repo can be removed safely."
echo

if vh_confirm "❓ Remove Vaulthalla-managed development packages (libpdfium-dev, libpqxx-vh-dev)?" "N" "N"; then
    remove_pkg_if_installed "libpdfium-dev" "libpdfium-dev"
    remove_pkg_if_installed "libpqxx-vh-dev" "libpqxx-vh-dev"
else
    echo "✅ Vaulthalla-managed development packages left installed."
fi

echo
if [[ "$REMOVE_BUILD_TOOLS" == "true" ]]; then
    echo "⚠️ REMOVE_BUILD_TOOLS=true, proceeding without prompt."
    remove_pkg_if_installed "meson" "Meson"
    remove_pkg_if_installed "ninja-build" "Ninja"
else
    if vh_confirm "❓ Remove Meson and Ninja build tools? These are common system-wide development tools." "N" "N"; then
        remove_pkg_if_installed "meson" "Meson"
        remove_pkg_if_installed "ninja-build" "Ninja"
    else
        echo "✅ Meson and Ninja left installed."
    fi
fi

echo
if vh_confirm "❓ Remove Vaulthalla APT repository and signing key?" "Y" "N"; then
    remove_repo_if_present
else
    echo "✅ Vaulthalla APT repo/key left installed."
fi

echo
echo "📝 Skipping removal of common shared libraries by design:"
echo "   postgresql, pkg-config, libsodium-dev, libcurl4-openssl-dev, libfuse3-dev, yaml-cpp, Boost, spdlog, TPM2 tools, etc."
echo "   Those are likely used elsewhere and shouldn't be nuked casually."

echo
if vh_confirm "❓ Run 'sudo apt autoremove -y' now? Review carefully; this may remove unrelated orphaned packages." "N" "N"; then
    sudo apt autoremove -y || echo "⚠️ apt autoremove encountered an issue"
else
    echo "✅ Skipped apt autoremove."
fi

echo
echo "🏁 Uninstall routine complete."
