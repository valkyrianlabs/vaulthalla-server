#!/usr/bin/env bash
# shellcheck source=bin/lib/platform.sh
source "$(dirname "$0")/../lib/platform.sh"
# Production's account (make uninstall --remove-users), or only the dev instance's (vaulthalla-dev).
vh_instance_layout "$(vh_selected_instance)"

if id "$VH_USER" &>/dev/null; then
    echo "👤 Removing system user '$VH_USER'..."
    sudo userdel -r "$VH_USER" || echo "⚠️  Could not delete home or user not removable"
else
    echo "✅ System user '$VH_USER' not present."
fi

# Remove the service group if it exists
if getent group "$VH_GROUP" > /dev/null; then
    echo "👥 Removing '$VH_GROUP' group..."
    sudo groupdel "$VH_GROUP" || echo "⚠️  Could not delete group '$VH_GROUP' or group not removable"
else
    echo "✅ '$VH_GROUP' group not present."
fi
