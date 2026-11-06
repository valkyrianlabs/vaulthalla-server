// ws models: paired devices (Vaulthalla Desktop). device::to_json(Device) (core/src/device/Device.cpp). Checked
// against its serializer by core/tests/unit/contract/models_devices.cpp.

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField deviceSpki(std::string name) {
    return str(std::move(name)).desc("SHA-256 of the device certificate's SubjectPublicKeyInfo (64 lowercase hex).");
}

WsField deviceTime(std::string name) { return integer(std::move(name)).desc("Unix seconds."); }

}

std::vector<WsModel> deviceModels() {
    std::vector<WsModel> out;

    out.push_back(model("Device",
        "A paired device (a devices row, migration 112): device::to_json(Device), core/src/device/Device.cpp.",
        {uinteger("id").desc("The row id: stable across key rotations."),
         deviceSpki("device_id").desc("The device id: the SHA-256 of its current certificate's SubjectPublicKeyInfo "
                                      "(64 lowercase hex digits)."),
         uinteger("user_id").desc("The account the device acts as."),
         str("user_name").desc("That account's name (empty when unknown)."),
         str("name"),
         str("platform").desc("\"macOS\"."),
         str("app_version").desc("Empty when the device didn't say."),
         deviceSpki("previous_device_id").nullable().desc(
             "The key before the last rotation, until the device first connects with the new one."),
         uinteger("approved_by").nullable().desc("The user who approved the pairing; null once that account is gone."),
         deviceTime("created_at"),
         deviceTime("last_seen_at").nullable(),
         str("last_ip").nullable().desc("The address of the device's last connection."),
         deviceTime("revoked_at").nullable(),
         boolean("revoked").desc("Revoked devices stay listed; their key never pairs again.")}));

    out.push_back(model("KeyBackupGrant",
        "A paired device's key-backup grant (#362, migration 129; MFA design note section 6.4): "
        "ops::backup_grants::toJson, core/src/ops/BackupGrants.cpp.",
        {uinteger("id"),
         deviceSpki("device_id").nullable().desc("The device the grant is bound to (null once the device row is gone)."),
         str("device_name").nullable(),
         str("origin").oneOf({"approved", "migrated"})
             .desc("approved: made or confirmed by a person's approval; migrated: carried over from before grants "
                   "existed (D1), with exactly the authority the device had then. Confirm or revoke it."),
         str("approved_via").oneOf({"webauthn", "password_totp", "device_approval", "console_approval"}).nullable()
             .desc("How the latest approval was given; null for a migrated grant never confirmed."),
         intArray("vault_ids").desc("The vaults whose keys the device may export without a prompt, ascending."),
         deviceTime("created_at"),
         deviceTime("confirmed_at").nullable(),
         deviceTime("last_used_at").nullable().desc("The latest export under the grant."),
         deviceTime("suspended_at").nullable()
             .desc("Set when more than 60 vault keys were exported in an hour; exports then need a person's approval "
                   "until the grant is confirmed again."),
         deviceTime("revoked_at").nullable(),
         str("revoked_reason").oneOf({"manual", "device_revoked", "user_inactive", "export_permission", "recovery_code",
                                      "admin_reset", "cli_reset", "device_idle"}).nullable(),
         boolean("active").desc("Live and not suspended: exports of its vaults need no prompt.")}));

    return out;
}

}
