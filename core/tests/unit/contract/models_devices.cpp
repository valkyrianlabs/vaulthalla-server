// Contract models: paired devices against their declared shape (see model_suites.hpp): device::to_json(Device).

#include "model_suites.hpp"

#include "device/Device.hpp"
#include "ops/BackupGrants.hpp"

#include <string>

namespace vh::test_contract_models_devices {

// A device that rotated its key, was seen, and was revoked: every member non-null.
device::Device rotatedRevokedDevice() {
    device::Device d;
    d.id = 7;
    d.user_id = 3;
    d.user_name = "alice";
    d.name = "Alice's MacBook";
    d.platform = "macOS";
    d.app_version = "1.0.3";
    d.spki_sha256 = std::string(64, 'a');
    d.previous_spki_sha256 = std::string(64, 'b');
    d.approved_by = 3;
    d.created_at = 1760000000;
    d.last_seen_at = 1760000600;
    d.last_ip = "10.0.0.42";
    d.revoked_at = 1760001200;
    return d;
}

// Just approved: never connected since, no rotation, approver gone (ON DELETE SET NULL), no app version.
device::Device freshDevice() {
    device::Device d;
    d.id = 8;
    d.user_id = 4;
    d.name = "Mac mini";
    d.platform = "macOS";
    d.spki_sha256 = std::string(64, 'c');
    d.created_at = 1760000000;
    return d;
}

// A migrated grant that was confirmed, used, suspended and revoked: every member non-null.
db::query::device::BackupGrant revokedGrant() {
    db::query::device::BackupGrant g;
    g.id = 4;
    g.device_id = 7;
    g.user_id = 3;
    g.origin = "approved";
    g.approved_via = "device_approval";
    g.vault_ids = {1, 5, 9};
    g.created_at = 1760000000;
    g.confirmed_at = 1760000100;
    g.last_used_at = 1760000200;
    g.suspended_at = 1760000300;
    g.revoked_at = 1760000400;
    g.revoked_reason = "recovery_code";
    return g;
}

// Just migrated (D1): never confirmed or used, no vaults yet; its device row gone.
db::query::device::BackupGrant migratedGrant() {
    db::query::device::BackupGrant g;
    g.id = 5;
    g.device_id = 8;
    g.user_id = 4;
    g.origin = "migrated";
    g.created_at = 1760000000;
    return g;
}

}

namespace vh::test::contract_models {

void checkDeviceModels(Checker& c) {
    using json = nlohmann::json;
    c.check(json(test_contract_models_devices::rotatedRevokedDevice()), "Device", "device.list devices[] (revoked)");
    c.check(json(test_contract_models_devices::freshDevice()), "Device", "device.pairing.approve device");
    c.check(ops::backup_grants::toJson(test_contract_models_devices::revokedGrant(),
                                       test_contract_models_devices::rotatedRevokedDevice()),
            "KeyBackupGrant", "device.backup.grant.list grants[] (revoked)");
    c.check(ops::backup_grants::toJson(test_contract_models_devices::migratedGrant(), std::nullopt), "KeyBackupGrant",
            "device.backup.grant.create grant (migrated, device gone)");
}

}
