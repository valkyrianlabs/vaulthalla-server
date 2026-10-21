// Contract models: paired devices against their declared shape (see model_suites.hpp): device::to_json(Device).

#include "model_suites.hpp"

#include "device/Device.hpp"

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

}

namespace vh::test::contract_models {

void checkDeviceModels(Checker& c) {
    using json = nlohmann::json;
    c.check(json(test_contract_models_devices::rotatedRevokedDevice()), "Device", "device.list devices[] (revoked)");
    c.check(json(test_contract_models_devices::freshDevice()), "Device", "device.pairing.approve device");
}

}
