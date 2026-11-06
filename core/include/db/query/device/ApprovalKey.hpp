#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The `device_approval_keys` table (migration 128, #361): one P-256 approval key per paired device. Trusted
// primitives: callers (ops::devices, auth::approval) authorize and validate the key.
namespace vh::db::query::device {

struct ApprovalKey {
    uint32_t device_id{};
    std::vector<uint8_t> public_key_spki{};  // DER SubjectPublicKeyInfo, 91 bytes
    std::string spki_sha256{};               // lowercase hex of SHA-256(public_key_spki)
    std::string registered_via{};            // "pairing" or "console_approval"
    std::time_t registered_at{};
    std::optional<std::time_t> revoked_at{};

    [[nodiscard]] bool revoked() const noexcept { return revoked_at.has_value(); }
};

class ApprovalKeys {
public:
    // The device's key, revoked or not.
    [[nodiscard]] static std::optional<ApprovalKey> forDevice(uint32_t deviceId);
    // Whether any device has (or had) this key.
    [[nodiscard]] static bool known(const std::string& spkiSha256);
    // Registers the key of a live device that has never had one (a key is registered once per device; a revoked one
    // stays recorded). ops::Conflict when the device has or had a key, the key is already known to this node (an
    // approval key or a device key), or the device is gone or revoked.
    static ApprovalKey registerKey(uint32_t deviceId, const std::vector<uint8_t>& spkiDer,
                                   const std::string& spkiSha256, const std::string& via);
    // Revokes the device's key. True when a live key was revoked. Devices::revoke and revokeAll revoke it with the
    // device in their own transaction.
    static bool revoke(uint32_t deviceId);
};

}
