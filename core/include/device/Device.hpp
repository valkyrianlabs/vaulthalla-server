#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

#include <nlohmann/json_fwd.hpp>

namespace vh::device {

// One approved device key (a `devices` row, migration 112). The protocol's device id is spki_sha256: the lowercase
// hex SHA-256 of the device certificate's SubjectPublicKeyInfo. `id` is the row id, stable across key rotations.
struct Device {
    uint32_t id{};
    uint32_t user_id{};
    std::string user_name;  // the owner's account name (joined; empty when unknown)
    std::string name;
    std::string platform;
    std::string app_version;
    std::string spki_sha256;
    std::optional<std::string> previous_spki_sha256;
    std::optional<uint32_t> approved_by;
    std::time_t created_at{};
    std::optional<std::time_t> last_seen_at;
    std::optional<std::string> last_ip;
    std::optional<std::time_t> revoked_at;

    [[nodiscard]] bool revoked() const noexcept { return revoked_at.has_value(); }
};

// {id, device_id, user_id, user_name, name, platform, app_version, previous_device_id, approved_by, created_at,
//  last_seen_at, last_ip, revoked_at, revoked}: times are Unix seconds or null.
void to_json(nlohmann::json& j, const Device& d);

// Device names (pairing requests, renames): 1-64 characters (UTF-8 code points), no control characters, trimmed.
// Returns the trimmed name or nullopt.
[[nodiscard]] std::optional<std::string> normalizeDeviceName(const std::string& name);

}
