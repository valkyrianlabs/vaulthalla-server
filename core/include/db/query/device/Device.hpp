#pragma once

#include "device/Device.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// The `devices` and `device_node` tables (migration 112). Trusted primitives: callers (ops::devices, the device
// listener's handshake) authorize.
namespace vh::db::query::device {

using vh::device::Device;

struct NewDevice {
    uint32_t user_id{};
    uint32_t approved_by{};
    std::string name{};
    std::string platform{};
    std::string app_version{};
    std::string spki_sha256{};
    std::string last_ip{};
};

class Devices {
public:
    [[nodiscard]] static std::optional<Device> byId(uint32_t id);
    // The row whose current key is `spkiHex`.
    [[nodiscard]] static std::optional<Device> byCurrentSpki(const std::string& spkiHex);
    // The row whose current or previous key is `spkiHex` (the handshake's lookup).
    [[nodiscard]] static std::optional<Device> byAnySpki(const std::string& spkiHex);
    // Whether any device (live or revoked) has `spkiHex` as its current or previous key.
    [[nodiscard]] static bool spkiKnown(const std::string& spkiHex);

    [[nodiscard]] static std::vector<Device> listForUser(uint32_t userId);
    [[nodiscard]] static std::vector<Device> listAll();

    // Throws ops::Conflict when the key is already a device's (current or previous).
    [[nodiscard]] static Device insert(const NewDevice& d);
    [[nodiscard]] static std::optional<Device> rename(uint32_t id, const std::string& name);
    // Sets revoked_at once (a revoked row keeps its first revocation time). Returns the row, or nullopt if absent.
    [[nodiscard]] static std::optional<Device> revoke(uint32_t id);
    // Compare-and-set rotation: previous = old, current = new, only while `oldSpki` is still current and the row is
    // live. False otherwise.
    [[nodiscard]] static bool rotate(uint32_t id, const std::string& oldSpki, const std::string& newSpki);
    // The first handshake with the new key ends the previous one's grace.
    static void clearPrevious(uint32_t id, const std::string& currentSpki);
    // last_seen_at / last_ip, written at most once a minute per device unless the address changed.
    static void touch(uint32_t id, const std::string& ip);
    // The app version a live device reports in meta.hello (pairing recorded the first one). Writes only when it
    // differs; true when it did.
    static bool updateAppVersion(uint32_t id, const std::string& appVersion);

    // This node's id for paired clients (device_node), created on first use.
    [[nodiscard]] static std::string nodeId();
};

}
