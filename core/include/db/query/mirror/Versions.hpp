#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <ctime>
#include <map>
#include <optional>

// Versions on the mirror, the database side (migration 167, mirror_vault.keep_versions; mirror/versions/Versions.hpp):
// the setting of each vault this server holds as another server's mirror. Trusted primitives: callers authorize.
namespace vh::db::query::mirror {

struct VersionsRow {
    nlohmann::json policy{};   // the local versioning policy's shape; null: off
    std::optional<uint32_t> set_by{};
    std::optional<std::time_t> set_at{};
};

class MirrorVersions {
public:
    // The vault's row (nullopt without a mirror_vault row).
    [[nodiscard]] static std::optional<VersionsRow> get(uint32_t vaultId);
    // Replaces the setting of a `mirror` row. False when the vault has none.
    static bool set(uint32_t vaultId, const nlohmann::json& policy, std::optional<uint32_t> by);
    // Every mirror row with a setting, by vault.
    [[nodiscard]] static std::map<uint32_t, nlohmann::json> all();
};

}
