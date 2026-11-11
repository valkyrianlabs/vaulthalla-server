#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The vaults enrolled in Vaulthalla Cloud recovery (migration 135).
namespace vh::db::query::cloud {

struct RecoveryVaultRow {
    uint32_t vault_id{};
    std::string vault_uid;
    std::string installation_id;
    std::string enrolled_by;
    std::time_t enrolled_at = 0;
    std::time_t last_upload_at = 0;
};

struct RecoveryVaults {
    [[nodiscard]] static std::vector<RecoveryVaultRow> list();
    [[nodiscard]] static std::optional<RecoveryVaultRow> get(uint32_t vaultId);
    // Inserts, or on a later upload updates last_upload_at (and the installation, after a relink).
    static void upsert(const RecoveryVaultRow& row);
    static bool remove(uint32_t vaultId);
};

}
