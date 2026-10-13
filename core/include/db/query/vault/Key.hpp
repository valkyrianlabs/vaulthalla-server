#pragma once

#include <ctime>
#include <memory>
#include <optional>

#include "vault/Fwd.hpp"

namespace vh::db::query::vault {

class Key {
    using K = vh::vault::model::Key;
    using KeyPtr = std::shared_ptr<K>;

public:
    [[nodiscard]] static unsigned int addVaultKey(const KeyPtr& key);
    static void deleteVaultKey(unsigned int vaultId);
    static void updateVaultKey(const KeyPtr& key);
    static KeyPtr getVaultKey(unsigned int vaultId);
    [[nodiscard]] static unsigned int rotateVaultKey(const KeyPtr& newKey);
    static void markKeyRotationFinished(unsigned int vaultId);
    [[nodiscard]] static bool keyRotationInProgress(unsigned int vaultId);
    [[nodiscard]] static KeyPtr getRotationInProgressOldKey(unsigned int vaultId);
    // Export tracking (#162): `vh vault keys export` records the version it exported. A rotation makes the current
    // version a new one, so an older export no longer counts.
    static void markExported(unsigned int vaultId, unsigned int version);
    // When the current key version was exported, or nullopt if it never was (or no export was recorded).
    [[nodiscard]] static std::optional<std::time_t> currentKeyExportedAt(unsigned int vaultId);
};

}
