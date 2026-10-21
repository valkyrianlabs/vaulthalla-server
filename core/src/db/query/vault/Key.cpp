#include "db/query/vault/Key.hpp"
#include "db/Transactions.hpp"
#include "vault/model/Key.hpp"
#include "db/encoding/bytea.hpp"
#include "db/encoding/timestamp.hpp"

namespace vh::db::query::vault {

using vh::db::encoding::to_hex_bytea;

unsigned int Key::addVaultKey(const KeyPtr& key) {
    return Transactions::exec("Key::addVaultKey", [&](pqxx::work& txn) {
        pqxx::params p{key->vaultId, to_hex_bytea(key->encrypted_key), to_hex_bytea(key->iv)};
        const auto res = txn.exec(pqxx::prepped{"insert_vault_key"}, p);
        if (res.empty()) throw std::runtime_error("Failed to add vault key: no result returned");
        return res.one_field_ref().as<unsigned int>();
    });
}

void Key::deleteVaultKey(unsigned int vaultId) {
    Transactions::exec("Key::deleteVaultKey", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"delete_vault_key"}, vaultId);
    });
}

void Key::updateVaultKey(const KeyPtr& key) {
    Transactions::exec("Key::updateVaultKey", [&](pqxx::work& txn) {
        pqxx::params p{key->vaultId, to_hex_bytea(key->encrypted_key), to_hex_bytea(key->iv)};
        txn.exec(pqxx::prepped{"update_vault_key"}, p);
    });
}

Key::KeyPtr Key::getVaultKey(unsigned int vaultId) {
    return Transactions::exec("Key::getVaultKey", [&](pqxx::work& txn) -> KeyPtr {
        const auto res = txn.exec(pqxx::prepped{"get_vault_key"}, vaultId);
        if (res.empty()) return nullptr;
        return std::make_shared<K>(res[0]);
    });
}

unsigned int Key::rotateVaultKey(const KeyPtr& newKey) {
    return Transactions::exec("Key::rotateVaultKey", [&](pqxx::work& txn) {
        pqxx::params p{newKey->vaultId, to_hex_bytea(newKey->encrypted_key), to_hex_bytea(newKey->iv)};
        const auto res = txn.exec(pqxx::prepped{"rotate_vault_key"}, p);
        if (res.empty()) throw std::runtime_error("Failed to rotate vault key: no result returned");
        return res.one_field_ref().as<unsigned int>();
    });
}

void Key::markKeyRotationFinished(unsigned int vaultId) {
    Transactions::exec("Key::markKeyRotationFinished", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"mark_vault_key_rotation_finished"}, vaultId);
    });
}

bool Key::keyRotationInProgress(unsigned int vaultId) {
    return Transactions::exec("Key::keyRotationInProgress", [&](pqxx::work& txn) {
        return txn.exec(pqxx::prepped{"vault_key_rotation_in_progress"}, vaultId).one_field_ref().as<bool>();
    });
}

void Key::markExported(const unsigned int vaultId, const unsigned int version) {
    Transactions::exec("Key::markExported", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_keys SET exported_version = $2, exported_at = NOW() WHERE vault_id = $1 AND version = $2",
                 pqxx::params{vaultId, version});
    });
}

std::optional<std::time_t> Key::currentKeyExportedAt(const unsigned int vaultId) {
    return Transactions::exec("Key::currentKeyExportedAt", [&](pqxx::work& txn) -> std::optional<std::time_t> {
        const auto res = txn.exec(
            "SELECT exported_at FROM vault_keys WHERE vault_id = $1 AND exported_version = version AND exported_at IS NOT NULL",
            pqxx::params{vaultId});
        if (res.empty()) return std::nullopt;
        return db::encoding::parsePostgresTimestamp(res.one_field_ref().c_str());
    });
}

Key::ExportRecord Key::exportRecord(const unsigned int vaultId) {
    return Transactions::exec("Key::exportRecord", [&](pqxx::work& txn) -> ExportRecord {
        const auto res = txn.exec("SELECT exported_version, exported_at FROM vault_keys WHERE vault_id = $1",
                                  pqxx::params{vaultId});
        if (res.empty()) return {};
        const auto row = res.one_row_ref();
        ExportRecord out;
        if (!row[0].is_null()) out.version = row[0].as<unsigned int>();
        if (!row[1].is_null()) out.at = db::encoding::parsePostgresTimestamp(row[1].c_str());
        return out;
    });
}

std::optional<std::time_t> Key::markExportedIfCurrent(const unsigned int vaultId, const unsigned int version) {
    return Transactions::exec("Key::markExportedIfCurrent", [&](pqxx::work& txn) -> std::optional<std::time_t> {
        const auto res = txn.exec(
            "UPDATE vault_keys SET exported_version = $2, exported_at = NOW() WHERE vault_id = $1 AND version = $2 "
            "RETURNING exported_at",
            pqxx::params{vaultId, version});
        if (res.empty()) return std::nullopt;
        return db::encoding::parsePostgresTimestamp(res.one_field_ref().c_str());
    });
}

std::vector<unsigned int> Key::rotationPendingKeyVersions(const unsigned int vaultId) {
    return Transactions::exec("Key::rotationPendingKeyVersions", [&](pqxx::work& txn) {
        std::vector<unsigned int> out;
        for (const auto& row : txn.exec("SELECT version FROM vault_keys_trashed WHERE vault_id = $1 AND "
                                        "rotation_completed_at IS NULL ORDER BY version",
                                        pqxx::params{vaultId}))
            out.push_back(row[0].as<unsigned int>());
        return out;
    });
}

Key::KeyPtr Key::getRotationInProgressOldKey(unsigned int vaultId) {
    return Transactions::exec("Key::getRotationInProgressOldKey", [&](pqxx::work& txn) -> KeyPtr {
        const auto res = txn.exec(pqxx::prepped{"get_rotation_old_vault_key"}, vaultId);
        if (res.empty()) throw std::runtime_error("No old vault key found for rotation in progress");
        return std::make_shared<K>(res[0]);
    });
}

Key::KeyPtr Key::getRetiredVaultKey(const unsigned int vaultId, const unsigned int version) {
    return Transactions::exec("Key::getRetiredVaultKey", [&](pqxx::work& txn) -> KeyPtr {
        const auto res = txn.exec(pqxx::prepped{"get_retired_vault_key"}, pqxx::params{vaultId, version});
        if (res.empty()) return nullptr;
        return std::make_shared<K>(res[0]);
    });
}

std::vector<unsigned int> Key::retiredKeyVersions(const unsigned int vaultId) {
    return Transactions::exec("Key::retiredKeyVersions", [&](pqxx::work& txn) {
        std::vector<unsigned int> out;
        for (const auto& row : txn.exec(pqxx::prepped{"list_retired_vault_key_versions"}, vaultId))
            out.push_back(row[0].as<unsigned int>());
        return out;
    });
}

bool Key::hasRetiredKeyVersion(const unsigned int vaultId, const unsigned int version) {
    return Transactions::exec("Key::hasRetiredKeyVersion", [&](pqxx::work& txn) {
        return txn.exec(pqxx::prepped{"retired_vault_key_version_exists"}, pqxx::params{vaultId, version})
            .one_field_ref().as<bool>();
    });
}

std::vector<unsigned int> Key::recoveryReferencedKeyVersions(const unsigned int vaultId) {
    return Transactions::exec("Key::recoveryReferencedKeyVersions", [&](pqxx::work& txn) {
        std::vector<unsigned int> out;
        for (const auto& row : txn.exec(pqxx::prepped{"list_recovery_referenced_key_versions"}, vaultId))
            out.push_back(row[0].as<unsigned int>());
        return out;
    });
}

}
