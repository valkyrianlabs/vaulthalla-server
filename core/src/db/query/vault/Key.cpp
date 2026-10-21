#include "db/query/vault/Key.hpp"
#include "db/Transactions.hpp"
#include "vault/model/Key.hpp"
#include "db/encoding/bytea.hpp"
#include "db/encoding/timestamp.hpp"
#include "fs/model/File.hpp"
#include "ops/Error.hpp"

#include <string>

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

void Key::writeImported(const unsigned int vaultId, const std::vector<SealedWrite>& writes) {
    Transactions::exec("Key::writeImported", [&](pqxx::work& txn) {
        txn.exec("SELECT pg_advisory_xact_lock($1::bigint)", pqxx::params{vaultId});
        for (const auto& w : writes) {
            const auto key = to_hex_bytea(w.encrypted_key), iv = to_hex_bytea(w.iv);
            pqxx::result res;
            if (w.expected) {
                const auto oldKey = to_hex_bytea(w.expected->first), oldIv = to_hex_bytea(w.expected->second);
                const pqxx::params p{vaultId, w.version, key, iv, oldKey, oldIv};
                switch (w.table) {
                    case SealedTable::Current:
                        res = txn.exec("UPDATE vault_keys SET encrypted_key = $3, iv = $4 WHERE vault_id = $1 AND "
                                       "version = $2 AND encrypted_key = $5 AND iv = $6", p);
                        break;
                    case SealedTable::Retired:
                        res = txn.exec("UPDATE vault_keys_trashed SET encrypted_key = $3, iv = $4 WHERE vault_id = $1 "
                                       "AND version = $2 AND encrypted_key = $5 AND iv = $6", p);
                        break;
                    case SealedTable::DeletionCopy:
                        res = txn.exec("UPDATE vault_deletion_key SET encrypted_key = $3, iv = $4 WHERE vault_id = $1 "
                                       "AND version = $2 AND encrypted_key = $5 AND iv = $6", p);
                        break;
                }
            } else {
                switch (w.table) {
                    case SealedTable::Current:
                        res = txn.exec("INSERT INTO vault_keys (vault_id, encrypted_key, iv, version) VALUES ($1, $3, $4, $2) "
                                       "ON CONFLICT (vault_id) DO NOTHING",
                                       pqxx::params{vaultId, w.version, key, iv});
                        break;
                    case SealedTable::Retired:
                        res = txn.exec("INSERT INTO vault_keys_trashed (vault_id, version, encrypted_key, iv, created_at, "
                                       "trashed_at, rotation_completed_at) VALUES ($1, $2, $3, $4, NOW(), NOW(), "
                                       "CASE WHEN $5 THEN NULL ELSE NOW() END) ON CONFLICT (vault_id, version) DO NOTHING",
                                       pqxx::params{vaultId, w.version, key, iv, w.rotation_pending});
                        break;
                    case SealedTable::DeletionCopy:
                        res = txn.exec("INSERT INTO vault_deletion_key (vault_id, version, encrypted_key, iv) "
                                       "VALUES ($1, $2, $3, $4) ON CONFLICT (vault_id, version) DO NOTHING",
                                       pqxx::params{vaultId, w.version, key, iv});
                        break;
                }
            }
            if (res.affected_rows() != 1)
                throw ops::Conflict("key version " + std::to_string(w.version) + " of vault " + std::to_string(vaultId) +
                                    " changed while it was being imported; nothing was written, try again");
        }
    });
}

std::vector<Key::SealedSample> Key::sampleSealedFiles(const unsigned int vaultId, const unsigned int version,
                                                      const unsigned int limit) {
    return Transactions::exec("Key::sampleSealedFiles", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT fs.*, f.* FROM files f JOIN fs_entry fs ON f.fs_entry_id = fs.id "
            "WHERE fs.vault_id = $1 AND f.encrypted_with_key_version = $2 AND f.encryption_iv IS NOT NULL "
            "AND f.encryption_iv <> '' ORDER BY f.size_bytes, fs.id LIMIT $3",
            pqxx::params{vaultId, version, limit});
        std::vector<SealedSample> out;
        for (const auto& file : vh::fs::model::files_from_pq_res(res))
            out.push_back({.path = file->backing_path.string(), .iv = file->encryption_iv,
                           .vault_path = file->path.string(), .plaintext_bytes = file->size_bytes});
        return out;
    });
}

std::vector<Key::SealedSample> Key::sampleRecoveryBlobs(const unsigned int vaultId, const unsigned int version,
                                                        const unsigned int limit) {
    return Transactions::exec("Key::sampleRecoveryBlobs", [&](pqxx::work& txn) {
        std::vector<SealedSample> out;
        for (const auto& row : txn.exec("SELECT storage_name, encryption_iv FROM recovery_blob WHERE vault_id = $1 AND "
                                        "key_version = $2 AND encryption_iv <> '' ORDER BY cipher_bytes, id LIMIT $3",
                                        pqxx::params{vaultId, version, limit}))
            out.push_back({.path = row[0].as<std::string>(), .iv = row[1].as<std::string>()});
        return out;
    });
}

bool Key::filesSealedUnder(const unsigned int vaultId, const unsigned int version) {
    return Transactions::exec("Key::filesSealedUnder", [&](pqxx::work& txn) {
        return txn.exec("SELECT EXISTS(SELECT 1 FROM files f JOIN fs_entry fs ON f.fs_entry_id = fs.id WHERE "
                        "fs.vault_id = $1 AND f.encrypted_with_key_version = $2 AND f.encryption_iv <> '')",
                        pqxx::params{vaultId, version})
            .one_field_ref().as<bool>();
    });
}

namespace {
// Every (source, key version) the vault's data records ciphertext under.
constexpr const char* kSealedVersionsSql =
    "SELECT 'file' AS source, f.encrypted_with_key_version AS v FROM files f JOIN fs_entry fs ON f.fs_entry_id = fs.id "
    "  WHERE fs.vault_id = $1 AND f.encryption_iv IS NOT NULL AND f.encryption_iv <> '' "
    "UNION ALL SELECT 'recovery blob', key_version FROM recovery_blob WHERE vault_id = $1 AND key_version > 0 "
    "UNION ALL SELECT 'provider version', key_version FROM upstream_object_version "
    "  WHERE vault_id = $1 AND gone_at IS NULL AND key_version IS NOT NULL AND key_version > 0 "
    "UNION ALL SELECT 'remote object', encrypted_with_key_version FROM remote_object_index "
    "  WHERE vault_id = $1 AND encrypted IS TRUE AND encrypted_with_key_version IS NOT NULL "
    "  AND encrypted_with_key_version > 0";
}

std::optional<std::string> Key::sealedContentSummary(const unsigned int vaultId) {
    return Transactions::exec("Key::sealedContentSummary", [&](pqxx::work& txn) -> std::optional<std::string> {
        std::string out;
        for (const auto& row : txn.exec(std::string("SELECT source, COUNT(*) FROM (") + kSealedVersionsSql +
                                            ") s GROUP BY source ORDER BY source",
                                        pqxx::params{vaultId})) {
            const auto n = row[1].as<uint64_t>();
            out += (out.empty() ? "" : ", ") + std::to_string(n) + " " + row[0].as<std::string>() + (n == 1 ? "" : "s");
        }
        if (out.empty()) return std::nullopt;
        return out;
    });
}

std::vector<unsigned int> Key::liveFileKeyVersions(const unsigned int vaultId) {
    return Transactions::exec("Key::liveFileKeyVersions", [&](pqxx::work& txn) {
        std::vector<unsigned int> out;
        for (const auto& row : txn.exec("SELECT DISTINCT f.encrypted_with_key_version FROM files f JOIN fs_entry fs ON "
                                        "f.fs_entry_id = fs.id WHERE fs.vault_id = $1 AND f.encryption_iv IS NOT NULL "
                                        "AND f.encryption_iv <> '' AND f.encrypted_with_key_version > 0 ORDER BY 1",
                                        pqxx::params{vaultId}))
            out.push_back(row[0].as<unsigned int>());
        return out;
    });
}

std::vector<unsigned int> Key::dataKeyVersions(const unsigned int vaultId) {
    return Transactions::exec("Key::dataKeyVersions", [&](pqxx::work& txn) {
        std::vector<unsigned int> out;
        for (const auto& row : txn.exec(std::string("SELECT DISTINCT v FROM (") + kSealedVersionsSql +
                                            ") s WHERE v > 0 ORDER BY 1",
                                        pqxx::params{vaultId}))
            out.push_back(row[0].as<unsigned int>());
        return out;
    });
}

bool Key::ciphertextExistsUnder(const unsigned int vaultId, const unsigned int version) {
    return Transactions::exec("Key::ciphertextExistsUnder", [&](pqxx::work& txn) {
        return txn.exec(std::string("SELECT EXISTS(SELECT 1 FROM (") + kSealedVersionsSql + ") s WHERE v = $2)",
                        pqxx::params{vaultId, version})
            .one_field_ref().as<bool>();
    });
}

std::vector<Key::RemoteSample> Key::remoteSamples(const unsigned int vaultId, const unsigned int version,
                                                  const unsigned int limit) {
    return Transactions::exec("Key::remoteSamples", [&](pqxx::work& txn) {
        std::vector<RemoteSample> out;
        for (const auto& row : txn.exec(
                 "SELECT object_key, size_bytes, encryption_iv FROM remote_object_index WHERE vault_id = $1 AND "
                 "encrypted IS TRUE AND encrypted_with_key_version = $2 AND encryption_iv IS NOT NULL AND "
                 "encryption_iv <> '' ORDER BY size_bytes, id LIMIT $3",
                 pqxx::params{vaultId, version, limit}))
            out.push_back({.object_key = row[0].as<std::string>(), .stored_bytes = row[1].as<uint64_t>(),
                           .iv = row[2].as<std::string>()});
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
