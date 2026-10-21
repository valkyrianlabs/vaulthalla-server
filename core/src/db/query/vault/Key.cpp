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

namespace {

// Writes `p` on the row (table, vault, version) unless it already records exactly that.
void storeProvenance(pqxx::work& txn, const std::string& table, const unsigned int vaultId, const unsigned int version,
                     const Key::Provenance& p) {
    const std::optional<std::string> sig =
        p.attestation.empty() ? std::nullopt : std::make_optional(to_hex_bytea(p.attestation));
    txn.exec("UPDATE " + table + " SET key_check = $3, attestation_key_id = $4, attestation = $5::bytea "
             "WHERE vault_id = $1 AND version = $2",
             pqxx::params{vaultId, version, p.key_check, p.attestation_key_id, sig});
}

}

unsigned int Key::addVaultKey(const KeyPtr& key, const std::optional<Provenance>& provenance) {
    return Transactions::exec("Key::addVaultKey", [&](pqxx::work& txn) {
        pqxx::params p{key->vaultId, to_hex_bytea(key->encrypted_key), to_hex_bytea(key->iv)};
        const auto res = txn.exec(pqxx::prepped{"insert_vault_key"}, p);
        if (res.empty()) throw std::runtime_error("Failed to add vault key: no result returned");
        const auto version = res.one_field_ref().as<unsigned int>();
        if (provenance && version == 1) storeProvenance(txn, "vault_keys", key->vaultId, version, *provenance);
        return version;
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

unsigned int Key::rotateVaultKey(const KeyPtr& newKey, const NewVersion& expected, const std::optional<Outgoing>& outgoing,
                                 const bool closePrior, const bool closeOutgoing) {
    return Transactions::exec("Key::rotateVaultKey", [&](pqxx::work& txn) {
        txn.exec("SELECT pg_advisory_xact_lock($1::bigint)", pqxx::params{newKey->vaultId});
        const auto key = to_hex_bytea(newKey->encrypted_key), iv = to_hex_bytea(newKey->iv);
        // Salvage must not leave two pending rotations (EncryptionManager holds one outgoing key).
        if (closePrior)
            txn.exec("UPDATE vault_keys_trashed SET rotation_completed_at = NOW() WHERE vault_id = $1 AND "
                     "rotation_completed_at IS NULL", pqxx::params{newKey->vaultId});
        unsigned int version = 0;
        if (txn.exec("SELECT 1 FROM vault_keys WHERE vault_id = $1 FOR UPDATE", pqxx::params{newKey->vaultId}).empty()) {
            // No current row (salvage over a lost key record): the next version is the caller's, never 0.
            if (expected.version == 0) throw std::invalid_argument("a key version is a positive integer");
            txn.exec("INSERT INTO vault_keys (vault_id, encrypted_key, iv, version, created_at) VALUES ($1, $2, $3, $4, "
                     "CURRENT_TIMESTAMP)", pqxx::params{newKey->vaultId, key, iv, expected.version});
            version = expected.version;
        } else {
            const auto res = txn.exec(pqxx::prepped{"rotate_vault_key"}, pqxx::params{newKey->vaultId, key, iv});
            if (res.empty() || res.one_field_ref().is_null())
                throw std::runtime_error("Failed to rotate vault key: no result returned");
            version = res.one_field_ref().as<unsigned int>();
        }
        if (expected.provenance && version == expected.version)
            storeProvenance(txn, "vault_keys", newKey->vaultId, version, *expected.provenance);
        if (outgoing)
            txn.exec("UPDATE vault_keys_trashed SET key_check = $3, attestation_key_id = $4, attestation = $5::bytea "
                     "WHERE vault_id = $1 AND version = $2 AND (key_check IS NULL OR attestation IS NULL)",
                     pqxx::params{newKey->vaultId, outgoing->version, outgoing->provenance.key_check,
                                  outgoing->provenance.attestation_key_id,
                                  outgoing->provenance.attestation.empty()
                                      ? std::nullopt
                                      : std::make_optional(to_hex_bytea(outgoing->provenance.attestation))});
        if (closeOutgoing)
            txn.exec("UPDATE vault_keys_trashed SET rotation_completed_at = NOW() WHERE vault_id = $1 AND "
                     "rotation_completed_at IS NULL", pqxx::params{newKey->vaultId});
        return version;
    });
}

unsigned int Key::recordProvenance(const K& rec, const Provenance& p) {
    return Transactions::exec("Key::recordProvenance", [&](pqxx::work& txn) {
        const std::optional<std::string> sig =
            p.attestation.empty() ? std::nullopt : std::make_optional(to_hex_bytea(p.attestation));
        const pqxx::params params{rec.vaultId, rec.version, p.key_check, p.attestation_key_id, sig,
                                  to_hex_bytea(rec.encrypted_key), to_hex_bytea(rec.iv)};
        // A row is rewritten when its check is missing or wrong, or it has no attestation yet (and one is offered).
        const auto res = txn.exec(
            "WITH a AS (UPDATE vault_keys SET key_check = $3, attestation_key_id = $4, attestation = $5::bytea "
            "           WHERE vault_id = $1 AND version = $2 AND encrypted_key = $6 AND iv = $7 "
            "           AND (key_check IS DISTINCT FROM $3 OR (attestation IS NULL AND $5::bytea IS NOT NULL)) RETURNING 1), "
            "     b AS (UPDATE vault_keys_trashed SET key_check = $3, attestation_key_id = $4, attestation = $5::bytea "
            "           WHERE vault_id = $1 AND version = $2 AND encrypted_key = $6 AND iv = $7 "
            "           AND (key_check IS DISTINCT FROM $3 OR (attestation IS NULL AND $5::bytea IS NOT NULL)) RETURNING 1), "
            "     c AS (UPDATE vault_deletion_key SET key_check = $3, attestation_key_id = $4, attestation = $5::bytea "
            "           WHERE vault_id = $1 AND version = $2 AND encrypted_key = $6 AND iv = $7 "
            "           AND (key_check IS DISTINCT FROM $3 OR (attestation IS NULL AND $5::bytea IS NOT NULL)) RETURNING 1) "
            "SELECT (SELECT count(*) FROM a) + (SELECT count(*) FROM b) + (SELECT count(*) FROM c)",
            params);
        return res.one_field_ref().as<unsigned int>();
    });
}

unsigned int Key::attestationKeyId(const std::vector<uint8_t>& publicKey) {
    return Transactions::exec("Key::attestationKeyId", [&](pqxx::work& txn) {
        const auto pk = to_hex_bytea(publicKey);
        auto res = txn.exec("SELECT id FROM key_attestation_keys WHERE public_key = $1::bytea", pqxx::params{pk});
        if (!res.empty()) return res.one_field_ref().as<unsigned int>();
        // A new signing key (first use, or the old one no longer unseals): older keys retire, their rows stay.
        txn.exec("UPDATE key_attestation_keys SET retired_at = NOW() WHERE retired_at IS NULL");
        res = txn.exec("INSERT INTO key_attestation_keys (public_key) VALUES ($1::bytea) ON CONFLICT (public_key) "
                       "DO UPDATE SET retired_at = NULL RETURNING id",
                       pqxx::params{pk});
        return res.one_field_ref().as<unsigned int>();
    });
}

std::optional<std::vector<uint8_t>> Key::attestationPublicKey(const unsigned int keyId) {
    return Transactions::exec("Key::attestationPublicKey", [&](pqxx::work& txn) -> std::optional<std::vector<uint8_t>> {
        const auto res = txn.exec("SELECT public_key FROM key_attestation_keys WHERE id = $1", pqxx::params{keyId});
        if (res.empty()) return std::nullopt;
        return db::encoding::from_hex_bytea(res.one_field_ref().as<std::string>());
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
            const auto& p = w.provenance;
            const std::optional<std::string> sig =
                p.attestation.empty() ? std::nullopt : std::make_optional(to_hex_bytea(p.attestation));
            const std::string table = w.table == SealedTable::Current   ? "vault_keys"
                                    : w.table == SealedTable::Retired   ? "vault_keys_trashed"
                                                                        : "vault_deletion_key";
            pqxx::result res;
            if (w.expected) {
                const auto oldKey = to_hex_bytea(w.expected->first), oldIv = to_hex_bytea(w.expected->second);
                res = txn.exec("UPDATE " + table + " SET encrypted_key = $3, iv = $4, key_check = $7, "
                               "attestation_key_id = $8, attestation = $9::bytea WHERE vault_id = $1 AND version = $2 "
                               "AND encrypted_key = $5 AND iv = $6",
                               pqxx::params{vaultId, w.version, key, iv, oldKey, oldIv, p.key_check,
                                            p.attestation_key_id, sig});
            } else {
                switch (w.table) {
                    case SealedTable::Current:
                        res = txn.exec("INSERT INTO vault_keys (vault_id, encrypted_key, iv, version, key_check, "
                                       "attestation_key_id, attestation) VALUES ($1, $3, $4, $2, $5, $6, $7::bytea) "
                                       "ON CONFLICT (vault_id) DO NOTHING",
                                       pqxx::params{vaultId, w.version, key, iv, p.key_check, p.attestation_key_id, sig});
                        break;
                    case SealedTable::Retired:
                        res = txn.exec("INSERT INTO vault_keys_trashed (vault_id, version, encrypted_key, iv, created_at, "
                                       "trashed_at, rotation_completed_at, key_check, attestation_key_id, attestation) "
                                       "VALUES ($1, $2, $3, $4, NOW(), NOW(), CASE WHEN $5 THEN NULL ELSE NOW() END, $6, "
                                       "$7, $8::bytea) ON CONFLICT (vault_id, version) DO NOTHING",
                                       pqxx::params{vaultId, w.version, key, iv, w.rotation_pending, p.key_check,
                                                    p.attestation_key_id, sig});
                        break;
                    case SealedTable::DeletionCopy:
                        res = txn.exec("INSERT INTO vault_deletion_key (vault_id, version, encrypted_key, iv, key_check, "
                                       "attestation_key_id, attestation) VALUES ($1, $2, $3, $4, $5, $6, $7::bytea) "
                                       "ON CONFLICT (vault_id, version) DO NOTHING",
                                       pqxx::params{vaultId, w.version, key, iv, p.key_check, p.attestation_key_id, sig});
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

std::vector<unsigned int> Key::referencedKeyVersions(const unsigned int vaultId) {
    return Transactions::exec("Key::referencedKeyVersions", [&](pqxx::work& txn) {
        std::vector<unsigned int> out;
        for (const auto& row : txn.exec(
                 std::string("SELECT DISTINCT v FROM ("
                             "SELECT version AS v FROM vault_keys WHERE vault_id = $1 "
                             "UNION ALL SELECT version FROM vault_keys_trashed WHERE vault_id = $1 "
                             // a retired version was rotated to the next one: that version existed
                             "UNION ALL SELECT version + 1 FROM vault_keys_trashed WHERE vault_id = $1 "
                             "UNION ALL SELECT version FROM vault_deletion_key WHERE vault_id = $1 "
                             "UNION ALL SELECT key_version FROM vault_deletion WHERE vault_id = $1 "
                             "  AND key_version IS NOT NULL "
                             "UNION ALL SELECT v FROM (") + kSealedVersionsSql + ") s) r WHERE v > 0 ORDER BY 1",
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

namespace {

std::vector<unsigned int> versionsFromCsv(const std::string& csv) {
    std::vector<unsigned int> out;
    std::size_t at = 0;
    while (at < csv.size()) {
        const auto comma = csv.find(',', at);
        const auto part = csv.substr(at, comma == std::string::npos ? std::string::npos : comma - at);
        if (!part.empty()) out.push_back(static_cast<unsigned int>(std::stoul(part)));
        if (comma == std::string::npos) break;
        at = comma + 1;
    }
    return out;
}

std::string versionsArrayLiteral(const std::vector<unsigned int>& versions) {
    std::string out = "{";
    for (const auto v : versions) out += (out.size() > 1 ? "," : "") + std::to_string(v);
    return out + "}";
}

Key::Salvage salvageFrom(const pqxx::row_ref row) {
    Key::Salvage s;
    s.id = row["id"].as<unsigned int>();
    s.vault_id = row["vault_id"].as<unsigned int>();
    s.versions = versionsFromCsv(row["versions_csv"].as<std::string>());
    if (!row["new_version"].is_null()) s.new_version = row["new_version"].as<unsigned int>();
    s.state = row["state"].as<std::string>();
    s.started_at = db::encoding::parsePostgresTimestamp(row["started_at"].as<std::string>());
    if (!row["finished_at"].is_null()) s.finished_at = db::encoding::parsePostgresTimestamp(row["finished_at"].as<std::string>());
    s.salvaged = row["salvaged"].as<unsigned int>();
    s.unrecoverable = row["unrecoverable"].as<unsigned int>();
    s.skipped_remote = row["skipped_remote"].as<unsigned int>();
    s.deferred = row["deferred"].as<unsigned int>();
    s.failed = row["failed"].as<unsigned int>();
    s.failures_json = row["failures"].as<std::string>();
    return s;
}

}

unsigned int Key::startSalvage(const unsigned int vaultId, const std::vector<unsigned int>& versions,
                               const std::optional<unsigned int> startedBy) {
    return Transactions::exec("Key::startSalvage", [&](pqxx::work& txn) {
        const auto res = txn.exec("INSERT INTO vault_key_salvage (vault_id, versions, started_by) VALUES ($1, $2::int[], $3) "
                                  "ON CONFLICT (vault_id) WHERE state = 'running' DO NOTHING RETURNING id",
                                  pqxx::params{vaultId, versionsArrayLiteral(versions), startedBy});
        if (res.empty()) throw ops::Conflict("a key salvage of vault " + std::to_string(vaultId) + " is already running");
        return res.one_field_ref().as<unsigned int>();
    });
}

std::optional<Key::Salvage> Key::runningSalvage(const unsigned int vaultId) {
    return Transactions::exec("Key::runningSalvage", [&](pqxx::work& txn) -> std::optional<Salvage> {
        const auto res = txn.exec("SELECT *, array_to_string(versions, ',') AS versions_csv FROM vault_key_salvage WHERE vault_id = $1 AND state = 'running'",
                                  pqxx::params{vaultId});
        if (res.empty()) return std::nullopt;
        return salvageFrom(res[0]);
    });
}

std::optional<Key::Salvage> Key::lastSalvage(const unsigned int vaultId) {
    return Transactions::exec("Key::lastSalvage", [&](pqxx::work& txn) -> std::optional<Salvage> {
        const auto res = txn.exec("SELECT *, array_to_string(versions, ',') AS versions_csv FROM vault_key_salvage WHERE vault_id = $1 ORDER BY id DESC LIMIT 1",
                                  pqxx::params{vaultId});
        if (res.empty()) return std::nullopt;
        return salvageFrom(res[0]);
    });
}

void Key::setSalvageNewVersion(const unsigned int id, const unsigned int newVersion) {
    Transactions::exec("Key::setSalvageNewVersion", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_key_salvage SET new_version = $2 WHERE id = $1", pqxx::params{id, newVersion});
    });
}

void Key::finishSalvage(const Salvage& r) {
    Transactions::exec("Key::finishSalvage", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_key_salvage SET state = 'finished', finished_at = NOW(), versions = $2::int[], "
                 "salvaged = $3, unrecoverable = $4, skipped_remote = $5, deferred = $6, failed = $7, failures = $8::jsonb "
                 "WHERE id = $1",
                 pqxx::params{r.id, versionsArrayLiteral(r.versions), r.salvaged, r.unrecoverable, r.skipped_remote,
                              r.deferred, r.failed, r.failures_json});
    });
}

std::vector<unsigned int> Key::salvageVersions(const unsigned int vaultId) {
    return Transactions::exec("Key::salvageVersions", [&](pqxx::work& txn) {
        std::vector<unsigned int> out;
        for (const auto& row : txn.exec("SELECT DISTINCT unnest(versions) FROM vault_key_salvage WHERE vault_id = $1 "
                                        "ORDER BY 1", pqxx::params{vaultId}))
            out.push_back(row[0].as<unsigned int>());
        return out;
    });
}

std::vector<std::shared_ptr<vh::fs::model::File>> Key::filesSealedUnderVersion(const unsigned int vaultId,
                                                                              const unsigned int version) {
    return Transactions::exec("Key::filesSealedUnderVersion", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT fs.*, f.* FROM files f JOIN fs_entry fs ON f.fs_entry_id = fs.id "
            "WHERE fs.vault_id = $1 AND f.encrypted_with_key_version = $2 AND f.encryption_iv IS NOT NULL "
            "AND f.encryption_iv <> '' ORDER BY fs.id",
            pqxx::params{vaultId, version});
        return vh::fs::model::files_from_pq_res(res);
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
