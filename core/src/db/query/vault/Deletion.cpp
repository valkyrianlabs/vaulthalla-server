#include "db/query/vault/Deletion.hpp"
#include "db/Transactions.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <stdexcept>

namespace vh::db::query::vault {

namespace {

using vh::vault::model::DeletionState;

int64_t epochSeconds(const Deletion::Clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

// The mount root (the one fs_entry with no parent and no vault).
constexpr auto kMountRootId =
    "(SELECT id FROM fs_entry WHERE parent_id IS NULL AND vault_id IS NULL AND path = '/' AND name = '/' LIMIT 1)";

Deletion::DeletionPtr deletionFrom(const pqxx::result& res) {
    if (res.empty()) return nullptr;
    return std::make_shared<vh::vault::model::Deletion>(res[0]);
}

}

Deletion::DeletionPtr Deletion::schedule(const Schedule& s) {
    return Transactions::exec("Deletion::schedule", [&](pqxx::work& txn) -> DeletionPtr {
        const auto vault = txn.exec(
            "SELECT v.id, v.name, v.owner_id, u.name AS owner_name, v.type, btrim(v.mount_point) AS backing_alias, "
            "       ak.provider, s.bucket, s.encrypt_upstream "
            "FROM vault v "
            "LEFT JOIN users u ON u.id = v.owner_id "
            "LEFT JOIN s3 s ON s.vault_id = v.id "
            "LEFT JOIN api_keys ak ON ak.id = s.api_key_id "
            "WHERE v.id = $1 AND v.deleted_at IS NULL "
            "FOR UPDATE OF v",
            pqxx::params{s.vault_id});
        if (vault.empty())
            throw std::runtime_error("vault " + std::to_string(s.vault_id) + " does not exist or is already deleted");
        const auto row = vault.one_row_ref();

        txn.exec("UPDATE vault SET deleted_at = NOW() WHERE id = $1", pqxx::params{s.vault_id});
        // Off the mount: the root is no longer a child of the mount root, and no inode leads into the vault.
        txn.exec("UPDATE fs_entry SET parent_id = NULL WHERE vault_id = $1 AND path = '/'", pqxx::params{s.vault_id});
        txn.exec("UPDATE fs_entry SET inode = NULL WHERE vault_id = $1 AND inode IS NOT NULL", pqxx::params{s.vault_id});

        const auto window = s.retention_window.count();
        const auto keyWindow = s.key_retention_window.count();
        txn.exec(
            "INSERT INTO vault_deletion (vault_id, vault_name, owner_id, owner_name, vault_type, backing_alias, provider, "
            "    bucket, encrypt_upstream, delete_upstream, deleted_by, deleted_at, purge_after, key_retain_until, "
            "    key_version, key_exported_at) "
            "SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW() + make_interval(secs => $12), "
            "       GREATEST(NOW() + make_interval(secs => $13), NOW() + make_interval(secs => $12)), "
            "       (SELECT version FROM vault_keys WHERE vault_id = $1), "
            "       (SELECT exported_at FROM vault_keys WHERE vault_id = $1 AND exported_version = version)",
            pqxx::params{
                s.vault_id,
                row["name"].as<std::string>(),
                row["owner_id"].is_null() ? std::optional<unsigned int>{} : row["owner_id"].as<unsigned int>(),
                row["owner_name"].is_null() ? std::optional<std::string>{} : row["owner_name"].as<std::string>(),
                row["type"].as<std::string>(),
                row["backing_alias"].as<std::string>(),
                row["provider"].is_null() ? std::optional<std::string>{} : row["provider"].as<std::string>(),
                row["bucket"].is_null() ? std::optional<std::string>{} : row["bucket"].as<std::string>(),
                row["encrypt_upstream"].is_null() ? std::optional<bool>{} : row["encrypt_upstream"].as<bool>(),
                s.delete_upstream,
                s.deleted_by,
                static_cast<double>(window),
                static_cast<double>(keyWindow)
            });

        // Every key version, still sealed by the TPM master key, outlives the vault row until key_retain_until.
        txn.exec(
            "INSERT INTO vault_deletion_key (vault_id, version, encrypted_key, iv, created_at, key_check, "
            "                                attestation_key_id, attestation) "
            "SELECT vault_id, version, encrypted_key, iv, created_at, key_check, attestation_key_id, attestation "
            "FROM vault_keys WHERE vault_id = $1 "
            "UNION ALL "
            "SELECT vault_id, version, encrypted_key, iv, created_at, key_check, attestation_key_id, attestation "
            "FROM vault_keys_trashed WHERE vault_id = $1 "
            "ON CONFLICT (vault_id, version) DO NOTHING",
            pqxx::params{s.vault_id});

        return deletionFrom(txn.exec("SELECT * FROM vault_deletion WHERE vault_id = $1", pqxx::params{s.vault_id}));
    });
}

bool Deletion::restore(const unsigned int vaultId) {
    return Transactions::exec("Deletion::restore", [&](pqxx::work& txn) {
        // Claiming the pending row is what makes restore and the purge mutually exclusive.
        const auto claimed = txn.exec(
            "DELETE FROM vault_deletion WHERE vault_id = $1 AND state = 'pending' RETURNING vault_id", pqxx::params{vaultId});
        if (claimed.empty()) return false;
        const auto revived = txn.exec("UPDATE vault SET deleted_at = NULL WHERE id = $1 AND deleted_at IS NOT NULL",
                                      pqxx::params{vaultId});
        if (revived.affected_rows() == 0)
            throw std::runtime_error("vault " + std::to_string(vaultId) + " has a pending deletion but no deleted vault row");
        txn.exec(std::string("UPDATE fs_entry SET parent_id = ") + kMountRootId + " WHERE vault_id = $1 AND path = '/'",
                 pqxx::params{vaultId});
        return true;
    });
}

Deletion::DeletionPtr Deletion::get(const unsigned int vaultId) {
    return Transactions::exec("Deletion::get", [&](pqxx::work& txn) {
        return deletionFrom(txn.exec("SELECT * FROM vault_deletion WHERE vault_id = $1", pqxx::params{vaultId}));
    });
}

std::vector<Deletion::DeletionPtr> Deletion::list() {
    return Transactions::exec("Deletion::list", [&](pqxx::work& txn) {
        std::vector<DeletionPtr> out;
        for (const auto& row : txn.exec("SELECT * FROM vault_deletion ORDER BY deleted_at DESC, vault_id DESC"))
            out.push_back(std::make_shared<vh::vault::model::Deletion>(row));
        return out;
    });
}

Deletion::DeletionPtr Deletion::findByName(const std::string& name, const std::optional<unsigned int> ownerId) {
    return Transactions::exec("Deletion::findByName", [&](pqxx::work& txn) {
        if (ownerId)
            return deletionFrom(txn.exec(
                "SELECT * FROM vault_deletion WHERE vault_name = $1 AND owner_id = $2 ORDER BY deleted_at DESC LIMIT 1",
                pqxx::params{name, *ownerId}));
        return deletionFrom(txn.exec("SELECT * FROM vault_deletion WHERE vault_name = $1 ORDER BY deleted_at DESC LIMIT 1",
                                     pqxx::params{name}));
    });
}

bool Deletion::expedite(const unsigned int vaultId, const std::optional<bool> deleteUpstream) {
    return Transactions::exec("Deletion::expedite", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "UPDATE vault_deletion SET "
            "    purge_after = LEAST(purge_after, NOW()), "
            "    next_attempt_at = CASE WHEN state = 'purging' THEN NOW() ELSE next_attempt_at END, "
            "    delete_upstream = COALESCE($2, delete_upstream) "
            "WHERE vault_id = $1 AND state IN ('pending', 'purging')",
            pqxx::params{vaultId, deleteUpstream});
        return res.affected_rows() > 0;
    });
}

std::vector<Deletion::DeletionPtr> Deletion::claimDue(const Clock::time_point now, const unsigned int limit) {
    return Transactions::exec("Deletion::claimDue", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "UPDATE vault_deletion SET state = 'purging', purge_started_at = COALESCE(purge_started_at, NOW()), "
            "    attempts = attempts + 1, next_attempt_at = NULL "
            "WHERE vault_id IN ("
            "    SELECT vault_id FROM vault_deletion "
            "    WHERE (state = 'pending' AND purge_after <= to_timestamp($1)) "
            "       OR (state = 'purging' AND (next_attempt_at IS NULL OR next_attempt_at <= to_timestamp($1))) "
            "    ORDER BY purge_after, vault_id LIMIT $2 FOR UPDATE SKIP LOCKED) "
            "RETURNING *",
            pqxx::params{static_cast<double>(epochSeconds(now)), limit});
        std::vector<DeletionPtr> out;
        for (const auto& row : res) out.push_back(std::make_shared<vh::vault::model::Deletion>(row));
        return out;
    });
}

void Deletion::markUpstreamPurged(const unsigned int vaultId) {
    Transactions::exec("Deletion::markUpstreamPurged", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_deletion SET upstream_purged_at = COALESCE(upstream_purged_at, NOW()) WHERE vault_id = $1",
                 pqxx::params{vaultId});
    });
}

void Deletion::recordFailure(const unsigned int vaultId, const std::string& error, const Clock::time_point retryAt) {
    Transactions::exec("Deletion::recordFailure", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_deletion SET last_error = $2, next_attempt_at = to_timestamp($3) "
                 "WHERE vault_id = $1 AND state = 'purging'",
                 pqxx::params{vaultId, error.substr(0, 2000), static_cast<double>(epochSeconds(retryAt))});
    });
}

void Deletion::deferPurge(const unsigned int vaultId, const Clock::time_point retryAt) {
    Transactions::exec("Deletion::deferPurge", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_deletion SET last_error = NULL, next_attempt_at = to_timestamp($2) "
                 "WHERE vault_id = $1 AND state = 'purging'",
                 pqxx::params{vaultId, static_cast<double>(epochSeconds(retryAt))});
    });
}

void Deletion::finishPurge(const unsigned int vaultId, const std::optional<std::string>& note) {
    Transactions::exec("Deletion::finishPurge", [&](pqxx::work& txn) {
        const auto state = txn.exec("SELECT state FROM vault_deletion WHERE vault_id = $1 FOR UPDATE", pqxx::params{vaultId});
        if (state.empty() || state.one_field_ref().as<std::string>() != "purging")
            throw std::runtime_error("vault " + std::to_string(vaultId) + " is not being purged");
        // deleted_at IS NOT NULL: a live vault is never deleted here, whatever the record says.
        txn.exec("DELETE FROM vault WHERE id = $1 AND deleted_at IS NOT NULL", pqxx::params{vaultId});
        txn.exec("UPDATE vault_deletion SET state = 'purged', purged_at = NOW(), next_attempt_at = NULL, last_error = $2 "
                 "WHERE vault_id = $1",
                 pqxx::params{vaultId, note});
    });
}

std::vector<unsigned int> Deletion::expireKeys(const Clock::time_point now) {
    return Transactions::exec("Deletion::expireKeys", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "UPDATE vault_deletion SET key_purged_at = NOW() "
            "WHERE state = 'purged' AND key_purged_at IS NULL AND key_retain_until <= to_timestamp($1) "
            "RETURNING vault_id",
            pqxx::params{static_cast<double>(epochSeconds(now))});
        std::vector<unsigned int> ids;
        for (const auto& row : res) {
            ids.push_back(row[0].as<unsigned int>());
            txn.exec("DELETE FROM vault_deletion_key WHERE vault_id = $1", pqxx::params{ids.back()});
        }
        return ids;
    });
}

std::vector<Deletion::KeyPtr> Deletion::retainedKeys(const unsigned int vaultId) {
    return Transactions::exec("Deletion::retainedKeys", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT vault_id, version, encrypted_key, iv, COALESCE(created_at, NOW()) AS created_at, "
            "       COALESCE(created_at, NOW()) AS updated_at, key_check, "
            "       attestation_key_id, attestation "
            "FROM vault_deletion_key WHERE vault_id = $1 ORDER BY version DESC",
            pqxx::params{vaultId});
        std::vector<KeyPtr> out;
        for (const auto& row : res) out.push_back(std::make_shared<vh::vault::model::Key>(row));
        return out;
    });
}

void Deletion::markKeyExported(const unsigned int vaultId) {
    Transactions::exec("Deletion::markKeyExported", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_deletion SET key_exported_at = NOW() WHERE vault_id = $1", pqxx::params{vaultId});
    });
}

std::shared_ptr<vh::vault::model::Vault> Deletion::getDeletedVault(const unsigned int vaultId) {
    return Transactions::exec("Deletion::getDeletedVault", [&](pqxx::work& txn) -> std::shared_ptr<vh::vault::model::Vault> {
        const auto res = txn.exec(
            "SELECT v.*, s.* FROM vault v LEFT JOIN s3 s ON v.id = s.vault_id WHERE v.id = $1 AND v.deleted_at IS NOT NULL",
            pqxx::params{vaultId});
        if (res.empty()) return nullptr;
        const auto row = res.one_row_ref();
        if (vh::vault::model::from_string(row["type"].as<std::string>()) == vh::vault::model::VaultType::S3)
            return std::make_shared<vh::vault::model::S3Vault>(row);
        return std::make_shared<vh::vault::model::Vault>(row);
    });
}

std::vector<std::string> Deletion::otherVaultsOnBucket(const unsigned int vaultId) {
    return Transactions::exec("Deletion::otherVaultsOnBucket", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT v.name || ' (ID ' || v.id || ')' AS label "
            "FROM s3 me "
            "JOIN api_keys mk ON mk.id = me.api_key_id "
            "JOIN s3 o ON o.bucket = me.bucket AND o.vault_id <> me.vault_id "
            "JOIN api_keys ok ON ok.id = o.api_key_id "
            "JOIN vault v ON v.id = o.vault_id "
            "WHERE me.vault_id = $1 AND COALESCE(ok.endpoint, '') = COALESCE(mk.endpoint, '') AND ok.region = mk.region "
            "ORDER BY v.id",
            pqxx::params{vaultId});
        std::vector<std::string> out;
        for (const auto& row : res) out.push_back(row[0].as<std::string>());
        return out;
    });
}

bool Deletion::backingAliasShared(const unsigned int vaultId, const std::string& alias) {
    return Transactions::exec("Deletion::backingAliasShared", [&](pqxx::work& txn) {
        return txn.exec("SELECT EXISTS(SELECT 1 FROM vault WHERE btrim(mount_point) = $2 AND id <> $1)",
                        pqxx::params{vaultId, alias})
            .one_field_ref()
            .as<bool>();
    });
}

}
