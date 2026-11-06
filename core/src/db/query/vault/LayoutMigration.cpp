#include "db/query/vault/LayoutMigration.hpp"

#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/encoding/u8.hpp"
#include "fs/model/File.hpp"
#include "sync/model/RemoteObject.hpp"

#include <pqxx/result>

#include <stdexcept>

namespace vh::db::query::vault {

namespace {

namespace lm = ::vh::vault::layout;

int64_t lmI64(const uint64_t v) { return static_cast<int64_t>(v); }

std::optional<int64_t> lmOptI64(const std::optional<uint64_t>& v) {
    return v ? std::make_optional(static_cast<int64_t>(*v)) : std::nullopt;
}

template <class T>
std::optional<T> lmOpt(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return f.as<T>();
}

std::optional<uint64_t> lmOptU64(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    const auto v = f.as<int64_t>();
    return v < 0 ? 0 : static_cast<uint64_t>(v);
}

std::optional<std::time_t> lmOptTime(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return static_cast<std::time_t>(f.as<int64_t>());
}

std::optional<int64_t> lmEpochOf(const std::optional<std::time_t>& t) {
    return t ? std::make_optional(static_cast<int64_t>(*t)) : std::nullopt;
}

constexpr const char* lmKRowColumns =
    "vault_id, state, started_by, extract(epoch from started_at)::BIGINT AS started_at, accept_unpriced, versioned, "
    "wait_days, attempts, extract(epoch from verified_at)::BIGINT AS verified_at, "
    "extract(epoch from cutover_at)::BIGINT AS cutover_at, extract(epoch from cleanup_after)::BIGINT AS cleanup_after, "
    "extract(epoch from manifest_verified_at)::BIGINT AS manifest_verified_at, "
    "extract(epoch from cleanup_confirmed_at)::BIGINT AS cleanup_confirmed_at, cleanup_confirmed_by, "
    "extract(epoch from cleanup_run_at)::BIGINT AS cleanup_run_at, "
    "extract(epoch from completed_at)::BIGINT AS completed_at, estimate::TEXT AS estimate, usage::TEXT AS usage, "
    "last_error, extract(epoch from updated_at)::BIGINT AS updated_at";

lm::Row lmRowFrom(const pqxx::row_ref r) {
    lm::Row row;
    row.vault_id = r["vault_id"].as<uint32_t>();
    row.state = lm::stateFromString(r["state"].as<std::string>());
    row.started_by = lmOpt<uint32_t>(r["started_by"]);
    row.started_at = static_cast<std::time_t>(r["started_at"].as<int64_t>());
    row.accept_unpriced = r["accept_unpriced"].as<bool>();
    row.versioned = lmOpt<bool>(r["versioned"]);
    row.wait_days = r["wait_days"].as<unsigned int>();
    row.attempts = r["attempts"].as<unsigned int>();
    row.verified_at = lmOptTime(r["verified_at"]);
    row.cutover_at = lmOptTime(r["cutover_at"]);
    row.cleanup_after = lmOptTime(r["cleanup_after"]);
    row.manifest_verified_at = lmOptTime(r["manifest_verified_at"]);
    row.cleanup_confirmed_at = lmOptTime(r["cleanup_confirmed_at"]);
    row.cleanup_confirmed_by = lmOpt<uint32_t>(r["cleanup_confirmed_by"]);
    row.cleanup_run_at = lmOptTime(r["cleanup_run_at"]);
    row.completed_at = lmOptTime(r["completed_at"]);
    if (!r["estimate"].is_null()) row.estimate = nlohmann::json::parse(r["estimate"].as<std::string>());
    if (!r["usage"].is_null()) row.usage = nlohmann::json::parse(r["usage"].as<std::string>());
    row.last_error = lmOpt<std::string>(r["last_error"]);
    row.updated_at = static_cast<std::time_t>(r["updated_at"].as<int64_t>());
    return row;
}

constexpr const char* lmKItemColumns =
    "id, vault_id, kind, legacy_key, legacy_version_id, legacy_etag, legacy_size, "
    "extract(epoch from legacy_last_modified)::BIGINT AS legacy_last_modified, legacy_storage_class, legacy_latest, seq, "
    "file_id, generation_id, object_uid::TEXT AS object_uid, source_generation, key_version, plaintext_bytes, "
    "content_hash, target_version_id, target_etag, target_generation, target_size, state, reason, error, "
    "cleanup_state, cleanup_reason, extract(epoch from retain_until)::BIGINT AS retain_until, cleanup_attempts";

lm::Item lmItemFrom(const pqxx::row_ref r) {
    lm::Item it;
    it.id = r["id"].as<int64_t>();
    it.vault_id = r["vault_id"].as<uint32_t>();
    it.kind = lm::itemKindFromString(r["kind"].as<std::string>());
    it.legacy_key = lmOpt<std::string>(r["legacy_key"]);
    it.legacy_version_id = lmOpt<std::string>(r["legacy_version_id"]);
    it.legacy_etag = lmOpt<std::string>(r["legacy_etag"]);
    it.legacy_size = lmOptU64(r["legacy_size"]);
    it.legacy_last_modified = lmOptTime(r["legacy_last_modified"]);
    it.legacy_storage_class = lmOpt<std::string>(r["legacy_storage_class"]);
    it.legacy_latest = r["legacy_latest"].as<bool>();
    it.seq = r["seq"].as<int>();
    it.file_id = lmOpt<uint32_t>(r["file_id"]);
    it.generation_id = lmOpt<int64_t>(r["generation_id"]);
    if (!r["object_uid"].is_null()) it.object_uid = crypto::id::fromUuid(r["object_uid"].as<std::string>());
    it.source_generation = lmOpt<std::string>(r["source_generation"]);
    it.key_version = lmOpt<unsigned int>(r["key_version"]);
    it.plaintext_bytes = lmOptU64(r["plaintext_bytes"]);
    it.content_hash = lmOpt<std::string>(r["content_hash"]);
    it.target_version_id = lmOpt<std::string>(r["target_version_id"]);
    it.target_etag = lmOpt<std::string>(r["target_etag"]);
    it.target_generation = lmOpt<std::string>(r["target_generation"]);
    it.target_size = lmOptU64(r["target_size"]);
    it.state = lm::itemStateFromString(r["state"].as<std::string>());
    it.reason = lmOpt<std::string>(r["reason"]);
    it.error = lmOpt<std::string>(r["error"]);
    it.cleanup_state = lmOpt<std::string>(r["cleanup_state"]);
    it.cleanup_reason = lmOpt<std::string>(r["cleanup_reason"]);
    it.retain_until = lmOptTime(r["retain_until"]);
    it.cleanup_attempts = r["cleanup_attempts"].as<unsigned int>();
    return it;
}

std::optional<std::string> lmUidText(const std::optional<crypto::id::ObjectUid>& uid) {
    return uid ? std::make_optional(crypto::id::toUuid(*uid)) : std::nullopt;
}

// Every column of an item, $1.. in this order (the insert and the update share it).
pqxx::params lmItemParams(const lm::Item& it) {
    return pqxx::params{it.vault_id,
                        std::string(lm::to_string(it.kind)),
                        it.legacy_key,
                        it.legacy_version_id,
                        it.legacy_etag,
                        lmOptI64(it.legacy_size),
                        lmEpochOf(it.legacy_last_modified),
                        it.legacy_storage_class,
                        it.legacy_latest,
                        it.seq,
                        it.file_id,
                        it.generation_id,
                        lmUidText(it.object_uid),
                        it.source_generation,
                        it.key_version,
                        lmOptI64(it.plaintext_bytes),
                        it.content_hash,
                        it.target_version_id,
                        it.target_etag,
                        it.target_generation,
                        lmOptI64(it.target_size),
                        std::string(lm::to_string(it.state)),
                        it.reason,
                        it.error,
                        it.cleanup_state,
                        it.cleanup_reason,
                        lmEpochOf(it.retain_until),
                        it.cleanup_attempts};
}

constexpr const char* lmKInsertItem =
    "INSERT INTO vault_layout_migration_item (vault_id, kind, legacy_key, legacy_version_id, legacy_etag, legacy_size, "
    "legacy_last_modified, legacy_storage_class, legacy_latest, seq, file_id, generation_id, object_uid, "
    "source_generation, key_version, plaintext_bytes, content_hash, target_version_id, target_etag, target_generation, "
    "target_size, state, reason, error, cleanup_state, cleanup_reason, retain_until, cleanup_attempts) "
    "VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7::BIGINT), $8, $9, $10, $11, $12, $13::uuid, $14, $15, $16, $17, "
    "$18, $19, $20, $21, $22, $23, $24, $25, $26, to_timestamp($27::BIGINT), $28) ";

lm::Item lmReturning(pqxx::work& txn, const pqxx::result& res) {
    if (res.empty()) throw std::runtime_error("layout migration item was not stored");
    const auto id = res[0][0].as<int64_t>();
    const auto out = txn.exec(std::string("SELECT ") + lmKItemColumns + " FROM vault_layout_migration_item WHERE id = $1",
                              pqxx::params{id});
    return lmItemFrom(out.one_row_ref());
}

}

std::optional<LayoutMigration::Row> LayoutMigration::get(const uint32_t vaultId) {
    return Transactions::read("LayoutMigration::get", [&](pqxx::transaction_base& txn) -> std::optional<Row> {
        const auto res = txn.exec(std::string("SELECT ") + lmKRowColumns + " FROM vault_layout_migration WHERE vault_id = $1",
                                  pqxx::params{vaultId});
        if (res.empty()) return std::nullopt;
        return lmRowFrom(res[0]);
    });
}

std::vector<LayoutMigration::Row> LayoutMigration::list() {
    return Transactions::read("LayoutMigration::list", [&](pqxx::transaction_base& txn) {
        std::vector<Row> out;
        for (const auto r : txn.exec(std::string("SELECT ") + lmKRowColumns + " FROM vault_layout_migration ORDER BY vault_id"))
            out.push_back(lmRowFrom(r));
        return out;
    });
}

std::optional<LayoutMigration::Row> LayoutMigration::start(const uint32_t vaultId, const std::optional<uint32_t> userId,
                                                           const unsigned int waitDays, const bool acceptUnpriced) {
    return Transactions::exec("LayoutMigration::start", [&](pqxx::work& txn) -> std::optional<Row> {
        const auto res = txn.exec(
            "INSERT INTO vault_layout_migration (vault_id, state, started_by, accept_unpriced, wait_days) "
            "VALUES ($1, 'copying', $2, $3, $4) "
            "ON CONFLICT (vault_id) DO UPDATE SET state = 'copying', started_by = EXCLUDED.started_by, "
            "  accept_unpriced = EXCLUDED.accept_unpriced, wait_days = EXCLUDED.wait_days, "
            "  attempts = vault_layout_migration.attempts + 1, last_error = NULL, updated_at = now() "
            "WHERE vault_layout_migration.state = 'failed' "
            "RETURNING vault_id",
            pqxx::params{vaultId, userId, acceptUnpriced, waitDays});
        if (res.empty()) return std::nullopt;
        const auto row = txn.exec(std::string("SELECT ") + lmKRowColumns + " FROM vault_layout_migration WHERE vault_id = $1",
                                  pqxx::params{vaultId});
        return lmRowFrom(row.one_row_ref());
    });
}

void LayoutMigration::setState(const uint32_t vaultId, const State state, const std::optional<std::string>& error) {
    if (!lm::beforeCutover(state)) throw std::logic_error("setState moves a migration before its cutover only");
    Transactions::exec("LayoutMigration::setState", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_layout_migration SET state = $2, last_error = $3, updated_at = now() "
                 "WHERE vault_id = $1 AND cutover_at IS NULL",
                 pqxx::params{vaultId, std::string(lm::to_string(state)), error});
    });
}

void LayoutMigration::setVersioned(const uint32_t vaultId, const bool versioned) {
    Transactions::exec("LayoutMigration::setVersioned", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_layout_migration SET versioned = $2, updated_at = now() WHERE vault_id = $1",
                 pqxx::params{vaultId, versioned});
    });
}

void LayoutMigration::setEstimate(const uint32_t vaultId, const nlohmann::json& estimate) {
    Transactions::exec("LayoutMigration::setEstimate", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_layout_migration SET estimate = $2::JSONB, updated_at = now() WHERE vault_id = $1",
                 pqxx::params{vaultId, estimate.dump()});
    });
}

void LayoutMigration::setUsage(const uint32_t vaultId, const nlohmann::json& usage) {
    Transactions::exec("LayoutMigration::setUsage", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_layout_migration SET usage = $2::JSONB, updated_at = now() WHERE vault_id = $1",
                 pqxx::params{vaultId, usage.dump()});
    });
}

void LayoutMigration::markVerified(const uint32_t vaultId) {
    Transactions::exec("LayoutMigration::markVerified", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_layout_migration SET verified_at = now(), updated_at = now() WHERE vault_id = $1",
                 pqxx::params{vaultId});
    });
}

void LayoutMigration::markManifestVerified(const uint32_t vaultId) {
    Transactions::exec("LayoutMigration::markManifestVerified", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_layout_migration SET manifest_verified_at = now(), last_error = NULL, updated_at = now() "
                 "WHERE vault_id = $1 AND cutover_at IS NOT NULL",
                 pqxx::params{vaultId});
    });
}

void LayoutMigration::setError(const uint32_t vaultId, const std::optional<std::string>& error) {
    Transactions::exec("LayoutMigration::setError", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_layout_migration SET last_error = $2, updated_at = now() WHERE vault_id = $1",
                 pqxx::params{vaultId, error});
    });
}

void LayoutMigration::confirmCleanup(const uint32_t vaultId, const uint32_t userId) {
    Transactions::exec("LayoutMigration::confirmCleanup", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "UPDATE vault_layout_migration SET state = 'cleanup', cleanup_confirmed_at = now(), cleanup_confirmed_by = $2, "
            "  updated_at = now() "
            "WHERE vault_id = $1 AND state IN ('cut_over', 'cleanup', 'cleanup_blocked') AND cleanup_after <= now() "
            "  AND manifest_verified_at IS NOT NULL",
            pqxx::params{vaultId, userId});
        if (res.affected_rows() != 1) throw std::runtime_error("the migration is not waiting for its cleanup");
    });
}

void LayoutMigration::finishCleanupRun(const uint32_t vaultId, const State state) {
    if (state != State::Complete && state != State::CleanupBlocked)
        throw std::logic_error("a cleanup run ends complete or cleanup_blocked");
    Transactions::exec("LayoutMigration::finishCleanupRun", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_layout_migration SET state = $2, cleanup_run_at = now(), "
                 "  completed_at = CASE WHEN $2 = 'complete' THEN now() ELSE NULL END, updated_at = now() "
                 "WHERE vault_id = $1 AND cutover_at IS NOT NULL",
                 pqxx::params{vaultId, std::string(lm::to_string(state))});
    });
}

LayoutMigration::Item LayoutMigration::upsertLegacy(const Item& item) {
    if (!item.legacy()) throw std::invalid_argument("a legacy item needs its key");
    return Transactions::exec("LayoutMigration::upsertLegacy", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            std::string(lmKInsertItem) +
                "ON CONFLICT (vault_id, legacy_key, coalesce(legacy_version_id, '')) WHERE legacy_key IS NOT NULL "
                "DO UPDATE SET legacy_etag = EXCLUDED.legacy_etag, legacy_size = EXCLUDED.legacy_size, "
                "  legacy_last_modified = EXCLUDED.legacy_last_modified, "
                "  legacy_storage_class = EXCLUDED.legacy_storage_class, legacy_latest = EXCLUDED.legacy_latest, "
                "  seq = EXCLUDED.seq, updated_at = now() "
                "RETURNING id",
            lmItemParams(item));
        return lmReturning(txn, res);
    });
}

LayoutMigration::Item LayoutMigration::upsertCurrent(const Item& item) {
    if (item.kind != lm::ItemKind::Current || !item.file_id) throw std::invalid_argument("a current item names its file");
    return Transactions::exec("LayoutMigration::upsertCurrent", [&](pqxx::work& txn) {
        const auto res = txn.exec(std::string(lmKInsertItem) +
                                      "ON CONFLICT (vault_id, file_id) WHERE kind = 'current' "
                                      "DO UPDATE SET seq = EXCLUDED.seq, updated_at = now() RETURNING id",
                                  lmItemParams(item));
        return lmReturning(txn, res);
    });
}

LayoutMigration::Item LayoutMigration::upsertBacklog(const Item& item) {
    if (item.kind != lm::ItemKind::Backlog || !item.generation_id)
        throw std::invalid_argument("a backlog item names its generation");
    return Transactions::exec("LayoutMigration::upsertBacklog", [&](pqxx::work& txn) {
        const auto res = txn.exec(std::string(lmKInsertItem) +
                                      "ON CONFLICT (vault_id, generation_id) WHERE kind = 'backlog' "
                                      "DO UPDATE SET seq = EXCLUDED.seq, updated_at = now() RETURNING id",
                                  lmItemParams(item));
        return lmReturning(txn, res);
    });
}

void LayoutMigration::updateItem(const Item& item) {
    Transactions::exec("LayoutMigration::updateItem", [&](pqxx::work& txn) {
        auto p = lmItemParams(item);
        p.append(item.id);
        txn.exec("UPDATE vault_layout_migration_item SET vault_id = $1, kind = $2, legacy_key = $3, "
                 "legacy_version_id = $4, legacy_etag = $5, legacy_size = $6, legacy_last_modified = to_timestamp($7::BIGINT), "
                 "legacy_storage_class = $8, legacy_latest = $9, seq = $10, file_id = $11, generation_id = $12, "
                 "object_uid = $13::uuid, source_generation = $14, key_version = $15, plaintext_bytes = $16, "
                 "content_hash = $17, target_version_id = $18, target_etag = $19, target_generation = $20, "
                 "target_size = $21, state = $22, reason = $23, error = $24, cleanup_state = $25, cleanup_reason = $26, "
                 "retain_until = to_timestamp($27::BIGINT), cleanup_attempts = $28, updated_at = now() WHERE id = $29",
                 p);
    });
}

void LayoutMigration::resetFailed(const uint32_t vaultId) {
    Transactions::exec("LayoutMigration::resetFailed", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_layout_migration_item SET state = 'pending', reason = NULL, error = NULL, updated_at = now() "
                 "WHERE vault_id = $1 AND state = 'failed'",
                 pqxx::params{vaultId});
    });
}

std::vector<LayoutMigration::Item> LayoutMigration::items(const uint32_t vaultId) {
    return Transactions::read("LayoutMigration::items", [&](pqxx::transaction_base& txn) {
        std::vector<Item> out;
        for (const auto r : txn.exec(std::string("SELECT ") + lmKItemColumns +
                                         " FROM vault_layout_migration_item WHERE vault_id = $1 ORDER BY id",
                                     pqxx::params{vaultId}))
            out.push_back(lmItemFrom(r));
        return out;
    });
}

std::vector<std::shared_ptr<::vh::fs::model::File>> LayoutMigration::liveFiles(const uint32_t vaultId) {
    return Transactions::read("LayoutMigration::liveFiles", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec("SELECT fs.*, f.* FROM files f JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                                  "WHERE fs.vault_id = $1 ORDER BY f.fs_entry_id",
                                  pqxx::params{vaultId});
        return ::vh::fs::model::files_from_pq_res(res);
    });
}

std::optional<LayoutMigration::BaselineRemote> LayoutMigration::baselineOf(const uint32_t fileId) {
    return Transactions::read("LayoutMigration::baselineOf", [&](pqxx::transaction_base& txn)
                                                                 -> std::optional<BaselineRemote> {
        const auto res = txn.exec("SELECT remote_content_hash, remote_etag, remote_size_bytes FROM sync_file_baseline "
                                  "WHERE file_id = $1",
                                  pqxx::params{fileId});
        if (res.empty()) return std::nullopt;
        return BaselineRemote{.remote_content_hash = lmOpt<std::string>(res[0]["remote_content_hash"]),
                              .remote_etag = lmOpt<std::string>(res[0]["remote_etag"]),
                              .remote_size_bytes = lmOptU64(res[0]["remote_size_bytes"])};
    });
}

LayoutMigration::CutoverOutcome LayoutMigration::cutover(const uint32_t vaultId, const CutoverInput& input) {
    return Transactions::exec("LayoutMigration::cutover", [&](pqxx::work& txn) {
        CutoverOutcome out;
        const auto s3 = txn.exec("SELECT storage_layout FROM s3 WHERE vault_id = $1 FOR UPDATE", pqxx::params{vaultId});
        if (s3.empty() || s3[0][0].as<std::string>() != "path_v0") {
            out.refused = "the vault is not on path_v0";
            return out;
        }
        const auto state = txn.exec("SELECT state FROM vault_layout_migration WHERE vault_id = $1 FOR UPDATE",
                                    pqxx::params{vaultId});
        if (state.empty() || state[0][0].as<std::string>() != "verifying") {
            out.refused = "the migration is not verified";
            return out;
        }

        // No legacy (gcm0) live row may be left once the index-only rows move to the generation they were re-sealed
        // into (rows uploaded from a local copy keep theirs). Checked before anything changes, under row locks.
        std::map<uint32_t, const CutoverFile*> byId;
        for (const auto& f : input.files) byId[f.file_id] = &f;
        const auto legacyRows = txn.exec(
            "SELECT f.fs_entry_id, f.encryption_iv, f.encrypted_with_key_version FROM files f "
            "JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = $1 AND f.content_format = 'gcm0' FOR UPDATE OF f",
            pqxx::params{vaultId});
        for (const auto r : legacyRows) {
            const auto id = r[0].as<uint32_t>();
            const auto it = byId.find(id);
            const bool moves = it != byId.end() && it->second->from_generation == r[1].as<std::string>() &&
                               it->second->key_version == r[2].as<unsigned int>() &&
                               it->second->to_generation != it->second->from_generation;
            if (!moves) out.changed.push_back(id);
        }
        out.legacy_rows = out.changed.size();
        out.legacy_backlog = txn.exec(
            "SELECT count(*) FROM file_versions fv JOIN recovery_blob b ON b.id = fv.blob_id "
            "WHERE fv.vault_id = $1 AND fv.upstream_state = 'pending' AND b.content_format = 'gcm0'",
            pqxx::params{vaultId}).one_field_ref().as<uint64_t>();
        if (out.legacy_rows || out.legacy_backlog) {
            out.refused = "legacy (gcm0) content is still live";
            return out;   // nothing was changed
        }
        for (const auto& f : input.files) {
            if (f.from_generation == f.to_generation || f.empty_object) continue;
            // The statement key rotation and the format conversion use (a re-seal: the content didn't change).
            (void)txn.exec(pqxx::prepped{"compare_and_set_file_encryption_iv_and_version"},
                           pqxx::params{vaultId, f.path, f.to_generation, f.key_version, f.from_generation,
                                        f.key_version});
        }

        txn.exec("UPDATE s3 SET storage_layout = 'opaque_v1' WHERE vault_id = $1", pqxx::params{vaultId});

        // The remote index and the sync baselines: every o/<uid> object as Vaulthalla's own upload of its file.
        txn.exec(pqxx::prepped{"remote_object_index.delete_for_vault"}, pqxx::params{vaultId});
        for (const auto& f : input.files) {
            auto indexed = std::make_shared<::vh::fs::model::File>();
            indexed->path = "/" + f.object_key;
            indexed->size_bytes = f.plaintext_bytes;
            indexed->content_hash = f.content_hash;
            indexed->remote_etag = f.etag;
            indexed->remote_version_id = f.version_id;
            indexed->remote_storage_class = f.storage_class;
            indexed->remote_encrypted = true;
            indexed->encryption_iv = f.empty_object ? std::string{} : f.to_generation;
            indexed->encrypted_with_key_version = f.empty_object ? 0 : f.key_version;
            indexed->updated_at = std::time(nullptr);
            const ::vh::sync::model::RemoteObject object(vaultId, indexed, "manifest");
            txn.exec(pqxx::prepped{"remote_object_index.upsert"},
                     pqxx::params{object.vault_id, encoding::to_utf8_string(object.object_key.u8string()),
                                  object.size_bytes, encoding::timestampToString(object.last_modified), object.etag,
                                  object.storage_class, object.restore_status, object.version_id,
                                  object.event_sequencer, object.content_hash, object.encrypted,
                                  object.encryption_iv.empty() ? std::optional<std::string>{}
                                                               : std::make_optional(object.encryption_iv),
                                  object.encrypted_with_key_version == 0
                                      ? std::optional<unsigned int>{}
                                      : std::make_optional(object.encrypted_with_key_version),
                                  object.source});
            txn.exec("INSERT INTO sync_file_baseline (file_id, vault_id, content_hash, size_bytes, remote_etag, "
                     "  remote_size_bytes, remote_content_hash, synced_at) "
                     "SELECT $1, $2, $3, $4, $5, $4, $3, now() WHERE EXISTS (SELECT 1 FROM files WHERE fs_entry_id = $1) "
                     "ON CONFLICT (file_id) DO UPDATE SET vault_id = EXCLUDED.vault_id, content_hash = EXCLUDED.content_hash, "
                     "  size_bytes = EXCLUDED.size_bytes, remote_etag = EXCLUDED.remote_etag, "
                     "  remote_size_bytes = EXCLUDED.remote_size_bytes, remote_content_hash = EXCLUDED.remote_content_hash, "
                     "  synced_at = now()",
                     pqxx::params{f.file_id, vaultId, f.content_hash, lmI64(f.plaintext_bytes), f.etag});
        }

        // The upstream backlog replays onto o/<uid> from now on; sent local versions name their re-sealed version.
        for (const auto& v : input.versions) {
            txn.exec("UPDATE file_versions SET upstream_key = $4, upstream_version_id = $5 WHERE vault_id = $1 "
                     "AND upstream_key = $2 AND upstream_version_id = $3",
                     pqxx::params{vaultId, v.legacy_key, v.legacy_version_id, v.object_key, v.version_id});
            // Retention counts from the version's own time, not from the PUT that re-sealed it (spec 01 §6.5).
            txn.exec("UPDATE upstream_object_version SET last_modified = coalesce(to_timestamp($4::BIGINT), last_modified), "
                     "  became_noncurrent_at = CASE WHEN is_latest THEN NULL "
                     "    ELSE coalesce(to_timestamp($5::BIGINT), became_noncurrent_at) END "
                     "WHERE vault_id = $1 AND object_key = $2 AND version_id = $3",
                     pqxx::params{vaultId, v.object_key, v.version_id, lmEpochOf(v.last_modified),
                                  lmEpochOf(v.superseded_at)});
        }

        // Pending rows, and rows the migration itself marked sent (their version id is one of o/<uid>'s).
        for (const auto& [legacyKey, objectKey] : input.keyOf)
            txn.exec("UPDATE file_versions SET upstream_key = $3 WHERE vault_id = $1 AND upstream_key = $2 "
                     "AND (upstream_state = 'pending' OR upstream_version_id IN ("
                     "  SELECT version_id FROM upstream_object_version WHERE vault_id = $1 AND object_key = $3))",
                     pqxx::params{vaultId, legacyKey, objectKey});

        txn.exec("UPDATE vault_layout_migration SET state = 'cut_over', cutover_at = now(), "
                 "  cleanup_after = now() + make_interval(days => $2), last_error = NULL, updated_at = now() "
                 "WHERE vault_id = $1",
                 pqxx::params{vaultId, static_cast<int>(input.wait_days)});
        out.done = true;
        return out;
    });
}

void LayoutMigration::markLegacyVersionGone(const uint32_t vaultId, const std::string& key,
                                            const std::optional<std::string>& versionId) {
    Transactions::exec("LayoutMigration::markLegacyVersionGone", [&](pqxx::work& txn) {
        txn.exec("UPDATE upstream_object_version SET gone_at = now() WHERE vault_id = $1 AND object_key = $2 "
                 "AND ($3::TEXT IS NULL OR version_id = $3) AND gone_at IS NULL",
                 pqxx::params{vaultId, key, versionId});
    });
}

LayoutMigration::LegacySummary LayoutMigration::legacySummary() {
    return Transactions::read("LayoutMigration::legacySummary", [&](pqxx::transaction_base& txn) {
        LegacySummary s;
        for (const auto r : txn.exec("SELECT s.vault_id FROM s3 s JOIN vault v ON v.id = s.vault_id "
                                     "WHERE s.storage_layout = 'path_v0' ORDER BY s.vault_id"))
            s.path_v0_vaults.push_back(r[0].as<uint32_t>());
        for (const auto r : txn.exec("SELECT vault_id FROM vault_layout_migration "
                                     "WHERE cutover_at IS NOT NULL AND state <> 'complete' ORDER BY vault_id"))
            s.migrations_unfinished.push_back(r[0].as<uint32_t>());
        s.legacy_files = txn.exec("SELECT count(*) FROM files WHERE content_format = 'gcm0'").one_field_ref().as<uint64_t>();
        s.legacy_blobs = txn.exec("SELECT count(*) FROM recovery_blob WHERE content_format = 'gcm0'")
                             .one_field_ref()
                             .as<uint64_t>();
        s.legacy_upload_files = txn.exec("SELECT count(*) FROM upload_session_file WHERE encryption_iv <> '' "
                                         "AND length(encryption_iv) <> 44 AND state NOT IN ('committed', 'failed')")
                                    .one_field_ref()
                                    .as<uint64_t>();
        return s;
    });
}

}
