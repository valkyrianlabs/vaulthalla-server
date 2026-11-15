#include "db/query/vault/RemoteDetach.hpp"

#include "db/Transactions.hpp"

#include <pqxx/result>

#include <stdexcept>

namespace vh::db::query::vault {

namespace {

namespace rd = ::vh::vault::remote::detach;

template <class T>
std::optional<T> rdOpt(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return f.as<T>();
}

std::optional<uint64_t> rdOptU64(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    const auto v = f.as<int64_t>();
    return v < 0 ? 0 : static_cast<uint64_t>(v);
}

std::optional<std::time_t> rdOptTime(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return static_cast<std::time_t>(f.as<int64_t>());
}

constexpr const char* rdKRowColumns =
    "vault_id, api_key_id, bucket, state, started_by, extract(epoch from started_at)::BIGINT AS started_at, attempts, "
    "passes, extract(epoch from verified_at)::BIGINT AS verified_at, "
    "extract(epoch from cutover_at)::BIGINT AS cutover_at, extract(epoch from done_at)::BIGINT AS done_at, "
    "extract(epoch from aborted_at)::BIGINT AS aborted_at, "
    "extract(epoch from abort_requested_at)::BIGINT AS abort_requested_at, abort_requested_by, "
    "estimate::TEXT AS estimate, last_error, extract(epoch from updated_at)::BIGINT AS updated_at";

rd::Row rdRowFrom(const pqxx::row_ref r) {
    rd::Row row;
    row.vault_id = r["vault_id"].as<uint32_t>();
    row.api_key_id = rdOpt<uint32_t>(r["api_key_id"]);
    row.bucket = r["bucket"].as<std::string>();
    row.state = rd::stateFromString(r["state"].as<std::string>());
    row.started_by = rdOpt<uint32_t>(r["started_by"]);
    row.started_at = static_cast<std::time_t>(r["started_at"].as<int64_t>());
    row.attempts = r["attempts"].as<unsigned int>();
    row.passes = r["passes"].as<unsigned int>();
    row.verified_at = rdOptTime(r["verified_at"]);
    row.cutover_at = rdOptTime(r["cutover_at"]);
    row.done_at = rdOptTime(r["done_at"]);
    row.aborted_at = rdOptTime(r["aborted_at"]);
    row.abort_requested_at = rdOptTime(r["abort_requested_at"]);
    row.abort_requested_by = rdOpt<uint32_t>(r["abort_requested_by"]);
    if (!r["estimate"].is_null()) row.estimate = nlohmann::json::parse(r["estimate"].as<std::string>());
    row.last_error = rdOpt<std::string>(r["last_error"]);
    row.updated_at = static_cast<std::time_t>(r["updated_at"].as<int64_t>());
    return row;
}

std::optional<rd::Row> rdRowIn(pqxx::transaction_base& txn, const uint32_t vaultId) {
    const auto res = txn.exec(std::string("SELECT ") + rdKRowColumns + " FROM vault_remote_detach WHERE vault_id = $1",
                              pqxx::params{vaultId});
    if (res.empty()) return std::nullopt;
    return rdRowFrom(res[0]);
}

constexpr const char* rdKItemColumns =
    "id, vault_id, kind, file_id, kid, generation, key_version, size, hydrated, state, error";

rd::Item rdItemFrom(const pqxx::row_ref r) {
    rd::Item it;
    it.id = r["id"].as<int64_t>();
    it.vault_id = r["vault_id"].as<uint32_t>();
    it.kind = rd::itemKindFromString(r["kind"].as<std::string>());
    it.file_id = rdOpt<uint32_t>(r["file_id"]);
    it.kid = rdOpt<std::string>(r["kid"]);
    it.generation = rdOpt<std::string>(r["generation"]);
    it.key_version = rdOpt<unsigned int>(r["key_version"]);
    it.size = rdOptU64(r["size"]);
    it.hydrated = r["hydrated"].as<bool>();
    it.state = rd::itemStateFromString(r["state"].as<std::string>());
    it.error = rdOpt<std::string>(r["error"]);
    return it;
}

pqxx::params rdItemParams(const rd::Item& it) {
    return pqxx::params{it.vault_id,
                        std::string(rd::to_string(it.kind)),
                        it.file_id,
                        it.kid,
                        it.generation,
                        it.key_version,
                        it.size ? std::make_optional(static_cast<int64_t>(*it.size)) : std::nullopt,
                        it.hydrated,
                        std::string(rd::to_string(it.state)),
                        it.error};
}

void rdUpdate(const char* ctx, const std::string& set, const pqxx::params& params) {
    Transactions::exec(ctx, [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_remote_detach SET " + set + ", updated_at = now() WHERE vault_id = $1", params);
    });
}

}

std::optional<RemoteDetach::Row> RemoteDetach::get(const uint32_t vaultId) {
    return Transactions::read("RemoteDetach::get", [&](pqxx::transaction_base& txn) { return rdRowIn(txn, vaultId); });
}

std::vector<RemoteDetach::Row> RemoteDetach::list() {
    return Transactions::read("RemoteDetach::list", [&](pqxx::transaction_base& txn) {
        std::vector<Row> out;
        for (const auto r : txn.exec(std::string("SELECT ") + rdKRowColumns + " FROM vault_remote_detach ORDER BY vault_id"))
            out.push_back(rdRowFrom(r));
        return out;
    });
}

RemoteDetach::Started RemoteDetach::start(const StartRequest& request) {
    return Transactions::exec("RemoteDetach::start", [&](pqxx::work& txn) {
        Started out;
        (void)txn.exec("SELECT 1 FROM vault WHERE id = $1 FOR UPDATE", pqxx::params{request.vault_id});
        const auto existing = rdRowIn(txn, request.vault_id);
        if (!existing || existing->state == State::Aborted || existing->state == State::Done) {
            if (existing) {
                txn.exec("DELETE FROM vault_remote_detach_item WHERE vault_id = $1", pqxx::params{request.vault_id});
                txn.exec("DELETE FROM vault_remote_detach WHERE vault_id = $1", pqxx::params{request.vault_id});
            }
            txn.exec("INSERT INTO vault_remote_detach (vault_id, api_key_id, bucket, state, started_by) "
                     "VALUES ($1, $2, $3, 'preparing', $4)",
                     pqxx::params{request.vault_id, request.api_key_id, request.bucket, request.started_by});
            out.outcome = StartOutcome::Started;
        } else if (existing->state == State::Failed) {
            txn.exec("UPDATE vault_remote_detach SET state = 'preparing', started_by = $2, attempts = attempts + 1, "
                     "  passes = 0, verified_at = NULL, last_error = NULL, abort_requested_at = NULL, "
                     "  abort_requested_by = NULL, updated_at = now() WHERE vault_id = $1",
                     pqxx::params{request.vault_id, request.started_by});
            txn.exec("UPDATE vault_remote_detach_item SET state = 'pending', error = NULL, updated_at = now() "
                     "WHERE vault_id = $1 AND state = 'failed'",
                     pqxx::params{request.vault_id});
            out.outcome = StartOutcome::Resumed;
        } else {
            out.outcome = StartOutcome::Busy;
            out.row = existing;
            return out;
        }
        out.row = rdRowIn(txn, request.vault_id);
        return out;
    });
}

void RemoteDetach::setState(const uint32_t vaultId, const State state, const std::optional<std::string>& error) {
    if (!rd::beforeCutover(state)) throw std::logic_error("setState moves a detach before its cutover only");
    Transactions::exec("RemoteDetach::setState", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_remote_detach SET state = $2, last_error = $3, updated_at = now() "
                 "WHERE vault_id = $1 AND cutover_at IS NULL AND state <> 'aborted'",
                 pqxx::params{vaultId, std::string(rd::to_string(state)), error});
    });
}

void RemoteDetach::setEstimate(const uint32_t vaultId, const nlohmann::json& estimate) {
    rdUpdate("RemoteDetach::setEstimate", "estimate = $2::JSONB", pqxx::params{vaultId, estimate.dump()});
}

void RemoteDetach::setPasses(const uint32_t vaultId, const unsigned int passes) {
    rdUpdate("RemoteDetach::setPasses", "passes = $2", pqxx::params{vaultId, passes});
}

void RemoteDetach::markVerified(const uint32_t vaultId) {
    rdUpdate("RemoteDetach::markVerified", "verified_at = now()", pqxx::params{vaultId});
}

void RemoteDetach::clearVerified(const uint32_t vaultId) {
    rdUpdate("RemoteDetach::clearVerified", "verified_at = NULL", pqxx::params{vaultId});
}

void RemoteDetach::setError(const uint32_t vaultId, const std::optional<std::string>& error) {
    rdUpdate("RemoteDetach::setError", "last_error = $2", pqxx::params{vaultId, error});
}

bool RemoteDetach::requestAbort(const uint32_t vaultId, const std::optional<uint32_t> userId) {
    return Transactions::exec("RemoteDetach::requestAbort", [&](pqxx::work& txn) {
        return txn.exec("UPDATE vault_remote_detach SET abort_requested_at = now(), abort_requested_by = $2, "
                        "  updated_at = now() WHERE vault_id = $1 AND cutover_at IS NULL AND state <> 'aborted'",
                        pqxx::params{vaultId, userId})
                   .affected_rows() == 1;
    });
}

void RemoteDetach::finishAbort(const uint32_t vaultId) {
    Transactions::exec("RemoteDetach::finishAbort", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_remote_detach SET state = 'aborted', aborted_at = now(), verified_at = NULL, "
                 "  last_error = NULL, updated_at = now() WHERE vault_id = $1 AND cutover_at IS NULL",
                 pqxx::params{vaultId});
    });
}

void RemoteDetach::markDone(const uint32_t vaultId) {
    Transactions::exec("RemoteDetach::markDone", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_remote_detach SET state = 'done', done_at = now(), last_error = NULL, updated_at = now() "
                 "WHERE vault_id = $1 AND state = 'cutover'",
                 pqxx::params{vaultId});
    });
}

std::vector<RemoteDetach::Item> RemoteDetach::items(const uint32_t vaultId) {
    return Transactions::read("RemoteDetach::items", [&](pqxx::transaction_base& txn) {
        std::vector<Item> out;
        for (const auto r : txn.exec(std::string("SELECT ") + rdKItemColumns +
                                         " FROM vault_remote_detach_item WHERE vault_id = $1 ORDER BY id",
                                     pqxx::params{vaultId}))
            out.push_back(rdItemFrom(r));
        return out;
    });
}

RemoteDetach::Item RemoteDetach::insertItem(const Item& item) {
    return Transactions::exec("RemoteDetach::insertItem", [&](pqxx::work& txn) {
        const auto res = txn.exec("INSERT INTO vault_remote_detach_item (vault_id, kind, file_id, kid, generation, "
                                  "  key_version, size, hydrated, state, error) "
                                  "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
                                  rdItemParams(item));
        auto stored = item;
        stored.id = res.one_field_ref().as<int64_t>();
        return stored;
    });
}

void RemoteDetach::updateItem(const Item& item) {
    Transactions::exec("RemoteDetach::updateItem", [&](pqxx::work& txn) {
        auto p = rdItemParams(item);
        p.append(item.id);
        txn.exec("UPDATE vault_remote_detach_item SET vault_id = $1, kind = $2, file_id = $3, kid = $4, "
                 "generation = $5, key_version = $6, size = $7, hydrated = $8, state = $9, error = $10, "
                 "updated_at = now() WHERE id = $11",
                 p);
    });
}

void RemoteDetach::deleteItem(const int64_t itemId) {
    Transactions::exec("RemoteDetach::deleteItem", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM vault_remote_detach_item WHERE id = $1", pqxx::params{itemId});
    });
}

uint64_t RemoteDetach::historyInBucketOnly(const uint32_t vaultId) {
    return Transactions::read("RemoteDetach::historyInBucketOnly", [&](pqxx::transaction_base& txn) {
        return txn.exec("SELECT count(*) FROM file_versions WHERE vault_id = $1 AND upstream_state = 'sent' "
                        "AND blob_id IS NULL",
                        pqxx::params{vaultId})
            .one_field_ref()
            .as<uint64_t>();
    });
}

std::vector<std::string> RemoteDetach::trashedBackingPaths(const uint32_t vaultId) {
    return Transactions::read("RemoteDetach::trashedBackingPaths", [&](pqxx::transaction_base& txn) {
        std::vector<std::string> out;
        for (const auto r : txn.exec("SELECT backing_path FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL "
                                     "ORDER BY id",
                                     pqxx::params{vaultId}))
            out.push_back(r[0].as<std::string>());
        return out;
    });
}

bool RemoteDetach::eventSubscriptionActive(const uint32_t vaultId) {
    return Transactions::read("RemoteDetach::eventSubscriptionActive", [&](pqxx::transaction_base& txn) {
        return !txn.exec("SELECT 1 FROM upstream_event_subscription WHERE vault_id = $1 AND state <> 'removed' LIMIT 1",
                         pqxx::params{vaultId})
                    .empty();
    });
}

uint64_t RemoteDetach::openConflicts(const uint32_t vaultId) {
    return Transactions::read("RemoteDetach::openConflicts", [&](pqxx::transaction_base& txn) {
        return txn.exec("SELECT count(*) FROM sync_conflicts c JOIN sync_event e ON e.id = c.event_id "
                        "WHERE e.vault_id = $1 AND c.resolved_at IS NULL",
                        pqxx::params{vaultId})
            .one_field_ref()
            .as<uint64_t>();
    });
}

bool RemoteDetach::layoutMigrationRunning(const uint32_t vaultId) {
    return Transactions::read("RemoteDetach::layoutMigrationRunning", [&](pqxx::transaction_base& txn) {
        return !txn.exec("SELECT 1 FROM vault_layout_migration WHERE vault_id = $1 "
                         "AND state NOT IN ('complete', 'failed') LIMIT 1",
                         pqxx::params{vaultId})
                    .empty();
    });
}

RemoteDetach::CutoverOutcome RemoteDetach::cutover(const uint32_t vaultId) {
    return Transactions::exec("RemoteDetach::cutover", [&](pqxx::work& txn) {
        CutoverOutcome out;
        const auto vault = txn.exec("SELECT type, deleted_at IS NOT NULL FROM vault WHERE id = $1 FOR UPDATE",
                                    pqxx::params{vaultId});
        if (vault.empty() || vault[0][1].as<bool>()) {
            out.refused = "the vault no longer exists";
            return out;
        }
        if (vault[0][0].as<std::string>() != "s3") {
            out.refused = "the vault is not an S3 vault";
            return out;
        }
        const auto detach = txn.exec("SELECT state, verified_at IS NOT NULL, abort_requested_at IS NOT NULL "
                                     "FROM vault_remote_detach WHERE vault_id = $1 FOR UPDATE",
                                     pqxx::params{vaultId});
        if (detach.empty() || detach[0][0].as<std::string>() != "verifying" || !detach[0][1].as<bool>()) {
            out.refused = "the detach is not verified";
            return out;
        }
        if (detach[0][2].as<bool>()) {
            out.refused = "an abort was requested";
            return out;
        }
        // Every live file with content is held here at the generation the catalog records, verified.
        const auto unverified = txn.exec(
            "SELECT count(*) FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
            "WHERE e.vault_id = $1 AND f.encryption_iv <> '' AND NOT EXISTS (SELECT 1 FROM vault_remote_detach_item i "
            "  WHERE i.vault_id = e.vault_id AND i.kind = 'content' AND i.file_id = f.fs_entry_id "
            "  AND i.state = 'verified' AND i.generation = f.encryption_iv)",
            pqxx::params{vaultId}).one_field_ref().as<uint64_t>();
        if (unverified > 0) {
            out.refused = std::to_string(unverified) + " file(s) changed since they were verified locally";
            return out;
        }
        // Recovery material is never left behind: a local vault keeps its envelopes in the database, so every row
        // must hold its bytes (a version wrapped since the copy is copied and verified first).
        if (!txn.exec("SELECT 1 FROM vault_key_envelope WHERE vault_id = $1 AND envelope IS NULL LIMIT 1",
                      pqxx::params{vaultId}).empty()) {
            out.refused = "a recovery envelope has no verified copy in the database yet";
            return out;
        }
        if (!txn.exec("SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = $1 "
                      "AND (f.content_format = 'gcm0' OR (f.content_format = 'plain' AND f.size_bytes > 0)) LIMIT 1",
                      pqxx::params{vaultId}).empty()) {
            out.refused = "legacy (gcm0 or plain) content appeared";
            return out;
        }

        // The vault becomes a local vault: its S3 binding, remote index, baselines and manifest position go.
        txn.exec("UPDATE vault SET type = 'local', updated_at = CURRENT_TIMESTAMP WHERE id = $1", pqxx::params{vaultId});
        txn.exec("DELETE FROM s3 WHERE vault_id = $1", pqxx::params{vaultId});

        // rsync -> fsync, keeping the vault's interval and enabled flag (they live on the sync row).
        const auto sync = txn.exec("SELECT id FROM sync WHERE vault_id = $1 FOR UPDATE", pqxx::params{vaultId});
        if (sync.empty()) throw std::runtime_error("the vault has no sync policy row");
        const auto syncId = sync[0][0].as<uint32_t>();
        txn.exec("DELETE FROM rsync WHERE sync_id = $1", pqxx::params{syncId});
        txn.exec("INSERT INTO fsync (sync_id) VALUES ($1) ON CONFLICT (sync_id) DO NOTHING", pqxx::params{syncId});
        txn.exec("UPDATE sync SET updated_at = NOW() WHERE id = $1", pqxx::params{syncId});

        txn.exec(pqxx::prepped{"remote_object_index.delete_for_vault"}, pqxx::params{vaultId});
        txn.exec("DELETE FROM sync_file_baseline WHERE vault_id = $1", pqxx::params{vaultId});
        txn.exec("DELETE FROM remote_manifest_state WHERE vault_id = $1", pqxx::params{vaultId});
        txn.exec("DELETE FROM remote_manifest_root WHERE vault_id = $1", pqxx::params{vaultId});
        txn.exec("DELETE FROM remote_manifest_gc WHERE vault_id = $1", pqxx::params{vaultId});
        // A local vault has no remote access to gate (migration 140).
        txn.exec("DELETE FROM vault_remote_access WHERE vault_id = $1", pqxx::params{vaultId});

        // A gateway bucket on a local vault is a local bucket (ops::s3_gateway).
        out.gateway_flipped = txn.exec("UPDATE s3_gateway_bucket SET mode = 'local' WHERE vault_id = $1 "
                                       "AND mode <> 'local'",
                                       pqxx::params{vaultId})
                                  .affected_rows() > 0;
        // The bucket stays the control plane's, with its ownership, but no vault uses it any more.
        out.bucket_unbound = txn.exec("UPDATE upstream_bucket SET vault_id = NULL, updated_at = now() WHERE vault_id = $1",
                                      pqxx::params{vaultId})
                                 .affected_rows() > 0;
        // Upstream history: nothing is replayed to a bucket the vault no longer uses. The local versions stay local
        // recovery points with their blobs; what the provider already holds stays in the bucket's history.
        out.backlog_skipped = static_cast<uint64_t>(
            txn.exec("UPDATE file_versions SET upstream_state = 'skipped', upstream_error = 'detached' "
                     "WHERE vault_id = $1 AND upstream_state = 'pending'",
                     pqxx::params{vaultId})
                .affected_rows());
        txn.exec("UPDATE vault_recovery_policy SET mode = 'local_snapshots', updated_at = now() "
                 "WHERE vault_id = $1 AND mode = 'provider_versioning'",
                 pqxx::params{vaultId});
        // The attach that made it an S3 vault (if one did) is over: a later attach starts afresh.
        txn.exec("DELETE FROM vault_remote_attach_item WHERE vault_id = $1", pqxx::params{vaultId});
        txn.exec("DELETE FROM vault_remote_attach WHERE vault_id = $1", pqxx::params{vaultId});

        txn.exec("UPDATE vault_remote_detach SET state = 'cutover', cutover_at = now(), last_error = NULL, "
                 "  updated_at = now() WHERE vault_id = $1",
                 pqxx::params{vaultId});
        out.done = true;
        return out;
    });
}

RemoteDetach::Summary RemoteDetach::summary() {
    return Transactions::read("RemoteDetach::summary", [&](pqxx::transaction_base& txn) {
        Summary s;
        for (const auto r : txn.exec("SELECT d.vault_id, d.state, v.name, d.last_error FROM vault_remote_detach d "
                                     "JOIN vault v ON v.id = d.vault_id "
                                     "WHERE v.deleted_at IS NULL AND d.state NOT IN ('done', 'aborted') "
                                     "ORDER BY d.vault_id")) {
            if (r[1].as<std::string>() == "failed")
                s.failed.push_back({.vault_id = r[0].as<uint32_t>(), .vault_name = r[2].as<std::string>(),
                                    .detail = rdOpt<std::string>(r[3]).value_or("")});
            else s.unfinished.push_back(r[0].as<uint32_t>());
        }
        return s;
    });
}

std::vector<std::pair<uint32_t, std::string>> RemoteDetach::states() {
    return Transactions::read("RemoteDetach::states", [&](pqxx::transaction_base& txn) {
        std::vector<std::pair<uint32_t, std::string>> out;
        for (const auto r : txn.exec("SELECT vault_id, state FROM vault_remote_detach ORDER BY vault_id"))
            out.emplace_back(r[0].as<uint32_t>(), r[1].as<std::string>());
        return out;
    });
}

}
