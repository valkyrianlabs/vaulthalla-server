#include "db/query/upstream/Inbox.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/timestamp.hpp"

#include <pqxx/result>

#include <algorithm>

namespace vh::db::query::upstream {

namespace {

namespace imodel = storage::upstream::model;

std::string inboxIdArray(const std::vector<int64_t>& ids) {
    std::string out = "{";
    for (const auto id : ids) out += (out.size() > 1 ? "," : "") + std::to_string(id);
    return out + "}";
}

unsigned int inboxLimit(const unsigned int limit) { return std::clamp(limit, 1u, 10000u); }

}

uint64_t Inbox::insertMany(const std::vector<InboxModel>& events) {
    if (events.empty()) return 0;
    return Transactions::exec("upstream::Inbox::insertMany", [&](pqxx::work& txn) {
        uint64_t inserted = 0;
        for (const auto& e : events) {
            const std::optional<int64_t> size =
                e.size_bytes ? std::make_optional(static_cast<int64_t>(*e.size_bytes)) : std::nullopt;
            const auto res = txn.exec(
                pqxx::prepped{"upstream_inbox_insert"},
                pqxx::params{e.channel_id, e.subscription_id, e.vault_id, e.provider, e.account_ref, e.bucket,
                             e.object_key, imodel::to_string(e.kind), e.event_name, e.dedupe_key, e.message_id,
                             e.sequencer, e.version_id, e.etag, size,
                             e.event_time_ms ? static_cast<double>(*e.event_time_ms) / 1000.0
                                             : static_cast<double>(e.event_time),
                             imodel::to_string(e.state), imodel::to_string(e.origin), e.note, e.event_time_ms});
            if (!res.empty()) ++inserted;
        }
        return inserted;
    });
}

std::vector<InboxModel> Inbox::claimForVault(const uint32_t vaultId, const unsigned int limit) {
    return Transactions::exec("upstream::Inbox::claimForVault", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_inbox_claim_for_vault"}, pqxx::params{vaultId, inboxLimit(limit)});
        return rowsAs<InboxModel>(res);
    });
}

std::vector<InboxModel> Inbox::listApplied(const uint32_t vaultId, const unsigned int limit) {
    return Transactions::exec("upstream::Inbox::listApplied", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_inbox_list_applied"}, pqxx::params{vaultId, inboxLimit(limit)});
        return rowsAs<InboxModel>(res);
    });
}

std::vector<uint32_t> Inbox::listVaultsWithWork() {
    return Transactions::exec("upstream::Inbox::listVaultsWithWork", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_inbox_list_vaults_with_work"});
        return mapRows(res, [](const pqxx::row_ref row) { return row["vault_id"].as<uint32_t>(); });
    });
}

void Inbox::markApplied(const std::vector<int64_t>& ids, const std::optional<imodel::InboxOrigin> origin) {
    if (ids.empty()) return;
    const std::optional<std::string> originText = origin ? std::make_optional(imodel::to_string(*origin)) : std::nullopt;
    Transactions::exec("upstream::Inbox::markApplied", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_inbox_mark_applied"}, pqxx::params{inboxIdArray(ids), originText});
    });
}

void Inbox::markDone(const std::vector<int64_t>& ids) {
    if (ids.empty()) return;
    Transactions::exec("upstream::Inbox::markDone", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_inbox_mark_done"}, pqxx::params{inboxIdArray(ids)});
    });
}

void Inbox::markSkipped(const std::vector<int64_t>& ids, const std::string& note, const imodel::InboxOrigin origin) {
    if (ids.empty()) return;
    Transactions::exec("upstream::Inbox::markSkipped", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_inbox_mark_skipped"},
                 pqxx::params{inboxIdArray(ids), note, imodel::to_string(origin)});
    });
}

void Inbox::markFailed(const int64_t id, const std::string& error, const std::optional<std::time_t> nextAttemptAt) {
    const std::optional<double> next = nextAttemptAt ? std::make_optional(static_cast<double>(*nextAttemptAt)) : std::nullopt;
    Transactions::exec("upstream::Inbox::markFailed", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_inbox_mark_failed"}, pqxx::params{id, error, next});
    });
}

void Inbox::requeueApplied(const uint32_t vaultId, const std::vector<int64_t>& ids, const std::time_t nextAttemptAt,
                           const std::string& error) {
    if (ids.empty()) return;
    Transactions::exec("upstream::Inbox::requeueApplied", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_inbox_requeue_applied"},
                 pqxx::params{vaultId, inboxIdArray(ids), static_cast<double>(nextAttemptAt), error});
    });
}

InboxCounts Inbox::counts(const uint32_t vaultId) {
    return Transactions::exec("upstream::Inbox::counts", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_inbox_counts"}, pqxx::params{vaultId});
        const auto row = res.one_row_ref();
        InboxCounts c;
        c.pending = row["pending"].as<uint64_t>();
        c.applied = row["applied"].as<uint64_t>();
        c.failed = row["failed"].as<uint64_t>();
        c.done_24h = row["done_24h"].as<uint64_t>();
        c.self_24h = row["self_24h"].as<uint64_t>();
        if (!row["last_event_at"].is_null())
            c.last_event_at = encoding::parsePostgresTimestamp(row["last_event_at"].as<std::string>());
        return c;
    });
}

uint64_t Inbox::routeUnassigned(const std::string& provider, const std::string& accountRef, const std::string& bucket,
                                const uint32_t vaultId, const int64_t subscriptionId, const std::string& prefix,
                                const std::time_t since) {
    return Transactions::exec("upstream::Inbox::routeUnassigned", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_inbox_route_unassigned"},
                                  pqxx::params{provider, accountRef, bucket, vaultId, subscriptionId, prefix,
                                               static_cast<double>(since)});
        return static_cast<uint64_t>(res.affected_rows());
    });
}

bool Inbox::settleOwnWrite(const int64_t rowId, const uint32_t vaultId, const std::string& key,
                           const imodel::WriteOp op, const std::optional<uint64_t> size, const std::time_t eventTime,
                           const std::optional<std::string>& etag, const std::string& note) {
    const std::optional<int64_t> sizeParam = size ? std::make_optional(static_cast<int64_t>(*size)) : std::nullopt;
    return Transactions::exec("upstream::Inbox::settleOwnWrite", [&](pqxx::work& txn) {
        const auto consumed = txn.exec(pqxx::prepped{"upstream_write_intent_consume"},
                                       pqxx::params{vaultId, key, imodel::to_string(op), sizeParam,
                                                    static_cast<double>(eventTime), etag});
        if (consumed.empty()) return false;
        txn.exec(pqxx::prepped{"upstream_inbox_mark_skipped"},
                 pqxx::params{inboxIdArray({rowId}), note, imodel::to_string(imodel::InboxOrigin::Self)});
        return true;
    });
}

uint64_t Inbox::sweepFinished(const std::chrono::seconds olderThan) {
    return Transactions::exec("upstream::Inbox::sweepFinished", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_inbox_sweep_finished"},
                                  pqxx::params{static_cast<double>(olderThan.count())});
        return static_cast<uint64_t>(res.affected_rows());
    });
}

std::optional<InboxModel> Inbox::latestForKey(const uint32_t vaultId, const std::string& key) {
    return Transactions::exec("upstream::Inbox::latestForKey", [&](pqxx::work& txn) -> std::optional<InboxModel> {
        const auto res = txn.exec(pqxx::prepped{"upstream_inbox_latest_for_key"}, pqxx::params{vaultId, key});
        if (res.empty()) return std::nullopt;
        return InboxModel(res.one_row_ref());
    });
}

}
