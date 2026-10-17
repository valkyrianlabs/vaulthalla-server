#include "db/query/recovery/Generation.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "db/query/recovery/detail/Fields.hpp"

#include <pqxx/result>

#include <algorithm>
#include <stdexcept>
#include <unordered_map>

namespace vh::db::query::recovery {

std::string to_string(const Origin o) { return o == Origin::Version ? "version" : "snapshot"; }

std::string to_string(const UpstreamState s) {
    switch (s) {
    case UpstreamState::None: return "none";
    case UpstreamState::Pending: return "pending";
    case UpstreamState::Sent: return "sent";
    case UpstreamState::Skipped: return "skipped";
    }
    return "none";
}

UpstreamState upstreamStateFromString(const std::string& s) {
    if (s == "none") return UpstreamState::None;
    if (s == "pending") return UpstreamState::Pending;
    if (s == "sent") return UpstreamState::Sent;
    if (s == "skipped") return UpstreamState::Skipped;
    throw std::invalid_argument("unknown upstream state '" + s + "'");
}

namespace {

GenerationRow generationFromRow(const pqxx::row_ref row) {
    GenerationRow g;
    g.id = row["id"].as<int64_t>();
    g.vault_id = detail::opt<uint32_t>(row["vault_id"]);
    g.file_id = detail::opt<uint32_t>(row["file_id"]);
    g.snapshot_id = detail::opt<int64_t>(row["snapshot_id"]);
    g.blob_id = detail::opt<int64_t>(row["blob_id"]);
    g.version_number = row["version_number"].as<int>();
    g.content_hash = detail::opt<std::string>(row["content_hash"]);
    g.size_bytes = detail::u64(row["size_bytes"]);
    g.mime_type = detail::opt<std::string>(row["mime_type"]);
    g.path = row["path"].as<std::string>();
    g.rel_path = detail::opt<std::string>(row["rel_path"]);
    g.mode = detail::opt<uint32_t>(row["mode"]);
    g.source_updated_at = detail::optTime(row["source_updated_at"]);
    g.created_at = detail::timeOr0(row["created_at"]);
    g.created_by = detail::opt<uint32_t>(row["created_by"]);
    g.origin = row["origin"].as<std::string>() == "version" ? Origin::Version : Origin::Snapshot;
    g.reason = detail::opt<std::string>(row["reason"]);
    g.upstream_state = upstreamStateFromString(row["upstream_state"].as<std::string>());
    g.upstream_key = detail::opt<std::string>(row["upstream_key"]);
    g.upstream_version_id = detail::opt<std::string>(row["upstream_version_id"]);
    g.upstream_attempts = row["upstream_attempts"].as<unsigned int>();
    g.upstream_error = detail::opt<std::string>(row["upstream_error"]);
    g.upstream_sent_at = detail::optTime(row["upstream_sent_at"]);
    g.storage_name = detail::opt<std::string>(row["storage_name"]);
    g.encryption_iv = detail::opt<std::string>(row["encryption_iv"]);
    g.key_version = detail::opt<unsigned int>(row["key_version"]);
    g.cipher_bytes = detail::optU64(row["cipher_bytes"]);
    return g;
}

std::optional<GenerationRow> firstGeneration(const pqxx::result& res) {
    if (res.empty()) return std::nullopt;
    return generationFromRow(res.one_row_ref());
}

// The file key a version number is allocated under: the live file, or (after it is gone) the vault path.
std::string generationLockKey(const NewGeneration& g) {
    if (g.file_id) return "vh.recovery.fv:f:" + std::to_string(*g.file_id);
    return "vh.recovery.fv:p:" + std::to_string(g.vault_id) + ":" + g.path;
}

InsertedGeneration insertGeneration(pqxx::work& txn, const NewGeneration& g, const Origin origin) {
    if (g.path.empty() || g.path.front() != '/') throw std::invalid_argument("generation path must be a vault path");
    txn.exec(pqxx::prepped{"recovery_generation_lock_key"}, pqxx::params{generationLockKey(g)});
    const auto next = g.file_id
        ? txn.exec(pqxx::prepped{"recovery_generation_next_number_file"}, pqxx::params{*g.file_id})
        : txn.exec(pqxx::prepped{"recovery_generation_next_number_path"}, pqxx::params{g.vault_id, g.path});
    const auto versionNumber = next.one_row_ref()[0].as<int>();

    const bool member = origin == Origin::Snapshot;
    const auto res = txn.exec(
        pqxx::prepped{"recovery_generation_insert"},
        pqxx::params{g.vault_id, g.file_id, member ? g.snapshot_id : std::nullopt, g.blob_id, versionNumber,
                     g.content_hash, static_cast<int64_t>(g.size_bytes), g.mime_type, g.path,
                     member ? g.rel_path : std::nullopt, g.mode, detail::optEpoch(g.source_updated_at), g.created_by,
                     to_string(origin), member ? std::nullopt : g.reason,
                     to_string(member ? UpstreamState::None : g.upstream_state),
                     member ? std::nullopt : g.upstream_key});
    return {.id = res.one_row_ref()["id"].as<int64_t>(), .version_number = versionNumber};
}

std::vector<int64_t> stillUnreferenced(pqxx::work& txn, std::vector<int64_t> blobIds) {
    std::ranges::sort(blobIds);
    blobIds.erase(std::ranges::unique(blobIds).begin(), blobIds.end());
    if (blobIds.empty()) return {};
    const auto res = txn.exec(pqxx::prepped{"recovery_blob_still_unreferenced"}, pqxx::params{detail::idArray(blobIds)});
    return mapRows(res, [](const pqxx::row_ref r) { return r[0].as<int64_t>(); });
}

}

InsertedGeneration Generation::insertSnapshotMember(pqxx::work& txn, const NewGeneration& g) {
    if (!g.snapshot_id || !g.rel_path) throw std::invalid_argument("a snapshot member needs snapshot_id and rel_path");
    return insertGeneration(txn, g, Origin::Snapshot);
}

InsertedGeneration Generation::insertLocalVersion(pqxx::work& txn, const NewGeneration& g) {
    if (!g.reason) throw std::invalid_argument("a local version needs a reason");
    return insertGeneration(txn, g, Origin::Version);
}

InsertedGeneration Generation::insertLocalVersion(const NewGeneration& g) {
    return Transactions::exec("recovery::Generation::insertLocalVersion",
                              [&](pqxx::work& txn) { return insertLocalVersion(txn, g); });
}

std::optional<GenerationRow> Generation::get(pqxx::transaction_base& txn, const int64_t id) {
    const auto res = txn.exec(pqxx::prepped{"recovery_generation_get"}, pqxx::params{id});
    return firstGeneration(res);
}

std::optional<GenerationRow> Generation::get(const int64_t id) {
    return Transactions::read("recovery::Generation::get", [&](pqxx::transaction_base& txn) { return get(txn, id); });
}

std::vector<GenerationRow> Generation::listByFile(const uint32_t fileId, const unsigned int limit) {
    return Transactions::read("recovery::Generation::listByFile", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_list_by_file"},
                                  pqxx::params{fileId, detail::clampLimit(limit)});
        return mapRows(res, generationFromRow);
    });
}

std::vector<GenerationRow> Generation::listByPath(const uint32_t vaultId, const std::string& path,
                                                  const std::optional<Origin> origin, const unsigned int limit) {
    const std::optional<std::string> originText = origin ? std::make_optional(to_string(*origin)) : std::nullopt;
    return Transactions::read("recovery::Generation::listByPath", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_list_by_path"},
                                  pqxx::params{vaultId, path, originText, detail::clampLimit(limit)});
        return mapRows(res, generationFromRow);
    });
}

std::vector<GenerationRow> Generation::listVersionsUnder(const uint32_t vaultId, const std::string& dirPath,
                                                         const unsigned int limit) {
    return Transactions::read("recovery::Generation::listVersionsUnder", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_list_versions_under"},
                                  pqxx::params{vaultId, detail::likeUnder(dirPath), detail::clampLimit(limit)});
        return mapRows(res, generationFromRow);
    });
}

std::vector<GenerationRow> Generation::listSnapshotMembers(const int64_t snapshotId, const std::string& afterRelPath,
                                                           const unsigned int limit) {
    return Transactions::read("recovery::Generation::listSnapshotMembers", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_list_snapshot_members"},
                                  pqxx::params{snapshotId, afterRelPath, detail::clampLimit(limit)});
        return mapRows(res, generationFromRow);
    });
}

uint64_t Generation::countSnapshotMembers(const int64_t snapshotId) {
    return Transactions::read("recovery::Generation::countSnapshotMembers", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_count_snapshot_members"}, pqxx::params{snapshotId});
        return detail::u64(res.one_row_ref()[0]);
    });
}

std::optional<int64_t> Generation::remove(pqxx::work& txn, const int64_t id) {
    const auto res = txn.exec(pqxx::prepped{"recovery_generation_delete"}, pqxx::params{id});
    if (res.empty() || res.one_row_ref()[0].is_null()) return std::nullopt;
    const auto freed = stillUnreferenced(txn, {res.one_row_ref()[0].as<int64_t>()});
    return freed.empty() ? std::nullopt : std::make_optional(freed.front());
}

std::optional<int64_t> Generation::remove(const int64_t id) {
    return Transactions::exec("recovery::Generation::remove", [&](pqxx::work& txn) { return remove(txn, id); });
}

std::optional<int64_t> Generation::releaseBlob(pqxx::work& txn, const int64_t id) {
    const auto res = txn.exec(pqxx::prepped{"recovery_generation_release_blob"}, pqxx::params{id});
    if (res.empty() || res.one_row_ref()[0].is_null()) return std::nullopt;
    const auto freed = stillUnreferenced(txn, {res.one_row_ref()[0].as<int64_t>()});
    return freed.empty() ? std::nullopt : std::make_optional(freed.front());
}

std::vector<GenerationRow> Generation::listPending(const uint32_t vaultId, const unsigned int limit) {
    return Transactions::read("recovery::Generation::listPending", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_list_pending"},
                                  pqxx::params{vaultId, detail::clampLimit(limit)});
        return mapRows(res, generationFromRow);
    });
}

std::vector<GenerationRow> Generation::listPendingForFile(const uint32_t fileId) {
    return Transactions::read("recovery::Generation::listPendingForFile", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_list_pending_for_file"}, pqxx::params{fileId});
        return mapRows(res, generationFromRow);
    });
}

bool Generation::markSent(pqxx::work& txn, const int64_t id, const std::string& upstreamVersionId) {
    const auto res = txn.exec(pqxx::prepped{"recovery_generation_mark_sent"}, pqxx::params{id, upstreamVersionId});
    return res.affected_rows() > 0;
}

bool Generation::markSent(const int64_t id, const std::string& upstreamVersionId) {
    return Transactions::exec("recovery::Generation::markSent",
                              [&](pqxx::work& txn) { return markSent(txn, id, upstreamVersionId); });
}

uint64_t Generation::markSkipped(const std::vector<int64_t>& ids) {
    if (ids.empty()) return 0;
    return Transactions::exec("recovery::Generation::markSkipped", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_mark_skipped"}, pqxx::params{detail::idArray(ids)});
        return static_cast<uint64_t>(res.affected_rows());
    });
}

void Generation::recordFailure(const int64_t id, const std::string& error) {
    Transactions::exec("recovery::Generation::recordFailure", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"recovery_generation_record_failure"}, pqxx::params{id, error});
    });
}

BacklogSummary Generation::backlog(const uint32_t vaultId) {
    return Transactions::read("recovery::Generation::backlog", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_backlog"}, pqxx::params{vaultId});
        const auto row = res.one_row_ref();
        return BacklogSummary{.pending = detail::u64(row["pending"]),
                              .pending_bytes = detail::u64(row["pending_bytes"]),
                              .oldest_pending_at = detail::optTime(row["oldest_pending_at"]),
                              .failing = detail::u64(row["failing"]),
                              .last_error = detail::opt<std::string>(row["last_error"])};
    });
}

GenerationUsage Generation::usage(const uint32_t vaultId) {
    return Transactions::read("recovery::Generation::usage", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_usage"}, pqxx::params{vaultId});
        const auto row = res.one_row_ref();
        GenerationUsage u;
        u.snapshots = {.count = detail::u64(row["snapshot_count"]),
                       .stored_bytes = detail::u64(row["snapshot_bytes"]),
                       .plaintext_bytes = detail::u64(row["snapshot_plaintext"])};
        u.versions = {.count = detail::u64(row["version_count"]),
                      .stored_bytes = detail::u64(row["version_bytes"]),
                      .plaintext_bytes = detail::u64(row["version_plaintext"])};
        return u;
    });
}

std::vector<GenerationRow> Generation::listPrunable(const uint32_t vaultId, const RetentionRule& rule, const std::time_t now) {
    if (!rule.keep_last && !rule.max_age_days && !rule.quota_bytes) return {};

    struct Candidate {
        GenerationRow row;
        uint64_t rank{};
        uint64_t blobVersionRefs{};
        bool prunable{};      // not pending, not a snapshot member
    };
    const auto candidates = Transactions::read("recovery::Generation::listPrunable", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_generation_retention_candidates"}, pqxx::params{vaultId});
        return mapRows(res, [](const pqxx::row_ref r) {
            Candidate c{.row = generationFromRow(r), .rank = detail::u64(r["rn"]),
                        .blobVersionRefs = detail::u64(r["blob_version_refs"]), .prunable = false};
            c.prunable = c.row.upstream_state != UpstreamState::Pending && !c.row.snapshot_id;
            return c;
        });
    });

    // Candidates arrive oldest first.
    std::vector<bool> selected(candidates.size(), false);
    const std::optional<std::time_t> cutoff =
        rule.max_age_days ? std::make_optional(now - static_cast<std::time_t>(*rule.max_age_days) * 86400) : std::nullopt;
    for (size_t i = 0; i < candidates.size(); ++i) {
        const auto& c = candidates[i];
        if (!c.prunable) continue;
        if (rule.keep_last && c.rank > *rule.keep_last) selected[i] = true;
        if (cutoff && c.row.created_at < *cutoff) selected[i] = true;
    }

    if (rule.quota_bytes) {
        // Physical bytes of version blobs; a blob is freed once every version row referencing it is pruned.
        std::unordered_map<int64_t, uint64_t> blobBytes, selectedRefs;
        uint64_t total = 0;
        for (const auto& c : candidates)
            if (c.row.blob_id && blobBytes.emplace(*c.row.blob_id, c.row.cipher_bytes.value_or(0)).second)
                total += c.row.cipher_bytes.value_or(0);
        uint64_t freed = 0;
        const auto select = [&](const size_t i) {
            selected[i] = true;
            const auto& c = candidates[i];
            if (!c.row.blob_id) return;
            if (++selectedRefs[*c.row.blob_id] == c.blobVersionRefs) freed += blobBytes[*c.row.blob_id];
        };
        for (size_t i = 0; i < candidates.size(); ++i)
            if (selected[i]) {
                selected[i] = false;
                select(i);
            }
        for (size_t i = 0; i < candidates.size() && total - freed > *rule.quota_bytes; ++i)
            if (candidates[i].prunable && !selected[i]) select(i);
    }

    std::vector<GenerationRow> out;
    for (size_t i = 0; i < candidates.size(); ++i)
        if (selected[i]) out.push_back(candidates[i].row);
    return out;
}

std::vector<int64_t> Generation::removeVersions(pqxx::work& txn, const uint32_t vaultId, const std::vector<int64_t>& ids) {
    if (ids.empty()) return {};
    const auto res = txn.exec(pqxx::prepped{"recovery_generation_delete_versions"},
                              pqxx::params{vaultId, detail::idArray(ids)});
    std::vector<int64_t> blobIds;
    for (const auto row : res)
        if (!row[0].is_null()) blobIds.push_back(row[0].as<int64_t>());
    return stillUnreferenced(txn, std::move(blobIds));
}

std::vector<int64_t> Generation::removeVersions(const uint32_t vaultId, const std::vector<int64_t>& ids) {
    return Transactions::exec("recovery::Generation::removeVersions",
                              [&](pqxx::work& txn) { return removeVersions(txn, vaultId, ids); });
}

}
