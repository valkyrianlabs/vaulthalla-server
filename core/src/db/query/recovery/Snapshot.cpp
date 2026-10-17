#include "db/query/recovery/Snapshot.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "db/query/recovery/detail/Fields.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/result>
#include <pqxx/subtransaction>

namespace vh::db::query::recovery {

namespace {

SnapshotRow snapshotFromRow(const pqxx::row_ref row) {
    SnapshotRow s;
    s.id = row["id"].as<int64_t>();
    s.vault_id = row["vault_id"].as<uint32_t>();
    s.name = detail::opt<std::string>(row["name"]);
    s.root_path = row["root_path"].as<std::string>();
    s.root_type = row["root_type"].as<std::string>() == "directory" ? vh::recovery::PointKind::Directory
                                                                     : vh::recovery::PointKind::File;
    s.root_entry_id = detail::opt<uint32_t>(row["root_entry_id"]);
    s.state = row["state"].as<std::string>();
    s.file_count = detail::u64(row["file_count"]);
    s.directory_count = detail::u64(row["directory_count"]);
    s.plaintext_bytes = detail::u64(row["plaintext_bytes"]);
    if (!row["empty_directories"].is_null()) {
        const auto dirs = nlohmann::json::parse(row["empty_directories"].as<std::string>(), nullptr, false);
        if (dirs.is_array())
            for (const auto& d : dirs)
                if (d.is_string()) s.empty_directories.push_back(d.get<std::string>());
    }
    s.skipped_json = row["skipped"].is_null() ? "[]" : row["skipped"].as<std::string>();
    s.created_at = detail::timeOr0(row["created_at"]);
    s.completed_at = detail::optTime(row["completed_at"]);
    s.created_by = detail::opt<uint32_t>(row["created_by"]);
    s.created_by_name = detail::opt<std::string>(row["created_by_name"]);
    s.error = detail::opt<std::string>(row["error"]);
    return s;
}

std::optional<SnapshotRow> firstSnapshot(const pqxx::result& res) {
    if (res.empty()) return std::nullopt;
    return snapshotFromRow(res.one_row_ref());
}

std::string snapshotSkippedJson(const std::string& raw) {
    const auto parsed = nlohmann::json::parse(raw, nullptr, false);
    return parsed.is_array() ? parsed.dump() : std::string("[]");
}

}

int64_t Snapshot::create(pqxx::work& txn, const NewSnapshot& s) {
    // A savepoint keeps the caller's transaction usable when the name is taken.
    pqxx::subtransaction sub(txn, "recovery_snapshot_create");
    try {
        const auto res = sub.exec(pqxx::prepped{"recovery_snapshot_insert"},
                                  pqxx::params{s.vault_id, s.name, s.root_path, vh::recovery::to_string(s.root_type),
                                               s.root_entry_id, s.created_by, s.created_by_name});
        const auto id = res.one_row_ref()["id"].as<int64_t>();
        sub.commit();
        return id;
    } catch (const pqxx::unique_violation&) {
        sub.abort();
        throw SnapshotNameTaken("a snapshot named '" + s.name.value_or("") + "' already exists in this vault");
    }
}

int64_t Snapshot::create(const NewSnapshot& s) {
    return Transactions::exec("recovery::Snapshot::create", [&](pqxx::work& txn) { return create(txn, s); });
}

bool Snapshot::finish(pqxx::work& txn, const int64_t id, const SnapshotTotals& totals) {
    const auto res = txn.exec(pqxx::prepped{"recovery_snapshot_finish"},
                              pqxx::params{id, static_cast<int64_t>(totals.file_count),
                                           static_cast<int64_t>(totals.directory_count),
                                           static_cast<int64_t>(totals.plaintext_bytes),
                                           nlohmann::json(totals.empty_directories).dump(),
                                           snapshotSkippedJson(totals.skipped_json)});
    return res.affected_rows() > 0;
}

bool Snapshot::finish(const int64_t id, const SnapshotTotals& totals) {
    return Transactions::exec("recovery::Snapshot::finish", [&](pqxx::work& txn) { return finish(txn, id, totals); });
}

bool Snapshot::fail(const int64_t id, const std::string& error) {
    return Transactions::exec("recovery::Snapshot::fail", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_snapshot_fail"}, pqxx::params{id, error});
        return res.affected_rows() > 0;
    });
}

std::optional<SnapshotRow> Snapshot::get(pqxx::transaction_base& txn, const int64_t id) {
    const auto res = txn.exec(pqxx::prepped{"recovery_snapshot_get"}, pqxx::params{id});
    return firstSnapshot(res);
}

std::optional<SnapshotRow> Snapshot::get(const int64_t id) {
    return Transactions::read("recovery::Snapshot::get", [&](pqxx::transaction_base& txn) { return get(txn, id); });
}

std::optional<SnapshotRow> Snapshot::getByName(const uint32_t vaultId, const std::string& name) {
    return Transactions::read("recovery::Snapshot::getByName", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_snapshot_get_by_name"}, pqxx::params{vaultId, name});
        return firstSnapshot(res);
    });
}

std::vector<SnapshotRow> Snapshot::listByVault(const uint32_t vaultId, const unsigned int limit, const int64_t beforeId) {
    return Transactions::read("recovery::Snapshot::listByVault", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_snapshot_list_by_vault"},
                                  pqxx::params{vaultId, detail::clampLimit(limit), beforeId});
        return mapRows(res, snapshotFromRow);
    });
}

std::vector<SnapshotRow> Snapshot::listUnderPath(const uint32_t vaultId, const std::string& path, const unsigned int limit) {
    return Transactions::read("recovery::Snapshot::listUnderPath", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_snapshot_list_under_path"},
                                  pqxx::params{vaultId, path, detail::likeUnder(path), detail::clampLimit(limit)});
        return mapRows(res, snapshotFromRow);
    });
}

std::vector<SnapshotRow> Snapshot::listContainingPath(const uint32_t vaultId, const std::string& path,
                                                      const unsigned int limit) {
    return Transactions::read("recovery::Snapshot::listContainingPath", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_snapshot_list_containing_path"},
                                  pqxx::params{vaultId, path, detail::likeUnder(path), detail::clampLimit(limit)});
        return mapRows(res, snapshotFromRow);
    });
}

bool Snapshot::markDeleting(const int64_t id) {
    return Transactions::exec("recovery::Snapshot::markDeleting", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_snapshot_mark_deleting"}, pqxx::params{id});
        return res.affected_rows() > 0;
    });
}

std::vector<int64_t> Snapshot::remove(pqxx::work& txn, const int64_t id) {
    const auto members = txn.exec(pqxx::prepped{"recovery_snapshot_member_blobs"}, pqxx::params{id});
    const auto blobIds = mapRows(members, [](const pqxx::row_ref r) { return r[0].as<int64_t>(); });
    txn.exec(pqxx::prepped{"recovery_snapshot_delete"}, pqxx::params{id});
    if (blobIds.empty()) return {};
    const auto unreferenced = txn.exec(pqxx::prepped{"recovery_blob_still_unreferenced"},
                                       pqxx::params{detail::idArray(blobIds)});
    return mapRows(unreferenced, [](const pqxx::row_ref r) { return r[0].as<int64_t>(); });
}

std::vector<int64_t> Snapshot::remove(const int64_t id) {
    return Transactions::exec("recovery::Snapshot::remove", [&](pqxx::work& txn) { return remove(txn, id); });
}

std::vector<SnapshotRow> Snapshot::listStaleCreating(const int64_t minAgeSeconds) {
    return Transactions::read("recovery::Snapshot::listStaleCreating", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_snapshot_list_stale_creating"},
                                  pqxx::params{static_cast<double>(minAgeSeconds)});
        return mapRows(res, snapshotFromRow);
    });
}

}
