#include "db/query/mirror/Copy.hpp"

#include "db/Transactions.hpp"
#include "ops/Error.hpp"

#include <pqxx/pqxx>

#include <algorithm>
#include <cstddef>
#include <string>

namespace vh::db::query::mirror {

namespace mirror_copy_query_detail {

constexpr auto kCopyColumns =
    "id, source_vault_id, vault_id, name, owner_id, state, entries_total, entries_done, bytes_total, bytes_done, "
    "skipped::text AS skipped, error, requested_by, cancelled_by, cancel_requested, attempts, "
    "EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at, "
    "EXTRACT(EPOCH FROM finished_at)::BIGINT AS finished_at";

std::vector<CopySkipped> skippedFrom(const std::string& text) {
    std::vector<CopySkipped> out;
    const auto j = nlohmann::json::parse(text, nullptr, false);
    if (!j.is_array()) return out;
    for (const auto& s : j)
        out.push_back({.path = s.value("path", std::string{}), .size_bytes = s.value("size_bytes", uint64_t{0}),
                       .reason = s.value("reason", std::string{})});
    return out;
}

CopyJob jobFrom(const pqxx::row_ref row) {
    CopyJob c;
    c.id = row["id"].as<uint64_t>();
    if (!row["source_vault_id"].is_null()) c.source_vault_id = row["source_vault_id"].as<uint32_t>();
    if (!row["vault_id"].is_null()) c.vault_id = row["vault_id"].as<uint32_t>();
    c.name = row["name"].as<std::string>();
    c.owner_id = row["owner_id"].as<uint32_t>();
    c.state = row["state"].as<std::string>();
    c.entries_total = row["entries_total"].as<uint64_t>();
    c.entries_done = row["entries_done"].as<uint64_t>();
    c.bytes_total = row["bytes_total"].as<uint64_t>();
    c.bytes_done = row["bytes_done"].as<uint64_t>();
    c.skipped = skippedFrom(row["skipped"].as<std::string>());
    if (!row["error"].is_null()) c.error = row["error"].as<std::string>();
    if (!row["requested_by"].is_null()) c.requested_by = row["requested_by"].as<uint32_t>();
    if (!row["cancelled_by"].is_null()) c.cancelled_by = row["cancelled_by"].as<uint32_t>();
    c.cancel_requested = row["cancel_requested"].as<bool>();
    c.attempts = row["attempts"].as<uint32_t>();
    c.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    c.updated_at = static_cast<std::time_t>(row["updated_at"].as<int64_t>());
    if (!row["finished_at"].is_null()) c.finished_at = static_cast<std::time_t>(row["finished_at"].as<int64_t>());
    return c;
}

std::optional<CopyJob> oneJob(const char* what, const std::string& where, const pqxx::params& p) {
    return Transactions::exec(what, [&](pqxx::work& txn) -> std::optional<CopyJob> {
        const auto r = txn.exec(std::string("SELECT ") + kCopyColumns + " FROM mirror_copy WHERE " + where, p);
        if (r.empty()) return std::nullopt;
        return jobFrom(r[0]);
    });
}

std::string idArray(const std::vector<uint32_t>& ids) {
    std::string out = "{";
    for (std::size_t i = 0; i < ids.size(); ++i) {
        if (i) out.push_back(',');
        out += std::to_string(ids[i]);
    }
    out.push_back('}');
    return out;
}

}

nlohmann::json toJson(const CopySkipped& s) {
    return {{"path", s.path}, {"size_bytes", s.size_bytes}, {"reason", s.reason}};
}

nlohmann::json toJson(const std::vector<CopySkipped>& s) {
    auto out = nlohmann::json::array();
    for (const auto& one : s) out.push_back(toJson(one));
    return out;
}

CopyJob MirrorCopies::insert(const NewCopy& in) {
    using namespace mirror_copy_query_detail;
    return Transactions::exec("mirror::MirrorCopies::insert", [&](pqxx::work& txn) {
        // The vault the copy reads, locked first: two people starting a copy of it at once meet here.
        txn.exec("SELECT id FROM vault WHERE id = $1 FOR UPDATE", pqxx::params{in.source_vault_id});
        if (!txn.exec("SELECT 1 FROM mirror_copy WHERE source_vault_id = $1 AND state = 'running'",
                      pqxx::params{in.source_vault_id}).empty())
            throw ops::Conflict("a copy of this vault is being written already (vh mirror detach " +
                                std::to_string(in.source_vault_id) + " --copy --status)");
        if (!txn.exec("SELECT 1 FROM mirror_copy WHERE owner_id = $1 AND name = $2 AND state = 'running'",
                      pqxx::params{in.owner_id, in.name}).empty())
            throw ops::Conflict("a copy named '" + in.name + "' is being written for this owner already");
        const auto r = txn.exec(std::string("INSERT INTO mirror_copy (source_vault_id, name, owner_id, requested_by, "
                                            "  entries_total, bytes_total, skipped) VALUES ($1, $2, $3, $4, $5, $6, "
                                            "  $7::jsonb) RETURNING ") + kCopyColumns,
                                pqxx::params{in.source_vault_id, in.name, in.owner_id, in.requested_by,
                                             static_cast<int64_t>(in.entries_total),
                                             static_cast<int64_t>(in.bytes_total), toJson(in.skipped).dump()});
        return jobFrom(r[0]);
    });
}

std::optional<CopyJob> MirrorCopies::get(const uint64_t id) {
    return mirror_copy_query_detail::oneJob("mirror::MirrorCopies::get", "id = $1",
                                            pqxx::params{static_cast<int64_t>(id)});
}

std::optional<CopyJob> MirrorCopies::latestFor(const uint32_t sourceVaultId) {
    return mirror_copy_query_detail::oneJob("mirror::MirrorCopies::latestFor",
                                            "source_vault_id = $1 ORDER BY id DESC LIMIT 1", pqxx::params{sourceVaultId});
}

std::vector<CopyJob> MirrorCopies::running() {
    using namespace mirror_copy_query_detail;
    return Transactions::exec("mirror::MirrorCopies::running", [&](pqxx::work& txn) {
        std::vector<CopyJob> out;
        for (const auto row : txn.exec(std::string("SELECT ") + kCopyColumns +
                                       " FROM mirror_copy WHERE state = 'running' ORDER BY id"))
            out.push_back(jobFrom(row));
        return out;
    });
}

std::vector<uint32_t> MirrorCopies::writingTargets() {
    return Transactions::exec("mirror::MirrorCopies::writingTargets", [&](pqxx::work& txn) {
        std::vector<uint32_t> out;
        for (const auto row : txn.exec("SELECT vault_id FROM mirror_copy WHERE state = 'running' AND vault_id IS NOT NULL "
                                       "ORDER BY vault_id"))
            out.push_back(row[0].as<uint32_t>());
        return out;
    });
}

bool MirrorCopies::nameReserved(const std::string& name, const uint32_t ownerId) {
    return Transactions::exec("mirror::MirrorCopies::nameReserved", [&](pqxx::work& txn) {
        return !txn.exec("SELECT 1 FROM mirror_copy WHERE owner_id = $1 AND name = $2 AND state = 'running'",
                         pqxx::params{ownerId, name}).empty();
    });
}

bool MirrorCopies::begin(const uint64_t id, const uint64_t entriesTotal, const uint64_t bytesTotal,
                         const std::vector<CopySkipped>& skipped) {
    return Transactions::exec("mirror::MirrorCopies::begin", [&](pqxx::work& txn) {
        return !txn.exec("UPDATE mirror_copy SET vault_id = NULL, entries_done = 0, bytes_done = 0, entries_total = $2, "
                         "  bytes_total = $3, skipped = $4::jsonb, attempts = attempts + 1, "
                         "  updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND state = 'running' RETURNING id",
                         pqxx::params{static_cast<int64_t>(id), static_cast<int64_t>(entriesTotal),
                                      static_cast<int64_t>(bytesTotal), toJson(skipped).dump()})
                    .empty();
    });
}

bool MirrorCopies::setTarget(const uint64_t id, const uint32_t vaultId) {
    return Transactions::exec("mirror::MirrorCopies::setTarget", [&](pqxx::work& txn) {
        return !txn.exec("UPDATE mirror_copy SET vault_id = $2, updated_at = CURRENT_TIMESTAMP "
                         "WHERE id = $1 AND state = 'running' RETURNING id",
                         pqxx::params{static_cast<int64_t>(id), vaultId})
                    .empty();
    });
}

void MirrorCopies::progress(const uint64_t id, const uint64_t entriesDone, const uint64_t bytesDone,
                            const std::vector<CopySkipped>& skipped) {
    Transactions::exec("mirror::MirrorCopies::progress", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_copy SET entries_done = $2, bytes_done = $3, skipped = $4::jsonb, "
                 "  updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND state = 'running'",
                 pqxx::params{static_cast<int64_t>(id), static_cast<int64_t>(entriesDone),
                              static_cast<int64_t>(bytesDone), toJson(skipped).dump()});
    });
}

bool MirrorCopies::requestCancel(const uint64_t id, const std::optional<uint32_t> by) {
    return Transactions::exec("mirror::MirrorCopies::requestCancel", [&](pqxx::work& txn) {
        return !txn.exec("UPDATE mirror_copy SET cancel_requested = TRUE, cancelled_by = $2, "
                         "  updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND state = 'running' RETURNING id",
                         pqxx::params{static_cast<int64_t>(id), by})
                    .empty();
    });
}

bool MirrorCopies::finish(const uint64_t id, const std::string& state, const std::optional<std::string>& error) {
    const auto text = error ? std::optional<std::string>(error->substr(0, 2000)) : std::nullopt;
    return Transactions::exec("mirror::MirrorCopies::finish", [&](pqxx::work& txn) {
        return !txn.exec("UPDATE mirror_copy SET state = $2, error = $3, finished_at = CURRENT_TIMESTAMP, "
                         "  updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND state = 'running' RETURNING id",
                         pqxx::params{static_cast<int64_t>(id), state, text})
                    .empty();
    });
}

std::vector<CopyEntry> MirrorCopies::entries(const uint32_t vaultId) {
    return Transactions::exec("mirror::MirrorCopies::entries", [&](pqxx::work& txn) {
        std::vector<CopyEntry> out;
        for (const auto row : txn.exec(
                 "SELECT e.id, CASE WHEN d.fs_entry_id IS NOT NULL THEN 'directory' WHEN f.fs_entry_id IS NOT NULL "
                 "  THEN 'file' ELSE 'symlink' END, e.path, COALESCE(e.mode, 0), COALESCE(f.size_bytes, 0), s.target "
                 "FROM fs_entry e LEFT JOIN directories d ON d.fs_entry_id = e.id "
                 "  LEFT JOIN files f ON f.fs_entry_id = e.id LEFT JOIN symlinks s ON s.fs_entry_id = e.id "
                 "WHERE e.vault_id = $1 AND (d.fs_entry_id IS NOT NULL OR f.fs_entry_id IS NOT NULL "
                 "  OR s.fs_entry_id IS NOT NULL)",
                 pqxx::params{vaultId})) {
            CopyEntry c;
            c.id = row[0].as<uint32_t>();
            c.kind = row[1].as<std::string>();
            c.path = row[2].as<std::string>();
            c.mode = row[3].as<uint32_t>();
            c.size_bytes = row[4].as<uint64_t>();
            if (!row[5].is_null()) c.target = row[5].as<std::string>();
            out.push_back(std::move(c));
        }
        std::ranges::sort(out, [](const CopyEntry& a, const CopyEntry& b) { return a.path < b.path; });
        return out;
    });
}

void MirrorCopies::copyAttributes(const std::vector<std::pair<uint32_t, uint32_t>>& sourceToNew,
                                  const std::optional<uint32_t> actorId) {
    using namespace mirror_copy_query_detail;
    if (sourceToNew.empty()) return;
    std::vector<uint32_t> from, to;
    from.reserve(sourceToNew.size());
    to.reserve(sourceToNew.size());
    for (const auto& [s, n] : sourceToNew) {
        from.push_back(s);
        to.push_back(n);
    }
    Transactions::exec("mirror::MirrorCopies::copyAttributes", [&](pqxx::work& txn) {
        txn.exec("SELECT set_config('vh.keep_mtime', 'on', true)");
        if (actorId) txn.exec("SELECT set_config('vh.actor', $1, true)", pqxx::params{std::to_string(*actorId)});
        txn.exec("UPDATE fs_entry t SET mode = s.mode, updated_at = s.updated_at "
                 "FROM unnest($1::integer[], $2::integer[]) AS m(src, dst) JOIN fs_entry s ON s.id = m.src "
                 "WHERE t.id = m.dst",
                 pqxx::params{idArray(from), idArray(to)});
    });
}

}
