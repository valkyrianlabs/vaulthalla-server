#include "db/query/fs/ChangeLog.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"

#include <pqxx/result>

#include <algorithm>
#include <map>
#include <utility>

namespace vh::db::query::fs {

namespace {

template <typename T>
std::optional<T> optField(const pqxx::row_ref row, const char* column) {
    if (row[column].is_null()) return std::nullopt;
    return row[column].as<T>();
}

Change changeFrom(const pqxx::row_ref row) {
    return {.revision = row["revision"].as<uint64_t>(),
            .kind = row["kind"].as<std::string>(),
            .vault_id = row["vault_id"].as<uint32_t>(),
            .entry_id = row["entry_id"].as<uint32_t>(),
            .parent_id = optField<uint32_t>(row, "parent_id"),
            .entry_type = optField<std::string>(row, "entry_type"),
            .name = row["name"].as<std::string>(),
            .path = row["path"].as<std::string>(),
            .old_parent_id = optField<uint32_t>(row, "old_parent_id"),
            .old_path = optField<std::string>(row, "old_path"),
            .changed_at = row["changed_at"].as<std::time_t>()};
}

}

Sequenced ChangeLog::sequence() {
    Sequenced out;
    std::map<uint32_t, uint64_t> vaults;
    for (;;) {
        // The revision row's lock serializes sequencers; READ COMMITTED gives each statement a snapshot taken after it.
        const auto batch = Transactions::exec("fs::ChangeLog::sequence", [&](pqxx::work& txn) -> uint64_t {
            // Nothing pending (the common case for a poller): no row lock taken, nothing written.
            if (!txn.exec("SELECT EXISTS (SELECT 1 FROM fs_change_log WHERE revision IS NULL)").one_field().as<bool>()) {
                out.revision = txn.exec("SELECT rev FROM fs_change_revision WHERE id = 1").one_field().as<uint64_t>();
                return 0;
            }
            const auto base = txn.exec("SELECT rev FROM fs_change_revision WHERE id = 1 FOR UPDATE").one_field().as<uint64_t>();
            const auto res = txn.exec(
                "WITH pending AS ("
                "  SELECT id, row_number() OVER (ORDER BY id) AS n FROM fs_change_log "
                "  WHERE revision IS NULL ORDER BY id LIMIT $2"
                ") "
                "UPDATE fs_change_log l SET revision = $1 + p.n FROM pending p WHERE l.id = p.id "
                "RETURNING l.revision, l.kind, l.vault_id, l.user_id",
                pqxx::params{base, kSequenceBatch});
            if (!res.empty())
                txn.exec("UPDATE fs_change_revision SET rev = $1 WHERE id = 1",
                         pqxx::params{base + static_cast<uint64_t>(res.size())});
            out.revision = base + static_cast<uint64_t>(res.size());
            for (const auto row : res) {
                const auto revision = row["revision"].as<uint64_t>();
                const auto vaultId = optField<uint32_t>(row, "vault_id");
                if (row["kind"].as<std::string>() == "reset") {
                    out.resets.push_back({.vault_id = vaultId, .user_id = optField<uint32_t>(row, "user_id"),
                                          .revision = revision});
                } else if (vaultId) {
                    auto& newest = vaults[*vaultId];
                    newest = std::max(newest, revision);
                }
            }
            return static_cast<uint64_t>(res.size());
        });
        out.numbered += batch;
        if (batch < kSequenceBatch) break;
    }
    out.vaults.reserve(vaults.size());
    for (const auto& [vaultId, revision] : vaults) out.vaults.push_back({.vault_id = vaultId, .revision = revision});
    std::ranges::sort(out.resets, {}, &Sequenced::Reset::revision);
    return out;
}

uint64_t ChangeLog::revision() {
    return Transactions::exec("fs::ChangeLog::revision", [](pqxx::work& txn) {
        return txn.exec("SELECT rev FROM fs_change_revision WHERE id = 1").one_field().as<uint64_t>();
    });
}

ChangePage ChangeLog::list(const uint32_t vaultId, const uint32_t userId, const uint64_t since, const uint64_t limit) {
    const auto pageSize = std::clamp<uint64_t>(limit, 1, 10'000);
    return Transactions::exec("fs::ChangeLog::list", [&](pqxx::work& txn) {
        ChangePage page;
        // The watermark first: anything numbered after this read is above it, so it is a safe cursor when the page
        // below comes back complete.
        const auto meta = txn.exec("SELECT rev, pruned_through FROM fs_change_revision WHERE id = 1").one_row();
        const auto watermark = meta["rev"].as<uint64_t>();
        page.revision = watermark;
        if (since > watermark || since < meta["pruned_through"].as<uint64_t>()) {
            page.expired = true;
            return page;
        }

        const auto reset = txn.exec(
            "SELECT EXISTS (SELECT 1 FROM fs_change_log WHERE kind = 'reset' AND revision > $1 "
            "  AND (vault_id IS NULL OR vault_id = $2) AND (user_id IS NULL OR user_id = $3))",
            pqxx::params{since, vaultId, userId}).one_field().as<bool>();
        if (reset) {
            page.expired = true;
            return page;
        }

        const auto res = txn.exec(
            "SELECT revision, kind, vault_id, entry_id, parent_id, entry_type, name, path, old_parent_id, old_path, "
            "       EXTRACT(EPOCH FROM changed_at)::bigint AS changed_at "
            "FROM fs_change_log WHERE vault_id = $1 AND revision > $2 AND kind <> 'reset' "
            "ORDER BY revision LIMIT $3",
            pqxx::params{vaultId, since, pageSize + 1});
        page.more = static_cast<uint64_t>(res.size()) > pageSize;
        page.changes.reserve(std::min<std::size_t>(res.size(), pageSize));
        for (const auto row : res) {
            if (page.changes.size() == pageSize) break;
            page.changes.push_back(changeFrom(row));
        }
        if (page.more) page.revision = page.changes.back().revision;
        else if (!page.changes.empty()) page.revision = std::max(watermark, page.changes.back().revision);

        // Retention may have dropped part of (since, ...] after the first check: the rows read above were visible
        // when it committed only if it came later.
        const auto pruned = txn.exec("SELECT pruned_through FROM fs_change_revision WHERE id = 1").one_field().as<uint64_t>();
        if (since < pruned) {
            page = ChangePage{.revision = std::max(watermark, page.revision), .expired = true};
        }
        return page;
    });
}

PruneResult ChangeLog::prune(const std::chrono::seconds retention, const uint64_t maxRevisions) {
    return Transactions::exec("fs::ChangeLog::prune", [&](pqxx::work& txn) {
        const auto meta = txn.exec("SELECT rev, pruned_through FROM fs_change_revision WHERE id = 1 FOR UPDATE").one_row();
        const auto watermark = meta["rev"].as<uint64_t>();
        auto cut = meta["pruned_through"].as<uint64_t>();
        if (watermark > maxRevisions) cut = std::max(cut, watermark - maxRevisions);

        // The oldest change still inside the retention window (revision order is close to time order): everything
        // numbered before it goes; with none, everything numbered does.
        const auto young = txn.exec(
            "SELECT revision FROM fs_change_log WHERE revision IS NOT NULL "
            "  AND changed_at >= NOW() - ($1::bigint * INTERVAL '1 second') ORDER BY revision LIMIT 1",
            pqxx::params{static_cast<int64_t>(retention.count())});
        cut = std::max(cut, young.empty() ? watermark : young.one_field().as<uint64_t>() - 1);

        PruneResult out{.removed = 0, .pruned_through = cut};
        if (cut == meta["pruned_through"].as<uint64_t>()) return out;
        out.removed = static_cast<uint64_t>(
            txn.exec("DELETE FROM fs_change_log WHERE revision IS NOT NULL AND revision <= $1", pqxx::params{cut})
                .affected_rows());
        txn.exec("UPDATE fs_change_revision SET pruned_through = $1 WHERE id = 1", pqxx::params{cut});
        return out;
    });
}

}
