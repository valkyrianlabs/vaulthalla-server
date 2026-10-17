#include "db/query/recovery/Usage.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "db/query/recovery/detail/Fields.hpp"

#include <pqxx/result>

#include <array>

namespace vh::db::query::recovery {

namespace {

// Every counter with its column, in the column order of recovery_usage_add ($3..$21).
struct UsageColumn {
    const char* name;
    uint64_t UsageCounters::* member;
};
constexpr std::array<UsageColumn, 19> kUsageColumns{{
    {"list_requests", &UsageCounters::list_requests},
    {"head_requests", &UsageCounters::head_requests},
    {"get_requests", &UsageCounters::get_requests},
    {"put_requests", &UsageCounters::put_requests},
    {"copy_requests", &UsageCounters::copy_requests},
    {"delete_requests", &UsageCounters::delete_requests},
    {"multipart_uploads", &UsageCounters::multipart_uploads},
    {"multipart_parts", &UsageCounters::multipart_parts},
    {"uploaded_bytes", &UsageCounters::uploaded_bytes},
    {"downloaded_bytes", &UsageCounters::downloaded_bytes},
    {"first_put_objects", &UsageCounters::first_put_objects},
    {"first_put_bytes", &UsageCounters::first_put_bytes},
    {"overwrite_objects", &UsageCounters::overwrite_objects},
    {"overwritten_bytes", &UsageCounters::overwritten_bytes},
    {"deleted_objects", &UsageCounters::deleted_objects},
    {"deleted_bytes", &UsageCounters::deleted_bytes},
    {"version_list_requests", &UsageCounters::version_list_requests},
    {"version_restore_requests", &UsageCounters::version_restore_requests},
    {"version_restore_bytes", &UsageCounters::version_restore_bytes},
}};

UsageCounters usageCountersFromRow(const pqxx::row_ref row) {
    UsageCounters c;
    for (const auto& [name, member] : kUsageColumns) c.*member = detail::u64(row[name]);
    return c;
}

UsageDay usageDayFromRow(const pqxx::row_ref row) {
    return {.vault_id = row["vault_id"].as<uint32_t>(), .day = row["day"].as<std::string>(),
            .counters = usageCountersFromRow(row)};
}

void addUsageDelta(pqxx::work& txn, const uint32_t vaultId, const std::string& day, const UsageCounters& delta) {
    if (delta.empty()) return;
    pqxx::params p{vaultId, day};
    for (const auto& column : kUsageColumns) p.append(static_cast<int64_t>(delta.*column.member));
    txn.exec(pqxx::prepped{"recovery_usage_add"}, p);
}

UsageTotals usageTotals(const uint32_t vaultId, const std::optional<std::string>& from, const std::optional<std::string>& to) {
    return Transactions::read("recovery::Usage::totals", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_usage_totals"}, pqxx::params{vaultId, from, to});
        const auto row = res.one_row_ref();
        return UsageTotals{.counters = usageCountersFromRow(row),
                           .days = static_cast<uint32_t>(detail::u64(row["days"])),
                           .first_day = detail::opt<std::string>(row["first_day"]),
                           .last_day = detail::opt<std::string>(row["last_day"])};
    });
}

}

UsageCounters& UsageCounters::operator+=(const UsageCounters& o) {
    for (const auto& column : kUsageColumns) this->*column.member += o.*column.member;
    return *this;
}

bool UsageCounters::empty() const { return *this == UsageCounters{}; }

void Usage::add(const uint32_t vaultId, const std::string& day, const UsageCounters& delta) {
    if (delta.empty()) return;
    Transactions::exec("recovery::Usage::add", [&](pqxx::work& txn) { addUsageDelta(txn, vaultId, day, delta); });
}

void Usage::addMany(const std::vector<UsageDay>& deltas) {
    if (deltas.empty()) return;
    Transactions::exec("recovery::Usage::addMany", [&](pqxx::work& txn) {
        for (const auto& d : deltas) addUsageDelta(txn, d.vault_id, d.day, d.counters);
    });
}

std::vector<UsageDay> Usage::range(const uint32_t vaultId, const std::string& fromDay, const std::string& toDay) {
    return Transactions::read("recovery::Usage::range", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_usage_range"}, pqxx::params{vaultId, fromDay, toDay});
        return mapRows(res, usageDayFromRow);
    });
}

std::vector<UsageDay> Usage::lastDays(const uint32_t vaultId, const unsigned int days) {
    return Transactions::read("recovery::Usage::lastDays", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_usage_last_days"},
                                  pqxx::params{vaultId, static_cast<int>(detail::clampLimit(days, 36500))});
        return mapRows(res, usageDayFromRow);
    });
}

UsageTotals Usage::totals(const uint32_t vaultId, const std::string& fromDay, const std::string& toDay) {
    return usageTotals(vaultId, fromDay, toDay);
}

UsageTotals Usage::totals(const uint32_t vaultId) { return usageTotals(vaultId, std::nullopt, std::nullopt); }

}
