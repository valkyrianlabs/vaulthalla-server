#pragma once

#include "recovery/Model.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// vault_recovery_policy (migration 111): a vault's recovery preference, snapshot quota, versioning cost alert and the
// opt-in local versioning harness. No row = defaults (mode off, local versioning off, no quotas).
namespace vh::db::query::recovery {

struct PolicyRow {
    uint32_t vault_id{};
    bool stored{false};                              // false: no row, these are the defaults
    vh::recovery::Mode mode{vh::recovery::Mode::Off};
    std::optional<uint64_t> snapshot_quota_bytes{};    // nullopt = no snapshot quota
    std::optional<std::string> cost_alert_monthly{};   // decimal text (NUMERIC(20,8)), never a float
    std::optional<std::string> cost_alert_currency{};
    vh::recovery::LocalVersioningPolicy local_versioning{};
    std::optional<std::time_t> updated_at{};
    std::optional<uint32_t> updated_by{};
};

class Policy {
public:
    // The vault's policy, or the defaults (stored=false) when it has none.
    [[nodiscard]] static PolicyRow get(uint32_t vaultId);

    // Writes every field of `row` (insert or replace; updated_at = now, updated_by = row.updated_by). Read with get(),
    // change, upsert. The table's CHECKs apply (keep_last 1..10000, max_age_days 1..36500, quotas >= 0): a violation
    // throws pqxx::check_violation.
    static void upsert(const PolicyRow& row);

    // Vaults with local versioning enabled (retention and backlog services walk these).
    [[nodiscard]] static std::vector<uint32_t> listLocalVersioningVaults();
};

}
