#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// vault_upstream_usage_daily (migration 111): local per-vault operational counters (UTC days) that recovery cost
// estimates are computed from. Nothing here is ever sent anywhere.
namespace vh::db::query::recovery {

struct UsageCounters {
    uint64_t list_requests{}, head_requests{}, get_requests{}, put_requests{}, copy_requests{}, delete_requests{};
    uint64_t multipart_uploads{}, multipart_parts{};
    uint64_t uploaded_bytes{}, downloaded_bytes{};
    uint64_t first_put_objects{}, first_put_bytes{};
    uint64_t overwrite_objects{}, overwritten_bytes{};
    uint64_t deleted_objects{}, deleted_bytes{};
    uint64_t version_list_requests{}, version_restore_requests{}, version_restore_bytes{};

    UsageCounters& operator+=(const UsageCounters& o);
    [[nodiscard]] bool empty() const;
    bool operator==(const UsageCounters&) const = default;
};

struct UsageDay {
    uint32_t vault_id{};
    std::string day{};                               // YYYY-MM-DD (UTC)
    UsageCounters counters{};
};

struct UsageTotals {
    UsageCounters counters{};
    uint32_t days{};                               // days with a row in the range
    std::optional<std::string> first_day{}, last_day{};
};

class Usage {
public:
    // Adds `delta` to the (vault, day) row, creating it. An empty delta writes nothing.
    static void add(uint32_t vaultId, const std::string& day, const UsageCounters& delta);
    // Several (vault, day) deltas in one transaction (the 60 s flush).
    static void addMany(const std::vector<UsageDay>& deltas);

    // Rows for days in [fromDay, toDay] (inclusive, YYYY-MM-DD), oldest first.
    [[nodiscard]] static std::vector<UsageDay> range(uint32_t vaultId, const std::string& fromDay, const std::string& toDay);
    // The last `days` UTC days up to and including today, oldest first (days without a row are absent).
    [[nodiscard]] static std::vector<UsageDay> lastDays(uint32_t vaultId, unsigned int days);
    [[nodiscard]] static UsageTotals totals(uint32_t vaultId, const std::string& fromDay, const std::string& toDay);
    // Every row of the vault (first measurement day = earliest).
    [[nodiscard]] static UsageTotals totals(uint32_t vaultId);
};

}
