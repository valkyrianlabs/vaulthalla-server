#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// recovery_plan (migration 111): a stored restore plan. JSON columns travel as JSON text (the ops layer owns their
// shape). States: planned → running → done | partial | failed; planned → expired (past expires_at). A running or
// partial plan can be resumed (running again).
namespace vh::db::query::recovery {

struct PlanRow {
    int64_t id{};
    uint32_t vault_id{};
    std::string token{};
    std::string source_json{"{}"};
    std::optional<std::string> destination{};
    std::string items_json{"[]"};
    std::string summary_json{"{}"};
    std::string state{"planned"};
    std::optional<std::string> result_json{};
    std::time_t created_at{};
    std::time_t expires_at{};
    std::optional<std::time_t> started_at{};
    std::optional<std::time_t> completed_at{};
    std::optional<uint32_t> created_by{};
};

class Plan {
public:
    // Inserts the plan (state planned; id, state, result, created/started/completed ignored). Returns its id.
    [[nodiscard]] static int64_t insert(const PlanRow& row);
    [[nodiscard]] static std::optional<PlanRow> get(int64_t id);

    // planned (not expired) | running | partial → running; started_at set on the first start. False otherwise (expired,
    // done, failed, or another state): the caller refuses.
    static bool start(int64_t id, std::time_t now);
    // running → done | partial | failed with the result and completed_at = now. False when it wasn't running.
    static bool finish(int64_t id, const std::string& state, const std::string& resultJson);
    // Progress while running (resume needs to know which items finished).
    static void saveResult(int64_t id, const std::string& resultJson);
    // Rewrites the items (e.g. per-item outcome) while running or planned.
    static void saveItems(int64_t id, const std::string& itemsJson);

    // planned plans past expires_at → expired. Returns how many.
    static uint64_t expire(std::time_t now);
    // Deletes finished or expired plans completed/created before `before`. Returns how many.
    static uint64_t purgeOlderThan(std::time_t before);

    [[nodiscard]] static std::vector<PlanRow> listByVault(uint32_t vaultId, unsigned int limit);
};

}
