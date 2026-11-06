#pragma once

#include "ops/Actor.hpp"
#include "vault/LayoutMigration.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

// The bucket layout migration path_v0 -> opaque_v1 (#373, vault/LayoutMigration.hpp) for operators:
// `vh vault migrate-layout`, ws vault.layout.status | vault.layout.migrate | vault.layout.cleanup.
//
// Who: status for super admins and holders of the encryption-key View permission (counts, states, legacy object keys
// and version ids: the bucket's names, no key material); start and cleanup for super admins and holders of the Rotate
// permission (the migration re-seals every object under the vault key, as a rotation re-keys it). Step-up (#359): a
// start is `keys` ("vault.layout.migrate:<id>"), the confirmed cleanup `data.destroy` ("vault.layout.cleanup:<id>"); the
// host CLI is exempt. Both are in the audit trail (vault.layout.migrate, vault.layout.cleanup); the service records the
// cutover, a failure and each cleanup run.
namespace vh::ops::vault_layout {

struct ItemCounts {
    uint64_t pending{}, verified{}, superseded{}, skipped{}, failed{};
};

struct Status {
    unsigned int vault_id{};
    std::string vault_name;
    std::string layout;                                  // transparent | path_v0 | opaque_v1
    std::optional<vault::layout::Row> migration;         // none until an operator starts one
    ItemCounts versions, markers, backlog, current;
    uint64_t legacy_listed{};       // legacy versions, markers and index objects the inventory saw (not deleted yet)
    uint64_t legacy_deleted{};
    // What keeps the migration short of complete: each legacy version that stays, with its reason (skipped while
    // copying, or blocked at cleanup) and, where known, the date it becomes deletable. The first 200.
    std::vector<vault::layout::CleanupEntry> blocked;
    uint64_t blocked_total{};
};

[[nodiscard]] std::vector<Status> status(const Actor& actor, std::optional<unsigned int> vaultId = std::nullopt);
[[nodiscard]] nlohmann::json toJson(const Status& status);

struct StartRequest {
    unsigned int vault_id{};
    bool accept_unpriced{false};
};
// Checks the preconditions now (so a refusal is immediate), records the migration (or restarts a failed one) and
// hands it to the LayoutMigrationService. Conflict when one is already running or done.
[[nodiscard]] Status start(const Actor& actor, const StartRequest& request);

struct CleanupRequest {
    unsigned int vault_id{};
    // Absent: the dry run (a listing matched against the inventory; nothing is deleted). Present: must be the vault's
    // name; the cleanup is confirmed and runs in the background.
    std::optional<std::string> confirm;
};
struct CleanupAnswer {
    bool dry_run{true};
    bool started{false};
    std::optional<std::time_t> cleanup_after;
    vault::layout::CleanupPlan plan;
};
[[nodiscard]] CleanupAnswer cleanup(const Actor& actor, const CleanupRequest& request);
[[nodiscard]] nlohmann::json toJson(const CleanupAnswer& answer);

}
