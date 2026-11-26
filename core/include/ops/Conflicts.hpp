#pragma once

#include "ops/Actor.hpp"
#include "db/query/sync/Conflict.hpp"
#include "preview/Plan.hpp"
#include "storage/Fwd.hpp"
#include "sync/ConflictResolver.hpp"

#include <cstdint>
#include <nlohmann/json_fwd.hpp>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Sync conflicts recorded under the `ask` remote conflict policy (#187), shared by `vh sync resolve` and the ws
// sync.conflicts.* commands.
//  - Who: vault permission vault.sync.action.resolve_conflicts: the owner's self scope and admins' vault globals
//    (the vault resolver), or a vault role on that vault (the account's or a group's). Listing and counts only ever
//    include vaults where the actor holds it.
//  - Resolving a conflict also needs filesystem Overwrite on the file, through filesystem RBAC; previewing a side
//    needs filesystem Read.
//  - A batch is per item: each id gets its own verdict and one failure never stops the rest.
namespace vh::ops::conflicts {

using ConflictRecord = db::query::sync::ConflictRecord;
using Decision = vh::sync::ConflictDecision;

struct ConflictView {
    ConflictRecord record;
    std::string vault_name;
    bool can_overwrite{false};
    preview::PreviewPlan preview;
};

struct VaultCount {
    uint32_t vault_id{};
    std::string vault_name;
    uint64_t count{};
};

struct Summary {
    uint64_t total{};
    std::vector<VaultCount> vaults;   // vaults with open conflicts the actor can resolve, by name
};

struct ItemResult {
    uint32_t conflict_id{};
    bool ok{false};
    // resolved | denied | not_found | conflict | invalid | unavailable | error
    std::string status;
    std::optional<std::string> message;
};

struct ResolveResult {
    Decision decision{Decision::KeepLocal};
    std::vector<ItemResult> results;
    uint64_t resolved{};
    uint64_t failed{};
};

constexpr std::size_t kMaxResolveBatch = 500;

// "keep_local" | "keep_remote" (also "local" / "remote"), else Invalid.
[[nodiscard]] Decision parseDecision(const std::string& value);

[[nodiscard]] bool canResolveIn(const Actor& actor, uint32_t vaultId);

[[nodiscard]] Summary summary(const Actor& actor);
// Open conflicts, newest first. A named vault the actor cannot resolve in is Denied (NotFound when it doesn't exist).
[[nodiscard]] std::vector<ConflictView> list(const Actor& actor, std::optional<uint32_t> vaultId = std::nullopt);
// Per-item verdicts. Invalid when ids is empty or longer than kMaxResolveBatch.
[[nodiscard]] ResolveResult resolve(const Actor& actor, Decision decision, const std::vector<uint32_t>& ids);

// The HTTP preview lane (/download/conflict): the open conflict, its engine and file, authorized for resolve
// conflicts + filesystem Read. Throws Denied, NotFound, or Conflict when the conflict is no longer open.
struct PreviewTarget {
    ConflictRecord record;
    std::shared_ptr<storage::CloudEngine> engine;
    std::shared_ptr<vh::fs::model::File> file;
};
[[nodiscard]] PreviewTarget previewTarget(const Actor& actor, uint32_t conflictId);

// The wire shapes both surfaces print (ws payloads, `vh sync resolve --json`); see WebSocketCommandMap.
void to_json(nlohmann::json& j, const ConflictView& view);
void to_json(nlohmann::json& j, const Summary& summary);
void to_json(nlohmann::json& j, const ResolveResult& result);

}
