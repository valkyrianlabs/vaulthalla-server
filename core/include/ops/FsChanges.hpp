#pragma once

#include "ops/Actor.hpp"
#include "db/query/fs/ChangeLog.hpp"

#include <cstdint>
#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <vector>

// The filesystem change feed (#259): what changed in a vault since a revision, for sync clients (Desktop's File
// Provider) that would otherwise re-list folders. Backed by the journal of migration 115 (db::query::fs::ChangeLog).
//  - Who: whoever may browse the vault (filesystem List on its root, the rule of storage.vault.accessible.list).
//  - What: changes to entries the caller can Lookup (rbac::fs::visibility, the rule of every listing). A rename or
//    move across the visibility line reads as a create (into view) or a delete (out of it); one entirely out of view
//    is left out. The cursor still advances past what was left out.
//  - Expiry: a cursor older than retention, newer than anything handed out (another database), or older than an
//    authorization change that can change what this account sees in the vault answers `expired` with the revision
//    to enumerate at: the client lists the vault again and continues from there.
//  - No `since`: the current revision and no changes (the anchor to take before a first enumeration).
namespace vh::ops::fs_changes {

inline constexpr uint64_t kDefaultLimit = 1000;
inline constexpr uint64_t kMaxLimit = 10'000;

struct ListRequest {
    uint32_t vault_id{};
    std::optional<uint64_t> since;
    uint64_t limit{kDefaultLimit};
};

struct ListResult {
    uint32_t vault_id{};
    uint64_t revision{};
    std::vector<db::query::fs::Change> changes;
    bool more{false};
    bool expired{false};
};

// Whether `actor` may follow `vaultId`'s changes (List on its root). False for a vault without a live engine.
[[nodiscard]] bool canFollow(const Actor& actor, uint32_t vaultId);

// Sequences pending changes first, so the caller reads its own writes. Denied when the actor can't follow the vault,
// NotFound without a live engine, Invalid for a limit outside 1..kMaxLimit.
ListResult list(const Actor& actor, const ListRequest& request);

// `changes` as `actor` may see them (see above), order kept.
[[nodiscard]] std::vector<db::query::fs::Change> visibleTo(const Actor& actor, uint32_t vaultId,
                                                           std::vector<db::query::fs::Change> changes);

nlohmann::json toJson(const db::query::fs::Change& change);
nlohmann::json toJson(const ListResult& result);

}
