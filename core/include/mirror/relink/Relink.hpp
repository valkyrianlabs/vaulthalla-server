#pragma once

#include "mirror/follow/Follower.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Relink: two linked servers that once mirrored a vault, and both hold it still (the same vault uid, keys and entry
// uids), mirror it again and resolve how their trees drifted (design/peers/mirror.md "As built: relink"; migration 171).
// Either server starts it (ops::mirrors authorizes: super admins, people only); the other answers over the link
// (peer.mirror.relink.*). A vault qualifies when neither server holds it as a live mirror pair: one detached it, the core
// ended the mirror (the copy was orphaned, or the servers were unlinked and linked again), or an old core stopped
// rejoining or forked after a take over.
//
//   compare   both trees by entry uid: what is only on one server, what both hold and one or both changed since the
//             last position both agreed on (each server's base: a take over's fork base, an old core's log back to the
//             fork point, a copy's recorded hashes, or the base kept when its mirror row ended), or that differs where
//             that cannot be told. Hashes only (vh_mirror_tree): no file's contents are read. Kept as an open plan.
//   plan      which server becomes the core, and one choice per drifted entry (this server's, the other's, or both: the
//             future mirror's version becomes a conflict copy beside the core's), with a default for the rest.
//   apply     the future mirror takes its records apart and holds a mirror row (stopped, mirror_relinking), the core
//             takes its own apart and starts the pair in a term above any either used, then the mirror brings each entry
//             whose chosen version is its own onto the core as its own changes (peer.mirror.submit, contents over the
//             sealed lane first), and starts its copy over from the core's tree (mirror::resync): nothing either had is
//             dropped. What leaves a tree is a held change (with its bytes), a conflict copy, or in the core's trash.
//   override  compare, then a plan whose every entry is the chosen server's, applied (--keep this | theirs).
//
// A plan is invalidated (stale) when either tree changed since it was compared. Refused while either side has pending
// changes, a switch running, a start or a copy running, or is deleting the vault.
namespace vh::mirror::relink {

inline constexpr std::size_t kTreePage = 2000;
inline constexpr std::size_t kPreparePage = 2000;
inline constexpr std::chrono::seconds kStepBudget{3};

struct Who {
    uint32_t id{};          // this server's account
    std::string name{};
};

// ---- a person on this server (ops::mirrors authorizes)

// Compares the vault here with the linked server's vault of the same uid and keeps the result as this vault's open plan
// (replacing an open one). Answers the summary (status()).
[[nodiscard]] nlohmann::json compare(uint32_t vaultId, uint32_t peerId, const Who& who,
                                     vh::mirror::follow::Transport& transport);
// The open (or last) relink of the vault: its sides, counts, blockers, plan and what each side gains and loses.
[[nodiscard]] nlohmann::json status(uint32_t vaultId);
// A page of the drifted entries, by path (kind narrows).
[[nodiscard]] nlohmann::json entries(uint32_t vaultId, const std::string& kind, uint64_t offset, uint64_t limit);

struct PlanEdit {
    std::optional<std::string> core{};            // this | theirs
    std::optional<std::string> default_choice{};  // this | theirs | both | "" (the core's)
    struct One {
        std::string uid{};
        std::optional<std::string> choice{};      // nullopt: back to the default
    };
    std::vector<One> set{};
    struct ByKind {
        std::string kind{};                       // a drift kind, or "" for every entry
        std::optional<std::string> choice{};
    };
    std::vector<ByKind> by_kind{};
    bool discard{false};                          // cancels the open plan
};
[[nodiscard]] nlohmann::json plan(uint32_t vaultId, const PlanEdit& edit);

// Carries the open plan out (confirm: the vault's name, typed). Answers status().
[[nodiscard]] nlohmann::json apply(uint32_t vaultId, const std::string& confirm, const Who& who,
                                   vh::mirror::follow::Transport& transport);
// Compare and apply at once, every entry the kept server's: keep is this | theirs.
[[nodiscard]] nlohmann::json override(uint32_t vaultId, uint32_t peerId, const std::string& keep,
                                      const std::string& confirm, const Who& who,
                                      vh::mirror::follow::Transport& transport);

// The follower's pass: the future mirror brings its chosen versions onto the core and starts its copy over; either
// side's relink is done once the copy completed and matched. How many moved on.
std::size_t tick(vh::mirror::follow::Transport& transport);

// ---- the wire (the other server's session; the handlers check it is a linked server)

[[nodiscard]] nlohmann::json serveState(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json serveTree(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json servePrepare(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json serveGo(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json serveAbort(uint32_t callerPeerId, const nlohmann::json& payload);

// Tests: forget the trees served (a page is cut from the tree read at the first page of a comparison).
void resetForTesting();

}
