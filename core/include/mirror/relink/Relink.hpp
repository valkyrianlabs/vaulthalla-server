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
//
// The handshake (two sides agree; trust between two servers about a vault ended with the detach, the ended mirror or the
// unlink, so neither server's word alone reconnects them):
//   request   comparing on X first asks Y (peer.mirror.relink.request). Y records it (requested, for a day) and says
//             nothing of its tree: until a super admin of Y, a person, accepts it (vh mirror pending, mirror.relink.accept)
//             peer.mirror.relink.state answers only whether Y holds a related vault and its status, and tree, prepare and
//             go are refused (mirror_relink_not_accepted). Y tells X its answer (peer.mirror.relink.answer); X asks again
//             when it compares, so a lost answer costs nothing. X may cancel (discard) at any time.
//   outcome   X's apply sends the outcome (peer.mirror.relink.propose: which server becomes the core, the mode, what Y's
//             vault gains and loses, both digests and the plan's hash) and waits ("awaiting the other server's approval").
//             Y's super admin approves it (mirror.relink.approve: the vault's name typed, the keys step-up in the console)
//             or declines. Only then does X carry it out (its apply again, or its follower's pass): Y prepares only the
//             approved plan (the same hash, the same counts, its tree unchanged). A changed plan or tree voids the
//             approval. Each step is audited on both servers; a decline or an expiry changes neither vault. There is no
//             "accept every relink" setting.
namespace vh::mirror::relink {

inline constexpr std::size_t kTreePage = 2000;
// How long a request waits for an answer, and an acceptance holds before the relink is carried out.
inline constexpr std::chrono::hours kRequestHolds{24};
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
// A change to a proposed (or approved) plan withdraws it: the other server's approval is void, ask again. discard ends
// the relink at any step before it is applied, and tells the other server.
[[nodiscard]] nlohmann::json plan(uint32_t vaultId, const PlanEdit& edit, vh::mirror::follow::Transport& transport);

// Proposes the open plan's outcome to the other server, and carries it out once its super admin approved it (confirm:
// the vault's name, typed). Answers status(): phase proposed while the approval waits.
[[nodiscard]] nlohmann::json apply(uint32_t vaultId, const std::string& confirm, const Who& who,
                                   vh::mirror::follow::Transport& transport);
// Compare and apply at once, every entry the kept server's: keep is this | theirs. Each step waits for the other
// server's super admin as compare and apply do: run it again once they answered.
[[nodiscard]] nlohmann::json override(uint32_t vaultId, uint32_t peerId, const std::string& keep,
                                      const std::string& confirm, const Who& who,
                                      vh::mirror::follow::Transport& transport);

// ---- a person on the other server, asked (ops::mirrors authorizes: super admins, people only)

// The linked servers' relinks of this server's vaults waiting for an answer or an approval here (and those accepted or
// approved and not carried out yet): who asks, which vault, what accepting discloses, the outcome in plain words.
[[nodiscard]] nlohmann::json requests();
// The vault's request: accepted (its tree may be served for the comparison), or declined (the relink ends on both).
[[nodiscard]] nlohmann::json accept(uint32_t vaultId, const Who& who, vh::mirror::follow::Transport& transport);
[[nodiscard]] nlohmann::json decline(uint32_t vaultId, const Who& who, vh::mirror::follow::Transport& transport);
// The outcome proposed for the vault, approved (confirm: its name, typed): refused (and void) when its tree changed
// since it was compared.
[[nodiscard]] nlohmann::json approve(uint32_t vaultId, const std::string& confirm, const Who& who,
                                     vh::mirror::follow::Transport& transport);

// The follower's pass: the future mirror brings its chosen versions onto the core and starts its copy over; either
// side's relink is done once the copy completed and matched. How many moved on.
std::size_t tick(vh::mirror::follow::Transport& transport);

// ---- the wire (the other server's session; the handlers check it is a linked server)

[[nodiscard]] nlohmann::json serveRequest(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json serveAnswer(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json servePropose(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json serveCancel(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json serveState(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json serveTree(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json servePrepare(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json serveGo(uint32_t callerPeerId, const nlohmann::json& payload);
[[nodiscard]] nlohmann::json serveAbort(uint32_t callerPeerId, const nlohmann::json& payload);

// Tests: forget the trees served (a page is cut from the tree read at the first page of a comparison).
void resetForTesting();

}
