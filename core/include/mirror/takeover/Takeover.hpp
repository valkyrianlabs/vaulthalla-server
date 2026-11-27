#pragma once

#include "db/query/mirror/Takeover.hpp"
#include "mirror/follow/Follower.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

// Take over: a mirror promotes itself to its vault's core while the core is gone or cannot be reached (design/
// peers/mirror.md "Forced promotion ("take over")", "As built: take over"; migration 168, mirror_takeover and
// mirror_fork_base).
//
// On the mirror, by a person holding "Take over as core" (ops::mirrors::requireTakeover; super admins until piece A's
// admin bit lands), with the vault's name typed and the data-destroy step-up in the console: the mirror records term + 1
// with itself as the core, the last position it applied as the fork point and its tree as the old core last confirmed
// it as the fork base (kept for the old core's return), lifts the gate (its pending changes become ordinary local
// changes; held ones stay listed), audits the promotion and warns that the old core may hold changes this server never
// received. Allowed while the link is down or the core does not answer; while the core answers it is refused
// (mirror_core_reachable: use the planned switch). Also the way out of a planned switch whose core never came back
// (a prepared or preparing switch ends `abandoned`, mirror_taken_over).
//
// The old core's return (merging what it committed after the fork point) is the next piece (peer.mirror.promoted). If
// the old core had decided that switch and tells it after the take over, the two agree already (the same fork point,
// the same next term, nothing committed by the old core since): it is answered as switched and the take over settles.
namespace vh::mirror::takeover {

// Takes over `vaultId` (held here as a mirror). `confirmName` must be the vault's name exactly. The answer: {vault_id,
// term, fork: {term, seq, digest, entries}, fork_base_matches, pending_made_local, held, contents_missing, warning}.
// ops::Refused: mirror_not_mirror, mirror_orphaned, mirror_first_copy, mirror_diverged, mirror_core_reachable,
// mirror_name_mismatch.
[[nodiscard]] nlohmann::json take(uint32_t vaultId, const std::string& confirmName, uint32_t actorId,
                                  const std::string& actorName, vh::mirror::follow::Transport& transport);

// The old core decided `switched` on a switch this server took over from, and tells it now: true when the take over is
// the switch's outcome (the same fork point and digest, the same next term, nothing pending was made local), which then
// settles (switched); told again after that, it answers true again. The caller answers the commit as switched.
[[nodiscard]] bool settledBySwitch(uint32_t vaultId, uint64_t switchTerm, uint64_t switchSeq,
                                   const vh::mirror::Digest& switchDigest);

[[nodiscard]] nlohmann::json toJson(const vh::db::query::mirror::Takeover& t);

// ---- the old core learns (step 4a; design/peers/mirror.md "As built: the old core learns")

// The follower's pass, both servers: the new core tells its old core peer.mirror.promoted on every pass while the link
// is up and the old core has not answered (nothing after an unlink); the old core decides each rejoin whose writers
// ended (following or rejoining). How many it moved on.
std::size_t tick(vh::mirror::follow::Transport& transport);

// peer.mirror.promoted {vault_uid, term, fork: {term, seq, digest, entries}, baseline: {digest, entries}} (new core ->
// old core): this server, the caller's core of the vault in a lower term, stops at once (read-only, rejoining) and
// answers {outcome: pending | following | rejoining | forced, changes?}. This server had taken over the vault too:
// forced, both read-only until an operator picks one. A server not behind in term refuses (mirror_term_stale).
[[nodiscard]] nlohmann::json servePromoted(uint32_t callerPeerId, const nlohmann::json& payload);

}
