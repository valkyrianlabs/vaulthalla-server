#pragma once

#include "db/query/mirror/Switch.hpp"
#include "mirror/follow/Follower.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <string>

// The planned switch of the core role between the two servers of a mirrored vault (design/peers/mirror.md "Planned
// switch", "As built: the planned switch"; migration 168, mirror_switch).
//
// The core coordinates, whichever server was asked; the mirror only ever prepares and is told:
//
//   1. freeze (core): the vault's core row becomes `switching` (every write surface refuses it, reason
//      mirror_switching; the triggers refuse a change that missed the gate), the writers already running are waited
//      for and the sequencer numbers what they logged: (term, seq) and the digest there are final.
//   2. prepare (core -> mirror, peer.mirror.switch.prepare, asked again until ready or the deadline): the mirror's row
//      becomes `switching` too (read-only), the follower catches up to (term, seq); it answers ready once it is there
//      with the core's digest, nothing pending or dirty and every file's contents here. It is then `prepared` and
//      waits for the decision; it never decides on its own.
//   3. decide (core): `switched` (its row becomes the mirror in term + 1, in one transaction that checks nothing moved)
//      or `abandoned` (its row goes live again: the deadline, a refusal, the vault stopped). Durable before anything is
//      told.
//   4. tell (core -> mirror, peer.mirror.switch.commit {outcome}, until answered): switched, the mirror becomes the core
//      in term + 1 and starts its log at (term + 1, 1), and once it answered the old core follows it; abandoned, the
//      mirror goes live again.
//
// So a stop, a timeout or a dropped link at any point ends with both servers as they were (abandoned) or switched, and
// the two servers never both accept changes as the vault's core (invariant 12): the old core stopped at the freeze and
// only the new core's confirmed decision makes it accept. Everything that waits runs from the follower's pass (tick),
// never on a link thread: the wire handlers only change rows. Asked on the mirror, it asks its core
// (peer.mirror.switch.request) to begin, and waits for the decision like the core's caller does.
namespace vh::mirror::switching {

// How long the core waits for its mirror to be ready before it abandons the switch.
inline constexpr std::chrono::seconds kTimeout{30};
// Between two tellings of a decision the mirror did not answer.
inline constexpr std::chrono::seconds kTellEvery{5};

// ---- a person's request (ops::mirrors::switchRole)

// Begins a switch of `vaultId` (this server its core or its mirror; the link up) and waits up to `wait` for its
// outcome. {vault_id, switch_id, outcome: switched | abandoned | running, role, term, reason, detail, told, peer_role}.
// ops::Refused: mirror_not_live, mirror_switch_running, mirror_submissions_queued, mirror_has_remote,
// mirror_pending_changes, mirror_core_unreachable, peer_link_down, mirror_orphaned, and the core's refusals.
//
// The old core keeps a role on the vault only through the new core's own policy for it (nothing is carried across:
// roles are never matched between servers). The mirror's prepare answers that role (`peer_role`); with none (no
// per-vault assignment, no link default, or "no access") the switch is abandoned before the core decides
// (mirror_switch_no_role), unless `acceptNoAccess`: then it goes ahead and the answer and the audit say the old core
// holds no role. The answer carries `peer_role` and `peer_access` (read-only | read-write | none).
[[nodiscard]] nlohmann::json request(uint32_t vaultId, uint32_t actorId, const std::string& actorName,
                                     vh::mirror::follow::Transport& transport, std::chrono::milliseconds wait,
                                     bool acceptNoAccess = false);

// The answer request() gives for a switch of `vaultId` here, as it stands now: the switch, its outcome (switched |
// abandoned | running), this server's role and term for the vault now, and the old core's role on the new core
// (peer_role, peer_access).
[[nodiscard]] nlohmann::json outcome(uint32_t vaultId, const std::string& switchId, const std::string& side);

// What a role document (mirror::start::grantFor's form, null for none) allows, in a word: read-only, read-write or
// none.
[[nodiscard]] std::string accessWord(const nlohmann::json& role);

// The core's freeze, for a person here or the mirror's request (`asked`): the switch, draining. Refusals as above.
[[nodiscard]] vh::db::query::mirror::Switch begin(uint32_t vaultId, const vh::db::query::mirror::SwitchAsked& asked,
                                                  vh::mirror::follow::Transport& transport,
                                                  bool acceptNoAccess = false);

// ---- the follower's pass

// One step of every active switch here (open, or decided and not yet told). How many it moved on.
std::size_t tick(vh::mirror::follow::Transport& transport);
// One step of one switch (tests drive it): drain, prepare, decide, tell, or a mirror's requested switch past its
// deadline. True when it moved.
bool advance(uint64_t switchId, vh::mirror::follow::Transport& transport);

// Whether the follower applies the core's log to `vaultId` while it is switching here (the mirror's switch is
// preparing).
[[nodiscard]] bool following(uint32_t vaultId);

// ---- the wire (peer sessions only; the caller must be the vault's linked server with the other role, else not_found)

// peer.mirror.switch.request {vault_uid, by: {id, name}, accept_no_access?} (mirror -> core): a super admin of the mirror asked; the core
// begins (begin) and answers {switch_id, term} at once.
[[nodiscard]] nlohmann::json serveRequest(uint32_t callerPeerId, const nlohmann::json& payload);
// peer.mirror.switch.prepare {vault_uid, switch_id, term, seq, digest, entries, by?} (core -> mirror): {ready, at:
// {term, seq}, digest, entries, waiting?, peer_role}. peer_role: the role the core will hold on the vault here once
// this server is its core (null: none). Refusals end the switch on the core.
[[nodiscard]] nlohmann::json servePrepare(uint32_t callerPeerId, const nlohmann::json& payload);
// peer.mirror.switch.commit {vault_uid, switch_id, outcome: switched | abandoned, reason?} (core -> mirror): the
// decision. {outcome, term, peer_role}. Asked again, it answers the same.
[[nodiscard]] nlohmann::json serveCommit(uint32_t callerPeerId, const nlohmann::json& payload);

// ---- shown

[[nodiscard]] nlohmann::json toJson(const vh::db::query::mirror::Switch& sw);

// Tests: the deadline new switches get (0 restores kTimeout), and no pause between tellings.
void setTimeoutForTesting(std::chrono::seconds timeout);
[[nodiscard]] std::chrono::seconds timeout();
void setTellPauseForTesting(bool none);

}
