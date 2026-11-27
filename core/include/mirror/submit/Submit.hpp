#pragma once

#include "mirror/follow/Follower.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <string>

// Submitting the mirror's changes to the core, and the core executing them (design/peers/mirror.md "A change made on the
// mirror" steps 3 to 5, "When the core refuses", "As built: a change made on the mirror").
//
// peer.mirror.submit {vault_uid, request_id, person: {node, id}, at: {term, seq}, op, entry_uid, args,
// base_generation?}: the mirror's pending change, every entry named by uid. Peer sessions only (the peer wire set),
// refused while peers.experimental is off; the caller must be the vault's mirror and this server its core (else
// not_found, the sealed lane's answer). The person must be one of the caller's own accounts (its node id). The core
// answers at once and never runs the change on the link's thread: a new request is queued (status queued) and executed
// on a pool thread, one vault's in the order received; asked again with the same request id it answers what it did the
// first time (queued, running, executed with the number of groups it logged, refused with the code), never executing
// twice.
//
// Executing: through ops::fs as the person (the remote account (mirror's node id, id there), created the first time it
// is named), inside an ops::fs::PeerSubmission: the linked server's vault role is the ceiling and, with no per-account
// rules yet, the decision; then the op's own checks (a name already taken is a conflict, never replaced: ops::fs
// refuses it; a missing entry or folder not_found). The created entry takes the uid the mirror chose. Every transaction
// it begins carries vh.mirror_origin (the request id, which the log records in `origin`) and vh.actor (the person), so
// the log's rows name the person and the request. The audit event names the person, the peer and the request.
//
// The mirror (submitPending, from the follower's visit of the vault, never on a FUSE worker or the link's thread):
// its pending changes in order, one at a time: submitted, asked again (bounded) until the core says what it did; then
// executed (confirmed when its groups come back: mirror::apply), or refused: a name taken becomes a conflict copy (the
// entry renamed to "name (conflict <uid>)" here and the change resubmitted under that name), anything else a held
// change (the entries settle back to the core's state, the change is kept in mirror_held with the reason).
namespace vh::mirror::submit {

// ---- the core

[[nodiscard]] nlohmann::json serveSubmit(uint32_t callerPeerId, const nlohmann::json& payload);

// Executes the vault's queued submissions in order, on this thread (the pool task's body; tests call it). Returns how
// many ran.
std::size_t drain(uint32_t vaultId);
// Queues a drain of the vault on the sync pool (one at a time per vault), or (tests) runs it inline.
void schedule(uint32_t vaultId);
// Tests: serveSubmit drains inline instead of on the pool.
void setInlineForTesting(bool inlineDrain);

// ---- the mirror

struct SubmitStep {
    std::size_t submitted{};   // changes the core said it executed or refused this visit
    bool waiting{false};       // the oldest change is still with the core (or the link did not answer)
    std::string detail{};
};

// The vault's pending changes, oldest first, until `deadline`: what the follower's visit runs before it pulls the log.
SubmitStep submitPending(uint32_t vaultId, vh::mirror::follow::Transport& transport,
                         std::chrono::steady_clock::time_point deadline);

// The core ended the mirror and this server keeps its copy (orphaned): the person's changes applied here stay its
// content, and every change still pending (never to be confirmed now) becomes a held change (reason mirror_orphaned)
// with its sealed bytes, listed until someone discards it; nothing stays dirty. Returns how many it kept.
std::size_t orphaned(uint32_t vaultId);
// The same for any reason the vault's pending changes can never be confirmed as they are (orphaned, a resync starting
// over from the core's tree): each becomes a held change with `code` and `why`, its sealed bytes with it; nothing stays
// dirty. Returns how many it kept.
std::size_t holdAllPending(uint32_t vaultId, const std::string& code, const std::string& why);

// Tests: how long submitPending waits between asking again about a change the core has queued (0: no pause).
void setPollPauseForTesting(std::chrono::milliseconds pause);

}
