#pragma once

#include "mirror/follow/Follower.hpp"

#include <chrono>
#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

// Resync and the scheduled scrub (wave 5 piece B; design/peers/mirror.md "Parity", "As built: moving the core and
// resync"; migration 168).
//
// Resync: a copy that stopped (diverged, expired, stopped) starts over from the core's tree without being made again.
// The mirror asks its core (peer.mirror.resync), which takes a fresh baseline (its log for the vault starts again, in
// the next term); then the mirror holds every pending change (reason mirror_resync), forgets its entry hashes and runs
// the first copy again over the entries it has: an entry of the core's tree that is here (by uid) is brought to the
// core's state in place, keeping its bytes when the generation is the one it holds (nothing identical is fetched); a
// file whose bytes differ keeps this server's version as a held change before the core's replaces it; when the copy is
// complete, every entry here that the core's tree does not hold leaves the tree as a held change (its bytes kept), so
// nothing a person wrote here is dropped and the digests agree.
//
// The scrub: each mirrored vault's entry hashes recomputed from its tables and compared with those recorded, every
// kScrubEvery on both servers (the follower's hourly pass). A difference stops the vault as diverged
// (mirror_scrub_mismatch, the first uids in the detail); a vault that is not mirrored is never looked at.
namespace vh::mirror::resync {

inline constexpr std::chrono::hours kScrubEvery{24};

// Core: peer.mirror.resync {vault_uid}. The caller must be the vault's mirror; the vault is not paused here. The
// baseline is taken again in term + 1 (MirrorVaults::remove then startCore: the log, entry hashes, submissions and
// baseline go, the tree is read again). Answers {term, baseline: {term, seq}, entries}. Audited mirror.resync.
[[nodiscard]] nlohmann::json serveResync(uint32_t callerPeerId, const nlohmann::json& payload);

// Mirror: a super admin here (ops::mirrors::resync authorizes) starts the copy over. The vault must be held here as a
// mirror and diverged, expired or stopped (ops::Conflict mirror_not_stopped otherwise); the core is asked first
// (ops::Refused mirror_core_unreachable when the link is down or it does not answer, mirror_core_gone when it no
// longer mirrors the vault with this server, its own code when it refuses), then this server resets. Audited
// mirror.resync. Returns the row's new state (live, first copy unfinished) and how many pending changes were held.
[[nodiscard]] nlohmann::json start(uint32_t vaultId, uint32_t actorId, const std::string& actorName,
                                   vh::mirror::follow::Transport& transport);

// The scrub of one vault now (either side). True when it matched; a mismatch stops the vault as diverged.
bool scrub(uint32_t vaultId);
// Every vault due a scrub (kScrubEvery, or `every`). Returns how many were scrubbed.
std::size_t scrubDue(std::chrono::hours every = kScrubEvery);
// Test instances only (paths::testMode, VH_TEST_FAULT_DIR/mirror-scrub-now): every vault is due at every pass of the
// follower, so `vhh drill peers` can see a planted difference caught. Never in a packaged daemon.
[[nodiscard]] bool scrubNowForTesting();

}
