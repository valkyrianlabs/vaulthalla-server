#pragma once

#include "db/query/mirror/Detach.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Start.hpp"
#include "peer/Peer.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// Leaving a mirror (server mirror phase 2, wave 5, piece A; design/peers/mirror.md "Leaving a mirror", "Detach",
// invariant 10, "As built: leaving a mirror").
//
// Detach turns a vault this server holds as another server's copy (role mirror in any state, first copy finished or
// not, link up, down or gone; or an orphaned copy) into an ordinary local vault here, without asking the core anything:
//
//   1. the person chooses the new owner (a sign-in account here; by default themselves);
//   2. preview(): what they would get, before anything happens: the last (term, seq) applied and confirmed, whether the
//      digest matched there, the pending and held changes, and every file whose contents are not here (exportable);
//   3. one transaction (vh::db::query::mirror::MirrorDetach::detach): the mirror row and what hangs off it go, so the gate
//      and the backstop no longer apply; pending changes become ordinary local changes (a write the file no longer
//      holds stays the person's, as a held change with its bytes); held changes stay listed until discarded; the
//      files whose contents never arrived stay in the tree marked missing (an open fails with mirror_contents_missing,
//      never empty, never another generation's bytes); the owner is set; the linked server's role goes;
//   4. the engine is reloaded as a plain local vault (storage::Manager::reloadEngine), no restart;
//   5. nothing is deleted on either server and no bucket is touched (the vault takes no remote);
//   6. audited here at once (mirror.detach: who, the fork point, the missing count; never a path);
//   7. the core is told, not asked, when it is next reachable (peer.mirror.detached, queued on the mirror's offer like
//      a cancel; dropped on unlink): it ends the mirror on its side as cancelOnCore does, records and audits it.
//
// Afterwards the vault shares its uid and keys with the original until the re-key pass runs (piece C): the two servers
// refuse to mirror it with each other (offerRefusal, on both ends), and `vh mirror info` recommends the re-key pass.
namespace vh::mirror::leave {

using json = nlohmann::json;

struct Preview {
    uint32_t vault_id{};
    std::string vault_name{};
    std::string role{};                    // mirror | orphaned
    std::string state{};                   // live | paused | diverged | expired | stopped
    std::optional<std::string> stop_reason{};
    std::optional<vh::peer::Record> peer{};
    bool link_up{false};
    bool copy_finished{false};
    uint64_t copy_cursor{}, baseline_rows{};
    vh::db::query::mirror::Position applied{};               // the last (term, seq) applied here
    std::optional<vh::db::query::mirror::Position> confirmed{};  // the last the core confirmed (acknowledged, digest equal)
    std::optional<bool> digest_matched{};                // at `confirmed`; false once diverged; nullopt: nothing yet
    uint64_t pending_changes{}, held_changes{};
    std::vector<vh::db::query::mirror::MissingFile> missing{};
    uint32_t owner_id{};
};

// What a detach of `vaultId` would give (a super admin or a holder of "Detach mirrored vaults"; ops::mirrors
// authorizes). ops::Refused mirror_not_held when the vault is not held here as another server's copy.
[[nodiscard]] Preview preview(uint32_t vaultId);

struct Detached {
    Preview before{};
    vh::db::query::mirror::DetachRecord record{};
    uint32_t owner_id{};
    uint64_t missing{};
    uint64_t pending_kept{};   // pending changes that became ordinary local changes
    uint64_t pending_held{};   // pending writes kept as held changes (the file holds another version)
    bool core_told_later{false};
};

// Steps 3 to 7 (ops::mirrors authorizes and resolves the owner: a local, active account). Audited mirror.detach.
[[nodiscard]] Detached detach(uint32_t vaultId, uint32_t ownerId, std::optional<uint32_t> actorId,
                              const std::string& actorName);

// The core end of a detach: peer.mirror.detached {offer_uid?, vault_uid, at: {term, seq}, missing}. Ends the mirror on
// this server as cancelOnCore does (core row, log, submissions, staged bytes), records it (side core, copy_outcome
// detached on the core's offer) and audits mirror.detached. Its own vault is untouched. {recorded}.
[[nodiscard]] json detachedReceived(const vh::peer::Record& from, const json& payload);
// What the mirror sends for its detached offer.
[[nodiscard]] json detachedPayload(const vh::db::query::mirror::Offer& offer);

// A vault with this uid was detached between this server and `peerId` and not re-keyed since: they hold vaults with
// the same uid and keys, so neither offers it to the other nor accepts it ({code mirror_detached_copy, sentence}).
[[nodiscard]] std::optional<std::pair<std::string, std::string>> offerRefusal(const std::string& vaultUuid,
                                                                             uint32_t peerId);

// ---- deleting a mirrored vault: the core's retention window (Cooper: the mirror matches the core until the core
// actually deletes the vault; decisions log 601-602)
//
//   schedule (ops::vaults::remove, no --now): the choice (remove | leave) is recorded on the core's row
//     (MirrorDetach::setDeletingCopy); the mirror is NOT ended. The core tells the mirror (peer.mirror.deleting
//     {vault_uid, deleting, purge_after, copy}, sent by the start service, again on every link-up and whenever it
//     changes), which pauses its copy with reason mirror_core_deleting (read-only with a sentence naming what happens
//     and when; vh mirror info shows the date and the choice). Nothing is submitted, pending changes stay pending;
//     detach works throughout.
//   restore (vault::retention::restore): the choice is cleared and the mirror told; it is live again where it was.
//   purge (the window's end, or --now; vault::retention::purgeOne): endForPurge ends the mirror with the recorded
//     choice exactly as mirror.cancel [--remove-copy] does, then the vault is purged.
inline constexpr std::string_view kCoreDeletingReason = "mirror_core_deleting";
// A vault with a `core` row here (or a start running) is mirrored, and its deletion must carry a choice.
[[nodiscard]] bool coreMirrored(uint32_t vaultId);
// The vault's pending deletion as the mirror sees it: {deleting, purge_after, copy} (core: from the deletion record and
// the recorded choice; mirror: what the core said), null when it is not being deleted.
[[nodiscard]] json deletionOf(uint32_t vaultId);
// Every pass of the start service (core side): tells each mirror whether its vault is being deleted, once per
// connection and whenever that changes.
void syncDeletionNotices();
// The mirror side of peer.mirror.deleting.
[[nodiscard]] json deletingReceived(const vh::peer::Record& from, const json& payload);
// The purge is about to remove the vault: its mirror ends with the recorded choice (leave when none was recorded:
// erring towards keeping). Nothing for a vault that is not mirrored.
void endForPurge(uint32_t vaultId);
// The deletion's choice (remove | leave), recorded at the schedule or changed during the window; the mirror is told.
void recordDeletionChoice(uint32_t vaultId, const std::string& copy);
// A pending deletion was restored: the choice is cleared and the mirror will be told.
void restored(uint32_t vaultId);
// Tests: forget which notices were sent.
void resetDeletionNoticesForTesting();

[[nodiscard]] json toJson(const Preview& p);
[[nodiscard]] json toJson(const Detached& d);
[[nodiscard]] json toJson(const vh::db::query::mirror::DetachRecord& r);

}
