#pragma once

#include "ops/Error.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The write gate of a vault this server holds as another server's copy (design/peers/mirror.md "Strict mode: read-only
// while the link is down", "The gate"; server mirror phase 2, wave 4, piece A).
//
// A vault whose mirror_vault row here has the role `mirror` or `orphaned` can be changed on this server by nothing but
// the follower applying its core's log. Every write surface asks requireWritable() before it changes anything (FUSE in
// fuse::Resolver and before a seal, ops::fs, vh::fs::Filesystem's mutating calls, the HTTP lanes, `vh fs put`, shares,
// the S3 gateway, recovery restores, vault settings) and reports the refusal in its own terms; the database refuses
// what a surface missed (migration 165, the backstop). Reads are untouched: what a reader may see is the core's grant
// (rbac::mirrored).
//
//   NotMirrored  not held here (no row, or this server is the vault's core): writes are the vault's own business,
//                except a core whose planned switch runs (migration 168: state `switching`): ReadOnly, kSwitching; an
//                old core that learned another server took over (`rejoining`: kRejoining) or both did (`forked`)
//   Live         role mirror, first copy finished, state live, the link to the core up
//   ReadOnly     anything else, with a reason code (below)
//
// Held in memory behind a shared lock, so a check never waits on the database (FUSE, HTTP and ws threads): one atomic
// load while nothing is held here (every server today), then a map lookup. Published from mirror_vault:
//   - at startup, before any engine serves a request (reload(); a failure stops the daemon, as for rbac::mirrored);
//   - by every db::query::mirror write that changes a held row's role, state, first copy or stop, before it returns;
//   - when a link comes up or goes down (peer::LinkService, linkChanged());
//   - within rbac::mirrored::Watcher::kWatchInterval of anything missed (reconcile(), on the same watcher): a psql edit
//     by hand, a link state the hook did not see.
// A database failure keeps what memory held: an unreadable database never turns a read-only copy writable.
//
// acceptsLocalChanges() is true (piece B): a Live mirror lets a person's change through, and the operation behind the
// gate takes it as pending and submits it to the core (mirror::submit); a mirror is read-only whenever it is not Live.
namespace vh::mirror::access {

enum class State { NotMirrored, Live, ReadOnly };
[[nodiscard]] std::string_view to_string(State state) noexcept;   // not_mirrored | live | read_only

// Reason codes (stable; ws data.reason, the HTTP lanes' code, the CLI's message).
inline constexpr std::string_view kOrphaned = "mirror_orphaned";          // the core ended the mirror; copy kept
inline constexpr std::string_view kFirstCopy = "mirror_first_copy";       // the first copy has not finished
inline constexpr std::string_view kDiverged = "mirror_diverged";          // stopped: differs from the core
inline constexpr std::string_view kExpired = "mirror_expired";            // stopped: behind retention, or core gone
inline constexpr std::string_view kStopped = "mirror_stopped";            // stopped: a key missing, an unknown op
inline constexpr std::string_view kPaused = "mirror_paused";              // following is paused
inline constexpr std::string_view kCoreDeleting = "mirror_core_deleting"; // paused: the core is deleting the vault
inline constexpr std::string_view kLinkDown = "mirror_link_down";         // the link to the core is down
inline constexpr std::string_view kWritesNotBuilt = "mirror_writes_not_built";  // Live, but piece B is not built
inline constexpr std::string_view kCoreOwned = "mirror_core_owned";      // settings, remote: the core's, always
inline constexpr std::string_view kSwitching = "mirror_switching";       // a planned switch of the core role runs
inline constexpr std::string_view kRejoining = "mirror_rejoining";       // old core with changes the new one lacks
inline constexpr std::string_view kForked = "mirror_both_forced";        // both servers took over
inline constexpr std::string_view kCopyWriting = "mirror_copy_writing";  // a copy of a held vault is written into it

// What the gate knows of a held vault (tests, status). nullopt: not held here.
struct Facts {
    uint32_t vault_id{};
    uint32_t peer_id{};
    std::string role{};             // mirror | orphaned
    std::string state{};            // live | paused | diverged | expired | stopped
    bool copy_finished{false};
    std::optional<std::string> stop_reason{};
    bool link_up{false};
};
[[nodiscard]] std::optional<Facts> facts(uint32_t vaultId);

// The vault's state now. NotMirrored for a vault not held here.
[[nodiscard]] State state(uint32_t vaultId) noexcept;
// Whether the vault is held here as another server's copy (role mirror or orphaned; a switching core is gated but not
// held).
[[nodiscard]] bool held(uint32_t vaultId) noexcept;
// The reason code requireWritable() would refuse a write with, "" when it would let it through: one of the codes above
// for ReadOnly; kWritesNotBuilt for Live while acceptsLocalChanges() is false; "" for NotMirrored.
[[nodiscard]] std::string reason(uint32_t vaultId);
// The sentence a person reads for a reason code (never a path, a name or key material).
[[nodiscard]] std::string sentence(std::string_view reasonCode);

// Whether a Live mirror takes local changes (piece B: applied as pending, sent to the core).
[[nodiscard]] bool acceptsLocalChanges() noexcept;

// The gate refused a write. ops::Refused with code "read_only" (ws data.code; the CLI and HTTP lanes map it), `reason`
// the reason code, what() the sentence followed by the operation.
struct MirrorReadOnly final : vh::ops::ReadOnly {
    uint32_t vault_id{};
    MirrorReadOnly(uint32_t vaultId, std::string reasonCode, std::string_view operation);
};

// Returns for a vault that is not held here (and for a Live one once acceptsLocalChanges()); throws MirrorReadOnly
// naming `operation` otherwise.
void requireWritable(uint32_t vaultId, std::string_view operation);
// The same check as a value: the refusal requireWritable() would throw, nullopt when it would return.
[[nodiscard]] std::optional<std::string> refusalReason(uint32_t vaultId);
// What is never a local change on a held vault, Live or not (its name, description, quota, owner, sync and recovery
// settings, a remote): the core's alone. MirrorReadOnly with kCoreOwned for any vault held here.
void refuseIfHeld(uint32_t vaultId, std::string_view operation);

// ---- publication

// Reads mirror_vault and publishes it (startup; every db::query::mirror write that changes a held row). Throws when
// the database can't be read; what was published stays.
void reload();
// reload() when the rows differ from what is published, and the links' state from peer::LinkService (when it runs).
// True when it changed something. rbac::mirrored::Watcher calls it on every pass.
bool reconcile();
// The link to `peerId` came up (peer.hello answered and the connection kept) or went down.
void linkChanged(uint32_t peerId, bool up) noexcept;
// ---- the new vault a copy of a held vault is written into (mirror::copy, "Detach a copy")
//
// Read-only (kCopyWriting) to every surface but the copy itself while the copy runs, so nothing anyone writes there can
// be lost when a failed or cancelled copy removes the vault. Published from running mirror_copy rows by reload() and
// reconcile() (so a daemon restart gates a partial vault before anything serves it), and by the copy itself the moment
// it creates the vault (beginCopyTarget, before its row says so) until it ends (endCopyTarget). Not held: its content is
// this server's own.
void beginCopyTarget(uint32_t vaultId);
void endCopyTarget(uint32_t vaultId);
// While one exists on a thread, that thread writes the copy's vault (nothing else is let through).
class CopyWriter {
public:
    explicit CopyWriter(uint32_t vaultId) noexcept;
    ~CopyWriter();
    CopyWriter(const CopyWriter&) = delete;
    CopyWriter& operator=(const CopyWriter&) = delete;

private:
    uint32_t previous_{};
};

// Every vault held here (tests, the background-job skips).
[[nodiscard]] std::vector<uint32_t> heldVaults();

// Tests: forget everything (a fresh schema holds nothing), and the links' state.
void resetForTesting() noexcept;

}
