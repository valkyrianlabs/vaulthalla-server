#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <pqxx/transaction>

// Resync and the scrub (migration 168; design/peers/mirror.md "Parity", "As built: moving the core and resync"). The
// rows mirror::resync reads and writes; callers authorize and hold the vault's change lock where it matters.
namespace vh::db::query::mirror {

// An entry of a mirror vault whose uid the core's tree does not hold (no recorded hash once a resync's copy is
// complete): the evidence of the divergence, kept as a held change.
struct Leftover {
    uint32_t id{};                  // fs_entry id, or files_trashed id when `trashed`
    std::string uid{};
    std::string kind{};             // file | directory | symlink
    bool trashed{false};
    std::string path{};             // vault-relative
    std::string name{};
    std::optional<std::string> parent_uid{};   // the vault's uid for an entry under the root
    std::string generation{};       // a file's files.encryption_iv
    uint32_t key_version{};
    uint64_t size{};
    std::string content_hash{};
    std::string backing{};          // where its bytes are on this disk (a file)
    std::string target{};           // a symlink's
    uint32_t depth{};
};

// A difference the scrub found: the uid, what the tables hash to now and what was recorded (hex, or null).
struct ScrubDifference {
    std::string uid{};
    std::optional<std::string> tables{};
    std::optional<std::string> recorded{};
};

struct ScrubFinding {
    uint64_t differences{};                   // how many uids differ
    std::vector<ScrubDifference> first{};     // the first few
    bool digestDrift{false};                  // mirror: the running digest is not the recorded hashes' sum
};

class Resync {
public:
    // ---- the mirror

    // In the caller's transaction (the vault's change lock held, pending changes already held): the copy starts over.
    // The entry hashes and dirty rows go; the row is live, its first copy unfinished at cursor 0 with no baseline and a
    // zero digest, the stop cleared, resync_at/by/count recorded. Pending-contents rows stay (a file whose bytes never
    // arrived is still expected when the core's tree names the same generation). False without a `mirror` row.
    static bool resetMirror(pqxx::work& txn, uint32_t vaultId, uint32_t actorId);
    // In the caller's transaction: every live entry and trash row of the vault whose uid has no recorded hash, deepest
    // first (files and symlinks before the folders that hold them).
    [[nodiscard]] static std::vector<Leftover> leftovers(pqxx::work& txn, uint32_t vaultId);
    // Whether an open held change keeps a version of the entry already.
    [[nodiscard]] static bool heldOpenFor(pqxx::work& txn, uint32_t vaultId, const std::string& uid);
    // ---- the core

    // Before its baseline is taken again (MirrorVaults::startCore in the next term): the vault's log, entry hashes,
    // baseline and submissions go and its row is `starting` (which startCore replaces; meanwhile the vault's writers
    // are not logged and are in the new baseline). False without a `core` row for `peerId`.
    static bool prepareCoreRebaseline(uint32_t vaultId, uint32_t peerId);
    // A rebaseline that failed (startCore refused: its writers did not finish in time) leaves the vault mirrored,
    // diverged (mirror_resync_failed), so that its mirror can ask again.
    static void restoreCoreRow(uint32_t vaultId, uint32_t peerId, uint64_t term, const std::string& why);
    // When its mirror last asked it to start over.
    static void recordCoreResync(uint32_t vaultId);

    // ---- the scrub, on either side

    // The vaults due a scrub (`every` since their last, or never): live, a core row or a mirror whose first copy is
    // complete. Never a vault that is not mirrored.
    [[nodiscard]] static std::vector<uint32_t> scrubDue(std::chrono::hours every);
    // The vault's entry hashes recomputed from its tables and compared, in one statement, with those recorded (an
    // entry a change made here still holds is skipped: its tables are this server's own until it settles); on the
    // mirror also its running digest. Records scrubbed_at.
    [[nodiscard]] static ScrubFinding scrub(uint32_t vaultId);
};

}
