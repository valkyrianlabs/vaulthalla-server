#pragma once

#include "db/query/mirror/MirrorVault.hpp"
#include "mirror/Hash.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/transaction>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

// The mirror's applier (design/peers/mirror.md "Starting a mirror" step 5, "Following the core", "As built: following
// the core"): takes the core's baseline (the first copy, page by page) and its replication log (group by group) into
// this server's copy of the vault. Each page or group is one database transaction under Log::markMirrorApply, so the
// replication log's triggers write nothing and fs_change_log still fires for this server's own clients.
//
//   * Entries are found by uid (fs::tree_apply::locate), never by path; inserted with the core's uids, generations,
//     times, modes, owners and attribution (accounts arrive as {node, id} and are mapped to this server's rows).
//   * Per uid, the first row's prev_hash is the compare-and-set against the entry hash this server recorded for it, and
//     the last row's state is the result (as-built deviation 4 of the log). Renames that swap or chain names inside one
//     group go through temporary names (".vh-mirror-<uid>"): the unique (parent_id, name) is not deferrable.
//   * After the changes, the hash of each entry is computed from this server's own tables and must be the core's: a
//     mismatch, a compare-and-set that fails, an entry the group cannot place, or a first copy whose digest is not the
//     baseline's stops the vault as `diverged` with the entry and both hashes, and nothing of the group is applied. A
//     key version this server does not hold stops it as `stopped` (mirror_key_missing); a key row naming a version the
//     core delivered ahead of its rotation (mirror/rotate) makes it current here, with the same key check
//     (mirror_key_mismatch otherwise), and the engine reloads its keys after the commit. The digest moves by each
//     entry's new hash less the one it replaced, as the core's does, so a scrub (Digests::recompute) agrees with it.
//   * Every file whose content this server does not hold at the row's generation gets its mirror_content_pending row in
//     the same transaction (a newer generation replaces an older one; a file removed or trashed drops it). Contents are
//     fetched by wave 2's lane (mirror::contents), never here.
//   * A group that would replace, trash or remove a file open on this server's mount waits whole (Deferred: nothing of
//     it is applied; the follower tries again until the file is closed), so a group stays atomic for the digest and
//     for the files on disk.
//   * After the commit, through the calls a local write uses: backing files and folders moved or removed, folders made,
//     derived artifacts dropped, the FUSE cache and the totals refreshed (fs::tree_apply).
namespace vh::mirror::apply {

using vh::db::query::mirror::Position;

// One row of a group as peer.mirror.log carries it.
struct LogRow {
    uint64_t seq{};
    std::string op{};
    std::optional<std::string> uid{};
    std::optional<std::string> type{};
    nlohmann::json state{};
    std::optional<vh::mirror::Hash> entry_hash{};
    std::optional<vh::mirror::Hash> prev_hash{};
    std::optional<std::string> origin{};   // a mirror's request id when the change was submitted by it
};

struct LogGroup {
    uint64_t term{};
    uint64_t txid{};
    uint64_t first_seq{};
    uint64_t last_seq{};
    std::vector<LogRow> rows{};
};

struct TreeItem {
    uint64_t ord{};
    nlohmann::json state{};
};

// One page of peer.mirror.tree.
struct TreePage {
    Position baseline{};
    vh::mirror::Digest digest{};
    uint64_t rows{};
    nlohmann::json vault{};
    std::vector<TreeItem> items{};
    bool more{false};
};

enum class Status {
    Applied,         // committed
    AlreadyApplied,  // nothing to do: this server is past it (a group or page applied twice is applied once)
    Deferred,        // a file it changes is open here: nothing applied, try again once it is closed
    Diverged,        // the vault stopped as diverged (recorded with the reason)
    Stopped,         // the vault stopped (expired, stopped: recorded), or is not live (nothing recorded)
    NotNext,         // not the next page or group for this server's position: nothing applied
    Gone,            // the vault has no mirror row here (any more): stop following it
};

[[nodiscard]] const char* toString(Status s);

struct Result {
    Status status{Status::Gone};
    std::string reason{};          // the stop's code, or why not applied
    nlohmann::json detail{};
    Position at{};                 // where the vault is now (a group: its last applied position)
    vh::mirror::Digest digest{};   // its digest there
    uint64_t copy_cursor{};        // the first copy: the last baseline entry applied
    bool copy_finished{false};     // the first copy is complete (this page finished it, or it was already)
    std::size_t changes{};         // entries the page or group changed
};

struct Options {
    // Whether a file is open on this server's mount (default: fuse::WorkingCopies).
    std::function<bool(uint64_t inode)> isOpen{};
};

// The next page of the first copy (its items must start right after the copy's cursor).
[[nodiscard]] Result applyTreePage(uint32_t vaultId, const TreePage& page, const Options& options = {});
// The next group of the log (it must start right after the last applied position). A group whose origin is one of
// this server's pending changes (mirror::submit) counts towards its confirmation; once all of the change's groups are
// here it is confirmed (never applied a second time: the tables hold the group's result) and the entries it held
// settle. An entry a change made here still holds is applied from wherever it stands here; one in the way of the
// core's change is brought back to what the core last confirmed for it, or (holding the name the core's entry needs)
// set aside to its conflict name.
[[nodiscard]] Result applyGroup(uint32_t vaultId, const LogGroup& group, const Options& options = {});

// Settles entries a pending change held (it was refused, or executed with nothing to apply here): each one no other
// pending change holds is brought back to the state the core last confirmed for it where its tables differ, and is
// clean again. `also` runs first in the same transaction (the pending row's removal, the held change it leaves). No
// position or digest moves. Applied, or the vault's state (Stopped, Gone) when it is not live here.
[[nodiscard]] Result settle(uint32_t vaultId, const std::vector<std::string>& uids,
                            const std::function<void(pqxx::work&)>& also = {});

}
