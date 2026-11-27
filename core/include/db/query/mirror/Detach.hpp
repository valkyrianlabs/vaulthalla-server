#pragma once

#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Pending.hpp"

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Leaving a mirror, the database side (migration 167; design/peers/mirror.md "Detach", "As built: leaving a mirror"):
// what a held copy would be without its core (the files whose contents never arrived), the one transaction that turns
// it into an ordinary local vault, and the record of a detach on both servers (mirror_detached). Trusted primitives:
// callers (mirror::leave, ops::mirrors) authorize.
namespace vh::db::query::mirror {

// A live file of a held copy whose current contents are not on this server (mirror_content_pending at the file's own
// generation): waiting or failed while the copy is held, missing once it is detached.
struct MissingFile {
    uint32_t file_id{};
    std::string uid{};           // the file's object uid (uuid text)
    std::string path{};          // vault-relative
    uint64_t size_bytes{};
    std::string state{};         // waiting | failed | missing
    std::optional<std::string> last_error{};
};

// One detach, as each server records it.
struct DetachRecord {
    uint32_t id{};
    std::string side{};          // mirror: this server detached its copy; core: this server's mirror left with its copy
    uint32_t vault_id{};
    std::string vault_uid{};     // uuid text
    uint32_t peer_id{};
    Position fork{};             // mirror: the last (term, seq) it applied; core: what the mirror said it applied
    std::optional<bool> digest_matched{};
    std::optional<std::string> was_state{};
    uint64_t missing{};
    std::optional<uint32_t> owner_id{}, detached_by{};
    std::time_t detached_at{};
    std::optional<std::time_t> rekeyed_at{};
};

// What the detach transaction does with the copy's pending changes (decided by the caller from Pending::list under the
// vault's local-change lock): a change whose effect the tree holds becomes an ordinary local change (its row and its
// pending bytes go); a write whose bytes the file no longer holds (the core's state came back over it) is kept for the
// person as a held change with those bytes.
struct DetachChanges {
    std::vector<uint64_t> dropped{};                      // pending rows that go
    std::vector<std::pair<uint64_t, HeldChange>> held{};  // pending row -> the held change that replaces it
};

struct DetachInput {
    uint32_t vault_id{};
    uint32_t owner_id{};
    std::optional<uint32_t> actor_id{};
    DetachChanges changes{};
    bool tell_core{false};       // the started offer waits to tell the core (peer.mirror.detached)
};

struct DetachOutcome {
    DetachRecord record{};
    MirrorVault was{};                                   // the row as it was
    uint64_t missing{};
    std::vector<std::pair<uint64_t, uint64_t>> held{};   // pending row -> held change id
    std::vector<uint64_t> dropped{};
    std::optional<uint32_t> previous_owner{};
};

class MirrorDetach {
public:
    // The copy's files whose current contents are not here, by path (every one: the list a person may export).
    [[nodiscard]] static std::vector<MissingFile> missing(uint32_t vaultId);
    [[nodiscard]] static uint64_t countMissing(uint32_t vaultId);

    // A row a detach takes: the vault's mirror or orphaned row, or (wave 5 piece B) a core row the other server's
    // take over left (rejoining, forked) or one this server's own open take over holds (the old core may still hold
    // the vault): leaving it makes the vault this server's alone, and the other server is told as a mirror's detach.
    [[nodiscard]] static bool detachable(const MirrorVault& row);

    // One transaction: the vault's mirror or orphaned row (locked first) and what hangs off it go (log, entry hashes,
    // baseline, dirty rows, submissions; the grant with the row; the linked server's vault-role assignments), the files
    // whose contents never arrived are marked missing (every other content row goes), the pending changes as `changes`
    // says, the owner is set, the mirror's offer of the vault ends `detached` (to be told when `tell_core`), and the
    // detach is recorded (side mirror). A core row (detachable) is taken the same way: its open take over and rejoin
    // settle `ended` and the fork base goes with the row (MirrorVaults::remove), its offer ends `detached` on the
    // mirror's side so the other server is told. ops::Conflict when the vault is not held here (or no longer). Republishes
    // nothing: the caller does (rbac::mirrored, mirror::access) once it returns.
    static DetachOutcome detach(const DetachInput& in);

    // The core was told its mirror detached the vault (peer.mirror.detached): recorded once per vault and peer.
    static DetachRecord recordCore(uint32_t vaultId, uint32_t peerId, Position fork, uint64_t missing);

    // The newest detach of the vault here not followed by a re-key, nullopt when there is none.
    [[nodiscard]] static std::optional<DetachRecord> forVault(uint32_t vaultId);
    // A detach between this server and `peerId` of the vault with this uid, not followed by a re-key: the two servers
    // hold vaults with the same uid and keys, so they may not mirror it with each other.
    [[nodiscard]] static std::optional<DetachRecord> between(const std::string& vaultUuid, uint32_t peerId);
    [[nodiscard]] static std::vector<DetachRecord> list();

    // ---- deleting a mirrored vault (its retention window; mirror/leave/Leave.hpp "Deleting")

    // The core: what the vault's purge does to the mirror's copy (remove | leave), recorded when its deletion is
    // scheduled or changed, cleared by a restore. False when the vault has no `core` row.
    static bool setDeletingCopy(uint32_t vaultId, const std::optional<std::string>& copy);
    [[nodiscard]] static std::optional<std::string> deletingCopy(uint32_t vaultId);
    // The mirror: its core is deleting the vault. A live copy (or one already paused for this) is paused with reason
    // `reason` and `detail`; any other state is left as it is. False when nothing changed.
    static bool pauseForCore(uint32_t vaultId, const std::string& reason, const nlohmann::json& detail);
    // Every planned switch of the vault here that is open (or decided and not yet told) ends: abandoned with `reason`,
    // nothing more told. How many there were.
    static std::size_t endSwitches(uint32_t vaultId, const std::string& reason);
    // The core restored it: a copy paused for `reason` is live again where it was. False when nothing changed.
    static bool resumeFromCore(uint32_t vaultId, const std::string& reason);
};

}
