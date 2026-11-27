#pragma once

#include "db/query/mirror/Log.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/transaction>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// A change made on the mirror (migration 166; design/peers/mirror.md "A change made on the mirror", "When the core
// refuses", "As built: a change made on the mirror"). Two sides:
//
//   * The mirror: its pending changes (mirror_pending, in submission order), the entries they hold dirty with the state
//     the core last confirmed for each (mirror_dirty), and the person's versions of refused changes (mirror_held).
//   * The core: the changes each mirror submitted, by request id, with what the core did the first time
//     (mirror_submission), so a repeated submit is answered and never executed twice.
//
// Trusted primitives: callers (mirror::submit, mirror::apply, ops::fs) authorize and hold the vault's order.
namespace vh::db::query::mirror {

// A pending change on the mirror.
struct PendingChange {
    uint64_t id{};
    uint32_t vault_id{};
    std::string request_id{};
    std::string entry_uid{};          // uuid text
    std::string op{};                 // mkdir | move | rename | remove | copy | write
    nlohmann::json args{};            // every entry by uid (parent_uid, name, ...)
    std::optional<std::string> base_generation{}, new_generation{};
    Account actor{};                  // this server's node id and the person's users.id
    std::vector<std::string> uids{};  // every entry the change touched here
    std::string state{};              // local | pending | submitted | executed
    std::optional<uint32_t> groups_expected{};
    uint32_t groups_applied{};
    uint32_t attempts{};
    std::optional<std::string> last_error{};
    std::time_t created_at{};

    // Executed and every one of its groups applied here.
    [[nodiscard]] bool confirmed() const noexcept {
        return state == "executed" && groups_expected && groups_applied >= *groups_expected;
    }
};

// An entry a pending change holds dirty, and what the core last confirmed for it.
struct DirtyEntry {
    std::string uid{};
    std::string kind{};               // live | trashed | none
    nlohmann::json confirmed{};       // the state document (null for none)
};

struct NewPending {
    uint32_t vault_id{};
    std::string request_id{};
    std::string entry_uid{};
    std::string op{};
    nlohmann::json args = nlohmann::json::object();
    std::optional<std::string> base_generation{}, new_generation{};
    Account actor{};
};

// A refused change kept for the person (kind held), or a conflict copy made beside an entry (kind conflict).
struct HeldChange {
    uint64_t id{};
    uint32_t vault_id{};
    std::string kind{};               // held | conflict
    std::string request_id{};
    std::string op{};
    std::optional<std::string> entry_uid{};
    nlohmann::json args{};
    std::optional<std::string> path{};       // where the person's version was (vault-relative)
    std::optional<std::string> copy_name{};  // conflict: the name the person's version took
    Account actor{};
    std::string reason_code{};
    std::string reason{};
    std::string state{};              // open | retried | discarded
    std::time_t created_at{};
    std::optional<std::time_t> resolved_at{};
    std::optional<uint32_t> resolved_by{};
};

// A change a mirror submitted, as the core holds it.
struct Submission {
    uint32_t vault_id{};
    std::string request_id{};
    uint32_t peer_id{};
    nlohmann::json payload{};
    std::string state{};              // queued | running | executed | refused
    std::optional<uint32_t> groups{};
    std::optional<std::string> code{}, error{};
};

class Pending {
public:
    // ---- the mirror: pending changes

    // Every live entry at `entryId` and (`subtree`) under it, with its state document as the tables hold it now (live
    // entries only; a vault root is never one).
    [[nodiscard]] static std::vector<DirtyEntry> capture(uint32_t entryId, bool subtree);
    // The trashed file `uid` of the vault (its newest trash row), as a dirty entry; nullopt without one.
    [[nodiscard]] static std::optional<DirtyEntry> captureTrashed(uint32_t vaultId, const std::string& uid);

    // Records a change being applied here (state local) with the entries it touches: `captured` as they are now (an
    // entry already dirty keeps the state recorded for it), `created` as entries that did not exist. Returns the row.
    static PendingChange open(const NewPending& change, const std::vector<DirtyEntry>& captured,
                              const std::vector<std::string>& created);
    // The change was applied here: it is to be submitted (with its arguments as they ended: a write's contents).
    static void ready(uint64_t id);
    static void ready(uint64_t id, const nlohmann::json& args, const std::optional<std::string>& baseGeneration,
                      const std::optional<std::string>& newGeneration);
    // The change was not applied (nothing of it happened here): the row and the dirty entries only it held go.
    static void abandon(uint64_t id);
    // Whether every captured entry still hashes as captured and no created entry exists (the change did nothing).
    [[nodiscard]] static bool unchanged(uint32_t vaultId, const std::vector<DirtyEntry>& captured,
                                        const std::vector<std::string>& created);

    [[nodiscard]] static std::vector<PendingChange> list(uint32_t vaultId);
    [[nodiscard]] static std::optional<PendingChange> get(uint64_t id);
    [[nodiscard]] static std::optional<PendingChange> byRequest(pqxx::work& txn, uint32_t vaultId,
                                                                const std::string& requestId);
    // The oldest change of the vault (the next to submit or to wait for), nullopt without one.
    [[nodiscard]] static std::optional<PendingChange> oldest(uint32_t vaultId);
    // Local rows left by a stop (the daemon ended while one was applied): to be submitted. Returns how many.
    static uint64_t promoteLocal(uint32_t vaultId);

    static void markSubmitted(uint64_t id);
    // The core executed it with `groups` groups. Returns the row as it now is.
    static std::optional<PendingChange> markExecuted(uint64_t id, uint32_t groups);
    static void noteError(uint64_t id, const std::string& error);
    // The same change, submitted again under a new request id with new arguments (a conflict copy's name): pending.
    static void resubmit(pqxx::work& txn, uint64_t id, const std::string& requestId, const nlohmann::json& args);
    // The same person's version, submitted again as another entry (a conflict copy of a write): a new request id, the
    // new entry (created, dirty, nothing confirmed for it), no base.
    static void resubmitAs(pqxx::work& txn, uint64_t id, const std::string& requestId, const std::string& entryUid,
                           const nlohmann::json& args);

    // In the applier's transaction: a group whose origin is `requestId` was applied. Returns the row as it now is
    // (nullopt: not one of this server's).
    static std::optional<PendingChange> countApplied(pqxx::work& txn, uint32_t vaultId, const std::string& requestId);
    static void remove(pqxx::work& txn, uint64_t id);

    // ---- the mirror: dirty entries

    [[nodiscard]] static std::vector<std::string> dirtyUids(uint32_t vaultId);
    [[nodiscard]] static std::map<std::string, DirtyEntry> dirty(pqxx::work& txn, uint32_t vaultId);
    // The core confirmed a new state for a dirty entry (its kind none when it is gone). Nothing for a clean entry.
    static void confirm(pqxx::work& txn, uint32_t vaultId, const std::string& uid, const std::string& kind,
                        const nlohmann::json& state);
    // Whether a pending change other than `exceptId` holds `uid`.
    [[nodiscard]] static bool held(pqxx::work& txn, uint32_t vaultId, const std::string& uid, uint64_t exceptId);
    static void clean(pqxx::work& txn, uint32_t vaultId, const std::string& uid);
    // The uid of a live entry (uuid text).
    [[nodiscard]] static std::optional<std::string> uidOfEntry(pqxx::work& txn, uint32_t entryId);

    // ---- the mirror: held changes and conflict records

    static uint64_t hold(pqxx::work& txn, const HeldChange& h);
    [[nodiscard]] static std::vector<HeldChange> heldChanges(uint32_t vaultId, bool includeResolved = false);
    [[nodiscard]] static std::optional<HeldChange> heldChange(uint64_t id);
    // open -> retried | discarded, by `by`. False when it was not open.
    static bool resolveHeld(uint64_t id, const std::string& state, uint32_t by);

    // ---- the transaction-local settings (db::SessionSettings) of a change applied here, and of one executed on the
    // core: the backstop's switch and the request's id; the origin the log records and the acting account.
    [[nodiscard]] static std::vector<std::pair<std::string, std::string>> localSettings(const std::string& requestId);
    [[nodiscard]] static std::vector<std::pair<std::string, std::string>> originSettings(const std::string& requestId,
                                                                                         uint32_t actorId);

    // ---- the core: submissions

    [[nodiscard]] static std::optional<Submission> submission(uint32_t vaultId, const std::string& requestId);
    // Queues a submission (state queued). False when that request id is already known for the vault.
    static bool enqueue(uint32_t vaultId, uint32_t peerId, const std::string& requestId, const nlohmann::json& payload);
    // The vault's oldest queued submission, now running; nullopt without one.
    [[nodiscard]] static std::optional<Submission> claimNext(uint32_t vaultId);
    static void finish(uint32_t vaultId, const std::string& requestId, const std::string& state,
                       std::optional<uint32_t> groups, const std::optional<std::string>& code,
                       const std::optional<std::string>& error);
    // The groups the log holds whose origin is `requestId` (numbered or not).
    [[nodiscard]] static uint32_t originGroups(uint32_t vaultId, const std::string& requestId);
    // Vaults with queued or running submissions (a restart's work).
    [[nodiscard]] static std::vector<uint32_t> vaultsWithQueued();
    // A running submission a stop interrupted: back to queued (nothing of it was logged) or executed (it was).
    static uint64_t recoverRunning(uint32_t vaultId);
    // Finished submissions older than `age` go.
    static uint64_t sweep(std::chrono::seconds age);
};

}
