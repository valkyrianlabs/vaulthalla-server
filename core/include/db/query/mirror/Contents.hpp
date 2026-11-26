#pragma once

#include "crypto/id/ObjectUid.hpp"

#include <pqxx/transaction>

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Sealed file contents between two linked servers (design/peers/mirror.md "Contents"): what the sealed lane may serve
// (SealedObjects) and what a mirror is still waiting for (PendingContents, migration 161's mirror_content_pending).
// Trusted primitives: callers (protocols::device::peer_object, mirror::contents) authorize.
namespace vh::db::query::mirror {

// One file as the sealed lane sees it: the vault it is in, the linked server of that vault and this server's role,
// and the file's current generation. Looked up by the vault's and the file's permanent ids.
struct SealedObject {
    uint32_t vault_id{};
    uint32_t peer_id{};      // mirror_vault.peer_id: the one linked server the vault's contents may go to
    std::string role{};      // this server's role for the vault: core | mirror | orphaned
    uint32_t file_id{};      // fs_entry id; 0 when the vault has no live file with that object uid
    uint64_t size_bytes{};   // plaintext size
    std::string generation{};   // files.encryption_iv
    uint32_t key_version{};
};

class SealedObjects {
public:
    // nullopt when no live vault has `vaultUid` or the vault is not mirrored on this server; file_id 0 when the vault
    // is but holds no live file with `objectUid`.
    [[nodiscard]] static std::optional<SealedObject> find(const vh::crypto::id::ObjectUid& vaultUid,
                                                          const vh::crypto::id::ObjectUid& objectUid);
    // The file's generation now (files.encryption_iv), nullopt when the file is gone.
    [[nodiscard]] static std::optional<std::string> generationOf(uint32_t fileId);
    // The live file of a vault with `objectUid` (its fs_entry id), nullopt when there is none.
    [[nodiscard]] static std::optional<uint32_t> fileIdOf(uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid);
};

// What a mirror expects for one file whose sealed bytes it does not hold yet.
struct Expected {
    uint32_t vault_id{};
    vh::crypto::id::ObjectUid object_uid{};
    std::string generation{};      // files.encryption_iv form
    uint32_t key_version{};
    uint64_t size_bytes{};         // plaintext
    std::string content_hash{};    // BLAKE2b over the sealed bytes, hex
    int64_t mtime_us{};            // the backing file's modification time once linked
    int16_t priority{0};           // higher first
    // Read back only:
    std::string state{"waiting"};  // waiting | failed
    uint32_t attempts{0};
    std::optional<std::string> last_error{};
    std::time_t expected_at{};
    std::optional<std::time_t> last_attempt_at{};

    [[nodiscard]] bool failed() const noexcept { return state == "failed"; }
};

class PendingContents {
public:
    // Failed attempts after which a file stops being retried until retry() (design/peers/mirror.md, "Receiving").
    static constexpr uint32_t kMaxAttempts = 3;

    // Marks a file of a vault this server is the mirror of as expected: its generation, key version, size, content
    // hash and modification time. A row for the same generation keeps its attempts and state; another generation
    // replaces it (waiting, no attempts). ops::NotFound without such a vault, ops::Invalid when this server is not
    // its mirror or the expectation is malformed (a generation that is neither empty nor VHF1 or GCM, a hash that is
    // not 64 hex digits).
    static void expect(const Expected& e);
    // The log applier's (mirror::apply): in the caller's transaction, for a vault the caller has checked this server
    // is the mirror of; the same row rules. forget() drops the file's row whatever it expects (the file is gone or in
    // the trash).
    static void expect(pqxx::work& txn, const Expected& e);
    static void forget(pqxx::work& txn, uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid);
    // The file's row, nullopt when nothing is pending for it.
    [[nodiscard]] static std::optional<Expected> get(uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid);
    // What is outstanding for a vault, in the order it is fetched: priority (higher first), then the order the file was
    // first expected in. Failed rows only with `includeFailed` (after every waiting one).
    [[nodiscard]] static std::vector<Expected> outstanding(uint32_t vaultId, std::size_t limit,
                                                           bool includeFailed = false);
    [[nodiscard]] static std::size_t countOutstanding(uint32_t vaultId);

    // One failed attempt at `generation`: attempts + 1, the reason, and `failed` at kMaxAttempts. The row as it now
    // is, nullopt when the row no longer expects that generation (nothing changed).
    static std::optional<Expected> recordFailure(uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid,
                                                 const std::string& generation, const std::string& reason);
    // Told to try again: a failed row waits again with no attempts. False when there is no failed row.
    static bool retry(uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid);
    // The row no longer applies (its file is gone or names another generation): removed when it still expects
    // `generation`. False otherwise.
    static bool dropSuperseded(uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid, const std::string& generation);

    // The receive path's compare-and-set, inside the caller's transaction: locks the row (FOR UPDATE) when it still
    // expects exactly `e`'s generation, key version, size and hash and is waiting, and the file's row (FOR SHARE: no
    // writer changes it until the transaction ends) when it still names that generation with that key version, size
    // and content hash. The file's id, or nullopt (nothing locked that matters) when either has moved on.
    [[nodiscard]] static std::optional<uint32_t> lockForLink(pqxx::work& txn, const Expected& e);
    // Inside the same transaction, after the bytes are in place: the row goes.
    static void clear(pqxx::work& txn, const Expected& e);

    // Whether the vault may have pending rows, without a query once known: a server with none at all (every server but
    // a mirror) answers false after one query per process, a mirror after one per vault; true stays until the process
    // ends (a stale true costs one indexed query per open). Rows are only ever written through this class, which marks
    // a vault the moment it gets one. A database that cannot answer gives false (asked again next time), so the open
    // path never fails on this check.
    [[nodiscard]] static bool mayHavePending(uint32_t vaultId);
};

}
