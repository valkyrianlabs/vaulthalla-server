#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// Detach a copy, the database side (migration 169; design/peers/mirror.md "Detach a copy", "As built: detach a copy"):
// one row per copy of a held vault written here as a new local vault, its progress and what it left out. Trusted
// primitives: callers (mirror::copy, ops::mirrors) authorize.
namespace vh::db::query::mirror {

// A file the copy left out, by path: its contents never arrived here (contents_missing), it was removed while the copy
// ran (removed), or its bytes failed authentication (unreadable).
struct CopySkipped {
    std::string path{};
    uint64_t size_bytes{};
    std::string reason{};   // contents_missing | removed | unreadable
};

struct CopyJob {
    uint64_t id{};
    std::optional<uint32_t> source_vault_id{};   // nullopt once the held vault is gone
    std::optional<uint32_t> vault_id{};          // the new vault, while it is written and once it is complete
    std::string name{};
    uint32_t owner_id{};
    std::string state{};                         // running | finished | failed | cancelled
    uint64_t entries_total{}, entries_done{}, bytes_total{}, bytes_done{};
    std::vector<CopySkipped> skipped{};
    std::optional<std::string> error{};
    std::optional<uint32_t> requested_by{}, cancelled_by{};
    bool cancel_requested{false};
    uint32_t attempts{};
    std::time_t created_at{}, updated_at{};
    std::optional<std::time_t> finished_at{};
};

// One live entry of the vault a copy reads (never trash, versions, shares or access rules: none of them is an entry).
struct CopyEntry {
    uint32_t id{};
    std::string kind{};          // directory | file | symlink
    std::string path{};          // vault-relative ("/" is the root)
    uint32_t mode{};
    uint64_t size_bytes{};       // a file's plaintext size
    std::optional<std::string> target{};   // a symlink's
};

struct NewCopy {
    uint32_t source_vault_id{};
    std::string name{};
    uint32_t owner_id{};
    std::optional<uint32_t> requested_by{};
    uint64_t entries_total{}, bytes_total{};
    std::vector<CopySkipped> skipped{};
};

class MirrorCopies {
public:
    // ops::Conflict when a copy of that vault runs already, or one with that owner and name.
    static CopyJob insert(const NewCopy& in);
    [[nodiscard]] static std::optional<CopyJob> get(uint64_t id);
    // The newest copy of the held vault (running or not).
    [[nodiscard]] static std::optional<CopyJob> latestFor(uint32_t sourceVaultId);
    [[nodiscard]] static std::vector<CopyJob> running();
    // The new vaults that running copies write (mirror::access gates them).
    [[nodiscard]] static std::vector<uint32_t> writingTargets();
    // Whether a running copy reserves this name for this owner.
    [[nodiscard]] static bool nameReserved(const std::string& name, uint32_t ownerId);

    // A running copy starts (again): no new vault yet, nothing done, the plan's totals and skipped list, one attempt
    // more. False when it is not running.
    static bool begin(uint64_t id, uint64_t entriesTotal, uint64_t bytesTotal, const std::vector<CopySkipped>& skipped);
    static bool setTarget(uint64_t id, uint32_t vaultId);
    static void progress(uint64_t id, uint64_t entriesDone, uint64_t bytesDone, const std::vector<CopySkipped>& skipped);
    // A cancel is asked for; false when the copy is not running.
    static bool requestCancel(uint64_t id, std::optional<uint32_t> by);
    // Ends a running copy: finished, failed (with the error) or cancelled. False when it was not running.
    static bool finish(uint64_t id, const std::string& state, const std::optional<std::string>& error);

    // Every live entry of the vault, the root first, then by path (bytewise, so a folder precedes what it holds).
    [[nodiscard]] static std::vector<CopyEntry> entries(uint32_t vaultId);
    // One transaction, with vh.keep_mtime: each new entry takes its source entry's mode and modification time exactly
    // (source entry id -> new entry id).
    static void copyAttributes(const std::vector<std::pair<uint32_t, uint32_t>>& sourceToNew,
                               std::optional<uint32_t> actorId);
};

[[nodiscard]] nlohmann::json toJson(const CopySkipped& s);
[[nodiscard]] nlohmann::json toJson(const std::vector<CopySkipped>& s);

}
