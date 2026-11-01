#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The filesystem change journal (migration 115, fs_change_log): triggers log every entry mutation in its own
// transaction with no revision; sequence() numbers the committed ones in commit order, and list() pages through a
// vault's numbered changes. Callers filter what a principal may see (ops::fs_changes); nothing here knows RBAC.
namespace vh::db::query::fs {

struct Change {
    uint64_t revision{};
    std::string kind{};                  // create | update | rename | move | delete
    uint32_t vault_id{};
    uint32_t entry_id{};
    std::optional<uint32_t> parent_id{};
    std::optional<std::string> entry_type{};  // file | directory | symlink (unknown for an entry in no type table)
    std::string name{};
    std::string path{};                  // vault path
    std::optional<uint32_t> old_parent_id{};  // rename and move
    std::optional<std::string> old_path{};    // rename and move
    std::time_t changed_at{};
};

// What one sequencing pass numbered: the new watermark, and per vault the newest revision it gave out. Resets name the
// vault and account they concern (nullopt: every vault / everyone).
struct Sequenced {
    struct Vault {
        uint32_t vault_id{};
        uint64_t revision{};
    };
    struct Reset {
        std::optional<uint32_t> vault_id{};
        std::optional<uint32_t> user_id{};
        uint64_t revision{};
    };

    uint64_t revision{};
    uint64_t numbered{};
    std::vector<Vault> vaults{};
    std::vector<Reset> resets{};
};

struct ChangePage {
    // The cursor to ask from next: the last change read when `more`, else the watermark.
    uint64_t revision{};
    std::vector<Change> changes{};
    bool more{false};
    // The cursor can't be served: retention dropped changes after it, an authorization change (reset) for this vault
    // and account came after it, or it is newer than anything handed out (another database). `revision` is then the
    // watermark to enumerate at.
    bool expired{false};
};

struct PruneResult {
    uint64_t removed{};
    uint64_t pruned_through{};
};

class ChangeLog {
public:
    // Rows per sequencing transaction; a pass loops until nothing is pending.
    static constexpr uint64_t kSequenceBatch = 10'000;

    // Numbers every committed unnumbered change (in batches) and returns what it handed out.
    static Sequenced sequence();

    // The last revision handed out.
    [[nodiscard]] static uint64_t revision();

    // Up to `limit` numbered changes of `vaultId` after `since`, oldest first (resets are not changes: they expire the
    // cursor when they concern `userId`). Does not sequence.
    [[nodiscard]] static ChangePage list(uint32_t vaultId, uint32_t userId, uint64_t since, uint64_t limit);

    // Drops numbered changes older than `retention`, and beyond the newest `maxRevisions`; never a pending one.
    static PruneResult prune(std::chrono::seconds retention, uint64_t maxRevisions);
};

}
