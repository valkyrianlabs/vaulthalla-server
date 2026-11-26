#pragma once

#include "db/query/mirror/MirrorVault.hpp"
#include "mirror/Hash.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <pqxx/transaction>

// The replication log of the vaults this server is the core of (migration 160, vault_replication_log; design/peers/
// mirror.md "The replication log"). Triggers write the rows in each mutation's own transaction with no sequence
// number; sequence() numbers them, whole transactions (groups) at a time, in commit order; groupsAfter() pages through
// what was numbered, cut only between groups. Consumers (the peer protocol, later) read through here.
namespace vh::db::query::mirror {

// An account as every server names it: its home server's node id and its id there (design/peers/identity.md).
struct Account {
    std::string node{};
    uint32_t id{};
};

struct Row {
    uint64_t term{};
    uint64_t seq{};
    uint64_t txid{};
    std::string op{};   // upsert | move | trash | restore | purge | delete | vault | key
    std::optional<std::string> entry_uid{};    // the entry's permanent id (the vault's uid for `vault`)
    std::optional<std::string> entry_type{};   // file | directory | symlink
    std::optional<std::string> parent_uid{};
    std::optional<std::string> name{};
    nlohmann::json state{};                    // the entry (vault, key record) as the change left it
    std::optional<vh::mirror::Hash> entry_hash{};   // of `state`; none for a removal, a vault or key record
    std::optional<vh::mirror::Hash> prev_hash{};    // of the state it replaced; none for a creation
    std::optional<Account> actor{};
    std::optional<std::string> origin{};       // a mirror's request id, when the change was submitted by it
    std::time_t logged_at{};
};

// The rows of one transaction on the core, in their order.
struct Group {
    uint64_t term{};
    uint64_t txid{};
    uint64_t first_seq{};
    uint64_t last_seq{};
    std::vector<Row> rows{};
};

struct Page {
    std::vector<Group> groups{};
    // Where the next page starts: the last row returned, or the position asked from when nothing was.
    Position last{};
    bool more{false};
    // The position asked from is below what retention kept (or the vault is not this server's core): the consumer
    // resynchronises.
    bool expired{false};
};

struct Sequenced {
    struct Vault {
        uint32_t vault_id{};
        Position last{};   // the newest row numbered
        uint64_t groups{};
        uint64_t rows{};
    };
    std::vector<Vault> vaults{};
    uint64_t rows{};
};

struct Pruned {
    uint64_t rows{};       // numbered rows retention dropped
    uint64_t orphans{};    // rows and entry hashes of vaults that are no longer mirrored here
};

class Log {
public:
    // Rows per numbering transaction (a group larger than this is still numbered whole, alone).
    static constexpr std::size_t kSequenceBatch = 10'000;
    static constexpr std::size_t kMaxPageRows = 10'000;

    // Whether any row is waiting for a number (a cheap read on the pending index).
    [[nodiscard]] static bool pending();

    // Numbers every committed group of every core vault: per vault, under its mirror_vault row lock, in the order
    // each group's last row was written, continuing the vault's sequence; the vault's digest moves with it. Rows of a
    // vault that is not (or no longer) this server's core, or of an older term, are left alone.
    static Sequenced sequence();
    static std::optional<Sequenced::Vault> sequence(uint32_t vaultId);

    // Up to `limit` rows (1..kMaxPageRows) of whole groups numbered after `after`, oldest first. A first group larger
    // than `limit` comes whole. Does not sequence.
    [[nodiscard]] static Page groupsAfter(uint32_t vaultId, Position after, std::size_t limit);
    // Up to `limit` numbered rows of one group (term, txid) after `afterSeq`, in order: a group too large for one answer
    // is served in parts (peer.mirror.log). Does not check retention: the caller pages from a groupsAfter it read.
    [[nodiscard]] static std::vector<Row> groupRows(uint32_t vaultId, uint64_t term, uint64_t txid, uint64_t afterSeq,
                                                    std::size_t limit);
    // The first and last numbered seq of one group, nullopt when no numbered row of it is in the log.
    [[nodiscard]] static std::optional<std::pair<uint64_t, uint64_t>> groupSpan(uint32_t vaultId, uint64_t term,
                                                                                uint64_t txid);

    // Retention (the Janitor): numbered rows older than `maxAge`, or more than `maxRows` behind the vault's last
    // number, go, but never one the mirror has not acknowledged; pending rows never. Rows and entry hashes of vaults
    // that have no core mirror_vault row are removed.
    static Pruned prune(std::chrono::seconds maxAge, uint64_t maxRows);

    // Marks `txn` as applying a core's changes (SET LOCAL vh.mirror_apply = 'on', the mirror's applier): its changes
    // write no log rows and move no entry hash.
    static void markMirrorApply(pqxx::work& txn);
};

class Digests {
public:
    // The vault's digest recomputed from its entries as the tables hold them now (the scrub; vh_mirror_tree), in
    // its own snapshot. Independent of the log and of the stored entry hashes.
    [[nodiscard]] static vh::mirror::Digest recompute(uint32_t vaultId);
    // The digest of the entry hashes the log last recorded (mirror_entry_hash), numbered or not.
    [[nodiscard]] static vh::mirror::Digest stored(uint32_t vaultId);
    // vh_mirror_state_hash of a state document (tests check it against mirror::entryHash).
    [[nodiscard]] static vh::mirror::Hash hashInDatabase(const nlohmann::json& state);
};

}
