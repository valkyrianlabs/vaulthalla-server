#pragma once

#include "mirror/Hash.hpp"

#include <compare>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The `mirror_vault` table (migration 160; design/peers/mirror.md "Moving the core"): one row per mirrored vault on
// this server. A row whose role is `core` is what switches the replication log on for its vault. Internal API: nothing
// creates rows yet but tests (no ws, CLI or peer command); callers authorize.
namespace vh::db::query::mirror {

// A place in a vault's replication log. Within a term, seq counts rows from 1 with no gaps.
struct Position {
    uint64_t term{};
    uint64_t seq{};
    auto operator<=>(const Position&) const = default;
};

struct MirrorVault {
    uint32_t vault_id{};
    uint32_t peer_id{};
    std::string role{};    // core | mirror | orphaned
    uint64_t term{};
    uint64_t last_seq{};   // core: the last row numbered; mirror: the last applied
    std::optional<Position> acked{};   // core: what the mirror acknowledged; mirror: what it last acknowledged
    Position pruned{};     // retention dropped every row at or below this
    vh::mirror::Digest digest{};       // core: the vault's digest at (term, last_seq)
    std::string state{};   // live | paused | diverged
    std::time_t created_at{};
    std::time_t updated_at{};
    std::optional<std::time_t> numbered_at{};
    std::optional<std::time_t> acked_at{};

    [[nodiscard]] Position position() const { return {term, last_seq}; }
};

class MirrorVaults {
public:
    [[nodiscard]] static std::optional<MirrorVault> get(uint32_t vaultId);
    [[nodiscard]] static std::vector<MirrorVault> list();

    // Makes this server the core of `vaultId` for the linked server `peerId`, at `term`: the log records the vault's
    // changes from this transaction's commit on, and the digest starts as the tree's. Holds a SHARE lock on the entry
    // tables while it reads the tree (every writer waits, briefly: the time to hash the vault's entries), so that no
    // change is half in the baseline and half missing from the log; it waits for no more than kLockWait at a time for
    // writers already running (and retries), so it never sits in a deadlock with one. Makes sure this server has its
    // node id (device_node), which names its local accounts. ops::NotFound without the vault or a live peer;
    // ops::Conflict when the vault is mirrored already.
    static constexpr int kLockWaitMs = 200;
    static constexpr int kLockAttempts = 50;
    static MirrorVault startCore(uint32_t vaultId, uint32_t peerId, uint64_t term = 1);

    // Ends the vault's mirror record on this server and drops its log and entry hashes. False when there was none.
    static bool remove(uint32_t vaultId);

    // Core: the mirror acknowledged every row up to `at`. Never moves backwards, never past what was numbered.
    // False (nothing changed) otherwise or when this server is not the vault's core.
    static bool acknowledge(uint32_t vaultId, Position at);

    // live | paused | diverged. False without a row.
    static bool setState(uint32_t vaultId, const std::string& state);
};

}
