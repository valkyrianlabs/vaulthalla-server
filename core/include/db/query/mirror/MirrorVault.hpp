#pragma once

#include "mirror/Hash.hpp"

#include <compare>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The `mirror_vault` table (migration 160; design/peers/mirror.md "Moving the core"): one row per mirrored vault on
// this server. A row whose role is `core` is what switches the replication log on for its vault; a `mirror` (or
// `orphaned`) row is a vault this server holds as another server's copy, with what that server granted it (migration
// 162; rbac::mirrored resolves it). Internal API: nothing creates rows yet but tests (no ws, CLI or peer command);
// callers authorize. Every write that adds, removes or changes a row's role or grant republishes rbac::mirrored before
// it returns.
namespace vh::db::query::mirror {

// A place in a vault's replication log. Within a term, seq counts rows from 1 with no gaps.
struct Position {
    uint64_t term{};
    uint64_t seq{};
    auto operator<=>(const Position&) const = default;
};

// What the core granted this server for a vault it mirrors (migration 162): the role by name with its actual
// permissions, in vault_role's bit layout (rbac::role::Vault's masks), the granting server's node id and when. Never
// matched to a role of this server (design/peers/identity.md).
struct Grant {
    std::string role_name{};
    uint64_t files{}, directories{}, sync{}, roles{};
    std::string granted_by_node{};
    std::time_t granted_at{};
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
    std::optional<Grant> grant{};      // mirror, orphaned: what the core granted this server; never on a core row

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

    // Makes this server the mirror of `vaultId` for the linked server `peerId` (its core), at `term`: the vault follows
    // that server, its files' contents may be waited for (PendingContents), and nothing is logged for it. It starts
    // with no grant: nobody here has access until the core's grant is recorded (recordGrant). Internal API: the first
    // copy (a later piece) creates the vault and calls this; until then only tests do.
    // ops::NotFound without the vault or a live peer; ops::Conflict when the vault is mirrored already.
    static MirrorVault startMirror(uint32_t vaultId, uint32_t peerId, uint64_t term = 1);

    // What the core granted this server for a vault it mirrors (replacing any earlier grant): role name 1-50
    // characters, node id 1-64; granted_at 0 means now. False when the vault has no mirror or orphaned row here.
    static bool recordGrant(uint32_t vaultId, const Grant& grant);
    // Forgets the grant (nobody here has access). False when there was none.
    static bool clearGrant(uint32_t vaultId);

    // Ends the vault's mirror record on this server and drops its log and entry hashes. False when there was none.
    static bool remove(uint32_t vaultId);

    // Core: the mirror acknowledged every row up to `at`. Never moves backwards, never past what was numbered.
    // False (nothing changed) otherwise or when this server is not the vault's core.
    static bool acknowledge(uint32_t vaultId, Position at);

    // live | paused | diverged. False without a row.
    static bool setState(uint32_t vaultId, const std::string& state);
};

}
