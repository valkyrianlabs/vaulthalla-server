#pragma once

#include "mirror/Hash.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/transaction>

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

    // Migration 164 (design/peers/mirror.md "As built: following the core").
    // Core: where the baseline was taken, its digest and how many entries it serves (until the mirror acknowledges);
    // mirror: what the core said of its baseline in its first tree answer.
    std::optional<Position> baseline{};
    std::optional<vh::mirror::Digest> baseline_digest{};
    uint64_t baseline_rows{};
    uint64_t copy_cursor{};            // mirror: the last baseline entry applied
    bool copy_finished{false};         // mirror: the first copy is complete and matched the baseline's digest
    // Why the state is diverged, expired or stopped: a code and its details (no key material ever).
    std::optional<std::string> stop_reason{};
    nlohmann::json stop_detail{};
    std::optional<std::time_t> stopped_at{};

    [[nodiscard]] Position position() const { return {term, last_seq}; }
};

// What the core answers an acknowledgement (peer.mirror.ack).
struct AckOutcome {
    bool known{false};       // the position is one the core can say its digest at (the baseline or a group's end)
    bool match{false};       // the mirror's digest there is the core's
    bool recorded{false};    // the acknowledgement moved (retention may now pass it)
    vh::mirror::Digest core_digest{};
};

class MirrorVaults {
public:
    [[nodiscard]] static std::optional<MirrorVault> get(uint32_t vaultId);
    // In the caller's transaction; `forUpdate` locks the row.
    [[nodiscard]] static std::optional<MirrorVault> get(pqxx::work& txn, uint32_t vaultId, bool forUpdate);
    [[nodiscard]] static std::vector<MirrorVault> list();

    // Makes this server the core of `vaultId` for the linked server `peerId`, at `term`: the log records the vault's
    // changes from the baseline's commit on, the digest starts as the tree's, and the tree as of that moment is kept
    // (mirror_baseline) for the mirror's first copy. Per vault (migration 164): a committed `starting` row first makes
    // every new writer of this vault wait in its trigger; the writers of the entry tables already running when it
    // committed are waited for (each a bounded wait, kLockWaitMs at a time, at most kLockAttempts); then, under the
    // row's lock, the tree is read, hashed and kept, and the row goes live. Writers of other vaults never wait; writers
    // of this one wait as long as the baseline takes. No change is half in the baseline and half missing from the log.
    // Makes sure this server has its node id (device_node), which names its local accounts. ops::NotFound without the
    // vault or a live peer; ops::Conflict when the vault is mirrored already (or another start of it is running, or its
    // writers did not finish within the bound: try again).
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

    // Ends the vault's mirror record on this server and drops its log, entry hashes and baseline. False when there was
    // none.
    static bool remove(uint32_t vaultId);

    // Core: the mirror acknowledged every row up to `at`. Never moves backwards, never past what was numbered.
    // False (nothing changed) otherwise or when this server is not the vault's core.
    static bool acknowledge(uint32_t vaultId, Position at);

    // live | paused | diverged | expired | stopped. False without a row. `live` clears a recorded stop.
    static bool setState(uint32_t vaultId, const std::string& state);

    // ---- following (migration 164; design/peers/mirror.md "As built: following the core")

    // The vault whose uid is `vaultUuid` (uuid text), with its mirror row; nullopt when no live vault has that uid or it
    // is not mirrored here.
    [[nodiscard]] static std::optional<MirrorVault> byVaultUid(const std::string& vaultUuid);
    // The vault's uid (uuid text), nullopt without a live vault.
    [[nodiscard]] static std::optional<std::string> vaultUidOf(uint32_t vaultId);

    // Stops the vault: `state` is diverged, expired or stopped, with a reason code and its details (bounded; never
    // key material). False without a row.
    static bool stop(uint32_t vaultId, const std::string& state, const std::string& reason,
                     const nlohmann::json& detail = nlohmann::json::object());

    // Core: the vault's digest at `at` (the baseline's position, or the end of a numbered group still in the log);
    // nullopt for any other position.
    [[nodiscard]] static std::optional<vh::mirror::Digest> digestAt(uint32_t vaultId, Position at);

    // Core: peer.mirror.ack. Compares `theirs` with the core's digest at `at`; equal: the acknowledgement is recorded
    // (acknowledge) and the baseline is dropped (the first copy is done); different: the vault stops as diverged
    // (mirror_digest_mismatch) and nothing is recorded. A position below what was acknowledged already is answered as
    // known and matching when it was (a repeated acknowledgement), without comparing.
    static AckOutcome acknowledgeChecked(uint32_t vaultId, Position at, const vh::mirror::Digest& theirs);

    // Mirror: what it last acknowledged to the core (never backwards).
    static bool recordAcknowledged(uint32_t vaultId, Position at);
};

}
