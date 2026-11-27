#pragma once

#include "db/query/mirror/Log.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "mirror/Hash.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// The planned switch of the core role (migration 168, mirror_switch; design/peers/mirror.md "Planned switch", "As
// built: the planned switch"). The rows mirror::switching reads and writes; callers authorize. Every write that changes
// a vault's role or its `switching` state republishes rbac::mirrored and mirror::access before it returns.
namespace vh::db::query::mirror {

struct Switch {
    uint64_t id{};
    std::string switch_id{};   // uuid text, the same on both servers
    uint32_t vault_id{};
    uint32_t peer_id{};
    std::string side{};        // this server's role when the switch began: core | mirror
    // core: draining | preparing | switched | abandoned; mirror: requested | preparing | prepared | switched | abandoned
    std::string phase{};
    uint64_t term{};           // the term the switch leaves (the new one is term + 1)
    std::optional<uint64_t> seq{};                 // the core's last numbered row under the freeze
    std::optional<vh::mirror::Digest> digest{};    // the core's digest there
    std::vector<std::string> writers{};            // core: the writers the freeze waits for
    bool notify{false};        // core: the decision is not yet told to the mirror
    bool accept_no_access{false};   // the old core may hold no role on the vault afterwards (the person said so)
    std::string asked_on{};    // core | mirror
    std::optional<Account> asked_by{};
    std::string asked_by_name{};
    std::optional<std::string> reason{};
    nlohmann::json detail{};
    std::time_t deadline{};
    std::time_t created_at{};
    std::time_t updated_at{};
    std::optional<std::time_t> ended_at{};

    [[nodiscard]] bool open() const { return !ended_at.has_value(); }
};

// Who asked for a switch and on which server.
struct SwitchAsked {
    std::string on{};          // core | mirror
    std::optional<Account> by{};
    std::string name{};
};

class Switches {
public:
    [[nodiscard]] static std::optional<Switch> get(uint64_t id);
    [[nodiscard]] static std::optional<Switch> bySwitchId(const std::string& switchId, const std::string& side);
    // The vault's open switch here (at most one), and the newest one whatever its phase.
    [[nodiscard]] static std::optional<Switch> openOf(uint32_t vaultId);
    [[nodiscard]] static std::optional<Switch> latestOf(uint32_t vaultId);
    // What the follower's pass looks at: every open switch, and every decided one not yet told.
    [[nodiscard]] static std::vector<Switch> active();
    // The vault's switches, newest first.
    [[nodiscard]] static std::vector<Switch> history(uint32_t vaultId, std::size_t limit);

    // ---- the core

    // The freeze: the vault's `core` row (live) becomes `switching` and a switch begins (phase draining), in one
    // transaction under the row's lock (FOR UPDATE, which every enqueue and claim of a submission takes a key share of:
    // none is queued or running after it, Pending). ops::Refused: mirror_not_live (the row is not a live core),
    // mirror_switch_running (one is open), mirror_submissions_queued (the mirror's changes are being executed here);
    // ops::NotFound without a core row.
    static Switch freeze(uint32_t vaultId, const SwitchAsked& asked, std::chrono::seconds timeout,
                         const std::optional<std::string>& switchId = std::nullopt, bool acceptNoAccess = false);
    // The writers of the vault tables running now (their virtual transaction ids: fs_entry, files, directories,
    // symlinks, files_trashed, vault, sync, fsync, rsync, vault_recovery_policy, vault_keys), read after the freeze
    // committed: every one that may have changed the vault without seeing it. Recorded on the switch.
    [[nodiscard]] static std::vector<std::string> writersNow();
    static void recordWriters(uint64_t id, const std::vector<std::string>& writers);
    [[nodiscard]] static bool anyRunning(const std::vector<std::string>& writers);
    // Once the writers ended and the sequencer numbered what they logged: the position and digest the switch hands
    // over (the row's last_seq and digest), phase preparing. nullopt and the reason when it can't: the row is no longer
    // a switching core of this switch, or a row still waits for a number.
    struct Drained {
        std::optional<Switch> sw{};
        std::string why{};
    };
    static Drained drained(uint64_t id);
    // The decision `switched` on the core, in one transaction under the row's lock: only while the row is still this
    // switch's switching core at the position drained, nothing waits for a number and no submission is queued or
    // running. The row becomes the vault's `mirror` in term + 1 (position (term + 1, 0), its digest and entry hashes
    // kept, first copy finished, still `switching` until the new core confirms), its log, baseline and submissions go,
    // the start's offer changes side; the switch is `switched`, the decision to be told. "" or the reason it could
    // not.
    static std::string commitCore(uint64_t id);
    // The decision `abandoned` on the core: a core row still switching for it goes live again in the same term; the
    // switch is `abandoned` with the reason, the decision to be told. False when the switch had ended already.
    static bool abandonCore(uint64_t id, const std::string& reason, const nlohmann::json& detail);
    // The mirror was told the decision: notify cleared; for `switched`, this server's row (now the mirror, switching)
    // goes live. False when there was nothing to tell.
    static bool told(uint64_t id);
    // The core's last word from the mirror (prepare's answer), kept for `vh mirror info` and the abandon's reason.
    static void noteDetail(uint64_t id, const nlohmann::json& detail);

    // ---- the mirror

    // This server asked its core for a switch and the core began one: recorded (phase requested) unless the core's
    // prepare arrived first. The vault's row is not frozen by this: the prepare freezes it.
    static Switch requested(uint32_t vaultId, uint32_t peerId, const std::string& switchId, uint64_t term,
                            const SwitchAsked& asked, std::chrono::seconds timeout, bool acceptNoAccess = false);
    // A requested switch the core never prepared, past its deadline: ended `abandoned` here. How many.
    static std::size_t expireRequested();

    // The core's prepare: the vault's `mirror` row (live, or switching for this switch) becomes `switching` and the
    // switch is `preparing` here (another switch of the vault still open here, which the core abandoned without this
    // server hearing it, ends abandoned: the core prepares one switch at a time). Under the row's lock with a bounded
    // wait (lock_timeout): ops::Conflict when the row is busy. ops::Refused mirror_not_live, mirror_switch_ended (this
    // switch ended here already). Returns the switch as it is now.
    static Switch prepareMirror(uint32_t vaultId, uint32_t peerId, const std::string& switchId, uint64_t term,
                                uint64_t seq, const vh::mirror::Digest& digest, const SwitchAsked& asked,
                                std::chrono::seconds timeout);
    // What stands between this mirror and the switch: changes made here still pending (or entries dirty), files whose
    // contents have not arrived here.
    struct Obstacles {
        uint64_t pending{};
        uint64_t dirty{};
        uint64_t contents{};
    };
    [[nodiscard]] static Obstacles obstacles(uint32_t vaultId);
    // The mirror is at the core's position with its digest and nothing stands in the way: `prepared` (it answers ready
    // and waits for the decision). False when the switch is not `preparing` here.
    static bool markPrepared(uint64_t id);
    // The decision `switched` on the mirror, in one transaction under the row's lock: only while the row is this
    // switch's switching mirror at the position prepared. The row becomes the vault's `core` in term + 1 (live, its log
    // starting at (term + 1, 1), its baseline position (term + 1, 0) with its digest, the grant gone), the start's offer
    // changes side; the switch is `switched`. "" or the reason it could not.
    static std::string becomeCore(uint64_t id);
    // The decision `abandoned` on the mirror (or a switch this server can't go on with): a row still switching for it
    // goes live again; the switch is `abandoned`. False when it had ended already.
    static bool abandonMirror(uint64_t id, const std::string& reason, const nlohmann::json& detail = nlohmann::json::object());

    // The link to the switch's other server is gone (unlinked, or its row removed): the switch ends here, open or not
    // (abandoned, mirror_unlinked, when it was open), nothing is left to tell, and the vault's row is no longer held
    // `switching` whatever its role now (a core goes live again; a copy the unlink orphaned keeps its role). False when
    // there was nothing to end.
    static bool endUnlinked(uint64_t id);

    // Whether the follower applies the core's log to the vault while it is switching here: the mirror's switch is
    // still `preparing` (it catches up to the core's position).
    [[nodiscard]] static bool following(uint32_t vaultId);
};

}
