#include "db/query/mirror/Switch.hpp"

#include "db/Transactions.hpp"
#include "mirror/access/Access.hpp"
#include "ops/Error.hpp"
#include "rbac/Mirrored.hpp"

#include <pqxx/pqxx>
#include <pqxx/subtransaction>

#include <string>
#include <vector>

namespace vh::db::query::mirror {

namespace {

constexpr const char* kSwitchColumns = R"SQL(
    id, switch_id::text AS switch_id, vault_id, peer_id, side, phase, term, seq, encode(digest, 'hex') AS digest,
    entries, COALESCE(array_to_json(writers)::text, '[]') AS writers, notify, accept_no_access, asked_on, asked_by_node, asked_by_id,
    asked_by_name, reason, detail::text AS detail,
    EXTRACT(EPOCH FROM deadline)::BIGINT AS deadline, EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at,
    EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at, EXTRACT(EPOCH FROM ended_at)::BIGINT AS ended_at
)SQL";

std::string switchSelect(const std::string& where) {
    return std::string("SELECT ") + kSwitchColumns + " FROM mirror_switch " + where;
}

Switch switchFrom(const pqxx::row_ref row) {
    Switch s;
    s.id = row["id"].as<uint64_t>();
    s.switch_id = row["switch_id"].as<std::string>();
    s.vault_id = row["vault_id"].as<uint32_t>();
    s.peer_id = row["peer_id"].as<uint32_t>();
    s.side = row["side"].as<std::string>();
    s.phase = row["phase"].as<std::string>();
    s.term = row["term"].as<uint64_t>();
    if (!row["seq"].is_null()) s.seq = row["seq"].as<uint64_t>();
    if (!row["digest"].is_null())
        s.digest = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(row["digest"].as<std::string>()),
                                                 row["entries"].is_null() ? 0 : row["entries"].as<int64_t>());
    for (const auto& w : nlohmann::json::parse(row["writers"].as<std::string>()))
        if (w.is_string()) s.writers.push_back(w.get<std::string>());
    s.notify = row["notify"].as<bool>();
    s.accept_no_access = row["accept_no_access"].as<bool>();
    s.asked_on = row["asked_on"].as<std::string>();
    if (!row["asked_by_node"].is_null() && !row["asked_by_id"].is_null())
        s.asked_by = Account{.node = row["asked_by_node"].as<std::string>(), .id = row["asked_by_id"].as<uint32_t>()};
    if (!row["asked_by_name"].is_null()) s.asked_by_name = row["asked_by_name"].as<std::string>();
    if (!row["reason"].is_null()) s.reason = row["reason"].as<std::string>();
    s.detail = row["detail"].is_null() ? nlohmann::json::object() : nlohmann::json::parse(row["detail"].as<std::string>());
    s.deadline = static_cast<std::time_t>(row["deadline"].as<int64_t>());
    s.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    s.updated_at = static_cast<std::time_t>(row["updated_at"].as<int64_t>());
    if (!row["ended_at"].is_null()) s.ended_at = static_cast<std::time_t>(row["ended_at"].as<int64_t>());
    return s;
}

std::optional<Switch> switchOne(pqxx::transaction_base& txn, const std::string& where, const pqxx::params& params) {
    const auto r = txn.exec(switchSelect(where), params);
    if (r.empty()) return std::nullopt;
    return switchFrom(r[0]);
}

// Whoever resolves a permission on the vault, and every write surface, sees the change before the write returns.
void switchRepublish(const bool roles) {
    if (roles) vh::rbac::mirrored::reload();
    vh::mirror::access::reload();
}

std::string switchDetail(const nlohmann::json& detail) {
    auto text = detail.is_null() ? std::string("{}") : detail.dump();
    if (text.size() > 8 * 1024) text = nlohmann::json{{"truncated", true}}.dump();
    return text;
}

// The start's offer of the vault (its last `started` one here) changes side with the role, so ending the mirror later
// is told to the other server from whichever side is the core now (mirror::start's cancel reads the core's offer).
void switchFlipOffer(pqxx::work& txn, const uint32_t vaultId) {
    txn.exec("UPDATE mirror_offer SET side = CASE side WHEN 'core' THEN 'mirror' ELSE 'core' END, "
             "  updated_at = CURRENT_TIMESTAMP "
             "WHERE id = (SELECT o.id FROM mirror_offer o JOIN vault v ON v.uid = o.vault_uid "
             "            WHERE v.id = $1 AND o.state = 'started' ORDER BY o.id DESC LIMIT 1)",
             pqxx::params{vaultId});
}

bool switchQueuedSubmissions(pqxx::work& txn, const uint32_t vaultId) {
    return txn.exec("SELECT EXISTS (SELECT 1 FROM mirror_submission WHERE vault_id = $1 AND state IN ('queued', 'running'))",
                    pqxx::params{vaultId})
        .one_field()
        .as<bool>();
}

bool switchUnnumbered(pqxx::work& txn, const uint32_t vaultId) {
    return txn.exec("SELECT EXISTS (SELECT 1 FROM vault_replication_log WHERE vault_id = $1 AND seq IS NULL)",
                    pqxx::params{vaultId})
        .one_field()
        .as<bool>();
}

// The row's lock with a bounded wait: a link thread never sits behind a long transaction.
void switchLockRow(pqxx::work& txn, const uint32_t vaultId, const char* timeout) {
    pqxx::subtransaction sub(txn, "mirror_switch_lock");
    try {
        sub.exec(std::string("SET LOCAL lock_timeout = '") + timeout + "'");
        sub.exec("SELECT 1 FROM mirror_vault WHERE vault_id = $1 FOR UPDATE", pqxx::params{vaultId});
        sub.exec("SET LOCAL lock_timeout TO DEFAULT");
        sub.commit();
    } catch (const pqxx::sql_error& e) {
        sub.abort();
        if (e.sqlstate() == "55P03") throw vh::ops::Conflict("the vault's mirror record is busy; try again");
        throw;
    }
}

// Who asked, as the four columns take it.
struct SwitchAskedColumns {
    std::string on{};
    std::optional<std::string> node{};
    std::optional<int64_t> id{};
    std::string name{};
};

SwitchAskedColumns switchAskedColumns(const SwitchAsked& asked) {
    SwitchAskedColumns c;
    c.on = asked.on;
    c.name = asked.name.substr(0, 255);
    if (asked.by) {
        c.node = asked.by->node.substr(0, 64);
        c.id = static_cast<int64_t>(asked.by->id);
    }
    return c;
}

}

std::optional<Switch> Switches::get(const uint64_t id) {
    return Transactions::exec("mirror::Switches::get", [&](pqxx::work& txn) {
        return switchOne(txn, "WHERE id = $1", pqxx::params{static_cast<int64_t>(id)});
    });
}

std::optional<Switch> Switches::bySwitchId(const std::string& switchId, const std::string& side) {
    return Transactions::exec("mirror::Switches::bySwitchId", [&](pqxx::work& txn) -> std::optional<Switch> {
        pqxx::subtransaction sub(txn, "mirror_switch_by_uid");
        try {
            auto out = switchOne(sub, "WHERE switch_id = $1::uuid AND side = $2", pqxx::params{switchId, side});
            sub.commit();
            return out;
        } catch (const pqxx::data_exception&) {
            sub.abort();
            return std::nullopt;   // not a uuid: no such switch
        }
    });
}

std::optional<Switch> Switches::openOf(const uint32_t vaultId) {
    return Transactions::exec("mirror::Switches::openOf", [&](pqxx::work& txn) {
        return switchOne(txn, "WHERE vault_id = $1 AND ended_at IS NULL", pqxx::params{vaultId});
    });
}

std::optional<Switch> Switches::latestOf(const uint32_t vaultId) {
    return Transactions::exec("mirror::Switches::latestOf", [&](pqxx::work& txn) {
        return switchOne(txn, "WHERE vault_id = $1 ORDER BY id DESC LIMIT 1", pqxx::params{vaultId});
    });
}

std::vector<Switch> Switches::active() {
    return Transactions::exec("mirror::Switches::active", [&](pqxx::work& txn) {
        std::vector<Switch> out;
        for (const auto row : txn.exec(switchSelect("WHERE ended_at IS NULL OR notify ORDER BY id")))
            out.push_back(switchFrom(row));
        return out;
    });
}

std::vector<Switch> Switches::history(const uint32_t vaultId, const std::size_t limit) {
    return Transactions::exec("mirror::Switches::history", [&](pqxx::work& txn) {
        std::vector<Switch> out;
        for (const auto row : txn.exec(switchSelect("WHERE vault_id = $1 ORDER BY id DESC LIMIT $2"),
                                       pqxx::params{vaultId, static_cast<int64_t>(limit)}))
            out.push_back(switchFrom(row));
        return out;
    });
}

// ---- the core ----------------------------------------------------------------------------------------------------------

Switch Switches::freeze(const uint32_t vaultId, const SwitchAsked& asked, const std::chrono::seconds timeout,
                        const std::optional<std::string>& switchId, const bool acceptNoAccess) {
    auto out = Transactions::exec("mirror::Switches::freeze", [&](pqxx::work& txn) {
        switchLockRow(txn, vaultId, "2s");
        const auto mv = MirrorVaults::get(txn, vaultId, false);
        if (!mv || mv->role != "core") throw vh::ops::NotFound("this server is not the vault's core");
        if (!txn.exec("SELECT 1 FROM mirror_switch WHERE vault_id = $1 AND ended_at IS NULL", pqxx::params{vaultId})
                 .empty())
            throw vh::ops::Refused("mirror_switch_running", "a switch of this vault is running already");
        if (mv->state != "live")
            throw vh::ops::Refused("mirror_not_live", "the vault's mirror is " + mv->state + " here; a switch needs it live");
        // Phase 3: a mirrored vault with a remote moves its remote sync with the role (design "A mirrored vault with a
        // remote"); not built, so such a vault keeps its core.
        if (txn.exec("SELECT type::text FROM vault WHERE id = $1", pqxx::params{vaultId}).one_field().as<std::string>() !=
            "local")
            throw vh::ops::Refused("mirror_has_remote",
                                   "this vault has a remote, whose sync runs on its core; moving the core of such a "
                                   "vault is not built yet");
        if (switchQueuedSubmissions(txn, vaultId))
            throw vh::ops::Refused("mirror_submissions_queued",
                                   "changes the mirror made are being executed here; switch once they are confirmed");
        const auto a = switchAskedColumns(asked);
        const pqxx::params params{switchId.value_or(""), vaultId, mv->peer_id, static_cast<int64_t>(mv->term),
                                  static_cast<int64_t>(timeout.count()), a.on, a.node, a.id, a.name, acceptNoAccess};
        const auto id = txn.exec("INSERT INTO mirror_switch (switch_id, vault_id, peer_id, side, phase, term, deadline, "
                                 "  asked_on, asked_by_node, asked_by_id, asked_by_name, accept_no_access) "
                                 "VALUES (COALESCE(NULLIF($1, '')::uuid, gen_random_uuid()), $2, $3, 'core', 'draining', "
                                 "  $4, CURRENT_TIMESTAMP + make_interval(secs => $5), $6, $7, $8, $9, $10) RETURNING id",
                                 params)
                            .one_field()
                            .as<int64_t>();
        txn.exec("UPDATE mirror_vault SET state = 'switching', updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1",
                 pqxx::params{vaultId});
        return *switchOne(txn, "WHERE id = $1", pqxx::params{id});
    });
    switchRepublish(false);
    return out;
}

std::vector<std::string> Switches::writersNow() {
    return Transactions::exec("mirror::Switches::writersNow", [](pqxx::work& txn) {
        std::vector<std::string> out;
        for (const auto row : txn.exec(
                 "SELECT DISTINCT l.virtualtransaction FROM pg_locks l "
                 "WHERE l.locktype = 'relation' AND l.granted AND l.mode = 'RowExclusiveLock' "
                 "  AND l.pid IS DISTINCT FROM pg_backend_pid() "
                 "  AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database()) "
                 "  AND l.relation IN ('fs_entry'::regclass, 'files'::regclass, 'directories'::regclass, "
                 "                     'symlinks'::regclass, 'files_trashed'::regclass, 'vault'::regclass, "
                 "                     'sync'::regclass, 'fsync'::regclass, 'rsync'::regclass, "
                 "                     'vault_recovery_policy'::regclass, 'vault_keys'::regclass)"))
            out.push_back(row[0].as<std::string>());
        return out;
    });
}

void Switches::recordWriters(const uint64_t id, const std::vector<std::string>& writers) {
    std::string list = "{";
    for (const auto& w : writers) {
        if (list.size() > 1) list += ',';
        list += '"' + w + '"';
    }
    list += '}';
    Transactions::exec("mirror::Switches::recordWriters", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_switch SET writers = $2::text[], updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), list});
    });
}

bool Switches::anyRunning(const std::vector<std::string>& writers) {
    if (writers.empty()) return false;
    std::string list = "{";
    for (const auto& w : writers) {
        if (list.size() > 1) list += ',';
        list += '"' + w + '"';
    }
    list += '}';
    return Transactions::exec("mirror::Switches::anyRunning", [&](pqxx::work& txn) {
        return txn.exec("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE virtualtransaction = ANY($1::text[]))",
                        pqxx::params{list})
            .one_field()
            .as<bool>();
    });
}

Switches::Drained Switches::drained(const uint64_t id) {
    return Transactions::exec("mirror::Switches::drained", [&](pqxx::work& txn) -> Drained {
        const auto sw = switchOne(txn, "WHERE id = $1 FOR UPDATE", pqxx::params{static_cast<int64_t>(id)});
        if (!sw || sw->phase != "draining") return {.why = "the switch is not draining"};
        const auto mv = MirrorVaults::get(txn, sw->vault_id, true);
        if (!mv || mv->role != "core" || mv->state != "switching" || mv->term != sw->term)
            return {.why = "the vault is no longer this server's switching core"};
        if (switchUnnumbered(txn, sw->vault_id)) return {.why = "a change still waits for its number"};
        txn.exec("UPDATE mirror_switch SET phase = 'preparing', seq = $2, digest = decode($3, 'hex'), entries = $4, "
                 "  updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), static_cast<int64_t>(mv->last_seq), mv->digest.hex(),
                              mv->digest.entries});
        return {.sw = switchOne(txn, "WHERE id = $1", pqxx::params{static_cast<int64_t>(id)})};
    });
}

std::string Switches::commitCore(const uint64_t id) {
    auto why = Transactions::exec("mirror::Switches::commitCore", [&](pqxx::work& txn) -> std::string {
        const auto sw = switchOne(txn, "WHERE id = $1 FOR UPDATE", pqxx::params{static_cast<int64_t>(id)});
        if (!sw || sw->side != "core") return "no such switch";
        if (sw->phase != "preparing" || !sw->seq || !sw->digest) return "the switch is " + sw->phase;
        const auto mv = MirrorVaults::get(txn, sw->vault_id, true);
        if (!mv || mv->role != "core" || mv->state != "switching") return "the vault is no longer this server's switching core";
        if (mv->term != sw->term || mv->last_seq != *sw->seq || mv->digest != *sw->digest)
            return "the vault moved since the switch numbered its last change";
        if (switchUnnumbered(txn, sw->vault_id)) return "a change waits for its number";
        if (switchQueuedSubmissions(txn, sw->vault_id)) return "changes the mirror made are queued here";
        // The mirror's vault in term + 1: its position (term + 1, 0), the tree as it is (entry hashes, digest), first
        // copy complete; still switching until the new core confirms it took the role.
        txn.exec("UPDATE mirror_vault SET role = 'mirror', term = term + 1, last_seq = 0, acked_term = NULL, "
                 "  acked_seq = NULL, acked_at = NULL, pruned_term = 0, pruned_seq = 0, numbered_at = NULL, "
                 "  baseline_term = NULL, baseline_seq = NULL, baseline_digest = NULL, baseline_entries = NULL, "
                 "  baseline_rows = NULL, baseline_vault = NULL, copy_finished = TRUE, "
                 "  vault_state = vh_mirror_vault_state($1), stop_reason = NULL, stop_detail = NULL, stopped_at = NULL, "
                 "  updated_at = CURRENT_TIMESTAMP "
                 "WHERE vault_id = $1",
                 pqxx::params{sw->vault_id});
        for (const auto* table : {"vault_replication_log", "mirror_baseline", "mirror_submission"})
            txn.exec(std::string("DELETE FROM ") + table + " WHERE vault_id = $1", pqxx::params{sw->vault_id});
        txn.exec("UPDATE mirror_switch SET phase = 'switched', notify = TRUE, ended_at = CURRENT_TIMESTAMP, "
                 "  updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id)});
        switchFlipOffer(txn, sw->vault_id);
        return {};
    });
    if (why.empty()) switchRepublish(true);
    return why;
}

bool Switches::abandonCore(const uint64_t id, const std::string& reason, const nlohmann::json& detail) {
    const bool done = Transactions::exec("mirror::Switches::abandonCore", [&](pqxx::work& txn) {
        const auto sw = switchOne(txn, "WHERE id = $1 FOR UPDATE", pqxx::params{static_cast<int64_t>(id)});
        if (!sw || sw->side != "core" || !sw->open()) return false;
        txn.exec("UPDATE mirror_vault SET state = 'live', updated_at = CURRENT_TIMESTAMP "
                 "WHERE vault_id = $1 AND role = 'core' AND state = 'switching'",
                 pqxx::params{sw->vault_id});
        txn.exec("UPDATE mirror_switch SET phase = 'abandoned', notify = TRUE, reason = $2, detail = $3::jsonb, "
                 "  ended_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), reason.substr(0, 64), switchDetail(detail)});
        return true;
    });
    if (done) switchRepublish(false);
    return done;
}

bool Switches::told(const uint64_t id) {
    const bool done = Transactions::exec("mirror::Switches::told", [&](pqxx::work& txn) {
        const auto sw = switchOne(txn, "WHERE id = $1 FOR UPDATE", pqxx::params{static_cast<int64_t>(id)});
        if (!sw || !sw->notify) return false;
        if (sw->phase == "switched")
            txn.exec("UPDATE mirror_vault SET state = 'live', updated_at = CURRENT_TIMESTAMP "
                     "WHERE vault_id = $1 AND role = 'mirror' AND state = 'switching'",
                     pqxx::params{sw->vault_id});
        txn.exec("UPDATE mirror_switch SET notify = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id)});
        return true;
    });
    if (done) switchRepublish(false);
    return done;
}

void Switches::noteDetail(const uint64_t id, const nlohmann::json& detail) {
    Transactions::exec("mirror::Switches::noteDetail", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_switch SET detail = $2::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), switchDetail(detail)});
    });
}

// ---- the mirror --------------------------------------------------------------------------------------------------------

Switch Switches::requested(const uint32_t vaultId, const uint32_t peerId, const std::string& switchId,
                           const uint64_t term, const SwitchAsked& asked, const std::chrono::seconds timeout,
                           const bool acceptNoAccess) {
    return Transactions::exec("mirror::Switches::requested", [&](pqxx::work& txn) {
        const auto a = switchAskedColumns(asked);
        const pqxx::params params{switchId, vaultId, peerId, static_cast<int64_t>(term),
                                  static_cast<int64_t>(timeout.count()), a.on, a.node, a.id, a.name, acceptNoAccess};
        txn.exec("INSERT INTO mirror_switch (switch_id, vault_id, peer_id, side, phase, term, deadline, asked_on, "
                 "  asked_by_node, asked_by_id, asked_by_name, accept_no_access) "
                 "SELECT $1::uuid, $2, $3, 'mirror', 'requested', $4, CURRENT_TIMESTAMP + make_interval(secs => $5), "
                 "  $6, $7, $8, $9, $10 "
                 "WHERE NOT EXISTS (SELECT 1 FROM mirror_switch WHERE vault_id = $2 AND ended_at IS NULL) "
                 "ON CONFLICT (switch_id, side) DO NOTHING",
                 params);
        const auto sw = switchOne(txn, "WHERE switch_id = $1::uuid AND side = 'mirror'", pqxx::params{switchId});
        if (!sw) throw vh::ops::Refused("mirror_switch_running", "another switch of this vault is open here");
        return *sw;
    });
}

std::size_t Switches::expireRequested() {
    return Transactions::exec("mirror::Switches::expireRequested", [](pqxx::work& txn) {
        return static_cast<std::size_t>(
            txn.exec("UPDATE mirror_switch SET phase = 'abandoned', reason = 'mirror_switch_not_begun', "
                     "  detail = jsonb_build_object('why', 'the core never prepared the switch it was asked for'), "
                     "  ended_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP "
                     "WHERE side = 'mirror' AND phase = 'requested' AND deadline < CURRENT_TIMESTAMP")
                .affected_rows());
    });
}

Switch Switches::prepareMirror(const uint32_t vaultId, const uint32_t peerId, const std::string& switchId,
                               const uint64_t term, const uint64_t seq, const vh::mirror::Digest& digest,
                               const SwitchAsked& asked, const std::chrono::seconds timeout) {
    bool froze = false;
    auto out = Transactions::exec("mirror::Switches::prepareMirror", [&](pqxx::work& txn) {
        switchLockRow(txn, vaultId, "500ms");
        const auto mv = MirrorVaults::get(txn, vaultId, false);
        if (!mv || mv->role != "mirror" || mv->peer_id != peerId) throw vh::ops::NotFound("Not found");
        if (mv->state != "live" && mv->state != "switching")
            throw vh::ops::Refused("mirror_not_live", "the copy is " + mv->state + " on the mirror");
        if (!mv->copy_finished)
            throw vh::ops::Refused("mirror_first_copy", "the mirror's first copy of the vault has not finished");
        if (mv->term != term)
            throw vh::ops::Refused("mirror_term_mismatch", "the mirror follows term " + std::to_string(mv->term));
        auto sw = switchOne(txn, "WHERE switch_id = $1::uuid AND side = 'mirror' FOR UPDATE", pqxx::params{switchId});
        if (sw && !sw->open()) throw vh::ops::Refused("mirror_switch_ended", "this switch ended on the mirror already");
        // Another switch still open here is one the core gave up without this server hearing it: the core prepares one
        // switch of a vault at a time.
        txn.exec("UPDATE mirror_switch SET phase = 'abandoned', reason = 'mirror_switch_superseded', "
                 "  ended_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP "
                 "WHERE vault_id = $1 AND ended_at IS NULL AND switch_id <> $2::uuid",
                 pqxx::params{vaultId, switchId});
        if (!sw) {
            const auto a = switchAskedColumns(asked);
            const pqxx::params params{switchId, vaultId, peerId, static_cast<int64_t>(term), static_cast<int64_t>(seq),
                                      digest.hex(), digest.entries, static_cast<int64_t>(timeout.count()),
                                      a.on, a.node, a.id, a.name};
            txn.exec("INSERT INTO mirror_switch (switch_id, vault_id, peer_id, side, phase, term, seq, digest, entries, "
                     "  deadline, asked_on, asked_by_node, asked_by_id, asked_by_name) "
                     "VALUES ($1::uuid, $2, $3, 'mirror', 'preparing', $4, $5, decode($6, 'hex'), $7, "
                     "  CURRENT_TIMESTAMP + make_interval(secs => $8), $9, $10, $11, $12)",
                     params);
        } else if (sw->phase == "requested") {
            txn.exec("UPDATE mirror_switch SET phase = 'preparing', seq = $2, digest = decode($3, 'hex'), entries = $4, "
                     "  updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                     pqxx::params{static_cast<int64_t>(sw->id), static_cast<int64_t>(seq), digest.hex(), digest.entries});
        }
        if (mv->state == "live") {
            txn.exec("UPDATE mirror_vault SET state = 'switching', updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1",
                     pqxx::params{vaultId});
            froze = true;
        }
        return *switchOne(txn, "WHERE switch_id = $1::uuid AND side = 'mirror'", pqxx::params{switchId});
    });
    if (froze) switchRepublish(false);
    return out;
}

Switches::Obstacles Switches::obstacles(const uint32_t vaultId) {
    return Transactions::exec("mirror::Switches::obstacles", [&](pqxx::work& txn) {
        const auto r = txn.exec(
            "SELECT (SELECT count(*) FROM mirror_pending WHERE vault_id = $1) AS pending, "
            "  (SELECT count(*) FROM mirror_dirty WHERE vault_id = $1) AS dirty, "
            "  (SELECT count(*) FROM mirror_content_pending p "
            "     JOIN files f ON f.object_uid = p.object_uid "
            "     JOIN fs_entry e ON e.id = f.fs_entry_id AND e.vault_id = p.vault_id "
            "   WHERE p.vault_id = $1 AND COALESCE(f.encryption_iv, '') = p.generation) AS contents",
            pqxx::params{vaultId});
        return Obstacles{.pending = r[0]["pending"].as<uint64_t>(), .dirty = r[0]["dirty"].as<uint64_t>(),
                         .contents = r[0]["contents"].as<uint64_t>()};
    });
}

bool Switches::markPrepared(const uint64_t id) {
    return Transactions::exec("mirror::Switches::markPrepared", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_switch SET phase = 'prepared', updated_at = CURRENT_TIMESTAMP "
                        "WHERE id = $1 AND side = 'mirror' AND phase = 'preparing'",
                        pqxx::params{static_cast<int64_t>(id)})
                   .affected_rows() > 0;
    });
}

std::string Switches::becomeCore(const uint64_t id) {
    auto why = Transactions::exec("mirror::Switches::becomeCore", [&](pqxx::work& txn) -> std::string {
        const auto sw = switchOne(txn, "WHERE id = $1 FOR UPDATE", pqxx::params{static_cast<int64_t>(id)});
        if (!sw || sw->side != "mirror") return "no such switch";
        if (sw->phase != "prepared" || !sw->seq || !sw->digest) return "the switch is " + sw->phase + " on the mirror";
        const auto mv = MirrorVaults::get(txn, sw->vault_id, true);
        if (!mv || mv->role != "mirror" || mv->state != "switching") return "the copy is no longer switching here";
        if (mv->term != sw->term || mv->last_seq != *sw->seq || mv->digest != *sw->digest)
            return "the copy moved since it was prepared";
        if (!txn.exec("SELECT 1 FROM mirror_pending WHERE vault_id = $1 UNION ALL "
                      "SELECT 1 FROM mirror_dirty WHERE vault_id = $1 LIMIT 1",
                      pqxx::params{sw->vault_id})
                 .empty())
            return "changes made here are pending";
        // The core in term + 1: live, its log from (term + 1, 1), the baseline position (term + 1, 0) at the digest
        // both servers hold (what the new mirror's first acknowledgement is compared with), nothing acknowledged yet,
        // the grant gone (a core holds none).
        txn.exec("UPDATE mirror_vault SET role = 'core', term = term + 1, last_seq = 0, acked_term = NULL, "
                 "  acked_seq = NULL, acked_at = NULL, pruned_term = 0, pruned_seq = 0, numbered_at = NULL, "
                 "  baseline_term = term + 1, baseline_seq = 0, baseline_digest = digest, "
                 "  baseline_entries = digest_entries, baseline_rows = NULL, baseline_vault = vh_mirror_vault_state($1), "
                 "  granted_role_name = NULL, granted_files_permissions = NULL, granted_directories_permissions = NULL, "
                 "  granted_sync_permissions = NULL, granted_roles_permissions = NULL, granted_by_node = NULL, "
                 "  granted_at = NULL, state = 'live', stop_reason = NULL, stop_detail = NULL, stopped_at = NULL, "
                 "  updated_at = CURRENT_TIMESTAMP "
                 "WHERE vault_id = $1",
                 pqxx::params{sw->vault_id});
        for (const auto* table : {"vault_replication_log", "mirror_baseline", "mirror_submission"})
            txn.exec(std::string("DELETE FROM ") + table + " WHERE vault_id = $1", pqxx::params{sw->vault_id});
        txn.exec("UPDATE mirror_switch SET phase = 'switched', ended_at = CURRENT_TIMESTAMP, "
                 "  updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id)});
        switchFlipOffer(txn, sw->vault_id);
        return {};
    });
    if (why.empty()) switchRepublish(true);
    return why;
}

bool Switches::abandonMirror(const uint64_t id, const std::string& reason, const nlohmann::json& detail) {
    const bool done = Transactions::exec("mirror::Switches::abandonMirror", [&](pqxx::work& txn) {
        const auto sw = switchOne(txn, "WHERE id = $1 FOR UPDATE", pqxx::params{static_cast<int64_t>(id)});
        if (!sw || sw->side != "mirror" || !sw->open()) return false;
        txn.exec("UPDATE mirror_vault SET state = 'live', updated_at = CURRENT_TIMESTAMP "
                 "WHERE vault_id = $1 AND role = 'mirror' AND state = 'switching'",
                 pqxx::params{sw->vault_id});
        txn.exec("UPDATE mirror_switch SET phase = 'abandoned', reason = $2, detail = $3::jsonb, "
                 "  ended_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), reason.substr(0, 64), switchDetail(detail)});
        return true;
    });
    if (done) switchRepublish(false);
    return done;
}

bool Switches::endUnlinked(const uint64_t id) {
    const bool done = Transactions::exec("mirror::Switches::endUnlinked", [&](pqxx::work& txn) {
        const auto sw = switchOne(txn, "WHERE id = $1 FOR UPDATE", pqxx::params{static_cast<int64_t>(id)});
        if (!sw || (!sw->open() && !sw->notify)) return false;
        txn.exec("UPDATE mirror_vault SET state = 'live', updated_at = CURRENT_TIMESTAMP "
                 "WHERE vault_id = $1 AND state = 'switching'",
                 pqxx::params{sw->vault_id});
        txn.exec("UPDATE mirror_switch SET phase = CASE WHEN ended_at IS NULL THEN 'abandoned' ELSE phase END, "
                 "  reason = CASE WHEN ended_at IS NULL THEN 'mirror_unlinked' ELSE reason END, notify = FALSE, "
                 "  detail = COALESCE(detail, '{}'::jsonb) || jsonb_build_object('unlinked', true), "
                 "  ended_at = COALESCE(ended_at, CURRENT_TIMESTAMP), updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id)});
        return true;
    });
    if (done) switchRepublish(false);
    return done;
}

bool Switches::following(const uint32_t vaultId) {
    return Transactions::exec("mirror::Switches::following", [&](pqxx::work& txn) {
        return txn.exec("SELECT EXISTS (SELECT 1 FROM mirror_switch WHERE vault_id = $1 AND side = 'mirror' "
                        "  AND phase = 'preparing' AND ended_at IS NULL)",
                        pqxx::params{vaultId})
            .one_field()
            .as<bool>();
    });
}

}
