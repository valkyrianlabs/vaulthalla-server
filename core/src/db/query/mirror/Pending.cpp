#include "db/query/mirror/Pending.hpp"

#include "db/Transactions.hpp"
#include "fs/tree_apply/TreeApply.hpp"
#include "mirror/Hash.hpp"

#include <pqxx/pqxx>

#include <algorithm>
#include <set>

namespace vh::db::query::mirror {

namespace {

using json = nlohmann::json;

std::string pendingUuidArray(const std::vector<std::string>& uids) {
    std::string out = "{";
    for (const auto& u : uids) {
        if (out.size() > 1) out += ',';
        out += u;
    }
    return out + '}';
}

std::vector<std::string> pendingUuidList(const pqxx::field_ref f) {
    std::vector<std::string> out;
    if (f.is_null()) return out;
    // A uuid[] as PostgreSQL writes it: {a,b,c} (uuids need no quoting).
    auto text = f.as<std::string>();
    if (text.size() < 2) return out;
    text = text.substr(1, text.size() - 2);
    std::size_t start = 0;
    while (start < text.size()) {
        const auto comma = text.find(',', start);
        out.push_back(text.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return out;
}

constexpr const char* kPendingSelect = R"SQL(
    SELECT id, vault_id, request_id, entry_uid::text AS entry_uid, op, args::text AS args, base_generation,
           new_generation, actor_node, actor_id, uids::text AS uids, state, groups_expected, groups_applied, attempts,
           last_error, EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at
    FROM mirror_pending
)SQL";

PendingChange pendingFrom(const pqxx::row_ref row) {
    PendingChange p;
    p.id = row["id"].as<uint64_t>();
    p.vault_id = row["vault_id"].as<uint32_t>();
    p.request_id = row["request_id"].as<std::string>();
    p.entry_uid = row["entry_uid"].as<std::string>();
    p.op = row["op"].as<std::string>();
    p.args = json::parse(row["args"].as<std::string>());
    if (!row["base_generation"].is_null()) p.base_generation = row["base_generation"].as<std::string>();
    if (!row["new_generation"].is_null()) p.new_generation = row["new_generation"].as<std::string>();
    p.actor = Account{.node = row["actor_node"].as<std::string>(), .id = row["actor_id"].as<uint32_t>()};
    p.uids = pendingUuidList(row["uids"]);
    p.state = row["state"].as<std::string>();
    if (!row["groups_expected"].is_null()) p.groups_expected = row["groups_expected"].as<uint32_t>();
    p.groups_applied = row["groups_applied"].as<uint32_t>();
    p.attempts = row["attempts"].as<uint32_t>();
    if (!row["last_error"].is_null()) p.last_error = row["last_error"].as<std::string>();
    p.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    return p;
}

constexpr const char* kHeldSelect = R"SQL(
    SELECT id, vault_id, kind, request_id, op, entry_uid::text AS entry_uid, args::text AS args, path, copy_name,
           actor_node, actor_id, reason_code, reason, state, EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at,
           EXTRACT(EPOCH FROM resolved_at)::BIGINT AS resolved_at, resolved_by
    FROM mirror_held
)SQL";

HeldChange heldFrom(const pqxx::row_ref row) {
    HeldChange h;
    h.id = row["id"].as<uint64_t>();
    h.vault_id = row["vault_id"].as<uint32_t>();
    h.kind = row["kind"].as<std::string>();
    h.request_id = row["request_id"].as<std::string>();
    h.op = row["op"].as<std::string>();
    if (!row["entry_uid"].is_null()) h.entry_uid = row["entry_uid"].as<std::string>();
    h.args = json::parse(row["args"].as<std::string>());
    if (!row["path"].is_null()) h.path = row["path"].as<std::string>();
    if (!row["copy_name"].is_null()) h.copy_name = row["copy_name"].as<std::string>();
    h.actor = Account{.node = row["actor_node"].as<std::string>(), .id = row["actor_id"].as<uint32_t>()};
    h.reason_code = row["reason_code"].as<std::string>();
    h.reason = row["reason"].as<std::string>();
    h.state = row["state"].as<std::string>();
    h.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    if (!row["resolved_at"].is_null()) h.resolved_at = static_cast<std::time_t>(row["resolved_at"].as<int64_t>());
    if (!row["resolved_by"].is_null()) h.resolved_by = row["resolved_by"].as<uint32_t>();
    return h;
}

constexpr const char* kSubmissionSelect = R"SQL(
    SELECT vault_id, request_id, peer_id, payload::text AS payload, state, groups, code, error FROM mirror_submission
)SQL";

Submission submissionFrom(const pqxx::row_ref row) {
    Submission s;
    s.vault_id = row["vault_id"].as<uint32_t>();
    s.request_id = row["request_id"].as<std::string>();
    s.peer_id = row["peer_id"].as<uint32_t>();
    s.payload = json::parse(row["payload"].as<std::string>());
    s.state = row["state"].as<std::string>();
    if (!row["groups"].is_null()) s.groups = row["groups"].as<uint32_t>();
    if (!row["code"].is_null()) s.code = row["code"].as<std::string>();
    if (!row["error"].is_null()) s.error = row["error"].as<std::string>();
    return s;
}

// The live state document of the entry with this uid in the vault, or of its trash row; nullopt without either.
std::optional<std::pair<std::string, json>> pendingCurrentState(pqxx::work& txn, const uint32_t vaultId,
                                                                const std::string& uid) {
    const auto at = vh::fs::tree_apply::locate(txn, vaultId, uid);
    if (!at) return std::nullopt;
    if (!at->trashed) {
        const auto r = txn.exec("SELECT vh_mirror_entry_state($1)::text", pqxx::params{at->id});
        if (r.empty() || r[0][0].is_null()) return std::nullopt;
        return std::make_pair(std::string("live"), json::parse(r[0][0].as<std::string>()));
    }
    const auto r = txn.exec("SELECT vh_mirror_trash_state(object_uid, size_bytes, path, trashed_at, trashed_by)::text "
                            "FROM files_trashed WHERE id = $1",
                            pqxx::params{at->id});
    if (r.empty() || r[0][0].is_null()) return std::nullopt;
    return std::make_pair(std::string("trashed"), json::parse(r[0][0].as<std::string>()));
}

}

// ---- the mirror: pending changes ---------------------------------------------------------------------------------------

std::vector<DirtyEntry> Pending::capture(const uint32_t entryId, const bool subtree) {
    return Transactions::exec("Pending::capture", [&](pqxx::work& txn) {
        std::vector<DirtyEntry> out;
        for (const auto row : txn.exec("WITH RECURSIVE t AS (SELECT id FROM fs_entry WHERE id = $1 AND path <> '/' "
                                       "  UNION ALL SELECT e.id FROM fs_entry e JOIN t ON e.parent_id = t.id WHERE $2) "
                                       "SELECT x.s::text FROM (SELECT vh_mirror_entry_state(t.id) AS s FROM t) x "
                                       "WHERE x.s IS NOT NULL",
                                       pqxx::params{entryId, subtree})) {
            auto state = json::parse(row[0].as<std::string>());
            const auto uid = state.value("uid", std::string{});
            if (uid.empty()) continue;
            out.push_back({.uid = uid, .kind = "live", .confirmed = std::move(state)});
        }
        return out;
    });
}

std::optional<DirtyEntry> Pending::captureTrashed(const uint32_t vaultId, const std::string& uid) {
    return Transactions::exec("Pending::captureTrashed", [&](pqxx::work& txn) -> std::optional<DirtyEntry> {
        const auto now = pendingCurrentState(txn, vaultId, uid);
        if (!now || now->first != "trashed") return std::nullopt;
        return DirtyEntry{.uid = uid, .kind = "trashed", .confirmed = now->second};
    });
}

PendingChange Pending::open(const NewPending& change, const std::vector<DirtyEntry>& captured,
                            const std::vector<std::string>& created) {
    return Transactions::exec("Pending::open", [&](pqxx::work& txn) {
        std::vector<std::string> uids;
        std::set<std::string> seen;
        for (const auto& d : captured)
            if (seen.insert(d.uid).second) uids.push_back(d.uid);
        for (const auto& u : created)
            if (seen.insert(u).second) uids.push_back(u);
        const auto row = txn.exec(std::string("INSERT INTO mirror_pending (vault_id, request_id, entry_uid, op, args, "
                                              "  base_generation, new_generation, actor_node, actor_id, uids) "
                                              "VALUES ($1, $2, $3::uuid, $4, $5::jsonb, $6, $7, $8, $9, $10::uuid[]) "
                                              "RETURNING id"),
                                  pqxx::params{change.vault_id, change.request_id, change.entry_uid, change.op,
                                               change.args.dump(), change.base_generation, change.new_generation,
                                               change.actor.node, change.actor.id, pendingUuidArray(uids)})
                             .one_field()
                             .as<uint64_t>();
        // An entry already dirty keeps what the core last confirmed for it.
        for (const auto& d : captured)
            txn.exec("INSERT INTO mirror_dirty (vault_id, entry_uid, confirmed, confirmed_kind) "
                     "VALUES ($1, $2::uuid, $3::jsonb, $4) ON CONFLICT (vault_id, entry_uid) DO NOTHING",
                     pqxx::params{change.vault_id, d.uid,
                                  d.kind == "none" ? std::nullopt : std::optional<std::string>(d.confirmed.dump()),
                                  d.kind});
        for (const auto& u : created)
            txn.exec("INSERT INTO mirror_dirty (vault_id, entry_uid, confirmed, confirmed_kind) "
                     "VALUES ($1, $2::uuid, NULL, 'none') ON CONFLICT (vault_id, entry_uid) DO NOTHING",
                     pqxx::params{change.vault_id, u});
        return pendingFrom(txn.exec(std::string(kPendingSelect) + " WHERE id = $1", pqxx::params{row})[0]);
    });
}

void Pending::ready(const uint64_t id) {
    Transactions::exec("Pending::ready", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_pending SET state = 'pending', updated_at = CURRENT_TIMESTAMP "
                 "WHERE id = $1 AND state = 'local'",
                 pqxx::params{id});
    });
}

void Pending::ready(const uint64_t id, const nlohmann::json& args, const std::optional<std::string>& baseGeneration,
                    const std::optional<std::string>& newGeneration) {
    Transactions::exec("Pending::ready", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_pending SET state = 'pending', args = $2::jsonb, base_generation = $3, new_generation = $4, "
                 "  updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND state = 'local'",
                 pqxx::params{id, args.dump(), baseGeneration, newGeneration});
    });
}

void Pending::abandon(const uint64_t id) {
    Transactions::exec("Pending::abandon", [&](pqxx::work& txn) {
        const auto r = txn.exec(std::string(kPendingSelect) + " WHERE id = $1 FOR UPDATE", pqxx::params{id});
        if (r.empty()) return;
        const auto p = pendingFrom(r[0]);
        txn.exec("DELETE FROM mirror_pending WHERE id = $1", pqxx::params{id});
        for (const auto& uid : p.uids)
            if (!held(txn, p.vault_id, uid, id)) clean(txn, p.vault_id, uid);
    });
}

bool Pending::unchanged(const uint32_t vaultId, const std::vector<DirtyEntry>& captured,
                        const std::vector<std::string>& created) {
    return Transactions::exec("Pending::unchanged", [&](pqxx::work& txn) {
        for (const auto& uid : created)
            if (vh::fs::tree_apply::locate(txn, vaultId, uid)) return false;
        for (const auto& d : captured) {
            const auto now = pendingCurrentState(txn, vaultId, d.uid);
            if (!now || now->first != d.kind) return false;
            if (vh::mirror::entryHash(now->second) != vh::mirror::entryHash(d.confirmed)) return false;
        }
        return true;
    });
}

std::vector<PendingChange> Pending::list(const uint32_t vaultId) {
    return Transactions::exec("Pending::list", [&](pqxx::work& txn) {
        std::vector<PendingChange> out;
        for (const auto row : txn.exec(std::string(kPendingSelect) + " WHERE vault_id = $1 ORDER BY id",
                                       pqxx::params{vaultId}))
            out.push_back(pendingFrom(row));
        return out;
    });
}

std::optional<PendingChange> Pending::get(const uint64_t id) {
    return Transactions::exec("Pending::get", [&](pqxx::work& txn) -> std::optional<PendingChange> {
        const auto r = txn.exec(std::string(kPendingSelect) + " WHERE id = $1", pqxx::params{id});
        if (r.empty()) return std::nullopt;
        return pendingFrom(r[0]);
    });
}

std::optional<PendingChange> Pending::byRequest(pqxx::work& txn, const uint32_t vaultId, const std::string& requestId) {
    const auto r = txn.exec(std::string(kPendingSelect) + " WHERE vault_id = $1 AND request_id = $2 FOR UPDATE",
                            pqxx::params{vaultId, requestId});
    if (r.empty()) return std::nullopt;
    return pendingFrom(r[0]);
}

std::optional<PendingChange> Pending::oldest(const uint32_t vaultId) {
    return Transactions::exec("Pending::oldest", [&](pqxx::work& txn) -> std::optional<PendingChange> {
        const auto r = txn.exec(std::string(kPendingSelect) + " WHERE vault_id = $1 ORDER BY id LIMIT 1",
                                pqxx::params{vaultId});
        if (r.empty()) return std::nullopt;
        return pendingFrom(r[0]);
    });
}

uint64_t Pending::promoteLocal(const uint32_t vaultId) {
    return Transactions::exec("Pending::promoteLocal", [&](pqxx::work& txn) {
        return static_cast<uint64_t>(txn.exec("UPDATE mirror_pending SET state = 'pending', updated_at = "
                                              "CURRENT_TIMESTAMP WHERE vault_id = $1 AND state = 'local'",
                                              pqxx::params{vaultId})
                                         .affected_rows());
    });
}

void Pending::markSubmitted(const uint64_t id) {
    Transactions::exec("Pending::markSubmitted", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_pending SET state = 'submitted', attempts = attempts + 1, "
                 "  submitted_at = COALESCE(submitted_at, CURRENT_TIMESTAMP), updated_at = CURRENT_TIMESTAMP "
                 "WHERE id = $1 AND state IN ('pending', 'submitted')",
                 pqxx::params{id});
    });
}

std::optional<PendingChange> Pending::markExecuted(const uint64_t id, const uint32_t groups) {
    return Transactions::exec("Pending::markExecuted", [&](pqxx::work& txn) -> std::optional<PendingChange> {
        const auto r = txn.exec(std::string("UPDATE mirror_pending SET state = 'executed', groups_expected = $2, "
                                            "  executed_at = COALESCE(executed_at, CURRENT_TIMESTAMP), last_error = NULL, "
                                            "  updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING id"),
                                pqxx::params{id, groups});
        if (r.empty()) return std::nullopt;
        return pendingFrom(txn.exec(std::string(kPendingSelect) + " WHERE id = $1", pqxx::params{id})[0]);
    });
}

void Pending::noteError(const uint64_t id, const std::string& error) {
    Transactions::exec("Pending::noteError", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_pending SET last_error = left($2, 500), updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{id, error});
    });
}

void Pending::resubmit(pqxx::work& txn, const uint64_t id, const std::string& requestId, const nlohmann::json& args) {
    txn.exec("UPDATE mirror_pending SET request_id = $2, args = $3::jsonb, state = 'pending', groups_expected = NULL, "
             "  groups_applied = 0, submitted_at = NULL, executed_at = NULL, last_error = NULL, "
             "  updated_at = CURRENT_TIMESTAMP WHERE id = $1",
             pqxx::params{id, requestId, args.dump()});
}

void Pending::resubmitAs(pqxx::work& txn, const uint64_t id, const std::string& requestId, const std::string& entryUid,
                         const nlohmann::json& args) {
    const auto vault = txn.exec("SELECT vault_id FROM mirror_pending WHERE id = $1", pqxx::params{id});
    if (vault.empty()) return;
    const auto vaultId = vault[0][0].as<uint32_t>();
    txn.exec("UPDATE mirror_pending SET request_id = $2, entry_uid = $3::uuid, args = $4::jsonb, base_generation = NULL, "
             "  uids = ARRAY[$3::uuid], state = 'pending', groups_expected = NULL, groups_applied = 0, submitted_at = NULL, "
             "  executed_at = NULL, last_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
             pqxx::params{id, requestId, entryUid, args.dump()});
    txn.exec("INSERT INTO mirror_dirty (vault_id, entry_uid, confirmed, confirmed_kind) VALUES ($1, $2::uuid, NULL, 'none') "
             "ON CONFLICT (vault_id, entry_uid) DO NOTHING",
             pqxx::params{vaultId, entryUid});
}

std::optional<PendingChange> Pending::countApplied(pqxx::work& txn, const uint32_t vaultId,
                                                   const std::string& requestId) {
    const auto r = txn.exec("UPDATE mirror_pending SET groups_applied = groups_applied + 1, updated_at = "
                            "CURRENT_TIMESTAMP WHERE vault_id = $1 AND request_id = $2 RETURNING id",
                            pqxx::params{vaultId, requestId});
    if (r.empty()) return std::nullopt;
    return pendingFrom(
        txn.exec(std::string(kPendingSelect) + " WHERE id = $1", pqxx::params{r[0][0].as<uint64_t>()})[0]);
}

void Pending::remove(pqxx::work& txn, const uint64_t id) {
    txn.exec("DELETE FROM mirror_pending WHERE id = $1", pqxx::params{id});
}

// ---- the mirror: dirty entries ------------------------------------------------------------------------------------------

std::vector<std::string> Pending::dirtyUids(const uint32_t vaultId) {
    return Transactions::exec("Pending::dirtyUids", [&](pqxx::work& txn) {
        std::vector<std::string> out;
        for (const auto row : txn.exec("SELECT entry_uid::text FROM mirror_dirty WHERE vault_id = $1 ORDER BY entry_uid",
                                       pqxx::params{vaultId}))
            out.push_back(row[0].as<std::string>());
        return out;
    });
}

std::map<std::string, DirtyEntry> Pending::dirty(pqxx::work& txn, const uint32_t vaultId) {
    std::map<std::string, DirtyEntry> out;
    for (const auto row : txn.exec("SELECT entry_uid::text, confirmed_kind, confirmed::text FROM mirror_dirty "
                                   "WHERE vault_id = $1 ORDER BY entry_uid FOR UPDATE",
                                   pqxx::params{vaultId})) {
        DirtyEntry d;
        d.uid = row[0].as<std::string>();
        d.kind = row[1].as<std::string>();
        d.confirmed = row[2].is_null() ? json(nullptr) : json::parse(row[2].as<std::string>());
        out.emplace(d.uid, std::move(d));
    }
    return out;
}

void Pending::confirm(pqxx::work& txn, const uint32_t vaultId, const std::string& uid, const std::string& kind,
                      const nlohmann::json& state) {
    txn.exec("UPDATE mirror_dirty SET confirmed = $3::jsonb, confirmed_kind = $4 WHERE vault_id = $1 AND entry_uid = $2::uuid",
             pqxx::params{vaultId, uid, kind == "none" ? std::nullopt : std::optional<std::string>(state.dump()), kind});
}

bool Pending::held(pqxx::work& txn, const uint32_t vaultId, const std::string& uid, const uint64_t exceptId) {
    return !txn.exec("SELECT 1 FROM mirror_pending WHERE vault_id = $1 AND id <> $3 AND $2::uuid = ANY(uids) LIMIT 1",
                     pqxx::params{vaultId, uid, exceptId})
                .empty();
}

void Pending::clean(pqxx::work& txn, const uint32_t vaultId, const std::string& uid) {
    txn.exec("DELETE FROM mirror_dirty WHERE vault_id = $1 AND entry_uid = $2::uuid", pqxx::params{vaultId, uid});
}

std::optional<std::string> Pending::uidOfEntry(pqxx::work& txn, const uint32_t entryId) {
    const auto r = txn.exec("SELECT COALESCE(f.object_uid, d.uid, s.uid)::text FROM fs_entry e "
                            "LEFT JOIN files f ON f.fs_entry_id = e.id LEFT JOIN directories d ON d.fs_entry_id = e.id "
                            "LEFT JOIN symlinks s ON s.fs_entry_id = e.id WHERE e.id = $1",
                            pqxx::params{entryId});
    if (r.empty() || r[0][0].is_null()) return std::nullopt;
    return r[0][0].as<std::string>();
}

// ---- the mirror: held changes --------------------------------------------------------------------------------------------

uint64_t Pending::hold(pqxx::work& txn, const HeldChange& h) {
    return txn.exec("INSERT INTO mirror_held (vault_id, kind, request_id, op, entry_uid, args, path, copy_name, "
                    "  actor_node, actor_id, reason_code, reason) "
                    "VALUES ($1, $2, $3, $4, $5::uuid, $6::jsonb, $7, $8, $9, $10, $11, left($12, 1000)) RETURNING id",
                    pqxx::params{h.vault_id, h.kind, h.request_id, h.op, h.entry_uid, h.args.dump(), h.path,
                                 h.copy_name, h.actor.node, h.actor.id, h.reason_code, h.reason})
        .one_field()
        .as<uint64_t>();
}

std::vector<HeldChange> Pending::heldChanges(const uint32_t vaultId, const bool includeResolved) {
    return Transactions::exec("Pending::heldChanges", [&](pqxx::work& txn) {
        std::vector<HeldChange> out;
        for (const auto row : txn.exec(std::string(kHeldSelect) + " WHERE vault_id = $1 AND ($2 OR state = 'open') "
                                                                  "ORDER BY id",
                                       pqxx::params{vaultId, includeResolved}))
            out.push_back(heldFrom(row));
        return out;
    });
}

std::optional<HeldChange> Pending::heldChange(const uint64_t id) {
    return Transactions::exec("Pending::heldChange", [&](pqxx::work& txn) -> std::optional<HeldChange> {
        const auto r = txn.exec(std::string(kHeldSelect) + " WHERE id = $1", pqxx::params{id});
        if (r.empty()) return std::nullopt;
        return heldFrom(r[0]);
    });
}

bool Pending::resolveHeld(const uint64_t id, const std::string& state, const uint32_t by) {
    return Transactions::exec("Pending::resolveHeld", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_held SET state = $2, resolved_at = CURRENT_TIMESTAMP, resolved_by = $3 "
                        "WHERE id = $1 AND state = 'open'",
                        pqxx::params{id, state, by})
                   .affected_rows() == 1;
    });
}

// ---- settings ------------------------------------------------------------------------------------------------------------

std::vector<std::pair<std::string, std::string>> Pending::localSettings(const std::string& requestId) {
    return {{"vh.mirror_local", "on"}, {"vh.mirror_request", requestId}};
}

std::vector<std::pair<std::string, std::string>> Pending::scratchSettings() { return {{"vh.mirror_local", "on"}}; }

std::vector<std::pair<std::string, std::string>> Pending::originSettings(const std::string& requestId,
                                                                         const uint32_t actorId) {
    return {{"vh.mirror_origin", requestId}, {"vh.actor", std::to_string(actorId)}};
}

// ---- the core: submissions -----------------------------------------------------------------------------------------------

std::optional<Submission> Pending::submission(const uint32_t vaultId, const std::string& requestId) {
    return Transactions::exec("Pending::submission", [&](pqxx::work& txn) -> std::optional<Submission> {
        const auto r = txn.exec(std::string(kSubmissionSelect) + " WHERE vault_id = $1 AND request_id = $2",
                                pqxx::params{vaultId, requestId});
        if (r.empty()) return std::nullopt;
        return submissionFrom(r[0]);
    });
}

bool Pending::enqueue(const uint32_t vaultId, const uint32_t peerId, const std::string& requestId,
                      const nlohmann::json& payload) {
    return Transactions::exec("Pending::enqueue", [&](pqxx::work& txn) {
        return txn.exec("INSERT INTO mirror_submission (vault_id, request_id, peer_id, payload) "
                        "VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT (vault_id, request_id) DO NOTHING",
                        pqxx::params{vaultId, requestId, peerId, payload.dump()})
                   .affected_rows() == 1;
    });
}

std::optional<Submission> Pending::claimNext(const uint32_t vaultId) {
    return Transactions::exec("Pending::claimNext", [&](pqxx::work& txn) -> std::optional<Submission> {
        const auto r = txn.exec(std::string(kSubmissionSelect) +
                                    " WHERE vault_id = $1 AND state = 'queued' ORDER BY seq LIMIT 1 FOR UPDATE SKIP LOCKED",
                                pqxx::params{vaultId});
        if (r.empty()) return std::nullopt;
        auto s = submissionFrom(r[0]);
        txn.exec("UPDATE mirror_submission SET state = 'running' WHERE vault_id = $1 AND request_id = $2",
                 pqxx::params{vaultId, s.request_id});
        s.state = "running";
        return s;
    });
}

void Pending::finish(const uint32_t vaultId, const std::string& requestId, const std::string& state,
                     const std::optional<uint32_t> groups, const std::optional<std::string>& code,
                     const std::optional<std::string>& error) {
    Transactions::exec("Pending::finish", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_submission SET state = $3, groups = $4, code = $5, error = left($6, 1000), "
                 "  finished_at = CURRENT_TIMESTAMP WHERE vault_id = $1 AND request_id = $2",
                 pqxx::params{vaultId, requestId, state, groups, code, error});
    });
}

uint32_t Pending::originGroups(const uint32_t vaultId, const std::string& requestId) {
    return Transactions::exec("Pending::originGroups", [&](pqxx::work& txn) {
        return txn.exec("SELECT count(DISTINCT txid) FROM vault_replication_log WHERE vault_id = $1 AND origin = $2",
                        pqxx::params{vaultId, requestId})
            .one_field()
            .as<uint32_t>();
    });
}

std::vector<uint32_t> Pending::vaultsWithQueued() {
    return Transactions::exec("Pending::vaultsWithQueued", [&](pqxx::work& txn) {
        std::vector<uint32_t> out;
        for (const auto row : txn.exec("SELECT DISTINCT vault_id FROM mirror_submission WHERE state IN ('queued', 'running') "
                                       "ORDER BY vault_id"))
            out.push_back(row[0].as<uint32_t>());
        return out;
    });
}

uint64_t Pending::recoverRunning(const uint32_t vaultId) {
    return Transactions::exec("Pending::recoverRunning", [&](pqxx::work& txn) {
        uint64_t n = 0;
        for (const auto row : txn.exec("SELECT request_id FROM mirror_submission WHERE vault_id = $1 AND state = 'running' "
                                       "FOR UPDATE",
                                       pqxx::params{vaultId})) {
            const auto rid = row[0].as<std::string>();
            const auto groups = txn.exec("SELECT count(DISTINCT txid) FROM vault_replication_log "
                                         "WHERE vault_id = $1 AND origin = $2",
                                         pqxx::params{vaultId, rid})
                                    .one_field()
                                    .as<uint32_t>();
            // Something of it was logged: it ran (an operation's transactions commit in order), never run it again.
            if (groups > 0)
                txn.exec("UPDATE mirror_submission SET state = 'executed', groups = $3, finished_at = CURRENT_TIMESTAMP "
                         "WHERE vault_id = $1 AND request_id = $2",
                         pqxx::params{vaultId, rid, groups});
            else
                txn.exec("UPDATE mirror_submission SET state = 'queued' WHERE vault_id = $1 AND request_id = $2",
                         pqxx::params{vaultId, rid});
            ++n;
        }
        return n;
    });
}

uint64_t Pending::sweep(const std::chrono::seconds age) {
    return Transactions::exec("Pending::sweep", [&](pqxx::work& txn) {
        return static_cast<uint64_t>(txn.exec("DELETE FROM mirror_submission WHERE state IN ('executed', 'refused') "
                                              "AND finished_at < CURRENT_TIMESTAMP - ($1::bigint * INTERVAL '1 second')",
                                              pqxx::params{static_cast<int64_t>(age.count())})
                                         .affected_rows());
    });
}

}
