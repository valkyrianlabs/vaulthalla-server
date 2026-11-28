#include "db/query/mirror/Apply.hpp"

#include "db/Transactions.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/mirror/Log.hpp"

#include <pqxx/pqxx>
#include <pqxx/subtransaction>

#include <algorithm>
#include <string>

namespace vh::db::query::mirror {

namespace {

// A time the core sent (microseconds since the epoch) as a timestamp, exactly (no float on the way).
std::string mirrorTs(const int param) {
    return "(TIMESTAMPTZ 'epoch' + ($" + std::to_string(param) + "::bigint * INTERVAL '1 microsecond'))";
}

std::string mirrorUuidArray(const std::vector<std::string>& uids) {
    std::string out = "{";
    for (const auto& u : uids) {
        if (out.size() > 1) out += ',';
        out += u;
    }
    return out + '}';
}

std::optional<vh::mirror::Hash> mirrorHashField(const pqxx::result& r) {
    if (r.empty() || r[0][0].is_null()) return std::nullopt;
    return vh::mirror::hashFromHex(r[0][0].as<std::string>());
}

}

// ---- the core's baseline ---------------------------------------------------------------------------------------------

BaselinePage Baseline::page(const uint32_t vaultId, const uint64_t afterOrd, const std::size_t limit,
                            const std::size_t maxBytes) {
    return Transactions::exec("mirror::Baseline::page", [&](pqxx::work& txn) {
        BaselinePage page;
        const auto mv = txn.exec("SELECT baseline_term, baseline_seq, encode(baseline_digest, 'hex') AS d, "
                                 "  baseline_entries, baseline_rows, baseline_vault::text AS vault "
                                 "FROM mirror_vault WHERE vault_id = $1 AND role = 'core' AND state <> 'starting' "
                                 "  AND baseline_term IS NOT NULL AND baseline_rows IS NOT NULL",
                                 pqxx::params{vaultId});
        if (mv.empty()) return page;
        page.exists = true;
        page.position = {mv[0]["baseline_term"].as<uint64_t>(), mv[0]["baseline_seq"].as<uint64_t>()};
        page.digest = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(mv[0]["d"].as<std::string>()),
                                                    mv[0]["baseline_entries"].as<int64_t>());
        page.rows = mv[0]["baseline_rows"].as<uint64_t>();
        page.vault = mv[0]["vault"].is_null() ? nlohmann::json::object()
                                              : nlohmann::json::parse(mv[0]["vault"].as<std::string>());
        const auto rows = static_cast<int64_t>(std::clamp<std::size_t>(limit, 1, 10'000));
        std::size_t bytes = 0;
        const auto res = txn.exec("SELECT ord, state::text AS state FROM mirror_baseline "
                                  "WHERE vault_id = $1 AND ord > $2 ORDER BY ord LIMIT $3",
                                  pqxx::params{vaultId, static_cast<int64_t>(afterOrd), rows + 1});
        for (pqxx::result::size_type i = 0; i < res.size(); ++i) {
            if (static_cast<int64_t>(i) == rows) {
                page.more = true;
                break;
            }
            auto state = res[i]["state"].as<std::string>();
            if (!page.items.empty() && bytes + state.size() > maxBytes) {
                page.more = true;
                break;
            }
            bytes += state.size();
            page.items.push_back({.ord = res[i]["ord"].as<uint64_t>(), .state = std::move(state)});
        }
        return page;
    });
}

// ---- the mirror's apply ----------------------------------------------------------------------------------------------

void ApplyRows::begin(pqxx::work& txn) {
    Log::markMirrorApply(txn);
    txn.exec("SELECT set_config('vh.keep_mtime', 'on', true)");
}

void ApplyRows::keepFolderTimes(pqxx::work& txn) { txn.exec("SELECT set_config('vh.keep_folder_times', 'on', true)"); }

std::optional<MirrorVault> ApplyRows::lock(pqxx::work& txn, const uint32_t vaultId) {
    return MirrorVaults::get(txn, vaultId, true);
}

std::map<std::string, vh::mirror::Hash> ApplyRows::recordedHashes(pqxx::work& txn, const uint32_t vaultId,
                                                                  const std::vector<std::string>& uids) {
    std::map<std::string, vh::mirror::Hash> out;
    if (uids.empty()) return out;
    for (const auto row : txn.exec("SELECT entry_uid::text, encode(entry_hash, 'hex') FROM mirror_entry_hash "
                                   "WHERE vault_id = $1 AND entry_uid = ANY($2::uuid[]) ORDER BY entry_uid FOR UPDATE",
                                   pqxx::params{vaultId, mirrorUuidArray(uids)}))
        out.emplace(row[0].as<std::string>(), vh::mirror::hashFromHex(row[1].as<std::string>()));
    return out;
}

void ApplyRows::setRecordedHash(pqxx::work& txn, const uint32_t vaultId, const std::string& uid,
                                const std::optional<vh::mirror::Hash>& hash) {
    if (!hash) {
        txn.exec("DELETE FROM mirror_entry_hash WHERE vault_id = $1 AND entry_uid = $2::uuid", pqxx::params{vaultId, uid});
        return;
    }
    txn.exec("INSERT INTO mirror_entry_hash (vault_id, entry_uid, entry_hash) VALUES ($1, $2::uuid, decode($3, 'hex')) "
             "ON CONFLICT (vault_id, entry_uid) DO UPDATE SET entry_hash = EXCLUDED.entry_hash",
             pqxx::params{vaultId, uid, vh::mirror::toHex(*hash)});
}

void ApplyRows::lockPending(pqxx::work& txn, const uint32_t vaultId, const std::vector<std::string>& uids) {
    if (uids.empty()) return;
    txn.exec("SELECT 1 FROM mirror_content_pending WHERE vault_id = $1 AND object_uid = ANY($2::uuid[]) "
             "ORDER BY object_uid FOR UPDATE",
             pqxx::params{vaultId, mirrorUuidArray(uids)});
}

std::optional<uint32_t> ApplyRows::account(pqxx::work& txn, const std::string& ownNode, const std::string& node,
                                           const uint32_t id) {
    if (node.empty()) return std::nullopt;
    if (node == ownNode) {
        const auto r = txn.exec("SELECT id FROM users WHERE id = $1 AND NOT remote", pqxx::params{id});
        if (r.empty()) return std::nullopt;
        return r[0][0].as<uint32_t>();
    }
    // Shown qualified ("#7@<node>"): a remote account may share a name with a local one, and its name is no identity.
    txn.exec("INSERT INTO users (name, password_hash, remote, home_node, home_id) "
             "VALUES ('#' || $2::text || '@' || left($1, 40), '', TRUE, $1, $3) "
             "ON CONFLICT (home_node, home_id) WHERE remote DO NOTHING",
             pqxx::params{node, std::to_string(id), static_cast<int64_t>(id)});
    const auto r = txn.exec("SELECT id FROM users WHERE remote AND home_node = $1 AND home_id = $2",
                            pqxx::params{node, static_cast<int64_t>(id)});
    if (r.empty()) return std::nullopt;
    return r[0][0].as<uint32_t>();
}

bool ApplyRows::keyHeld(pqxx::work& txn, const uint32_t vaultId, const uint32_t version) {
    // The current version or a retired one this server still holds (a rotation's outgoing version, whose files arrive
    // re-sealed later; a version delivered ahead of the core's rotation).
    return !txn.exec("SELECT 1 FROM vault_keys WHERE vault_id = $1 AND version = $2 UNION ALL "
                     "SELECT 1 FROM vault_keys_trashed WHERE vault_id = $1 AND version = $2",
                     pqxx::params{vaultId, static_cast<int64_t>(version)})
                .empty();
}

std::optional<uint32_t> ApplyRows::rootOf(pqxx::work& txn, const uint32_t vaultId) {
    const auto r = txn.exec("SELECT id FROM fs_entry WHERE vault_id = $1 AND path = '/'", pqxx::params{vaultId});
    if (r.empty()) return std::nullopt;
    return r[0][0].as<uint32_t>();
}

std::optional<uint32_t> ApplyRows::named(pqxx::work& txn, const uint32_t parentId, const std::string& name) {
    const auto r = txn.exec("SELECT id FROM fs_entry WHERE parent_id = $1 AND name = $2", pqxx::params{parentId, name});
    if (r.empty()) return std::nullopt;
    return r[0][0].as<uint32_t>();
}

uint64_t ApplyRows::childCount(pqxx::work& txn, const uint32_t dirId) {
    return txn.exec("SELECT count(*) FROM fs_entry WHERE parent_id = $1", pqxx::params{dirId}).one_field().as<uint64_t>();
}

bool ApplyRows::inodeTaken(pqxx::work& txn, const uint64_t inode) {
    return !txn.exec("SELECT 1 FROM fs_entry WHERE inode = $1", pqxx::params{static_cast<int64_t>(inode)}).empty();
}

std::vector<uint32_t> ApplyRows::children(pqxx::work& txn, const uint32_t dirId) {
    std::vector<uint32_t> out;
    for (const auto row : txn.exec("SELECT id FROM fs_entry WHERE parent_id = $1 ORDER BY id", pqxx::params{dirId}))
        out.push_back(row[0].as<uint32_t>());
    return out;
}

bool ApplyRows::within(pqxx::work& txn, const uint32_t entryId, const uint32_t ancestorId) {
    return txn.exec("WITH RECURSIVE up AS (SELECT id, parent_id FROM fs_entry WHERE id = $1 "
                    "  UNION ALL SELECT e.id, e.parent_id FROM fs_entry e JOIN up ON e.id = up.parent_id) "
                    "SELECT EXISTS (SELECT 1 FROM up WHERE id = $2)",
                    pqxx::params{entryId, ancestorId})
        .one_field()
        .as<bool>();
}

uint32_t ApplyRows::depthOf(pqxx::work& txn, const uint32_t entryId) {
    const auto n = txn.exec("WITH RECURSIVE up AS (SELECT id, parent_id, path FROM fs_entry WHERE id = $1 "
                            "  UNION ALL SELECT e.id, e.parent_id, e.path FROM fs_entry e JOIN up ON e.id = up.parent_id) "
                            "SELECT count(*) FROM up WHERE path <> '/'",
                            pqxx::params{entryId})
                       .one_field()
                       .as<int64_t>();
    return n > 0 ? static_cast<uint32_t>(n - 1) : 0u;
}

std::string ApplyRows::pathOf(pqxx::work& txn, const uint32_t entryId) {
    return txn.exec("SELECT path FROM fs_entry WHERE id = $1", pqxx::params{entryId}).one_field().as<std::string>();
}

uint32_t ApplyRows::insertEntry(pqxx::work& txn, const NewEntry& e) {
    const auto& f = e.fields;
    const auto id =
        txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, created_at, updated_at, "
                 "  last_modified_by, path, mode, owner_uid, group_gid, is_hidden, is_system, inode) "
                 "VALUES ($1, $2, $3, $4, $5, COALESCE(" + mirrorTs(6) + ", NOW()), COALESCE(" + mirrorTs(7) + ", NOW()), "
                 "  $8, $9, $10, $11, $12, $13, false, $14) RETURNING id",
                 pqxx::params{e.vault_id, e.parent_id, e.name, e.alias, f.created_by, f.created_at_us, f.modified_at_us,
                              f.modified_by, e.path, f.mode, f.owner_uid, f.owner_gid, f.hidden,
                              e.inode ? std::optional<int64_t>(static_cast<int64_t>(*e.inode)) : std::nullopt})
            .one_field()
            .as<uint32_t>();
    if (e.type == "directory") {
        txn.exec("INSERT INTO directories (fs_entry_id, file_count, subdirectory_count, size_bytes, uid) "
                 "VALUES ($1, 0, 0, 0, $2::uuid)",
                 pqxx::params{id, e.uid});
        db::query::fs::Directory::addToAncestorStats(txn, e.parent_id, 0, 0, 1);
    } else if (e.type == "file") {
        txn.exec("INSERT INTO files (fs_entry_id, size_bytes, mime_type, content_hash, encryption_iv, "
                 "  encrypted_with_key_version, object_uid) VALUES ($1, $2, $3, $4, $5, $6, $7::uuid)",
                 pqxx::params{id, f.size, f.mime, f.content_hash, f.generation, f.key_version, e.uid});
        db::query::fs::Directory::addToAncestorStats(txn, e.parent_id, f.size.value_or(0), 1, 0);
    } else {
        txn.exec("INSERT INTO symlinks (fs_entry_id, target, uid) VALUES ($1, $2, $3::uuid)",
                 pqxx::params{id, f.target, e.uid});
        // A symlink counts its target's length, as a local one does (Symlink::upsertSymlink, subtreeTotalsOf).
        db::query::fs::Directory::addToAncestorStats(
            txn, e.parent_id, static_cast<int64_t>(f.target ? f.target->size() : 0), 1, 0);
    }
    return id;
}

void ApplyRows::moveEntry(pqxx::work& txn, const uint32_t id, const uint32_t newParentId, const std::string& newName) {
    const auto totals = db::query::fs::Directory::subtreeTotalsOf(txn, id);
    const auto oldParent = db::query::fs::Directory::parentIdOf(txn, id);
    txn.exec("UPDATE fs_entry SET parent_id = $2, name = $3 WHERE id = $1", pqxx::params{id, newParentId, newName});
    if (totals && oldParent != std::optional<unsigned int>(newParentId))
        db::query::fs::Directory::shiftSubtreeTotals(txn, oldParent, newParentId, *totals);
}

void ApplyRows::updateEntry(pqxx::work& txn, const uint32_t id, const std::string& type, const EntryFields& f) {
    txn.exec("UPDATE fs_entry SET mode = $2, is_hidden = $3, owner_uid = $4, group_gid = $5, "
             "  created_at = COALESCE(" + mirrorTs(6) + ", created_at), "
             "  updated_at = COALESCE(" + mirrorTs(7) + ", updated_at), created_by = $8, last_modified_by = $9 "
             "WHERE id = $1",
             pqxx::params{id, f.mode, f.hidden, f.owner_uid, f.owner_gid, f.created_at_us, f.modified_at_us,
                          f.created_by, f.modified_by});
    if (type == "file") {
        const auto before = txn.exec("SELECT COALESCE(f.size_bytes, 0), e.parent_id FROM files f "
                                     "JOIN fs_entry e ON e.id = f.fs_entry_id WHERE f.fs_entry_id = $1",
                                     pqxx::params{id});
        txn.exec("UPDATE files SET size_bytes = $2, mime_type = $3, content_hash = $4, encryption_iv = $5, "
                 "  encrypted_with_key_version = $6 WHERE fs_entry_id = $1",
                 pqxx::params{id, f.size, f.mime, f.content_hash, f.generation, f.key_version});
        if (!before.empty() && !before[0][1].is_null()) {
            const auto delta = f.size.value_or(0) - before[0][0].as<int64_t>();
            if (delta != 0) db::query::fs::Directory::addToAncestorStats(txn, before[0][1].as<unsigned int>(), delta, 0, 0);
        }
    } else if (type == "symlink") {
        const auto before = txn.exec("SELECT COALESCE(octet_length(s.target), 0)::bigint, e.parent_id FROM symlinks s "
                                     "JOIN fs_entry e ON e.id = s.fs_entry_id WHERE s.fs_entry_id = $1",
                                     pqxx::params{id});
        txn.exec("UPDATE symlinks SET target = $2 WHERE fs_entry_id = $1 AND target IS DISTINCT FROM $2",
                 pqxx::params{id, f.target});
        if (!before.empty() && !before[0][1].is_null()) {
            const auto delta = static_cast<int64_t>(f.target ? f.target->size() : 0) - before[0][0].as<int64_t>();
            if (delta != 0) db::query::fs::Directory::addToAncestorStats(txn, before[0][1].as<unsigned int>(), delta, 0, 0);
        }
    }
}

void ApplyRows::removeEntry(pqxx::work& txn, const uint32_t id) {
    const auto totals = db::query::fs::Directory::subtreeTotalsOf(txn, id);
    const auto parent = db::query::fs::Directory::parentIdOf(txn, id);
    // The entry's type row leaves with it (ON DELETE CASCADE).
    txn.exec("DELETE FROM fs_entry WHERE id = $1", pqxx::params{id});
    if (totals) db::query::fs::Directory::addToAncestorStats(txn, parent, -totals->size_bytes, -totals->files,
                                                          -totals->subdirs);
}

void ApplyRows::rewritePath(pqxx::work& txn, const uint32_t id) {
    txn.exec("WITH RECURSIVE t AS ("
             "  SELECT e.id, CASE WHEN p.path = '/' THEN '/' || e.name ELSE p.path || '/' || e.name END AS path "
             "  FROM fs_entry e JOIN fs_entry p ON p.id = e.parent_id WHERE e.id = $1 "
             "  UNION ALL "
             "  SELECT c.id, t.path || '/' || c.name FROM fs_entry c JOIN t ON c.parent_id = t.id) "
             "UPDATE fs_entry e SET path = t.path FROM t WHERE e.id = t.id AND e.path IS DISTINCT FROM t.path",
             pqxx::params{id});
}

void ApplyRows::insertTrash(pqxx::work& txn, const TrashFields& t) {
    txn.exec("INSERT INTO files_trashed (vault_id, path, backing_path, base32_alias, size_bytes, trashed_at, trashed_by, "
             "  object_uid) VALUES ($1, $2, $3, $4, $5, COALESCE(" + mirrorTs(6) + ", NOW()), $7, $8::uuid)",
             pqxx::params{t.vault_id, t.path, t.backing_path, t.alias, t.size, t.trashed_at_us, t.trashed_by, t.uid});
}

void ApplyRows::updateTrash(pqxx::work& txn, const uint32_t trashId, const TrashFields& t) {
    txn.exec("UPDATE files_trashed SET path = $2, size_bytes = $3, trashed_at = COALESCE(" + mirrorTs(4) +
                 ", trashed_at), trashed_by = $5 WHERE id = $1",
             pqxx::params{trashId, t.path, t.size, t.trashed_at_us, t.trashed_by});
}

void ApplyRows::endTrash(pqxx::work& txn, const uint32_t trashId) {
    txn.exec("UPDATE files_trashed SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL", pqxx::params{trashId});
}

std::optional<vh::mirror::Hash> ApplyRows::liveHash(pqxx::work& txn, const uint32_t entryId) {
    return mirrorHashField(txn.exec("SELECT encode(vh_mirror_state_hash(x.s), 'hex') "
                                    "FROM (SELECT vh_mirror_entry_state($1) AS s) x WHERE x.s IS NOT NULL",
                                    pqxx::params{entryId}));
}

nlohmann::json ApplyRows::liveState(pqxx::work& txn, const uint32_t entryId) {
    const auto r = txn.exec("SELECT vh_mirror_entry_state($1)::text", pqxx::params{entryId});
    if (r.empty() || r[0][0].is_null()) return nullptr;
    return nlohmann::json::parse(r[0][0].as<std::string>());
}

std::optional<vh::mirror::Hash> ApplyRows::trashHash(pqxx::work& txn, const uint32_t vaultId, const std::string& uid) {
    return mirrorHashField(txn.exec(
        "SELECT encode(vh_mirror_state_hash(vh_mirror_trash_state(object_uid, size_bytes, path, trashed_at, trashed_by)), "
        "  'hex') FROM files_trashed WHERE vault_id = $1 AND object_uid = $2::uuid AND deleted_at IS NULL "
        "ORDER BY id DESC LIMIT 1",
        pqxx::params{vaultId, uid}));
}

std::vector<std::string> ApplyRows::applyVault(pqxx::work& txn, const uint32_t vaultId, const nlohmann::json& doc,
                                               const std::optional<uint32_t> owner) {
    std::vector<std::string> notes;
    if (const auto name = doc.find("name"); name != doc.end() && name->is_string()) {
        pqxx::subtransaction sub(txn, "mirror_vault_name");
        try {
            const auto renamed = sub.exec("UPDATE vault SET name = $2 WHERE id = $1 AND name IS DISTINCT FROM $2 "
                                          "  AND NOT EXISTS (SELECT 1 FROM vault o WHERE o.name = $2 AND o.id <> $1)",
                                          pqxx::params{vaultId, name->get<std::string>()});
            sub.commit();
            if (renamed.affected_rows() == 0 &&
                !txn.exec("SELECT 1 FROM vault WHERE id = $1 AND name IS DISTINCT FROM $2",
                          pqxx::params{vaultId, name->get<std::string>()})
                     .empty())
                notes.push_back("name: another vault on this server is named " + name->get<std::string>());
        } catch (const pqxx::sql_error& e) {
            sub.abort();
            notes.push_back(std::string("name not applied: ") + e.what());
        }
    }
    std::optional<std::string> description;
    if (const auto d = doc.find("description"); d != doc.end() && d->is_string()) description = d->get<std::string>();
    std::optional<int64_t> quota;
    if (const auto q = doc.find("quota"); q != doc.end() && q->is_number_integer()) quota = q->get<int64_t>();
    txn.exec("UPDATE vault SET description = COALESCE($2, description), quota = COALESCE($3, quota), "
             "  owner_id = COALESCE($4, owner_id) WHERE id = $1",
             pqxx::params{vaultId, description, quota, owner});
    if (doc.contains("owner") && !owner) notes.push_back("owner: the core's owner has no account here");
    txn.exec("UPDATE mirror_vault SET vault_state = $2::jsonb, updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1",
             pqxx::params{vaultId, doc.dump()});
    return notes;
}

void ApplyRows::recordBaseline(pqxx::work& txn, const uint32_t vaultId, const Position at,
                               const vh::mirror::Digest& digest, const uint64_t rows) {
    txn.exec("UPDATE mirror_vault SET baseline_term = $2, baseline_seq = $3, baseline_digest = decode($4, 'hex'), "
             "  baseline_entries = $5, baseline_rows = $6, updated_at = CURRENT_TIMESTAMP "
             "WHERE vault_id = $1 AND role = 'mirror'",
             pqxx::params{vaultId, static_cast<int64_t>(at.term), static_cast<int64_t>(at.seq), digest.hex(),
                          digest.entries, static_cast<int64_t>(rows)});
}

void ApplyRows::advanceCopy(pqxx::work& txn, const uint32_t vaultId, const uint64_t cursor,
                            const vh::mirror::Digest& digest, const bool finished, const Position baseline) {
    txn.exec("UPDATE mirror_vault SET copy_cursor = $2, digest = decode($3, 'hex'), digest_entries = $4, "
             "  copy_finished = $5, term = CASE WHEN $5 THEN $6 ELSE term END, "
             "  last_seq = CASE WHEN $5 THEN $7 ELSE last_seq END, updated_at = CURRENT_TIMESTAMP "
             "WHERE vault_id = $1 AND role = 'mirror'",
             pqxx::params{vaultId, static_cast<int64_t>(cursor), digest.hex(), digest.entries, finished,
                          static_cast<int64_t>(baseline.term), static_cast<int64_t>(baseline.seq)});
}

void ApplyRows::advance(pqxx::work& txn, const uint32_t vaultId, const Position at, const vh::mirror::Digest& digest) {
    txn.exec("UPDATE mirror_vault SET term = $2, last_seq = $3, digest = decode($4, 'hex'), digest_entries = $5, "
             "  updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1 AND role = 'mirror'",
             pqxx::params{vaultId, static_cast<int64_t>(at.term), static_cast<int64_t>(at.seq), digest.hex(),
                          digest.entries});
}

}
