#include "db/query/sync/ManifestApply.hpp"

#include "db/query/device/Device.hpp"

#include "crypto/id/Generator.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/Directory.hpp"
#include <vl/vaultfmt/manifest/Objects.hpp>
#include "vault/Content.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <map>
#include <stdexcept>

namespace vh::db::query::sync {

namespace manifest_apply_detail {

// The transaction writes fs_entry times itself (migration 149): the trigger keeps them, equal to the old one too.
void keepMtimes(pqxx::work& txn) { txn.exec("SELECT set_config('vh.keep_mtime', 'on', true)"); }

namespace mf = vl::vaultfmt::manifest;

std::string uuidOf(const std::string& uid) { return vh::crypto::id::toUuid(mf::parseUid(uid, "bad_segment", "entry uid")); }

std::string uidOfUuid(const std::string& uuid) { return mf::uidText(vh::crypto::id::fromUuid(uuid)); }

std::optional<std::string> optText(const pqxx::field_ref& f) {
    if (f.is_null()) return std::nullopt;
    return f.as<std::string>();
}

std::string alias(const std::string& token) { return vh::crypto::id::Generator({.namespace_token = token}).generate(); }

std::string objectKey(const std::string& uid) { return std::string(mf::kObjectPrefix) + uid; }

ApplyRow::Kind kindOf(const std::string& k) {
    if (k == "dir") return ApplyRow::Kind::Dir;
    if (k == "symlink") return ApplyRow::Kind::Symlink;
    return ApplyRow::Kind::File;
}

}

std::optional<std::string> ManifestApply::hexOfB64(const std::optional<std::string>& b64) {
    if (!b64 || b64->empty()) return std::nullopt;
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (const auto b : vh::crypto::util::b64_decode(*b64)) {
        out += kHex[b >> 4];
        out += kHex[b & 0x0f];
    }
    return out;
}

std::optional<std::string> ManifestApply::b64OfHex(const std::optional<std::string>& hex) {
    if (!hex || hex->empty() || hex->size() % 2) return std::nullopt;
    std::vector<uint8_t> bytes;
    for (std::size_t i = 0; i < hex->size(); i += 2) bytes.push_back(static_cast<uint8_t>(std::stoi(hex->substr(i, 2), nullptr, 16)));
    return vh::crypto::util::b64_encode(bytes);
}

std::optional<ApplyRow> ManifestApply::row(const uint32_t vaultId, const std::string& uid) {
    return Transactions::exec("ManifestApply::row", [&](pqxx::work& txn) { return row(txn, vaultId, uid); });
}

std::optional<ApplyRow> ManifestApply::row(pqxx::work& txn, const uint32_t vaultId, const std::string& uid) {
    using namespace manifest_apply_detail;
    const auto uuid = uuidOf(uid);
    const auto live = txn.exec(
        "SELECT e.id, e.parent_id, e.name, e.path, e.inode, pd.uid::text AS parent_uid, f.encryption_iv, "
        "       roi.encryption_iv AS index_iv, "
        "       CASE WHEN d.fs_entry_id IS NOT NULL THEN 'dir' WHEN f.fs_entry_id IS NOT NULL THEN 'file' "
        "            ELSE 'symlink' END AS kind "
        "FROM fs_entry e LEFT JOIN directories d ON d.fs_entry_id = e.id LEFT JOIN files f ON f.fs_entry_id = e.id "
        "LEFT JOIN symlinks s ON s.fs_entry_id = e.id LEFT JOIN directories pd ON pd.fs_entry_id = e.parent_id "
        "LEFT JOIN remote_object_index roi ON roi.vault_id = e.vault_id AND roi.object_key = $3 "
        "WHERE e.vault_id = $1 AND (d.uid = $2::uuid OR f.object_uid = $2::uuid OR s.uid = $2::uuid)",
        pqxx::params{vaultId, uuid, objectKey(uid)});
    if (!live.empty()) {
        const auto r = live[0];
        ApplyRow out;
        out.kind = kindOf(r["kind"].as<std::string>());
        out.id = r["id"].as<unsigned int>();
        if (!r["parent_id"].is_null()) out.parent_id = r["parent_id"].as<unsigned int>();
        if (const auto p = optText(r["parent_uid"])) out.parent_uid = uidOfUuid(*p);
        out.name = r["name"].as<std::string>();
        out.path = r["path"].as<std::string>();
        if (!r["inode"].is_null()) out.inode = r["inode"].as<uint64_t>();
        out.files_generation = hexOfB64(optText(r["encryption_iv"]));
        out.index_generation = hexOfB64(optText(r["index_iv"]));
        return out;
    }
    const auto trashed = txn.exec(
        "SELECT t.id, t.path, t.backing_path, roi.encryption_iv AS index_iv FROM files_trashed t "
        "LEFT JOIN remote_object_index roi ON roi.vault_id = t.vault_id AND roi.object_key = $3 "
        "WHERE t.vault_id = $1 AND t.object_uid = $2::uuid AND t.deleted_at IS NULL ORDER BY t.id DESC LIMIT 1",
        pqxx::params{vaultId, uuid, objectKey(uid)});
    if (trashed.empty()) return std::nullopt;
    ApplyRow out;
    out.trashed = true;
    out.id = trashed[0]["id"].as<unsigned int>();
    out.path = trashed[0]["path"].as<std::string>();
    out.backing_path = optText(trashed[0]["backing_path"]);
    out.index_generation = hexOfB64(optText(trashed[0]["index_iv"]));
    return out;
}

std::optional<unsigned int> ManifestApply::createEntry(pqxx::work& txn, const uint32_t vaultId, const unsigned int ownerId,
                                                       const vl::vaultfmt::manifest::Entry& e, const unsigned int parentId,
                                                       const std::string& path, const std::optional<uint64_t> inode) {
    using namespace manifest_apply_detail;
    if (const auto r = row(txn, vaultId, e.uid); r && !r->trashed) return std::nullopt;   // the uid is live already
    const auto mode = e.mode.value_or(e.kind == mf::EntryKind::Dir ? 0755u : 0644u);
    const auto inserted = txn.exec(
        "INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, created_at, updated_at, "
        "  last_modified_by, path, mode, owner_uid, group_gid, is_hidden, is_system, inode) "
        "VALUES ($1, $2, $3, $4, $5, COALESCE($6::timestamptz, NOW()), COALESCE($7::timestamptz, NOW()), $5, $8, $9, "
        "  $10, $11, false, false, $12) ON CONFLICT DO NOTHING RETURNING id",
        pqxx::params{vaultId, parentId, e.name, alias(e.name), ownerId, e.ctime, e.mtime, path, static_cast<int>(mode),
                     e.owner ? std::optional<int64_t>(e.owner->uid) : std::nullopt,
                     e.owner ? std::optional<int64_t>(e.owner->gid) : std::nullopt,
                     inode ? std::optional<int64_t>(static_cast<int64_t>(*inode)) : std::nullopt});
    if (inserted.empty()) return std::nullopt;   // the name is taken in that folder
    const auto id = inserted[0][0].as<unsigned int>();
    const auto uuid = uuidOf(e.uid);
    switch (e.kind) {
    case mf::EntryKind::Dir:
        txn.exec("INSERT INTO directories (fs_entry_id, file_count, subdirectory_count, size_bytes, uid) "
                 "VALUES ($1, 0, 0, 0, $2)",
                 pqxx::params{id, uuid});
        db::query::fs::Directory::addToAncestorStats(txn, parentId, 0, 0, 1);
        break;
    case mf::EntryKind::File: {
        const auto gen = b64OfHex(e.generation);
        txn.exec("INSERT INTO files (fs_entry_id, size_bytes, mime_type, content_hash, encryption_iv, "
                 "encrypted_with_key_version, object_uid) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                 pqxx::params{id, static_cast<int64_t>(e.size.value_or(0)), e.mime, e.content_hash, gen.value_or(""),
                              static_cast<int>(gen ? e.key_version.value_or(0) : 0), uuid});
        db::query::fs::Directory::addToAncestorStats(txn, parentId, static_cast<int64_t>(e.size.value_or(0)), 1, 0);
        break;
    }
    case mf::EntryKind::Symlink:
        txn.exec("INSERT INTO symlinks (fs_entry_id, target, uid) VALUES ($1, $2, $3)",
                 pqxx::params{id, e.target.value_or(""), uuid});
        db::query::fs::Directory::addToAncestorStats(txn, parentId, 0, 1, 0);
        break;
    case mf::EntryKind::Tombstone: throw std::invalid_argument("a tombstone is not an entry");
    }
    return id;
}

void ManifestApply::createTrashed(pqxx::work& txn, const uint32_t vaultId, const unsigned int ownerId,
                                  const vl::vaultfmt::manifest::Entry& e, const std::string& path) {
    using namespace manifest_apply_detail;
    txn.exec("INSERT INTO files_trashed (vault_id, path, backing_path, base32_alias, size_bytes, trashed_at, trashed_by, "
             "  object_uid) VALUES ($1, $2, '', $3, $4, COALESCE(NULLIF($5, '')::timestamptz, NOW()), $6, $7)",
             pqxx::params{vaultId, path, alias(path + ":" + e.uid), static_cast<int64_t>(e.size.value_or(0)),
                          e.trashed ? std::optional(e.trashed->at) : std::nullopt, ownerId, uuidOf(e.uid)});
}

void ManifestApply::upsertIndex(pqxx::work& txn, const uint32_t vaultId, const vl::vaultfmt::manifest::Entry& e) {
    using namespace manifest_apply_detail;
    if (!e.object) return;
    const auto gen = b64OfHex(e.generation);
    const auto size = gen ? e.size.value_or(0) : e.object->size;
    txn.exec("INSERT INTO remote_object_index (vault_id, object_key, size_bytes, last_modified, etag, storage_class, "
             "  version_id, source, content_hash, encrypted, encryption_iv, encrypted_with_key_version) "
             "VALUES ($1, $2, $3, $4::timestamptz, $5, $6, $7, 'manifest', $8, true, $9, $10) "
             "ON CONFLICT (vault_id, object_key) DO UPDATE SET size_bytes = EXCLUDED.size_bytes, "
             "  last_modified = EXCLUDED.last_modified, etag = EXCLUDED.etag, storage_class = EXCLUDED.storage_class, "
             "  version_id = EXCLUDED.version_id, source = 'manifest', content_hash = EXCLUDED.content_hash, "
             "  encrypted = true, encryption_iv = EXCLUDED.encryption_iv, "
             "  encrypted_with_key_version = EXCLUDED.encrypted_with_key_version",
             pqxx::params{vaultId, objectKey(e.uid), static_cast<int64_t>(size), e.mtime, e.object->etag,
                          e.object->storage_class, e.object->version_id, e.content_hash, gen,
                          gen ? std::optional<int>(static_cast<int>(e.key_version.value_or(0))) : std::nullopt});
}

void ManifestApply::deleteIndex(pqxx::work& txn, const uint32_t vaultId, const std::string& uid) {
    using namespace manifest_apply_detail;
    txn.exec("DELETE FROM remote_object_index WHERE vault_id = $1 AND object_key = $2", pqxx::params{vaultId, objectKey(uid)});
}

bool ManifestApply::replaceContent(pqxx::work& txn, const unsigned int fileId, const vl::vaultfmt::manifest::Entry& e,
                                   const std::optional<std::string>& expectedHex) {
    const auto gen = b64OfHex(e.generation);
    // The entry's row before its files row: one lock order for an entry's rows (files.cpp, set_file_encryption_iv...).
    txn.exec("SELECT 1 FROM fs_entry WHERE id = $1 FOR NO KEY UPDATE", pqxx::params{fileId});
    const auto before = txn.exec("SELECT f.size_bytes, f.encryption_iv, e.parent_id FROM files f "
                                 "JOIN fs_entry e ON e.id = f.fs_entry_id WHERE f.fs_entry_id = $1 FOR UPDATE",
                                 pqxx::params{fileId});
    if (before.empty()) return false;
    std::optional<std::string> iv;
    if (!before[0][1].is_null()) iv = before[0][1].as<std::string>();
    if (hexOfB64(iv) != expectedHex) return false;
    const auto oldSize = before[0][0].as<int64_t>();
    txn.exec("UPDATE files SET size_bytes = $2, mime_type = COALESCE($3, mime_type), content_hash = $4, "
             "  encryption_iv = $5, encrypted_with_key_version = $6 WHERE fs_entry_id = $1",
             pqxx::params{fileId, static_cast<int64_t>(e.size.value_or(0)), e.mime, e.content_hash, gen.value_or(""),
                          static_cast<int>(gen ? e.key_version.value_or(0) : 0)});
    manifest_apply_detail::keepMtimes(txn);
    txn.exec("UPDATE fs_entry SET updated_at = COALESCE($2::timestamptz, NOW()) WHERE id = $1",
             pqxx::params{fileId, e.mtime});
    if (!before[0][2].is_null())
        db::query::fs::Directory::addToAncestorStats(txn, before[0][2].as<unsigned int>(),
                                      static_cast<int64_t>(e.size.value_or(0)) - oldSize, 0, 0);
    return true;
}

void ManifestApply::setMtime(pqxx::work& txn, const unsigned int entryId, const std::string& mtime) {
    manifest_apply_detail::keepMtimes(txn);
    txn.exec("UPDATE fs_entry SET updated_at = $2::timestamptz WHERE id = $1", pqxx::params{entryId, mtime});
}

bool ManifestApply::moveRow(pqxx::work& txn, const unsigned int id, const unsigned int fromParentId,
                            const std::string& fromName, const unsigned int toParentId, const std::string& toName,
                            const std::string& toPath, const std::optional<std::string>& mtime) {
    const auto totals = db::query::fs::Directory::subtreeTotalsOf(txn, id);
    if (!totals) return false;
    manifest_apply_detail::keepMtimes(txn);
    const auto moved = txn.exec("UPDATE fs_entry SET parent_id = $2, name = $3, path = $4, "
                                "  updated_at = COALESCE($7::timestamptz, NOW()) "
                                "WHERE id = $1 AND parent_id = $5 AND name = $6 RETURNING id",
                                pqxx::params{id, toParentId, toName, toPath, fromParentId, fromName, mtime});
    if (moved.empty()) return false;
    db::query::fs::Directory::shiftSubtreeTotals(txn, fromParentId, toParentId, *totals);
    return true;
}

bool ManifestApply::setAttributes(pqxx::work& txn, const unsigned int entryId, const vl::vaultfmt::manifest::Entry& ours,
                                  const vl::vaultfmt::manifest::Entry& target) {
    const auto opt = [](const auto& o) {
        return o ? std::optional<int64_t>(static_cast<int64_t>(*o)) : std::nullopt;
    };
    manifest_apply_detail::keepMtimes(txn);
    const auto updated = txn.exec(
        "UPDATE fs_entry SET mode = COALESCE($2, mode), owner_uid = $3, group_gid = $4, "
        "  updated_at = COALESCE($8::timestamptz, NOW()) WHERE id = $1 "
        // ours.owner as the collector reads it: present when either id is set, a missing one as 0.
        "AND mode IS NOT DISTINCT FROM COALESCE($5, mode) "
        "AND ((owner_uid IS NULL AND group_gid IS NULL AND $6::bigint IS NULL) "
        "     OR (COALESCE(owner_uid, 0) = $6 AND COALESCE(group_gid, 0) = $7)) RETURNING id",
        pqxx::params{entryId, opt(target.mode), target.owner ? std::optional(target.owner->uid) : std::nullopt,
                     target.owner ? std::optional(target.owner->gid) : std::nullopt, opt(ours.mode),
                     ours.owner ? std::optional(ours.owner->uid) : std::nullopt,
                     ours.owner ? std::optional(ours.owner->gid) : std::nullopt, target.mtime});
    if (updated.empty()) return false;
    if (target.kind == vl::vaultfmt::manifest::EntryKind::Symlink && target.target != ours.target)
        txn.exec("UPDATE symlinks SET target = $2 WHERE fs_entry_id = $1 AND target IS NOT DISTINCT FROM $3",
                 pqxx::params{entryId, target.target.value_or(""), ours.target});
    return true;
}

void ManifestApply::addHistory(pqxx::work& txn, const uint32_t vaultId, const vl::vaultfmt::manifest::Entry& e) {
    using namespace manifest_apply_detail;
    for (std::size_t i = 0; i < e.versions.size(); ++i) {
        const auto& v = e.versions[i];
        const auto vgen = b64OfHex(v.generation);
        const bool latest = e.object ? (e.object->version_id && *e.object->version_id == v.version_id) : false;
        std::optional<int64_t> plain;
        if (v.size && vgen)
            if (const auto p = vh::vault::content::plaintextSizeOfGeneration(*v.size, *vgen)) plain = static_cast<int64_t>(*p);
        txn.exec("INSERT INTO upstream_object_version (vault_id, object_key, version_id, is_delete_marker, is_latest, "
                 "  etag, size_bytes, last_modified, origin, encrypted, encryption_iv, key_version, plaintext_bytes, "
                 "  became_noncurrent_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, 'observed', $9, $10, "
                 "  $11, $12, $13::timestamptz) ON CONFLICT (vault_id, object_key, version_id) DO UPDATE SET "
                 "  became_noncurrent_at = EXCLUDED.became_noncurrent_at, is_latest = false "
                 "  WHERE upstream_object_version.became_noncurrent_at IS NULL "
                 "    AND EXCLUDED.became_noncurrent_at IS NOT NULL",
                 pqxx::params{vaultId, objectKey(e.uid), v.version_id, v.delete_marker, latest, v.etag,
                              v.size ? std::optional<int64_t>(static_cast<int64_t>(*v.size)) : std::nullopt,
                              v.last_modified, !v.delete_marker, vgen,
                              v.key_version ? std::optional<int>(static_cast<int>(*v.key_version)) : std::nullopt,
                              plain, v.noncurrent_at});
    }
}

void ManifestApply::createSnapshot(pqxx::work& txn, const uint32_t vaultId, const unsigned int ownerId,
                                   const vl::vaultfmt::manifest::SnapshotRecord& s,
                                   const vl::vaultfmt::manifest::Content& result) {
    using namespace manifest_apply_detail;
    (void)ownerId;
    const auto sid = txn.exec("INSERT INTO recovery_snapshot (vault_id, name, root_path, root_type, state, file_count, "
                              "  directory_count, plaintext_bytes, created_at, completed_at, uid) "
                              "VALUES ($1, $2, $3, 'directory', 'ready', $4, 0, 0, "
                              "  COALESCE(NULLIF($5, '')::timestamptz, NOW()), COALESCE(NULLIF($5, '')::timestamptz, NOW()), "
                              "  $6::uuid) ON CONFLICT DO NOTHING RETURNING id",
                              pqxx::params{vaultId, s.name, s.root_path.empty() ? "/" : s.root_path,
                                           static_cast<int64_t>(s.members.size()), s.created_at, uuidOf(s.uid)});
    if (sid.empty()) return;   // a local snapshot of that name, or the uid exists
    const auto snapshotId = sid[0][0].as<int64_t>();
    std::map<std::string, int> numbers;
    int64_t bytes = 0;
    for (const auto& m : s.members) {
        std::optional<unsigned int> fileId;
        uint64_t size = 0;
        if (m.uid) {
            const auto f = txn.exec("SELECT f.fs_entry_id FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                                    "WHERE e.vault_id = $1 AND f.object_uid = $2::uuid",
                                    pqxx::params{vaultId, uuidOf(*m.uid)});
            if (!f.empty()) fileId = f[0][0].as<unsigned int>();
            if (const auto e = std::ranges::find(result.entries, *m.uid, &mf::Entry::uid); e != result.entries.end())
                size = e->size.value_or(0);
        }
        bytes += static_cast<int64_t>(size);
        const int number = m.uid ? ++numbers[*m.uid] : 1;
        std::string rel = m.path_at_capture;
        if (const auto& rp = s.root_path; !rp.empty() && rp != "/" && rel.starts_with(rp + "/")) rel = rel.substr(rp.size() + 1);
        else if (rel.starts_with("/")) rel = rel.substr(1);
        const bool fromBucket = m.restorable_from_bucket && m.uid.has_value();
        txn.exec("INSERT INTO file_versions (vault_id, file_id, snapshot_id, blob_id, version_number, content_hash, "
                 "  size_bytes, path, rel_path, created_at, origin, upstream_state, upstream_key, upstream_version_id) "
                 "VALUES ($1, $2, $3, NULL, $4, NULL, $5, $6, $7, COALESCE(NULLIF($8, '')::timestamptz, NOW()), "
                 "  'snapshot', $9, $10, $11)",
                 pqxx::params{vaultId, fileId, snapshotId, number, static_cast<int64_t>(size), m.path_at_capture, rel,
                              s.created_at, fromBucket ? "sent" : "none",
                              fromBucket ? std::optional<std::string>(objectKey(*m.uid)) : std::nullopt,
                              fromBucket ? m.provider_version_id : std::nullopt});
    }
    txn.exec("UPDATE recovery_snapshot SET plaintext_bytes = $2 WHERE id = $1", pqxx::params{snapshotId, bytes});
}

std::optional<int64_t> ManifestApply::snapshotId(const uint32_t vaultId, const std::string& uid) {
    using namespace manifest_apply_detail;
    return Transactions::exec("ManifestApply::snapshotId", [&](pqxx::work& txn) -> std::optional<int64_t> {
        const auto r = txn.exec("SELECT id FROM recovery_snapshot WHERE vault_id = $1 AND uid = $2::uuid",
                                pqxx::params{vaultId, uuidOf(uid)});
        if (r.empty()) return std::nullopt;
        return r[0][0].as<int64_t>();
    });
}

std::vector<std::string> ManifestApply::setVault(pqxx::work& txn, const uint32_t vaultId,
                                                 const vl::vaultfmt::manifest::VaultInfo& ours,
                                                 const vl::vaultfmt::manifest::VaultInfo& target) {
    std::vector<std::string> notes;
    if (target.name != ours.name) {
        const auto taken = txn.exec("SELECT 1 FROM vault WHERE name = $1 AND id <> $2", pqxx::params{target.name, vaultId});
        if (taken.empty())
            txn.exec("UPDATE vault SET name = $2 WHERE id = $1 AND name = $3", pqxx::params{vaultId, target.name, ours.name});
        else notes.push_back("the vault name is held by another vault on this server; kept");
    }
    if (target.quota_bytes != ours.quota_bytes)
        txn.exec("UPDATE vault SET quota = $2 WHERE id = $1",
                 pqxx::params{vaultId, static_cast<int64_t>(target.quota_bytes.value_or(0))});
    if (target.sync_strategy != ours.sync_strategy) {
        if (target.sync_strategy == "cache" || target.sync_strategy == "sync")
            txn.exec("UPDATE rsync r SET strategy = $2 FROM sync s WHERE s.id = r.sync_id AND s.vault_id = $1",
                     pqxx::params{vaultId, *target.sync_strategy});
        else notes.push_back("the sync strategy " + target.sync_strategy.value_or("(none)") + " is not taken by a replica");
    }
    if (target.recovery_policy != ours.recovery_policy)
        notes.push_back("the file-recovery policy is set on each server (vh vault recovery); kept");
    return notes;
}

std::set<std::string> ManifestApply::knownKids(const uint32_t vaultId) {
    return Transactions::exec("ManifestApply::knownKids", [&](pqxx::work& txn) {
        std::set<std::string> out;
        for (const auto r : txn.exec("SELECT kid FROM vault_key_envelope WHERE vault_id = $1 UNION "
                                     "SELECT kid FROM manifest_foreign_envelope WHERE vault_id = $1",
                                     pqxx::params{vaultId}))
            out.insert(r[0].as<std::string>());
        return out;
    });
}

void ManifestApply::addForeignEnvelope(const uint32_t vaultId, const std::string& kid, const uint32_t keyVersion,
                                       const std::string& recipientIdHex) {
    Transactions::exec("ManifestApply::addForeignEnvelope", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO manifest_foreign_envelope (vault_id, kid, key_version, recipient_id) VALUES ($1, $2, $3, $4) "
                 "ON CONFLICT (vault_id, kid) DO NOTHING",
                 pqxx::params{vaultId, kid, static_cast<int>(keyVersion), recipientIdHex});
    });
}

void ManifestApply::saveReport(const uint32_t vaultId, const Report& r) {
    Transactions::exec("ManifestApply::saveReport", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO manifest_apply_report (vault_id, epoch, root_sha256, producer, recorded, union_base, applied, "
                 "  skipped, deferred, kept, conflicts_decided, conflicts_open, notes, applied_at) "
                 "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, CURRENT_TIMESTAMP) "
                 "ON CONFLICT (vault_id) DO UPDATE SET epoch = EXCLUDED.epoch, root_sha256 = EXCLUDED.root_sha256, "
                 "  producer = EXCLUDED.producer, recorded = EXCLUDED.recorded, union_base = EXCLUDED.union_base, "
                 "  applied = EXCLUDED.applied, skipped = EXCLUDED.skipped, deferred = EXCLUDED.deferred, "
                 "  kept = EXCLUDED.kept, conflicts_decided = EXCLUDED.conflicts_decided, "
                 "  conflicts_open = EXCLUDED.conflicts_open, notes = EXCLUDED.notes, applied_at = CURRENT_TIMESTAMP, "
                 "  stopped_reason = NULL, stopped_root_sha256 = NULL, stopped_at = NULL",
                 pqxx::params{vaultId, static_cast<int64_t>(r.epoch), r.root_sha256, r.producer, r.recorded, r.union_base,
                              static_cast<int>(r.applied), static_cast<int>(r.skipped), static_cast<int>(r.deferred),
                              static_cast<int>(r.kept), static_cast<int>(r.conflicts_decided),
                              static_cast<int>(r.conflicts_open), nlohmann::json(r.notes).dump()});
    });
}

bool ManifestApply::noteStopped(const uint32_t vaultId, const uint64_t epoch, const std::string& rootSha256,
                                const std::string& producer, const std::string& reason) {
    return Transactions::exec("ManifestApply::noteStopped", [&](pqxx::work& txn) {
        const auto r = txn.exec(
            "INSERT INTO manifest_apply_report (vault_id, epoch, root_sha256, producer, recorded, union_base, "
            "  stopped_reason, stopped_root_sha256, stopped_at) VALUES ($1, $2, $3, $4, false, false, $5, $3, "
            "  CURRENT_TIMESTAMP) "
            "ON CONFLICT (vault_id) DO UPDATE SET stopped_reason = EXCLUDED.stopped_reason, "
            "  stopped_root_sha256 = EXCLUDED.stopped_root_sha256, stopped_at = EXCLUDED.stopped_at "
            "WHERE manifest_apply_report.stopped_root_sha256 IS DISTINCT FROM EXCLUDED.stopped_root_sha256 "
            "   OR manifest_apply_report.stopped_reason IS DISTINCT FROM EXCLUDED.stopped_reason RETURNING 1",
            pqxx::params{vaultId, static_cast<int64_t>(epoch), rootSha256, producer, reason});
        return !r.empty();
    });
}

void ManifestApply::clearStopped(const uint32_t vaultId, const std::string& reason) {
    Transactions::exec("ManifestApply::clearStopped", [&](pqxx::work& txn) {
        txn.exec("UPDATE manifest_apply_report SET stopped_reason = NULL, stopped_root_sha256 = NULL, stopped_at = NULL "
                 "WHERE vault_id = $1 AND stopped_reason = $2",
                 pqxx::params{vaultId, reason});
    });
}

nlohmann::json ManifestApply::status(const uint32_t vaultId) {
    using namespace manifest_apply_detail;
    return Transactions::exec("ManifestApply::status", [&](pqxx::work& txn) {
        nlohmann::json out{{"epoch", nullptr}, {"own_epoch", nullptr}, {"applying_epoch", nullptr},
                           {"writers", nlohmann::json::array()}, {"deferred", 0}, {"last_apply", nullptr},
                           {"replicas", nlohmann::json::array()}, {"writers_change", nullptr}, {"behind", false},
                           {"cloud_only", nlohmann::json::array()}};   // the cloud's side: ops::cloud_storage::describeReplicas
        const auto s = txn.exec("SELECT epoch, own_epoch, applying_epoch, array_to_json(writers)::text, "
                                "  writers_change::text FROM remote_manifest_state WHERE vault_id = $1 AND "
                                "  manifest_key = '.vaulthalla/root'",
                                pqxx::params{vaultId});
        if (!s.empty()) {
            for (const auto* k : {"epoch", "own_epoch", "applying_epoch"})
                if (!s[0][k].is_null()) out[k] = s[0][k].as<uint64_t>();
            out["writers"] = nlohmann::json::parse(s[0][3].as<std::string>());
            if (!s[0][4].is_null()) out["writers_change"] = nlohmann::json::parse(s[0][4].as<std::string>());
        }
        // Each writer the recorded root names, with its last root this server recorded (none yet: nulls).
        const auto self = db::query::device::Devices::nodeId();
        for (const auto& w : out["writers"]) {
            const auto node = w.get<std::string>();
            nlohmann::json rep{{"node_id", node}, {"self", node == self}, {"last_epoch", nullptr},
                               {"last_root_sha256", nullptr}, {"last_published_at", nullptr}, {"cloud", nullptr}};
            const auto r = txn.exec("SELECT epoch, root_sha256, to_char(published_at AT TIME ZONE 'UTC', "
                                    "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM manifest_writer_root WHERE vault_id = $1 AND "
                                    "node_id = $2",
                                    pqxx::params{vaultId, node});
            if (!r.empty()) {
                rep["last_epoch"] = r[0][0].as<uint64_t>();
                rep["last_root_sha256"] = r[0][1].as<std::string>();
                if (!r[0][2].is_null()) rep["last_published_at"] = r[0][2].as<std::string>();
            }
            out["replicas"].push_back(std::move(rep));
        }
        out["deferred"] = txn.exec("SELECT count(*) FROM manifest_apply_deferred WHERE vault_id = $1",
                                   pqxx::params{vaultId}).one_field_ref().as<int64_t>();
        const auto r = txn.exec("SELECT epoch, producer, recorded, union_base, applied, skipped, deferred, kept, "
                                "  conflicts_decided, conflicts_open, notes::text, "
                                "  to_char(applied_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
                                "  stopped_reason, epoch FROM manifest_apply_report WHERE vault_id = $1",
                                pqxx::params{vaultId});
        if (!r.empty()) {
            const auto row = r[0];
            out["last_apply"] = {{"epoch", row[0].as<uint64_t>()},
                                 {"producer", row[1].as<std::string>()},
                                 {"recorded", row[2].as<bool>()},
                                 {"union_base", row[3].as<bool>()},
                                 {"applied", row[4].as<int64_t>()},
                                 {"skipped", row[5].as<int64_t>()},
                                 {"deferred", row[6].as<int64_t>()},
                                 {"kept", row[7].as<int64_t>()},
                                 {"conflicts_decided", row[8].as<int64_t>()},
                                 {"conflicts_open", row[9].as<int64_t>()},
                                 {"notes", nlohmann::json::parse(row[10].as<std::string>())},
                                 {"at", row[11].as<std::string>()},
                                 {"stopped", row[12].is_null() ? nlohmann::json(nullptr)
                                                               : nlohmann::json(row[12].as<std::string>())}};
        }
        // Behind: this server has not taken in everything the bucket's head says (an apply in progress, skipped or
        // stopped, or entries waiting for an open file), or a writers change is not published yet.
        const auto& a = out["last_apply"];
        out["behind"] = !out["applying_epoch"].is_null() || out["deferred"].get<int64_t>() > 0 ||
                        (a.is_object() && (!a["recorded"].get<bool>() || !a["stopped"].is_null())) ||
                        !out["writers_change"].is_null();
        return out;
    });
}

void ManifestApply::notePurgedLocally(const uint32_t vaultId, const std::string& objectKey) {
    Transactions::exec("ManifestApply::notePurgedLocally", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO manifest_shared_purge (vault_id, object_key) VALUES ($1, $2) "
                 "ON CONFLICT (vault_id, object_key) DO NOTHING",
                 pqxx::params{vaultId, objectKey});
    });
}

std::vector<std::string> ManifestApply::purgedLocallyBefore(const uint32_t vaultId, const std::time_t cutoff) {
    return Transactions::exec("ManifestApply::purgedLocallyBefore", [&](pqxx::work& txn) {
        std::vector<std::string> out;
        for (const auto r : txn.exec("SELECT object_key FROM manifest_shared_purge WHERE vault_id = $1 "
                                     "AND purged_at < to_timestamp($2) ORDER BY purged_at",
                                     pqxx::params{vaultId, static_cast<int64_t>(cutoff)}))
            out.push_back(r[0].as<std::string>());
        return out;
    });
}

void ManifestApply::dropPurgedLocally(const uint32_t vaultId, const std::string& objectKey) {
    Transactions::exec("ManifestApply::dropPurgedLocally", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM manifest_shared_purge WHERE vault_id = $1 AND object_key = $2",
                 pqxx::params{vaultId, objectKey});
    });
}

void ManifestApply::defer(pqxx::work& txn, const uint32_t vaultId, const DeferredEntry& d) {
    using namespace manifest_apply_detail;
    txn.exec("INSERT INTO manifest_apply_deferred (vault_id, uid, op, target, ours_generation, root_epoch, root_sha256) "
             "VALUES ($1, $2::uuid, $3, $4::jsonb, $5, $6, $7) ON CONFLICT (vault_id, uid) DO UPDATE SET op = EXCLUDED.op, "
             "  target = EXCLUDED.target, ours_generation = EXCLUDED.ours_generation, root_epoch = EXCLUDED.root_epoch, "
             "  root_sha256 = EXCLUDED.root_sha256, deferred_at = CURRENT_TIMESTAMP",
             pqxx::params{vaultId, uuidOf(d.uid), d.op,
                          d.target ? std::optional<std::string>(mf::canonicalJson(mf::toJson(*d.target))) : std::nullopt,
                          d.ours_generation, static_cast<int64_t>(d.root_epoch), d.root_sha256});
}

std::vector<DeferredEntry> ManifestApply::deferred(const uint32_t vaultId) {
    using namespace manifest_apply_detail;
    return Transactions::exec("ManifestApply::deferred", [&](pqxx::work& txn) {
        std::vector<DeferredEntry> out;
        for (const auto r : txn.exec("SELECT uid::text, op, target::text, ours_generation, root_epoch, root_sha256 "
                                     "FROM manifest_apply_deferred WHERE vault_id = $1 ORDER BY deferred_at",
                                     pqxx::params{vaultId})) {
            DeferredEntry d;
            d.uid = uidOfUuid(r[0].as<std::string>());
            d.op = r[1].as<std::string>();
            if (const auto t = optText(r[2])) d.target = mf::entryFromJson(nlohmann::json::parse(*t));
            d.ours_generation = optText(r[3]);
            d.root_epoch = r[4].as<uint64_t>();
            d.root_sha256 = r[5].as<std::string>();
            out.push_back(std::move(d));
        }
        return out;
    });
}

void ManifestApply::dropDeferred(pqxx::work& txn, const uint32_t vaultId, const std::string& uid) {
    using namespace manifest_apply_detail;
    txn.exec("DELETE FROM manifest_apply_deferred WHERE vault_id = $1 AND uid = $2::uuid", pqxx::params{vaultId, uuidOf(uid)});
}

}
