#include "fs/tree_apply/TreeApply.hpp"

#include "db/Transactions.hpp"
#include "db/query/fs/Entry.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"

#include <fmt/format.h>
#include <pqxx/pqxx>

#include <stdexcept>
#include <system_error>

namespace vh::fs::tree_apply {

Target Target::of(const uint32_t vaultId) {
    Target t;
    t.vaultId = vaultId;
    const auto& deps = runtime::Deps::get();
    if (deps.storageManager) t.engine = deps.storageManager->getEngine(vaultId);
    if (!t.engine) throw std::runtime_error(fmt::format("vault {} has no storage engine to apply a tree to", vaultId));
    t.cache = deps.fsCache;
    return t;
}

std::filesystem::path Target::fuse(const std::string& vaultPath) const { return engine->vaultPathToFusePath(vaultPath); }

std::optional<Located> locate(pqxx::work& txn, const uint32_t vaultId, const std::string& uuid) {
    const auto live = txn.exec(
        "SELECT e.id, e.parent_id, e.name, e.path, e.base32_alias, e.inode, "
        "       CASE WHEN pe.path = '/' THEN v.uid::text ELSE pd.uid::text END AS parent_uid, "
        "       COALESCE(f.encryption_iv, '') AS generation, COALESCE(f.encrypted_with_key_version, 0) AS key_version, "
        "       CASE WHEN d.fs_entry_id IS NOT NULL THEN 'directory' WHEN f.fs_entry_id IS NOT NULL THEN 'file' "
        "            ELSE 'symlink' END AS kind "
        "FROM fs_entry e LEFT JOIN directories d ON d.fs_entry_id = e.id LEFT JOIN files f ON f.fs_entry_id = e.id "
        "LEFT JOIN symlinks s ON s.fs_entry_id = e.id LEFT JOIN fs_entry pe ON pe.id = e.parent_id "
        "LEFT JOIN directories pd ON pd.fs_entry_id = e.parent_id JOIN vault v ON v.id = e.vault_id "
        "WHERE e.vault_id = $1 AND e.path <> '/' AND (d.uid = $2::uuid OR f.object_uid = $2::uuid OR s.uid = $2::uuid)",
        pqxx::params{vaultId, uuid});
    if (!live.empty()) {
        const auto r = live[0];
        Located out;
        const auto kind = r["kind"].as<std::string>();
        out.kind = kind == "directory" ? Located::Kind::Directory
                   : kind == "file"    ? Located::Kind::File
                                       : Located::Kind::Symlink;
        out.id = r["id"].as<uint32_t>();
        if (!r["parent_id"].is_null()) out.parent_id = r["parent_id"].as<uint32_t>();
        if (!r["parent_uid"].is_null()) out.parent_uid = r["parent_uid"].as<std::string>();
        out.name = r["name"].as<std::string>();
        out.path = r["path"].as<std::string>();
        if (!r["base32_alias"].is_null()) out.base32_alias = r["base32_alias"].as<std::string>();
        if (!r["inode"].is_null()) out.inode = r["inode"].as<uint64_t>();
        out.generation = r["generation"].as<std::string>();
        out.key_version = r["key_version"].as<uint32_t>();
        return out;
    }
    const auto trashed = txn.exec("SELECT id, path, base32_alias FROM files_trashed "
                                  "WHERE vault_id = $1 AND object_uid = $2::uuid AND deleted_at IS NULL "
                                  "ORDER BY id DESC LIMIT 1",
                                  pqxx::params{vaultId, uuid});
    if (trashed.empty()) return std::nullopt;
    Located out;
    out.trashed = true;
    out.id = trashed[0]["id"].as<uint32_t>();
    out.path = trashed[0]["path"].as<std::string>();
    out.base32_alias = trashed[0]["base32_alias"].as<std::string>();
    return out;
}

std::optional<Located> locate(const uint32_t vaultId, const std::string& uuid) {
    return db::Transactions::exec("tree_apply::locate", [&](pqxx::work& txn) { return locate(txn, vaultId, uuid); });
}

void cacheFresh(const Target& target, const unsigned int entryId) {
    if (!target.cache) return;
    if (const auto entry = db::query::fs::Entry::getFSEntryById(entryId)) {
        if (!entry->inode) entry->inode = target.cache->getOrAssignInode(entry->fuse_path);
        target.cache->cacheEntry(entry);
        if (entry->parent_id) (void)target.cache->refreshDirStats(*entry->parent_id);
    }
}

void evicted(const Target& target, const std::string& vaultPath, const std::optional<unsigned int> parentId) {
    if (!target.cache) return;
    target.cache->evictPath(target.fuse(vaultPath));
    if (parentId) (void)target.cache->refreshDirStats(*parentId);
}

void ensureBackingDirectory(const std::filesystem::path& backing) {
    if (backing.empty()) return;
    std::error_code ec;
    std::filesystem::create_directories(backing, ec);
}

}
