#include "db/query/fs/Symlink.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/u8.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/File.hpp"
#include "fs/model/Symlink.hpp"

#include <pqxx/pqxx>

namespace vh::db::query::fs {

using vh::db::encoding::to_utf8_string;

unsigned int Symlink::upsertSymlink(const SymlinkPtr& symlink) {
    if (!symlink) throw std::invalid_argument("Symlink cannot be null");
    if (!symlink->path.string().starts_with("/"))
        symlink->setPath("/" + to_utf8_string(symlink->path.u8string()));

    return Transactions::exec("Symlink::upsertSymlink", [&](pqxx::work& txn) {
        pqxx::params p;
        p.append(symlink->vault_id);
        p.append(symlink->parent_id);
        p.append(symlink->name);
        p.append(symlink->base32_alias);
        p.append(symlink->created_by);
        p.append(symlink->last_modified_by);
        p.append(to_utf8_string(symlink->path.u8string()));
        p.append(symlink->inode);
        p.append(symlink->mode);
        p.append(symlink->owner_uid);
        p.append(symlink->group_gid);
        p.append(symlink->is_hidden);
        p.append(symlink->is_system);
        p.append(symlink->target);

        const auto id = txn.exec(pqxx::prepped{"insert_symlink_full"}, p).one_field_ref().as<unsigned int>();

        Directory::addToAncestorStats(txn, symlink->parent_id, static_cast<int64_t>(symlink->target.size()), 1, 0);

        return id;
    });
}

void Symlink::deleteSymlink(const SymlinkPtr& symlink) {
    if (!symlink) throw std::invalid_argument("Symlink cannot be null");

    Transactions::exec("Symlink::deleteSymlink", [&](pqxx::work& txn) { deleteSymlink(txn, symlink->id); });
}

void Symlink::deleteSymlink(pqxx::work& txn, const unsigned int id) {
    const auto row = txn.exec(pqxx::prepped{"get_symlink_parent_id_and_size"}, id).one_row();
    const auto parentId = row["parent_id"].as<std::optional<unsigned int>>();
    const auto sizeBytes = row["size_bytes"].as<std::uint64_t>();

    txn.exec(pqxx::prepped{"delete_fs_entry"}, id);

    File::updateParentStats(txn, parentId, sizeBytes);
}

Symlink::SymlinkPtr Symlink::getSymlinkById(const unsigned int id) {
    return Transactions::exec("Symlink::getSymlinkById", [&](pqxx::work& txn) -> SymlinkPtr {
        const auto res = txn.exec(pqxx::prepped{"get_symlink_by_id"}, id);
        if (res.empty()) return nullptr;
        const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, res.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
        return std::make_shared<S>(res.one_row_ref(), parentRows);
    });
}

Symlink::SymlinkPtr Symlink::getSymlinkByPath(const unsigned int vaultId, const std::filesystem::path& relPath) {
    return Transactions::exec("Symlink::getSymlinkByPath", [&](pqxx::work& txn) -> SymlinkPtr {
        const auto res = txn.exec(pqxx::prepped{"get_symlink_by_path"}, pqxx::params{vaultId, to_utf8_string(relPath.u8string())});
        if (res.empty()) return nullptr;
        const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, res.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
        return std::make_shared<S>(res.one_row_ref(), parentRows);
    });
}

Symlink::SymlinkPtr Symlink::getSymlinkByInode(const ino_t ino) {
    return Transactions::exec("Symlink::getSymlinkByInode", [&](pqxx::work& txn) -> SymlinkPtr {
        const auto res = txn.exec(pqxx::prepped{"get_symlink_by_inode"}, ino);
        if (res.empty()) return nullptr;
        const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, res.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
        return std::make_shared<S>(res.one_row_ref(), parentRows);
    });
}

std::vector<Symlink::SymlinkPtr> Symlink::listSymlinksInDir(const unsigned int parentId, const bool recursive) {
    return Transactions::exec("Symlink::listSymlinksInDir", [&](pqxx::work& txn) {
        const auto res = recursive
            ? txn.exec(pqxx::prepped{"list_symlinks_in_dir_by_parent_id_recursive"}, parentId)
            : txn.exec(pqxx::prepped{"list_symlinks_in_dir_by_parent_id"}, parentId);

        return vh::fs::model::symlinks_from_pq_res(res);
    });
}

}
