#include "db/query/fs/Entry.hpp"
#include "db/Transactions.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/Symlink.hpp"
#include "db/encoding/u8.hpp"
#include "log/Registry.hpp"

namespace vh::db::query::fs {

using vh::db::encoding::to_utf8_string;

bool Entry::rootExists() {
    return Transactions::exec("Entry::rootExists", [&](pqxx::work& txn) {
        return txn.exec(pqxx::prepped{"root_entry_exists"}).one_field_ref().as<bool>();
    });
}

Entry::EntryPtr Entry::getRootEntry() {
    return Transactions::exec("Entry::getRootEntry", [&](pqxx::work& txn) -> EntryPtr {
        const auto res = txn.exec(pqxx::prepped{"get_root_entry"});
        if (res.empty()) {
            log::Registry::db()->warn("[Entry::getRootEntry] No root entry found in the database");
            return nullptr;
        }
        return std::make_shared<vh::fs::model::Directory>(res.one_row_ref(), pqxx::result{});
    });
}

void Entry::updateFSEntry(const EntryPtr& entry) {
    Transactions::exec("Entry::updateFSEntry", [&](pqxx::work& txn) {
        pqxx::params p;
        p.append(entry->inode);
        p.append(entry->vault_id);
        p.append(entry->parent_id);
        p.append(entry->name);
        p.append(entry->base32_alias);
        p.append(entry->last_modified_by);
        p.append(to_utf8_string(entry->path.u8string()));
        p.append(entry->mode);
        p.append(entry->owner_uid);
        p.append(entry->group_gid);
        p.append(entry->is_hidden);
        p.append(entry->is_system);

        txn.exec(pqxx::prepped{"update_fs_entry_by_inode"}, p);
    });
}

bool Entry::setAttributes(const unsigned int entryId, const Attributes& attrs, const std::optional<unsigned int> actorId) {
    if (attrs.empty()) return true;
    return Transactions::exec("Entry::setAttributes", [&](pqxx::work& txn) {
        txn.exec("SELECT set_config('vh.keep_mtime', 'on', true)");
        if (actorId) txn.exec("SELECT set_config('vh.actor', $1, true)", pqxx::params{std::to_string(*actorId)});
        const std::optional<int64_t> mode =
            attrs.mode ? std::optional<int64_t>(static_cast<int64_t>(*attrs.mode & 07777u)) : std::nullopt;
        const std::optional<double> mtime =
            attrs.mtime_us ? std::optional<double>(static_cast<double>(*attrs.mtime_us) / 1e6) : std::nullopt;
        return !txn.exec("UPDATE fs_entry SET mode = COALESCE($2::integer, mode), "
                         "  owner_uid = COALESCE($3::integer, owner_uid), group_gid = COALESCE($4::integer, group_gid), "
                         "  updated_at = COALESCE(to_timestamp($5::double precision), updated_at) "
                         "WHERE id = $1 RETURNING id",
                         pqxx::params{entryId, mode, attrs.owner_uid, attrs.group_gid, mtime})
                    .empty();
    });
}

Entry::EntryPtr Entry::getFSEntry(const std::string& base32) {
    return Transactions::exec("Entry::getFSEntry", [&](pqxx::work& txn) -> Entry::EntryPtr {
        const auto fileRes = txn.exec(pqxx::prepped{"get_file_by_base32_alias"}, base32);
        if (!fileRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, fileRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::File>(fileRes.one_row_ref(), parentRows);
        }

        const auto symlinkRes = txn.exec(pqxx::prepped{"get_symlink_by_base32_alias"}, base32);
        if (!symlinkRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, symlinkRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::Symlink>(symlinkRes.one_row_ref(), parentRows);
        }

        const auto dirRes = txn.exec(pqxx::prepped{"get_dir_by_base32_alias"}, base32);
        if (!dirRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, dirRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::Directory>(dirRes.one_row_ref(), parentRows);
        }

        return nullptr;
    });
}

Entry::EntryPtr Entry::getFSEntryByInode(const ino_t ino) {
    return Transactions::exec("Entry::getFSEntryByInode", [&](pqxx::work& txn) -> Entry::EntryPtr {
        const auto fileRes = txn.exec(pqxx::prepped{"get_file_by_inode"}, ino);
        if (!fileRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, fileRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::File>(fileRes.one_row_ref(), parentRows);
        }

        const auto symlinkRes = txn.exec(pqxx::prepped{"get_symlink_by_inode"}, ino);
        if (!symlinkRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, symlinkRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::Symlink>(symlinkRes.one_row_ref(), parentRows);
        }

        const auto dirRes = txn.exec(pqxx::prepped{"get_dir_by_inode"}, ino);
        if (!dirRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, dirRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::Directory>(dirRes.one_row_ref(), parentRows);
        }

        return nullptr;
    });
}

Entry::EntryPtr Entry::getFSEntryByPath(const unsigned int vaultId, const std::filesystem::path& relPath) {
    return Transactions::exec("Entry::getFSEntryByPath", [&](pqxx::work& txn) -> Entry::EntryPtr {
        const pqxx::params params{vaultId, to_utf8_string(relPath.u8string())};

        const auto fileRes = txn.exec(pqxx::prepped{"get_file_by_path"}, params);
        if (!fileRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, fileRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::File>(fileRes.one_row_ref(), parentRows);
        }

        const auto symlinkRes = txn.exec(pqxx::prepped{"get_symlink_by_path"}, params);
        if (!symlinkRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, symlinkRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::Symlink>(symlinkRes.one_row_ref(), parentRows);
        }

        const auto dirRes = txn.exec(pqxx::prepped{"get_dir_by_path"}, params);
        if (!dirRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, dirRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::Directory>(dirRes.one_row_ref(), parentRows);
        }

        return nullptr;
    });
}


Entry::EntryPtr Entry::getFSEntryById(unsigned int entryId) {
    return Transactions::exec("Entry::getFSEntryById", [&](pqxx::work& txn) -> Entry::EntryPtr {
        const auto res = txn.exec(pqxx::prepped{"get_fs_entry_by_id"}, entryId);
        if (res.empty()) return nullptr;

        const auto fileRes = txn.exec(pqxx::prepped{"get_file_by_id"}, entryId);
        if (!fileRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, fileRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::File>(fileRes.one_row_ref(), parentRows);
        }

        const auto symlinkRes = txn.exec(pqxx::prepped{"get_symlink_by_id"}, entryId);
        if (!symlinkRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, symlinkRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::Symlink>(symlinkRes.one_row_ref(), parentRows);
        }

        const auto dirRes = txn.exec(pqxx::prepped{"get_dir_by_id"}, entryId);
        if (!dirRes.empty()) {
            const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, dirRes.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
            return std::make_shared<vh::fs::model::Directory>(dirRes.one_row_ref(), parentRows);
        }

        return nullptr;
    });
}

void Entry::renameEntry(const EntryPtr& entry) {
    if (entry->parent_id && *entry->parent_id == 0) entry->parent_id = std::nullopt;
    Transactions::exec("Entry::renameEntry", [&](pqxx::work& txn) {
        pqxx::params p{entry->id, entry->name,
                       to_utf8_string(entry->path.u8string()),
                       to_utf8_string(entry->fuse_path.u8string()),
                       entry->parent_id};
        txn.exec(pqxx::prepped{"rename_fs_entry"}, p);
    });
}

std::vector<Entry::EntryPtr> Entry::listDir(const std::optional<unsigned int>& entryId, const bool recursive) {
    if (!entryId) {
        log::Registry::db()->warn("[Entry::listDir] entryId is null, returning empty list");
        return {};
    }

    log::Registry::db()->debug("[Entry::listDir] Listing directory with parent ID: {}, recursive: {}", *entryId, recursive);

    return Transactions::exec("Entry::listDirById", [&](pqxx::work& txn) {
        const auto files = vh::fs::model::files_from_pq_res(
            recursive
                ? txn.exec(pqxx::prepped{"list_files_in_dir_by_parent_id_recursive"}, entryId)
                : txn.exec(pqxx::prepped{"list_files_in_dir_by_parent_id"}, entryId),
            txn);

        log::Registry::db()->info("[Entry::listDir] Executing queries for directories...");
        const auto directories = vh::fs::model::directories_from_pq_res(
            recursive
                ? txn.exec(pqxx::prepped{"list_dirs_in_dir_by_parent_id_recursive"}, entryId)
                : txn.exec(pqxx::prepped{"list_dirs_in_dir_by_parent_id"}, entryId),
            txn);

        const auto symlinks = vh::fs::model::symlinks_from_pq_res(
            recursive
                ? txn.exec(pqxx::prepped{"list_symlinks_in_dir_by_parent_id_recursive"}, entryId)
                : txn.exec(pqxx::prepped{"list_symlinks_in_dir_by_parent_id"}, entryId),
            txn);

        return merge_entries(files, symlinks, directories);
    });
}

std::vector<Entry::EntryPtr> Entry::listSubtree(const unsigned int dirId) {
    // The directories under dirId (recursing through directories only), then what each of them and dirId hold.
    static constexpr auto kTree = R"SQL(
        WITH RECURSIVE tree AS (
            SELECT e.id FROM fs_entry e WHERE e.id = $1
          UNION ALL
            SELECT c.id FROM fs_entry c JOIN directories d ON d.fs_entry_id = c.id JOIN tree t ON c.parent_id = t.id
        )
    )SQL";

    struct Rows { pqxx::result files, symlinks, directories; };
    return Transactions::exec("Entry::listSubtree", [&](pqxx::work& txn) {
        const pqxx::params p{dirId};
        const Rows rows{
            txn.exec(std::string(kTree) +
                     "SELECT fs.*, f.* FROM fs_entry fs JOIN files f ON f.fs_entry_id = fs.id "
                     "WHERE fs.parent_id IN (SELECT id FROM tree)", p),
            txn.exec(std::string(kTree) +
                     "SELECT s.target, char_length(s.target)::bigint AS size_bytes, fs.* FROM fs_entry fs "
                     "JOIN symlinks s ON s.fs_entry_id = fs.id WHERE fs.parent_id IN (SELECT id FROM tree)", p),
            txn.exec(pqxx::prepped{"list_dirs_in_dir_by_parent_id_recursive"}, p)
        };
        // Each entry's parent chain (fuse and backing paths) is read in this transaction, on its connection.
        return merge_entries(vh::fs::model::files_from_pq_res(rows.files, txn),
                             vh::fs::model::symlinks_from_pq_res(rows.symlinks, txn),
                             vh::fs::model::directories_from_pq_res(rows.directories, txn));
    });
}

ino_t Entry::getNextInode() {
    return Transactions::exec("Entry::getNextInode", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"get_next_inode"});
        if (res.empty()) throw std::runtime_error("No inode available");
        return res.one_field_ref().as<ino_t>();
    });
}

pqxx::result Entry::collectParentChain(unsigned int parentId) {
    return Transactions::exec("Entry::collectParentChain", [&](pqxx::work& txn) {
        return collectParentChain(txn, parentId);
    });
}

pqxx::result Entry::collectParentChain(pqxx::transaction_base& txn, const unsigned int parentId) {
    return txn.exec(pqxx::prepped{"collect_parent_chain"}, parentId);
}

}
