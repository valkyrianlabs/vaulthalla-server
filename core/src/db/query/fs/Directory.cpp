#include "db/query/fs/Directory.hpp"
#include "db/Transactions.hpp"
#include "fs/model/Directory.hpp"
#include "db/encoding/u8.hpp"
#include "fs/model/Path.hpp"

#include <algorithm>
#include <optional>
#include <ctime>
#include <vector>

namespace vh::db::query::fs {

using vh::db::encoding::to_utf8_string;

unsigned int Directory::upsertDirectory(const DirPtr& directory) {
    if (!directory->path.string().starts_with("/")) directory->setPath("/" + to_utf8_string(directory->path.u8string()));
    if (directory->created_at == 0) directory->created_at = std::time(nullptr);
    if (directory->updated_at == 0) directory->updated_at = directory->created_at;
    return Transactions::exec("Directory::addDirectory", [&](pqxx::work& txn) {
        const auto exists = txn.exec(pqxx::prepped{"fs_entry_exists_by_inode"}, directory->inode).one_field_ref().as<bool>();
        if (directory->inode && *directory->inode != 1) txn.exec(pqxx::prepped{"delete_fs_entry_by_inode"}, directory->inode);

        pqxx::params p;
        p.append(directory->vault_id);
        p.append(directory->parent_id);
        p.append(directory->name);
        p.append(directory->base32_alias);
        p.append(directory->created_by);
        p.append(directory->last_modified_by);
        p.append(to_utf8_string(directory->path.u8string()));
        p.append(directory->inode);
        p.append(directory->mode);
        p.append(directory->owner_uid);
        p.append(directory->group_gid);
        p.append(directory->is_hidden);
        p.append(directory->is_system);
        p.append(directory->size_bytes);
        p.append(directory->file_count);
        p.append(directory->subdirectory_count);

        const auto id = txn.exec(pqxx::prepped{"upsert_directory"}, p).one_field_ref().as<unsigned int>();

        addToAncestorStats(txn, directory->parent_id, 0, 0, exists ? 0 : 1); // a new subdirectory

        return id;
    });
}

bool Directory::isDirectoryEmpty(unsigned int id) {
    return Transactions::exec("Directory::isDirectoryEmpty", [&](pqxx::work& txn) -> bool {
        const auto res = txn.exec(pqxx::prepped{"is_dir_empty"}, id);
        return res.one_field_ref().as<bool>();
    });
}

void Directory::moveDirectory(const DirPtr& directory, const std::filesystem::path& newPath, unsigned int userId) {
    if (!directory) throw std::invalid_argument("Directory cannot be null");
    if (!newPath.string().starts_with("/")) throw std::invalid_argument("New path must start with '/'");

    const auto commonPath = vh::fs::model::common_path_prefix(directory->path, newPath);

    Transactions::exec("Directory::moveDirectory", [&](pqxx::work& txn) {
        // update parents of the directory up to the common path
        std::optional<unsigned int> parentId = directory->parent_id;
        std::filesystem::path path = directory->path;
        while (parentId && path != commonPath) {
            pqxx::params stats_params{parentId, -static_cast<int>(directory->size_bytes), -static_cast<int>(directory->file_count), 0};
            txn.exec(pqxx::prepped{"update_dir_stats"}, stats_params);
            const auto row = txn.exec(pqxx::prepped{"get_fs_entry_parent_id_and_path"}, parentId).one_row();
            parentId = row["parent_id"].as<std::optional<unsigned int>>();
            path = row["path"].as<std::string>();
        }

        // Update the directory's path and parent_id
        directory->path = newPath;
        pqxx::params search_params{userId, to_utf8_string(newPath.parent_path().u8string())};
        directory->parent_id = txn.exec(pqxx::prepped{"get_fs_entry_id_by_path"}, search_params).one_field_ref().as<unsigned int>();
        directory->last_modified_by = userId;

        pqxx::params p;
        p.append(directory->vault_id);
        p.append(directory->parent_id);
        p.append(directory->name);
        p.append(directory->created_by);
        p.append(directory->last_modified_by);
        p.append(to_utf8_string(directory->path.u8string()));
        p.append(directory->size_bytes);
        p.append(directory->file_count);
        p.append(directory->subdirectory_count);

        txn.exec(pqxx::prepped{"upsert_directory"}, p);

        // Update parent directories stats
        parentId = directory->parent_id;
        path = directory->path;
        while (parentId && path != commonPath) {
            pqxx::params stats_params{parentId, directory->size_bytes, directory->file_count, 0}; // Increment size_bytes and file_count
            txn.exec(pqxx::prepped{"update_dir_stats"}, stats_params);
            const auto nextRow = txn.exec(pqxx::prepped{"get_fs_entry_parent_id_and_path"}, parentId).one_row();
            parentId = nextRow["parent_id"].as<std::optional<unsigned int>>();
            path = nextRow["path"].as<std::string>();
        }
    });
}

std::optional<Directory::SubtreeTotals> Directory::subtreeTotalsOf(pqxx::work& txn, const unsigned int id) {
    const auto res = txn.exec(R"SQL(
        SELECT
            (d.fs_entry_id IS NOT NULL) AS is_dir,
            COALESCE(d.size_bytes, f.size_bytes, octet_length(s.target)::bigint, 0) AS size_bytes,
            COALESCE(d.file_count, 0) AS file_count,
            COALESCE(d.subdirectory_count, 0) AS subdirectory_count
        FROM fs_entry e
        LEFT JOIN directories d ON d.fs_entry_id = e.id
        LEFT JOIN files f ON f.fs_entry_id = e.id
        LEFT JOIN symlinks s ON s.fs_entry_id = e.id
        WHERE e.id = $1
    )SQL", pqxx::params{id});
    if (res.empty()) return std::nullopt;

    const auto row = res.one_row_ref();
    const auto size = row["size_bytes"].as<int64_t>();
    if (row["is_dir"].as<bool>())
        return SubtreeTotals{.size_bytes = size, .files = row["file_count"].as<int64_t>(),
                             .subdirs = row["subdirectory_count"].as<int64_t>() + 1};
    return SubtreeTotals{.size_bytes = size, .files = 1, .subdirs = 0};
}

std::optional<unsigned int> Directory::parentIdOf(pqxx::work& txn, const unsigned int id) {
    const auto res = txn.exec(pqxx::prepped{"get_fs_entry_parent_id"}, pqxx::params{id});
    if (res.empty()) return std::nullopt;
    return res.one_field_ref().as<std::optional<unsigned int>>();
}

void Directory::addToAncestorStats(pqxx::work& txn, const std::optional<unsigned int> dirId,
                                   const int64_t sizeBytes, const int64_t files, const int64_t subdirs) {
    if (!dirId) return;
    txn.exec(pqxx::prepped{"add_to_ancestor_dir_stats"}, pqxx::params{*dirId, sizeBytes, files, subdirs});
}

namespace {

// `id` and every directory above it, nearest first (one statement).
std::vector<unsigned int> ancestorChain(pqxx::work& txn, const std::optional<unsigned int> id) {
    if (!id) return {};
    std::vector<unsigned int> chain{*id};
    for (const auto& row : txn.exec(pqxx::prepped{"collect_ancestor_ids"}, pqxx::params{*id}))
        chain.push_back(row[0].as<unsigned int>());
    return chain;
}

void addToDirStats(pqxx::work& txn, const unsigned int dirId, const Directory::SubtreeTotals& t, const int sign) {
    txn.exec(pqxx::prepped{"update_dir_stats"},
             pqxx::params{dirId, sign * t.size_bytes, sign * t.files, sign * t.subdirs});
}

}

std::vector<unsigned int> Directory::ancestorsOf(const unsigned int id) {
    return Transactions::exec("Directory::ancestorsOf", [&](pqxx::work& txn) {
        return ancestorChain(txn, parentIdOf(txn, id));
    });
}

void Directory::shiftSubtreeTotals(pqxx::work& txn, const std::optional<unsigned int> oldParentId,
                                   const std::optional<unsigned int> newParentId, const SubtreeTotals& totals) {
    if (oldParentId == newParentId) return;
    const auto oldChain = ancestorChain(txn, oldParentId);
    const auto newChain = ancestorChain(txn, newParentId);
    for (const auto id : oldChain)
        if (std::ranges::find(newChain, id) == newChain.end()) addToDirStats(txn, id, totals, -1);
    for (const auto id : newChain)
        if (std::ranges::find(oldChain, id) == oldChain.end()) addToDirStats(txn, id, totals, 1);
}

void Directory::deleteDirectoryTree(const unsigned int id) {
    Transactions::exec("Directory::deleteDirectoryTree", [&](pqxx::work& txn) {
        const auto totals = subtreeTotalsOf(txn, id);
        if (!totals) return;
        addToAncestorStats(txn, parentIdOf(txn, id), -totals->size_bytes, -totals->files, -totals->subdirs);
        txn.exec(pqxx::prepped{"delete_fs_entry"}, pqxx::params{id}); // children cascade
    });
}

bool Directory::deleteEmptyDirectory(const unsigned int id) {
    return Transactions::exec("Directory::deleteEmptyDirectory", [&](pqxx::work& txn) {
        if (!txn.exec(pqxx::prepped{"is_dir_empty"}, pqxx::params{id}).one_field_ref().as<bool>()) return false;
        const auto totals = subtreeTotalsOf(txn, id);
        if (!totals) return true;  // already gone
        addToAncestorStats(txn, parentIdOf(txn, id), -totals->size_bytes, -totals->files, -totals->subdirs);
        txn.exec(pqxx::prepped{"delete_fs_entry"}, pqxx::params{id});
        return true;
    });
}

Directory::DirPtr Directory::getDirectoryByPath(const unsigned int vaultId, const std::filesystem::path& relPath) {
    return Transactions::exec("Directory::getDirectoryByPath", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"get_dir_by_path"}, pqxx::params{vaultId, relPath.string()});
        const auto row = res.one_row_ref();
        const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, row["parent_id"].as<std::optional<unsigned int>>());
        return std::make_shared<Dir>(row, parentRows);
    });
}

std::optional<unsigned int> Directory::getDirectoryIdByPath(const unsigned int vaultId, const std::filesystem::path& path) {
    return Transactions::exec("Directory::getDirectoryIdByPath", [&](pqxx::work& txn) -> std::optional<unsigned int> {
        pqxx::params p{vaultId, path.string()};
        const auto res = txn.exec(pqxx::prepped{"get_fs_entry_id_by_path"}, p);
        if (res.empty()) return std::nullopt;
        return res.one_row_ref()["id"].as<unsigned int>();
    });
}

unsigned int Directory::getRootDirectoryId(const unsigned int vaultId) {
    return Transactions::exec("Directory::getRootDirectoryId", [&](pqxx::work& txn) -> unsigned int {
        pqxx::params p{vaultId, "/"};
        return txn.exec(pqxx::prepped{"get_fs_entry_id_by_path"}, p).one_row_ref()["id"].as<unsigned int>();
    });
}

bool Directory::isDirectory(const unsigned int vaultId, const std::filesystem::path& relPath) {
    return Transactions::exec("Directory::isDirectory", [&](pqxx::work& txn) -> bool {
        pqxx::params p{vaultId, relPath.string()};
        return txn.exec(pqxx::prepped{"is_directory"}, p).one_row_ref()["exists"].as<bool>();
    });
}

bool Directory::directoryExists(const unsigned int vaultId, const std::filesystem::path& relPath) {
    return isDirectory(vaultId, relPath);
}

std::vector<Directory::DirPtr> Directory::listDirectoriesInDir(const unsigned int parentId, const bool recursive) {
    return Transactions::exec("Directory::listDirectoriesInDir", [&](pqxx::work& txn) {
        const auto res = recursive
            ? txn.exec(pqxx::prepped{"list_dirs_in_dir_by_parent_id_recursive"}, parentId)
            : txn.exec(pqxx::prepped{"list_dirs_in_dir_by_parent_id"}, parentId);

        return vh::fs::model::directories_from_pq_res(res);
    });
}

std::optional<Directory::ListingShape> Directory::listingShape(const unsigned int dirId) {
    return Transactions::read("Directory::listingShape", [&](pqxx::transaction_base& txn) -> std::optional<ListingShape> {
        const auto res = txn.exec(
            "SELECT (SELECT count(*) FROM fs_entry c WHERE c.parent_id = d.fs_entry_id AND c.id != 1) AS direct, "
            "       d.file_count + d.subdirectory_count AS subtree "
            "FROM directories d WHERE d.fs_entry_id = $1",
            pqxx::params{dirId});
        if (res.empty()) return std::nullopt;
        const auto row = res.one_row_ref();
        return ListingShape{.direct = row["direct"].as<uint64_t>(), .subtree = row["subtree"].as<uint64_t>()};
    });
}

pqxx::result Directory::collectParentStats(unsigned int parentId) {
    return Transactions::exec("Directory::collectParentStats", [&](pqxx::work& txn) {
        return txn.exec(pqxx::prepped{"collect_parent_dir_stats"}, parentId);
    });
}

}
