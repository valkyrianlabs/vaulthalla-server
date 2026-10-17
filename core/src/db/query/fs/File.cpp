#include "db/query/fs/File.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/file/Trashed.hpp"
#include "db/encoding/u8.hpp"
#include "fs/model/Path.hpp"
#include "runtime/Deps.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/stats/Extension.hpp"
#include "crypto/id/Generator.hpp"

#include <optional>
#include <stdexcept>
#include <ctime>

namespace vh::db::query::fs {

using vh::db::encoding::to_utf8_string;

unsigned int File::upsertFile(const FilePtr& file) {
    if (!file) throw std::invalid_argument("File cannot be null");
    if (!file->path.string().starts_with("/")) file->setPath("/" + to_utf8_string(file->path.u8string()));
    if (file->created_at == 0) file->created_at = std::time(nullptr);
    if (file->updated_at == 0) file->updated_at = file->created_at;

    return Transactions::exec("File::addFile", [&](pqxx::work& txn) {
        const auto exists = txn.exec(pqxx::prepped{"fs_entry_exists_by_inode"}, file->inode).one_field_ref().as<bool>();
        const auto sizeRes = txn.exec(pqxx::prepped{"get_file_size_by_inode"}, file->inode);
        const auto existingSize = sizeRes.empty() ? 0 : sizeRes.one_field_ref().as<uintmax_t>();
        if (file->inode) txn.exec(pqxx::prepped{"delete_fs_entry_by_inode"}, file->inode);

        pqxx::params p;
        p.append(file->vault_id);
        p.append(file->parent_id);
        p.append(file->name);
        p.append(file->base32_alias);
        p.append(file->created_by);
        p.append(file->last_modified_by);
        p.append(to_utf8_string(file->path.u8string()));
        p.append(file->inode);
        p.append(file->mode);
        p.append(file->owner_uid);
        p.append(file->group_gid);
        p.append(file->is_hidden);
        p.append(file->is_system);
        p.append(file->size_bytes);
        p.append(file->mime_type);
        p.append(file->content_hash);
        p.append(file->encryption_iv);
        p.append(file->encrypted_with_key_version);

        const auto fileId = txn.exec(pqxx::prepped{"upsert_file_full"}, p).one_row_ref()["fs_entry_id"].as<unsigned int>();
        txn.exec(
            pqxx::prepped{"insert_file_activity"},
            pqxx::params{
                fileId,
                exists ? file->last_modified_by : file->created_by,
                exists ? "modified" : "created"
            }
        );

        Directory::addToAncestorStats(txn, file->parent_id,
                                      static_cast<int64_t>(file->size_bytes) - static_cast<int64_t>(existingSize),
                                      exists ? 0 : 1, 0);

        return fileId;
    });
}

void File::updateFile(const FilePtr& file) {
    if (!file) throw std::invalid_argument("File cannot be null");
    if (file->id == 0) throw std::invalid_argument("File ID cannot be zero");
    if (!file->path.string().starts_with("/")) file->setPath("/" + to_utf8_string(file->path.u8string()));

    Transactions::exec("File::updateFile", [&](pqxx::work& txn) {
        const auto exists = txn.exec(pqxx::prepped{"fs_entry_exists_by_inode"}, file->inode).one_field_ref().as<bool>();
        const auto sizeRes = txn.exec(pqxx::prepped{"get_file_size_by_inode"}, file->inode);
        const auto existingSize = sizeRes.empty() ? 0 : sizeRes.one_field_ref().as<uintmax_t>();

        pqxx::params p;
        p.append(file->id);
        p.append(file->size_bytes);
        p.append(file->mime_type);
        p.append(file->content_hash);
        p.append(file->encryption_iv);
        p.append(file->encrypted_with_key_version);
        p.append(file->last_modified_by);

        file->updated_at = std::time(nullptr);
        txn.exec(pqxx::prepped{"update_file_only"}, p);
        txn.exec(
            pqxx::prepped{"insert_file_activity"},
            pqxx::params{file->id, file->last_modified_by, "modified"}
        );

        Directory::addToAncestorStats(txn, file->parent_id,
                                      static_cast<int64_t>(file->size_bytes) - static_cast<int64_t>(existingSize),
                                      exists ? 0 : 1, 0);
    });
}

void File::markTrashedFileDeleted(const unsigned int id) {
    Transactions::exec("File::deleteFile", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"mark_trashed_file_deleted_by_id"}, id);
    });
}

void File::deleteFile(const unsigned int userId, const FilePtr& file) {
    if (!file) throw std::invalid_argument("File cannot be null");

    Transactions::exec("File::deleteFileByPath", [&](pqxx::work& txn) {
        const auto path = to_utf8_string(file->path.u8string());

        pqxx::params p{file->vault_id, path};
        const auto row = txn.exec(pqxx::prepped{"get_file_parent_id_and_size_by_path"}, p).one_row();
        const auto parentId = row["parent_id"].as<std::optional<unsigned int> >();
        const auto sizeBytes = row["size_bytes"].as<std::uint64_t>();

        txn.exec(
            pqxx::prepped{"mark_file_trashed"},
            pqxx::params{file->vault_id, path, userId, to_utf8_string(file->backing_path.u8string())}
        );

        updateParentStats(txn, parentId, sizeBytes);

        txn.exec(pqxx::prepped{"mark_trashed_file_deleted_by_base32_alias"}, pqxx::params{file->base32_alias});
    });
}

void File::moveFile(const FilePtr& file, const std::filesystem::path& newPath, unsigned int userId) {
    const auto commonPath = vh::fs::model::common_path_prefix(file->path, newPath);
    Transactions::exec("File::moveFile", [&](pqxx::work& txn) {
        // Update the file's path and parent_id up to the common path
        std::optional<unsigned int> parentId = file->parent_id;
        std::filesystem::path path = file->path;
        while (parentId && path != commonPath) {
            pqxx::params stats_params{parentId, -static_cast<int>(file->size_bytes), -1, 0};
            txn.exec(pqxx::prepped{"update_dir_stats"}, stats_params);
            const auto row = txn.exec(pqxx::prepped{"get_fs_entry_parent_id_and_path"}, parentId).one_row();
            parentId = row["parent_id"].as<std::optional<unsigned int>>();
            path = row["path"].as<std::string>();
        }

        // update the file's path and parent_id
        file->path = newPath;
        pqxx::params search_params{userId, to_utf8_string(newPath.parent_path().u8string())};
        file->parent_id = txn.exec(pqxx::prepped{"get_fs_entry_id_by_path"}, search_params).one_field_ref().as<unsigned int>();
        file->last_modified_by = userId;

        pqxx::params p;
        p.append(file->vault_id);
        p.append(file->parent_id);
        p.append(file->name);
        p.append(file->base32_alias);
        p.append(file->created_by);
        p.append(file->last_modified_by);
        p.append(to_utf8_string(file->path.u8string()));
        p.append(file->inode);
        p.append(file->mode);
        p.append(file->owner_uid);
        p.append(file->group_gid);
        p.append(file->is_hidden);
        p.append(file->is_system);
        p.append(file->size_bytes);
        p.append(file->mime_type);
        p.append(file->content_hash);
        p.append(file->encryption_iv);
        p.append(file->encrypted_with_key_version);

        txn.exec(pqxx::prepped{"upsert_file_full"}, p);

        // Update parent directories stats
        parentId = file->parent_id;
        path = file->path;
        while (parentId && path != commonPath) {
            pqxx::params stats_params{parentId, file->size_bytes, 1, 0}; // Increment size_bytes and file_count
            txn.exec(pqxx::prepped{"update_dir_stats"}, stats_params);
            const auto nextRow = txn.exec(pqxx::prepped{"get_fs_entry_parent_id_and_path"}, parentId).one_row();
            parentId = nextRow["parent_id"].as<std::optional<unsigned int> >();
            path = nextRow["path"].as<std::string>();
        }
    });
}

File::FilePtr File::getFileByPath(const unsigned int vaultId, const std::filesystem::path& relPath) {
    return Transactions::exec("File::getFileByPath", [&](pqxx::work& txn) -> FilePtr {
        const auto res = txn.exec(pqxx::prepped{"get_file_by_path"}, pqxx::params{vaultId, to_utf8_string(relPath.u8string())});
        if (res.empty()) return nullptr;
        const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, res.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
        return std::make_shared<F>(res.one_row_ref(), parentRows);
    });
}

File::FilePtr File::getFileById(unsigned int id) {
    return Transactions::exec("File::getFileById", [&](pqxx::work& txn) -> FilePtr {
        const auto res = txn.exec(pqxx::prepped{"get_file_by_id"}, id);
        if (res.empty()) return nullptr; // No file found with the given ID
        const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, res.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
        return std::make_shared<F>(res.one_row_ref(), parentRows);
    });
}


std::string File::getMimeType(const unsigned int vaultId, const std::filesystem::path& relPath) {
    return Transactions::exec("File::getMimeType", [&](pqxx::work& txn) -> std::string {
        pqxx::params p{vaultId, to_utf8_string(relPath.u8string())};
        const auto res = txn.exec(pqxx::prepped{"get_file_mime_type"}, p);
        if (res.empty()) return "application/octet-stream"; // Default MIME type if not found
        return res.one_field_ref().as<std::string>();
    });
}

bool File::isFile(const unsigned int vaultId, const std::filesystem::path& relPath) {
    return Transactions::exec("File::isFile", [&](pqxx::work& txn) -> bool {
        pqxx::params p{vaultId, to_utf8_string(relPath.u8string())};
        return txn.exec(pqxx::prepped{"is_file"}, p).one_row_ref()["exists"].as<bool>();
    });
}

std::vector<File::FilePtr> File::listFilesInDir(
    const unsigned int vaultId, const std::filesystem::path& path, const bool recursive) {
    return Transactions::exec("File::listFilesInDir", [&](pqxx::work& txn) {
        const auto patterns = computePatterns(path.string(), recursive);
        const auto res = recursive
                             ? txn.exec(pqxx::prepped{"list_files_in_dir_recursive"}, pqxx::params{vaultId, patterns.like})
                             : txn.exec(pqxx::prepped{"list_files_in_dir"},
                                                 pqxx::params{vaultId, patterns.like, patterns.not_like});

        return vh::fs::model::files_from_pq_res(res);
    });
}

std::vector<File::TrashedFilePtr> File::listTrashedFiles(unsigned int vaultId) {
    return Transactions::exec("File::listTrashedFiles", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"list_trashed_files"}, vaultId);
        return db::sharedRows<vh::fs::model::file::Trashed>(res);
    });
}

void File::markFileAsTrashed(const unsigned int userId, const unsigned int vaultId,
                                    const std::filesystem::path& relPath) {
    const auto file = getFileByPath(vaultId, relPath);
    if (!file) throw std::runtime_error("[markFileAsTrashed] File not found: " + to_utf8_string(relPath.u8string()));

    Transactions::exec("File::markFileAsTrashed", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"get_file_parent_id_and_size_by_path"},
                                           pqxx::params{vaultId, to_utf8_string(relPath.u8string())});
        if (res.empty()) throw std::runtime_error("[markFileAsTrashed] File not found: " + to_utf8_string(relPath.u8string()));

        const auto row = res[0];
        const auto parentId = row["parent_id"].as<std::optional<unsigned int> >();
        const auto sizeBytes = row["size_bytes"].as<std::uint64_t>();

        txn.exec(pqxx::prepped{"mark_file_trashed"}, pqxx::params{vaultId, to_utf8_string(relPath.u8string()), userId, to_utf8_string(file->backing_path.u8string())});

        updateParentStats(txn, parentId, sizeBytes);
    });
}

void File::markFileAsTrashed(const unsigned int userId, const unsigned int fsId) {
    const auto file = getFileById(fsId);
    if (!file) throw std::runtime_error("[markFileAsTrashed] File not found with ID: " + std::to_string(fsId));

    Transactions::exec("File::markFileAsTrashed", [&](pqxx::work& txn) {
        markFileAsTrashed(txn, userId, fsId, file->backing_path);
    });
}

void File::markFileAsTrashed(pqxx::work& txn, const std::optional<unsigned int> userId, const unsigned int fsId,
                             const std::filesystem::path& backingPath) {
    const auto row = txn.exec(pqxx::prepped{"get_file_parent_id_and_size"}, fsId).one_row();
    const auto parentId = row["parent_id"].as<std::optional<unsigned int>>();
    const auto sizeBytes = row["size_bytes"].as<std::uint64_t>();

    pqxx::params p{fsId, userId, to_utf8_string(backingPath.u8string())};
    txn.exec(pqxx::prepped{"mark_file_trashed_by_id"}, p);

    updateParentStats(txn, parentId, sizeBytes);
}

void File::markRemoteFileAsTrashed(
    const unsigned int userId,
    const unsigned int vaultId,
    const std::filesystem::path& relPath,
    const std::uint64_t sizeBytes) {
    auto normalized = vh::fs::model::makeAbsolute(relPath);
    const auto path = to_utf8_string(normalized.u8string());
    const auto base32Alias = vh::crypto::id::Generator({.namespace_token = path + ":" + std::to_string(std::time(nullptr))}).generate();

    Transactions::exec("File::markRemoteFileAsTrashed", [&](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                INSERT INTO files_trashed
                    (vault_id, path, backing_path, base32_alias, size_bytes, trashed_at, trashed_by)
                SELECT $1, $2, '', $3, $4, NOW(), $5
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM files_trashed
                    WHERE vault_id = $1 AND path = $2 AND deleted_at IS NULL
                )
            )SQL",
            pqxx::params{vaultId, path, base32Alias, sizeBytes, userId});
    });
}

// A removed file (or symlink) comes off the subtree totals of every ancestor. Folders are never removed with it: a
// folder the delete leaves without files stays, in the database and on disk, like in any file manager (#168).
void File::updateParentStats(pqxx::work& txn, std::optional<unsigned int> parentId, const std::uint64_t sizeBytes) {
    Directory::addToAncestorStats(txn, parentId, -static_cast<int64_t>(sizeBytes), -1, 0);
}

std::optional<std::pair<std::string, unsigned int>>  File::getEncryptionIVAndVersion(const unsigned int vaultId, const std::filesystem::path& relPath) {
    return Transactions::exec("File::getEncryptionIV", [&](pqxx::work& txn) -> std::optional<std::pair<std::string, unsigned int>> {
        pqxx::params p{vaultId, to_utf8_string(relPath.u8string())};
        const auto res = txn.exec(pqxx::prepped{"get_file_encryption_iv_and_version"}, p);
        if (res.empty()) return std::nullopt;
        const auto row = res.one_row_ref();
        if (row["encryption_iv"].is_null() || row["encrypted_with_key_version"].is_null())
            return std::nullopt;
        const auto iv = row["encryption_iv"].as<std::string>();
        const auto keyVersion = row["encrypted_with_key_version"].as<unsigned int>();
        if (iv.empty() || keyVersion == 0) return std::nullopt;
        return std::make_pair(iv, keyVersion);
    });
}

void File::setEncryptionIVAndVersion(const FilePtr& f) {
    Transactions::exec("File::setEncryptionIVAndVersion", [&](pqxx::work& txn) {
        pqxx::params p{f->vault_id, to_utf8_string(f->path.u8string()), f->encryption_iv, f->encrypted_with_key_version};
        txn.exec(pqxx::prepped{"set_file_encryption_iv_and_version"}, p);
    });
}

bool File::compareAndSetEncryptionIVAndVersion(const F& f, const std::string& expectedIv, const unsigned int expectedVersion) {
    if (!f.vault_id) throw std::invalid_argument("File::compareAndSetEncryptionIVAndVersion: file has no vault");
    return Transactions::exec("File::compareAndSetEncryptionIVAndVersion", [&](pqxx::work& txn) {
        pqxx::params p{*f.vault_id, to_utf8_string(f.path.u8string()), f.encryption_iv, f.encrypted_with_key_version,
                       expectedIv, expectedVersion};
        return txn.exec(pqxx::prepped{"compare_and_set_file_encryption_iv_and_version"}, p).affected_rows() == 1;
    });
}

std::string File::getContentHash(const unsigned int vaultId, const std::filesystem::path& relPath) {
    return Transactions::exec("File::getContentHash", [&](pqxx::work& txn) -> std::string {
        pqxx::params p{vaultId, to_utf8_string(relPath.u8string())};
        return txn.exec(pqxx::prepped{"get_file_content_hash"}, p).one_field_ref().as<std::string>();
    });
}

std::vector<File::FilePtr> File::getFilesOlderThanKeyVersion(unsigned int vaultId, unsigned int keyVersion) {
    return Transactions::exec("File::getFilesOlderThanKeyVersion", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"get_files_older_than_key_version"}, pqxx::params{vaultId, keyVersion});
        if (res.empty()) return std::vector<FilePtr>();
        return vh::fs::model::files_from_pq_res(res);
    });
}

File::FilePtr File::getLargestFile(unsigned int vaultId) {
    return Transactions::exec("File::getLargestFile", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"get_n_largest_files"}, pqxx::params{vaultId, 1});
        if (res.empty()) return FilePtr();
        const auto parentRows = txn.exec(pqxx::prepped{"collect_parent_chain"}, res.one_row_ref()["parent_id"].as<std::optional<unsigned int>>());
        return std::make_shared<F>(res.one_row_ref(), parentRows);
    });
}

std::vector<File::FilePtr> File::getNLargestFiles(unsigned int vaultId, unsigned int n) {
    return Transactions::exec("File::getNLargestFile", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"get_n_largest_files"}, pqxx::params{vaultId, n});
        if (res.empty()) return std::vector<FilePtr>();
        return vh::fs::model::files_from_pq_res(res);
    });
}

std::vector<File::FilePtr> File::getAllFiles(unsigned int vaultId) {
    return Transactions::exec("File::getAllFiles", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"get_all_files"}, pqxx::params{vaultId});
        if (res.empty()) return std::vector<FilePtr>();
        return vh::fs::model::files_from_pq_res(res);
    });
}

std::vector<vh::fs::model::stats::Extension> File::getTopExtensionsBySize(const unsigned int vaultId, const unsigned int limit) {
    if (limit == 0) return {};

    return Transactions::exec("File::getTopExtensionsBySize", [&](pqxx::work& txn) {
        pqxx::params p;
        p.append(vaultId);
        p.append(limit);

        const auto res = txn.exec(pqxx::prepped{"get_top_extensions_by_size"}, p);
        if (res.empty()) return std::vector<vh::fs::model::stats::Extension>{};

        std::vector<vh::fs::model::stats::Extension> out;
        out.reserve(res.size());

        for (const auto& row : res) {
            vh::fs::model::stats::Extension s{};
            s.extension   = row["ext"].as<std::string>();
            s.total_bytes = row["total_bytes"].as<std::uint64_t>(0);
            out.emplace_back(std::move(s));
        }

        return out;
    });
}

}
