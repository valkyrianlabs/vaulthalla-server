#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <pqxx/pqxx>
#include "fs/Fwd.hpp"

namespace vh::fs::model {
namespace stats { struct Extension; }
}

namespace vh::db::query::fs {

class File {
    using F = vh::fs::model::File;
    using T = vh::fs::model::file::Trashed;
    using FilePtr = std::shared_ptr<F>;
    using TrashedFilePtr = std::shared_ptr<T>;
    using EncryptionPair = std::optional<std::pair<std::string, unsigned int>>;

public:
    File() = default;

    static unsigned int upsertFile(const FilePtr& file);

    static void updateFile(const FilePtr& file);

    static void markTrashedFileDeleted(unsigned int id);

    static void deleteFile(unsigned int userId, const FilePtr& file);

    [[nodiscard]] static std::string getMimeType(unsigned int vaultId, const std::filesystem::path& relPath);

    [[nodiscard]] static bool isFile(unsigned int vaultId, const std::filesystem::path& relPath);

    static FilePtr getFileById(unsigned int id);

    static FilePtr getFileByPath(unsigned int vaultId, const std::filesystem::path& relPath);

    static void moveFile(const FilePtr& file, const std::filesystem::path& newPath, unsigned int userId);

    static std::vector<FilePtr> listFilesInDir(unsigned int vaultId, const std::filesystem::path& path = {"/"}, bool recursive = true);

    static std::vector<TrashedFilePtr> listTrashedFiles(unsigned int vaultId);

    static void markFileAsTrashed(unsigned int userId, unsigned int vaultId, const std::filesystem::path& relPath);

    static void markFileAsTrashed(unsigned int userId, unsigned int fsId);

    // The same, inside the caller's transaction (a rename replacing the file). `backingPath` is what the trash row
    // records; the caller removes the bytes once the transaction has committed.
    static void markFileAsTrashed(pqxx::work& txn, std::optional<unsigned int> userId, unsigned int fsId,
                                  const std::filesystem::path& backingPath);

    static void markRemoteFileAsTrashed(
        unsigned int userId,
        unsigned int vaultId,
        const std::filesystem::path& relPath,
        std::uint64_t sizeBytes = 0);

    // Takes a removed file's (or symlink's) size and count off every ancestor's subtree totals. Never removes a
    // folder: one left without files stays (#168).
    static void updateParentStats(pqxx::work& txn, std::optional<unsigned int> parentId, std::uint64_t sizeBytes);

    [[nodiscard]] static EncryptionPair getEncryptionIVAndVersion(unsigned int vaultId, const std::filesystem::path& relPath);

    static void setEncryptionIVAndVersion(const FilePtr& f);

    // Compare-and-set: records f's IV and key version only while the row (same vault and path) still holds
    // expectedIv / expectedVersion. False when it no longer does (rewritten, moved or deleted meanwhile).
    [[nodiscard]] static bool compareAndSetEncryptionIVAndVersion(const F& f,
                                                                  const std::string& expectedIv,
                                                                  unsigned int expectedVersion);

    // Encrypted files (non-empty IV) sealed with a key version older than keyVersion: what a key rotation still has
    // to re-encrypt. Empty files and legacy plaintext carry no IV and are not included.
    static std::vector<FilePtr> getFilesOlderThanKeyVersion(unsigned int vaultId, unsigned int keyVersion);

    [[nodiscard]] static std::string getContentHash(unsigned int vaultId, const std::filesystem::path& relPath);

    static FilePtr getLargestFile(unsigned int vaultId);

    static std::vector<FilePtr> getNLargestFiles(unsigned int vaultId, unsigned int n = 1);

    static std::vector<FilePtr> getAllFiles(unsigned int vaultId);

    static std::vector<vh::fs::model::stats::Extension> getTopExtensionsBySize(unsigned int vaultId, unsigned int limit = 10);
};

}
