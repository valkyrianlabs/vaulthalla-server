#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include <optional>

#include <pqxx/pqxx>
#include "fs/Fwd.hpp"

namespace vh::db::query::fs {

class Directory {
    using Dir = vh::fs::model::Directory;
    using DirPtr = std::shared_ptr<Dir>;
    using Dirs = std::vector<DirPtr>;

public:
    Directory() = default;

    static unsigned int upsertDirectory(const DirPtr& directory);

    [[nodiscard]] static bool isDirectory(unsigned int vaultId, const std::filesystem::path& relPath);

    [[nodiscard]] static bool directoryExists(unsigned int vaultId, const std::filesystem::path& relPath);

    static void moveDirectory(const DirPtr& directory, const std::filesystem::path& newPath, unsigned int userId);

    static DirPtr getDirectoryByPath(unsigned int vaultId, const std::filesystem::path& relPath);

    [[nodiscard]] static std::optional<unsigned int> getDirectoryIdByPath(unsigned int vaultId, const std::filesystem::path& path);

    [[nodiscard]] static unsigned int getRootDirectoryId(unsigned int vaultId);

    static Dirs listDirectoriesInDir(unsigned int parentId, bool recursive = false);

    [[nodiscard]] static pqxx::result collectParentStats(unsigned int parentId);

    // What a cached listing of `dirId` must hold to be complete: its direct children and its whole subtree
    // (subtree totals, #158). One statement; nullopt when `dirId` is not a directory.
    struct ListingShape {
        uint64_t direct = 0;
        uint64_t subtree = 0;
    };
    [[nodiscard]] static std::optional<ListingShape> listingShape(unsigned int dirId);

    // rmdir(2): deletes directory `id` only while nothing is under it (false otherwise, nothing changed), taking it off
    // every ancestor's subdirectory count. It used to drop a non-empty directory with everything under it (cascade)
    // and only decrement its parent.
    [[nodiscard]] static bool deleteEmptyDirectory(unsigned int id);

    [[nodiscard]] static bool isDirectoryEmpty(unsigned int id);

    // Directory size_bytes / file_count / subdirectory_count are subtree totals kept on every ancestor (#158).
    struct SubtreeTotals {
        int64_t size_bytes = 0;
        int64_t files = 0;
        int64_t subdirs = 0;
    };

    // What entry `id` contributes to each ancestor: a directory its own totals plus itself, a file or symlink its
    // size and one entry. nullopt when the entry doesn't exist.
    [[nodiscard]] static std::optional<SubtreeTotals> subtreeTotalsOf(pqxx::work& txn, unsigned int id);

    [[nodiscard]] static std::optional<unsigned int> parentIdOf(pqxx::work& txn, unsigned int id);

    // Adds the deltas to directory `dirId` and every directory above it (one statement). No-op without a dirId.
    static void addToAncestorStats(pqxx::work& txn, std::optional<unsigned int> dirId,
                                   int64_t sizeBytes, int64_t files, int64_t subdirs);

    // The ids of entry `id`'s ancestors, nearest first.
    [[nodiscard]] static std::vector<unsigned int> ancestorsOf(unsigned int id);

    // Moves `totals` off oldParentId and its ancestors onto newParentId and its ancestors; ancestors both chains
    // share are left alone. A no-op when the parents are the same.
    static void shiftSubtreeTotals(pqxx::work& txn, std::optional<unsigned int> oldParentId,
                                   std::optional<unsigned int> newParentId, const SubtreeTotals& totals);

    // Deletes directory `id` and everything still under it, taking its totals off its ancestors. A no-op when the
    // directory is already gone.
    static void deleteDirectoryTree(unsigned int id);
};

}
