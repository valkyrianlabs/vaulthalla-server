#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include <pqxx/pqxx>
#include "fs/Fwd.hpp"

namespace vh::db::query::fs {

class Symlink {
    using S = vh::fs::model::Symlink;
    using SymlinkPtr = std::shared_ptr<S>;

public:
    Symlink() = default;

    static unsigned int upsertSymlink(const SymlinkPtr& symlink);

    static void deleteSymlink(const SymlinkPtr& symlink);

    // The same, inside the caller's transaction (a rename replacing the symlink).
    static void deleteSymlink(pqxx::work& txn, unsigned int id);

    static SymlinkPtr getSymlinkById(unsigned int id);

    static SymlinkPtr getSymlinkByPath(unsigned int vaultId, const std::filesystem::path& relPath);

    static SymlinkPtr getSymlinkByInode(ino_t ino);

    static std::vector<SymlinkPtr> listSymlinksInDir(unsigned int parentId, bool recursive = false);
};

}
