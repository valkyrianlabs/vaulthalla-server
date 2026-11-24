#pragma once

#include <filesystem>
#include <memory>
#include <vector>
#include <optional>
#include <pqxx/result>
#include "fs/Fwd.hpp"

namespace fs = std::filesystem;

namespace vh::db::query::fs {

class Entry {
    using FSEntry = vh::fs::model::Entry;
    using EntryPtr = std::shared_ptr<FSEntry>;

public:
    static void updateFSEntry(const EntryPtr& entry);

    static EntryPtr getFSEntry(const std::string& base32);

    static EntryPtr getFSEntryByInode(ino_t ino);

    static EntryPtr getFSEntryByPath(unsigned int vaultId, const std::filesystem::path& relPath);

    static EntryPtr getFSEntryById(unsigned int entryId);

    static std::vector<EntryPtr> listDir(const std::optional<unsigned int>& entryId, bool recursive = false);

    // Every entry under directory `dirId` at any depth (directories, files and symlinks). listDir(id, true) is not
    // that: its file and symlink queries recurse through files, so they return only direct children (startup cache
    // seeding relies on that shape, so it is left alone).
    [[nodiscard]] static std::vector<EntryPtr> listSubtree(unsigned int dirId);

    static void renameEntry(const EntryPtr& entry);

    [[nodiscard]] static ino_t getNextInode();

    [[nodiscard]] static bool rootExists();

    [[nodiscard]] static EntryPtr getRootEntry();

    // Opens a transaction of its own: never call it while holding one (each Transactions call leases a pooled
    // connection, and a caller already holding one can wait on itself once the pool is in use). Inside a
    // transaction use the overload that takes it.
    [[nodiscard]] static pqxx::result collectParentChain(unsigned int parentId);
    [[nodiscard]] static pqxx::result collectParentChain(pqxx::transaction_base& txn, unsigned int parentId);
};

}
