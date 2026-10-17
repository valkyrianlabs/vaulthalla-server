#pragma once

#include "ops/Actor.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "storage/Fwd.hpp"

#include <map>
#include <memory>
#include <string>
#include <tuple>

// Filesystem RBAC for recovery (ops::recovery internals). Recovery points outlive the files they kept, so a path may
// no longer exist: it is then judged as the file (or folder) it was — a synthetic entry at the historical path, so
// every path override (glob) applies exactly as it did — AND the nearest existing folder must allow Read + List.
// Neither alone is enough: the folder check keeps a deleted file's history as private as the folder's listing, the
// historical-path check keeps a deny override on a deleted or renamed folder in force.
namespace vh::ops::recovery::access {

using FsAction = rbac::permission::vault::FilesystemAction;

class Gate {
public:
    Gate(Actor actor, std::shared_ptr<storage::Engine> engine);

    // Read on a file (Read + List on a directory), or the historical rule above for a path that is gone.
    [[nodiscard]] bool canRead(const std::string& vaultPath, bool directory = false);
    // `action` on the path as it is, or as it was (historical rule; the folder check stays Read + List).
    [[nodiscard]] bool allows(const std::string& vaultPath, FsAction action, bool directory = false);

    // The nearest existing folder of a path (the vault root at worst).
    [[nodiscard]] std::string existingAncestor(const std::string& vaultPath) const;
    [[nodiscard]] bool exists(const std::string& vaultPath) const;

private:
    [[nodiscard]] bool evaluate(const std::string& vaultPath, FsAction action, bool directory);

    Actor actor_;
    std::shared_ptr<storage::Engine> engine_;
    std::map<std::tuple<std::string, FsAction, bool>, bool> cache_;
};

// "/a/../b//c/" → "/b/c"; refuses paths escaping the root.
[[nodiscard]] std::string normalize(const std::string& path);

}
