#pragma once

#include "fs/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "rbac/Fwd.hpp"

#include <filesystem>
#include <memory>
#include <optional>

// Whether an entry may be placed at a new path: what creating it there would need (#256). FUSE rename and ws
// fs.entry.move / fs.entry.rename into another folder, beside fs.entry.copy's per-entry authorizer (#167).
namespace vh::rbac::fs::placement {

// The action creating `entry` needs: Touch for a folder (mkdir), Write for a file or symlink (create, upload).
[[nodiscard]] permission::vault::FilesystemAction createAction(const vh::fs::model::Entry& entry);

// A folder moves with everything in it. The first new FUSE path, among the entries below `source` (not `source`
// itself, which the caller checks with its own surface's answer), where `user` may not create that entry once
// `source` sits at `destination` (a FUSE path); nullopt when all of them may be placed, or `source` is no folder.
[[nodiscard]] std::optional<std::filesystem::path> firstRefusedDescendant(
    const std::shared_ptr<identities::User>& user,
    const std::shared_ptr<vh::fs::model::Entry>& source,
    const std::filesystem::path& destination);

}
