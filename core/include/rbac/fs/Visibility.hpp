#pragma once

#include "fs/Fwd.hpp"
#include "identities/Fwd.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

// Which entries of a vault directory a caller may see: deny means hidden (#170). An entry the caller cannot Lookup is
// left out of a listing, and out of the folder totals shown next to it. One rule for every surface that lists a
// directory (FUSE readdir, ws fs.dir.list / fs.list, `vh fs ls`), decided by the filesystem evaluator
// (rbac::resolver::Vault::has, FilesystemAction::Lookup) over the cached entries, without database round trips
// except a subtree listing when totals have to be recounted (#255).
//
// Not for the mount root (no vault): FUSE lists vault roots by its own rule (fuse/Resolver.cpp).
namespace vh::rbac::fs::visibility {

using EntryPtr = std::shared_ptr<vh::fs::model::Entry>;

// Whether `user` may Lookup `entry`. Hidden is an answer here, not a refused request: denials are not logged.
[[nodiscard]] bool canLookup(const std::shared_ptr<identities::User>& user, const EntryPtr& entry);

// Whether `user` can see every entry in `directory`'s subtree, so a listing and the stored totals need no filtering.
// True for a super admin and the vault's owner (FUSE readdir's long-standing rule), and when no override of the
// user's can reach the subtree and the base permissions show both files and folders there.
[[nodiscard]] bool seesWholeSubtree(const std::shared_ptr<identities::User>& user, const EntryPtr& directory);

// `children` (the entries directly in `directory`) without the ones `user` cannot Lookup, order kept.
[[nodiscard]] std::vector<EntryPtr> visibleChildren(const std::shared_ptr<identities::User>& user,
                                                    const EntryPtr& directory, std::vector<EntryPtr> children);

// A folder's subtree totals as `user` sees them: what a walk down through visible folders would find.
struct Totals {
    std::uintmax_t size_bytes{0};
    unsigned int file_count{0};          // files and symlinks
    unsigned int subdirectory_count{0};

    bool operator==(const Totals&) const = default;
};

// nullopt when the stored totals already are what `user` sees (seesWholeSubtree); otherwise recounted over the
// visible part of the subtree (one cached subtree listing).
[[nodiscard]] std::optional<Totals> visibleTotals(const std::shared_ptr<identities::User>& user,
                                                  const EntryPtr& directory);

}
