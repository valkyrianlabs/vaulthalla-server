#include "rbac/fs/Visibility.hpp"

#include "fs/cache/Registry.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "identities/Group.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/fs/policy/Evaluator.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/VaultScope.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/vault/Global.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <exception>
#include <string>
#include <unordered_map>
#include <utility>

namespace vh::rbac::fs::visibility {

namespace {

using Action = permission::vault::FilesystemAction;

[[nodiscard]] std::shared_ptr<::vh::vault::model::Vault> vaultOf(const EntryPtr& entry) {
    if (!entry || !entry->vault_id) return nullptr;
    const auto& manager = runtime::Deps::get().storageManager;
    if (!manager) return nullptr;
    return manager->getVault(static_cast<unsigned int>(*entry->vault_id));
}

[[nodiscard]] bool isVaultOwner(const std::shared_ptr<identities::User>& user, const EntryPtr& entry) {
    const auto vault = vaultOf(entry);
    return user && vault && vault->owner_id == user->id;
}

[[nodiscard]] bool roleMayAffect(const std::shared_ptr<const role::Vault>& role,
                                 const std::filesystem::path& directory) {
    return role && policy::Evaluator::overridesMayAffectListing(role->fs, directory);
}

// Whether any override the evaluator would read for `user` in this vault (its own vault role, its groups' vault roles,
// the global policy in the vault's scope) can reach `directory` or anything below it.
[[nodiscard]] bool overridesMayReach(const std::shared_ptr<identities::User>& user, const EntryPtr& directory) {
    const auto vaultId = static_cast<std::uint32_t>(*directory->vault_id);
    const auto& vaultPath = directory->path;
    const auto view = user->authz();
    if (!view.authorizing()) return true;  // nothing is visible; take the filtered (denying) path

    if (roleMayAffect(view.directVaultRole(vaultId), vaultPath)) return true;

    for (const auto& group : view.groups) {
        if (!group) continue;
        const auto it = group->roles.vaults.find(vaultId);
        if (it != group->roles.vaults.end() && roleMayAffect(it->second, vaultPath)) return true;
    }

    const auto* globals = view.vaultGlobals();
    if (!globals) return false;

    // Only the scope the evaluator reads for this vault; an unknown owner takes the filtered (denying) path.
    const auto vault = vaultOf(directory);
    const auto scope = vault ? resolver::vaultScope(*user, vault->owner_id) : std::nullopt;
    if (!scope) return true;
    return policy::Evaluator::overridesMayAffectListing(resolver::inScope(*scope, *globals).fs, vaultPath);
}

// A stand-in for "an entry of this kind inside `directory`". With no override reaching the subtree, the evaluator
// judges every entry there by the base permissions of the stage that decides, by kind only (path plays no part), so
// one probe per kind answers for all of them.
[[nodiscard]] EntryPtr probeIn(const EntryPtr& directory, const bool asDirectory) {
    EntryPtr probe = asDirectory ? EntryPtr(std::make_shared<::vh::fs::model::Directory>())
                                 : EntryPtr(std::make_shared<::vh::fs::model::File>());
    probe->vault_id = directory->vault_id;
    probe->parent_id = static_cast<std::int32_t>(directory->id);
    probe->name = ".vh-visibility-probe";
    probe->path = directory->path / probe->name;
    probe->fuse_path = directory->fuse_path / probe->name;
    return probe;
}

[[nodiscard]] std::optional<Totals> storedTotals(const EntryPtr& directory) {
    const auto dir = std::dynamic_pointer_cast<::vh::fs::model::Directory>(directory);
    if (!dir) return std::nullopt;
    return Totals{.size_bytes = dir->size_bytes, .file_count = dir->file_count,
                  .subdirectory_count = dir->subdirectory_count};
}

}

bool canLookup(const std::shared_ptr<identities::User>& user, const EntryPtr& entry) {
    if (!user || !entry) return false;
    const resolver::vault::QuietFilesystemDenials quiet;
    try {
        return resolver::Vault::has<Action>({.user = user, .permission = Action::Lookup, .entry = entry});
    } catch (const std::exception& e) {
        // Failing to decide hides the entry rather than showing it.
        log::Registry::auth()->warn("[visibility] Failed to evaluate Lookup on {}: {}", entry->fuse_path.string(),
                                    e.what());
        return false;
    }
}

bool seesWholeSubtree(const std::shared_ptr<identities::User>& user, const EntryPtr& directory) {
    if (!user || !directory || !directory->vault_id) return false;
    if (user->isSuperAdmin()) return true;
    if (isVaultOwner(user, directory)) return true;
    if (overridesMayReach(user, directory)) return false;
    return canLookup(user, probeIn(directory, true)) && canLookup(user, probeIn(directory, false));
}

std::vector<EntryPtr> visibleChildren(const std::shared_ptr<identities::User>& user, const EntryPtr& directory,
                                      std::vector<EntryPtr> children) {
    std::erase(children, nullptr);
    if (seesWholeSubtree(user, directory)) return children;
    std::erase_if(children, [&](const EntryPtr& child) { return !canLookup(user, child); });
    return children;
}

std::optional<Totals> visibleTotals(const std::shared_ptr<identities::User>& user, const EntryPtr& directory) {
    if (!directory || !directory->isDirectory()) return std::nullopt;
    if (seesWholeSubtree(user, directory)) return std::nullopt;

    // One cached listing of the whole subtree, grouped by parent, then a walk down through the visible folders.
    std::unordered_map<std::int32_t, std::vector<EntryPtr>> byParent;
    for (auto& entry : runtime::Deps::get().fsCache->listDir(directory->id, true))
        if (entry && entry->parent_id) byParent[*entry->parent_id].push_back(std::move(entry));

    Totals totals;
    std::vector<EntryPtr> pending{directory};
    while (!pending.empty()) {
        const auto dir = std::move(pending.back());
        pending.pop_back();
        const auto it = byParent.find(static_cast<std::int32_t>(dir->id));
        if (it == byParent.end()) continue;

        for (const auto& child : visibleChildren(user, dir, std::move(it->second))) {
            if (!child->isDirectory()) {
                ++totals.file_count;
                totals.size_bytes += child->size_bytes;
                continue;
            }
            ++totals.subdirectory_count;
            // A folder whose whole subtree is visible counts as stored, without walking it.
            if (const auto stored = seesWholeSubtree(user, child) ? storedTotals(child) : std::nullopt) {
                totals.file_count += stored->file_count;
                totals.subdirectory_count += stored->subdirectory_count;
                totals.size_bytes += stored->size_bytes;
            } else pending.push_back(child);
        }
    }
    return totals;
}

}
