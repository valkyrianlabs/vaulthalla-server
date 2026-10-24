#include "rbac/fs/Placement.hpp"

#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "identities/User.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "runtime/Deps.hpp"

#include <cstdint>

namespace vh::rbac::fs::placement {

permission::vault::FilesystemAction createAction(const vh::fs::model::Entry& entry) {
    return entry.isDirectory() ? permission::vault::FilesystemAction::Touch
                               : permission::vault::FilesystemAction::Write;
}

std::optional<std::filesystem::path> firstRefusedDescendant(const std::shared_ptr<identities::User>& user,
                                                            const std::shared_ptr<vh::fs::model::Entry>& source,
                                                            const std::filesystem::path& destination) {
    if (!source || !source->isDirectory()) return std::nullopt;

    std::optional<std::uint32_t> vaultId;
    if (source->vault_id) vaultId = static_cast<std::uint32_t>(*source->vault_id);

    for (const auto& entry : runtime::Deps::get().fsCache->listDir(source->id, true)) {
        if (!entry) continue;
        const auto placed = destination / entry->fuse_path.lexically_relative(source->fuse_path);
        if (!resolver::Vault::has<permission::vault::FilesystemAction>({
                .user = user,
                .permission = createAction(*entry),
                .vault_id = vaultId,
                .path = placed
            }))
            return placed;
    }
    return std::nullopt;
}

}
