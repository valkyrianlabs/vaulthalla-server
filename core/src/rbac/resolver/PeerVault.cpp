#include "rbac/resolver/PeerVault.hpp"

#include "db/query/peer/VaultPolicy.hpp"
#include "rbac/fs/policy/Evaluator.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/role/Vault.hpp"

namespace vh::rbac::resolver {

std::string_view to_string(const PeerVaultRole::Source source) noexcept {
    switch (source) {
        case PeerVaultRole::Source::None: return "none";
        case PeerVaultRole::Source::Vault: return "vault";
        case PeerVaultRole::Source::LinkDefault: return "link_default";
    }
    return "none";
}

PeerVaultRole PeerVault::role(const uint32_t peerId, const uint32_t vaultId) {
    PeerVaultRole out;
    if (peerId == 0 || vaultId == 0) return out;
    const auto standing = db::query::peer::VaultPolicy::standing(peerId, vaultId);
    out.linked = standing.exists && standing.live;
    out.mirrored = out.linked && standing.mirrored_from_here;
    if (!out.linked || !standing.vault_live) return out;

    if (standing.vault_role) {
        out.source = PeerVaultRole::Source::Vault;
        if (standing.vault_role->name == kPeerNoAccessRole) {
            out.no_access = true;
            return out;
        }
        // The definition only: whatever an assignment row might carry, a linked server's role is whole.
        auto whole = std::make_shared<rbac::role::Vault>(*standing.vault_role);
        whole->fs.overrides.clear();
        out.role = std::move(whole);
        return out;
    }
    if (standing.link_default) {
        out.source = PeerVaultRole::Source::LinkDefault;
        auto whole = std::make_shared<rbac::role::Vault>(*standing.link_default);
        whole->fs.overrides.clear();
        whole->assignment.reset();
        out.role = std::move(whole);
    }
    return out;
}

bool PeerVault::may(const uint32_t peerId, const uint32_t vaultId, const permission::vault::FilesystemAction action,
                    const std::filesystem::path& vaultPath, const bool exists, const bool isDirectory) {
    const auto standing = role(peerId, vaultId);
    if (!standing.mirrored || !standing.role) return false;
    return fs::policy::Evaluator::evaluate(standing.role->fs, {.action = action,
                                                           .vaultPath = vaultPath.empty() ? std::filesystem::path{"/"} : vaultPath,
                                                           .exists = exists,
                                                           .isDirectory = isDirectory})
        .allowed;
}

}
