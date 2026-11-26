#include "rbac/s3/policy/Evaluator.hpp"

#include "db/query/s3/Gateway.hpp"
#include "identities/User.hpp"
#include "rbac/fs/policy/Evaluator.hpp"
#include "rbac/Mirrored.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Vault.hpp"

#include <algorithm>

namespace vh::rbac::s3::policy {
namespace {
using FsAction = permission::vault::FilesystemAction;

bool principalHas(const S3PolicyRequest& request, const FsAction action) {
    if (!request.principal) return false;
    // Not on a vault held here as another server's copy: there the resolver answers from its core's grant alone.
    if (request.principal->isSuperAdmin() && !vh::rbac::mirrored::find(request.vault_id))
        return true;
    return resolver::Vault::has<FsAction>({
        .user = request.principal,
        .permission = action,
        .vault_id = request.vault_id,
        .path = request.fuse_path ? *request.fuse_path : request.vault_path
    });
}
}

std::optional<FsAction> Evaluator::filesystemActionFor(
    const S3Action action,
    const bool objectExists,
    const bool isDirectoryMarker) {
    switch (action) {
    case S3Action::ListBuckets:
    case S3Action::HeadBucket:
    case S3Action::ListObjects:
    case S3Action::ListMultipartUploads:
        return FsAction::List;

    case S3Action::HeadObject:
    case S3Action::GetObject:
    case S3Action::CopyObjectSource:
    case S3Action::ListParts:
        return FsAction::Read;

    case S3Action::PutObject:
    case S3Action::CopyObjectDestination:
    case S3Action::CreateMultipartUpload:
    case S3Action::UploadPart:
    case S3Action::CompleteMultipartUpload:
        if (isDirectoryMarker) return FsAction::Touch;
        return objectExists ? FsAction::Overwrite : FsAction::Write;

    case S3Action::DeleteObject:
    case S3Action::DeleteObjects:
    case S3Action::AbortMultipartUpload:
        return FsAction::Delete;

    case S3Action::CreateBucket:
    case S3Action::DeleteBucket:
    case S3Action::ManageBucketBinding:
    case S3Action::ManageCredential:
    case S3Action::ManageBudget:
        return std::nullopt;
    }
    return std::nullopt;
}

Decision Evaluator::evaluate(const S3PolicyRequest& request) {
    if (!request.principal)
        return {
            .allowed = false,
            .reason = Decision::Reason::MissingPrincipal
        };

    if (request.vault_id == 0)
        return {
            .allowed = false,
            .reason = Decision::Reason::MissingVault
        };

    const auto fsAction = filesystemActionFor(request.action, request.object_exists, request.is_directory_marker);
    if (!fsAction)
        return {
            .allowed = false,
            .reason = Decision::Reason::NoFilesystemMapping
        };

    if (!principalHas(request, *fsAction))
        return {
            .allowed = false,
            .reason = Decision::Reason::PrincipalRbacDenied,
            .principal_allowed = false
        };

    if (request.credential_id == 0)
        return {
            .allowed = true,
            .reason = Decision::Reason::Allowed,
            .principal_allowed = true,
            .credential_allowed = true
        };

    if (request.scope_mode == "user_access")
        return {
            .allowed = true,
            .reason = Decision::Reason::Allowed,
            .principal_allowed = true,
            .credential_allowed = true
        };

    if (request.scope_mode == "global") {
        if (!request.principal->isAdmin())
            return {
                .allowed = false,
                .reason = Decision::Reason::GlobalPrincipalRequired,
                .principal_allowed = true,
                .credential_allowed = false
            };
    }

    if (request.scope_mode == "vault_allowlist") {
        const auto selectedVaults = db::query::s3::Gateway::listCredentialSelectedVaults(request.credential_id);
        const auto selected = std::ranges::any_of(selectedVaults, [&](const auto& selectedVault) {
            return selectedVault.vault_id == request.vault_id && selectedVault.enabled;
        });
        if (!selected)
            return {
                .allowed = false,
                .reason = Decision::Reason::VaultNotSelected,
                .principal_allowed = true,
                .credential_allowed = false
            };
    }

    const auto defaultRole = db::query::s3::Gateway::getCredentialDefaultVaultRole(request.credential_id);
    if ((request.scope_mode == "vault_allowlist" || request.scope_mode == "global") &&
        (!defaultRole || !defaultRole->enabled))
        return {
            .allowed = false,
            .reason = Decision::Reason::MissingDefaultRole,
            .principal_allowed = true,
            .credential_allowed = false
        };

    const auto credentialRole = db::query::s3::Gateway::getEffectiveCredentialVaultRole(
        request.credential_id,
        request.vault_id,
        request.scope_mode);
    if (!credentialRole)
        return {
            .allowed = false,
            .reason = Decision::Reason::CredentialRoleMissing,
            .principal_allowed = true,
            .credential_allowed = false
        };

    const auto credentialDecision = fs::policy::Evaluator::evaluate(
        credentialRole->fs,
        fs::policy::Evaluator::ResolvedRequest{
            .action = *fsAction,
            .vaultPath = request.vault_path,
            .exists = request.object_exists,
            .isDirectory = request.is_directory_marker || request.vault_path == std::filesystem::path{"/"}
        });

    if (!credentialDecision.allowed)
        return {
            .allowed = false,
            .reason = Decision::Reason::EffectiveCredentialRoleDenied,
            .principal_allowed = true,
            .credential_allowed = false,
            .credential_decision = credentialDecision
        };

    return {
        .allowed = true,
        .reason = Decision::Reason::Allowed,
        .principal_allowed = true,
        .credential_allowed = true,
        .credential_decision = credentialDecision
    };
}

} // namespace vh::rbac::s3::policy
