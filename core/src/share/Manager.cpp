#include "share/Manager.hpp"
#include "ops/Error.hpp"
#include "rbac/PolicyEpoch.hpp"

#include "db/query/fs/Entry.hpp"
#include "db/query/share/AuditEvent.hpp"
#include "db/query/share/EmailChallenge.hpp"
#include "db/query/share/Link.hpp"
#include "db/query/share/Session.hpp"
#include "db/query/share/Upload.hpp"
#include "db/query/share/VaultRole.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "fs/model/Entry.hpp"
#include "identities/User.hpp"
#include "rbac/fs/policy/Share.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "share/AuditEvent.hpp"
#include "share/EmailChallenge.hpp"
#include "share/Policy.hpp"
#include "share/PrincipalResolver.hpp"
#include "share/Token.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <utility>

namespace vh::share {
namespace {
using FilesystemAction = rbac::permission::vault::FilesystemAction;

constexpr std::string_view kSessionOpen = "share.session.open";
constexpr std::string_view kChallengeCreated = "share.email.challenge.created";
constexpr std::string_view kChallengeConfirm = "share.email.challenge.confirm";
constexpr std::string_view kPrincipalResolve = "share.principal.resolve";
constexpr std::string_view kScopeAuthorize = "share.scope.authorize";
constexpr std::string_view kUploadStart = "share.upload.start";
constexpr std::string_view kUploadChunk = "share.upload.chunk";
constexpr std::string_view kUploadFinish = "share.upload.finish";
constexpr std::string_view kUploadCancel = "share.upload.cancel";
constexpr std::string_view kUploadFail = "share.upload.fail";
constexpr std::string_view kUploadStaleSweep = "share.upload.stale_sweep";

class QueryShareStore final : public ShareStore {
public:
    std::shared_ptr<Link> createLink(const std::shared_ptr<Link>& link) override {
        return db::query::share::Link::create(link);
    }

    std::shared_ptr<Link> getLink(const std::string& id) override { return db::query::share::Link::get(id); }

    std::shared_ptr<Link> getLinkByLookupId(const std::string& lookupId) override {
        return db::query::share::Link::getByLookupId(lookupId);
    }

    std::vector<std::shared_ptr<Link>> listLinksForUser(
        const uint32_t userId,
        const db::model::ListQueryParams& params
    ) override {
        return db::query::share::Link::listForUser(userId, params);
    }

    std::vector<std::shared_ptr<Link>> listLinksForVault(
        const uint32_t vaultId,
        const db::model::ListQueryParams& params
    ) override {
        return db::query::share::Link::listForVault(vaultId, params);
    }

    std::shared_ptr<Link> updateLink(const std::shared_ptr<Link>& link) override {
        return db::query::share::Link::update(link);
    }

    void revokeLink(const std::string& id, const uint32_t revokedBy) override {
        db::query::share::Link::revoke(id, revokedBy);
    }

    void rotateLinkToken(
        const std::string& id,
        const std::string& lookupId,
        const std::vector<uint8_t>& tokenHash,
        const uint32_t updatedBy
    ) override {
        db::query::share::Link::rotateToken(id, lookupId, tokenHash, updatedBy);
    }

    void touchLinkAccess(const std::string& id) override { db::query::share::Link::touchAccess(id); }

    void incrementDownload(const std::string& id) override { db::query::share::Link::incrementDownload(id); }
    bool consumeDownload(const std::string& id) override { return db::query::share::Link::consumeDownload(id); }

    void incrementUpload(const std::string& id) override { db::query::share::Link::incrementUpload(id); }

    void upsertVaultRoleForShare(
        const std::string& shareId,
        const uint32_t vaultId,
        const std::shared_ptr<rbac::role::Vault>& role
    ) override {
        db::query::share::VaultRole::upsertForShare(shareId, vaultId, role);
    }

    std::shared_ptr<rbac::role::Vault> getVaultRoleForShare(const std::string& shareId) override {
        return db::query::share::VaultRole::getForShare(shareId);
    }

    std::shared_ptr<rbac::role::Vault> getRecipientVaultRoleForShare(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        return db::query::share::VaultRole::getRecipientAssignment(shareId, emailHash);
    }

    std::shared_ptr<rbac::role::Vault> getVaultRoleTemplate(const uint32_t roleId) override {
        return db::query::rbac::role::Vault::get(roleId);
    }

    std::shared_ptr<rbac::role::Vault> getVaultRoleTemplateByName(const std::string& name) override {
        return db::query::rbac::role::Vault::get(name);
    }

    void upsertPublicVaultRoleAssignment(
        const std::string& shareId,
        const uint32_t vaultId,
        const uint32_t roleId,
        const std::vector<rbac::permission::Override>& overrides
    ) override {
        db::query::share::VaultRole::upsertPublicAssignment(shareId, vaultId, roleId, overrides);
    }

    uint32_t upsertValidatedRecipient(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        return db::query::share::VaultRole::upsertRecipient(shareId, emailHash);
    }

    void upsertRecipientVaultRoleAssignment(
        const std::string& shareId,
        const uint32_t vaultId,
        const uint32_t recipientId,
        const uint32_t roleId,
        const std::vector<rbac::permission::Override>& overrides
    ) override {
        db::query::share::VaultRole::upsertRecipientAssignment(
            shareId,
            vaultId,
            recipientId,
            roleId,
            overrides
        );
    }

    void replaceRecipientVaultRoleAssignments(
        const std::string& shareId,
        const uint32_t vaultId,
        const std::vector<RecipientAssignmentInput>& assignments
    ) override {
        std::vector<db::query::share::VaultRole::RecipientAssignmentInput> dbAssignments;
        dbAssignments.reserve(assignments.size());
        for (const auto& assignment : assignments) {
            dbAssignments.push_back({
                .email_hash = assignment.email_hash,
                .vault_role_id = assignment.vault_role_id,
                .overrides = assignment.overrides
            });
        }
        db::query::share::VaultRole::replaceRecipientAssignments(shareId, vaultId, dbAssignments);
    }

    void removeVaultRoleForShare(const std::string& shareId) override {
        db::query::share::VaultRole::removeForShare(shareId);
    }

    std::shared_ptr<Session> createSession(const std::shared_ptr<Session>& session) override {
        return db::query::share::Session::create(session);
    }

    std::shared_ptr<Session> getSession(const std::string& id) override {
        return db::query::share::Session::get(id);
    }

    std::shared_ptr<Session> getSessionByLookupId(const std::string& lookupId) override {
        return db::query::share::Session::getByLookupId(lookupId);
    }

    void verifySession(const std::string& sessionId, const std::vector<uint8_t>& emailHash) override {
        db::query::share::Session::verify(sessionId, emailHash);
    }

    void touchSession(const std::string& sessionId) override { db::query::share::Session::touch(sessionId); }

    void revokeSession(const std::string& sessionId) override { db::query::share::Session::revoke(sessionId); }

    void revokeSessionsForShare(const std::string& shareId) override {
        db::query::share::Session::revokeForShare(shareId);
    }

    std::shared_ptr<EmailChallenge> createEmailChallenge(
        const std::shared_ptr<EmailChallenge>& challenge
    ) override {
        return db::query::share::EmailChallenge::create(challenge);
    }

    std::shared_ptr<EmailChallenge> getEmailChallenge(const std::string& id) override {
        return db::query::share::EmailChallenge::get(id);
    }

    std::shared_ptr<EmailChallenge> getActiveEmailChallenge(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        return db::query::share::EmailChallenge::getActive(shareId, emailHash);
    }

    void recordEmailChallengeAttempt(const std::string& challengeId) override {
        db::query::share::EmailChallenge::recordAttempt(challengeId);
    }

    void consumeEmailChallenge(const std::string& challengeId) override {
        db::query::share::EmailChallenge::consume(challengeId);
    }

    void appendAuditEvent(const std::shared_ptr<AuditEvent>& event) override {
        db::query::share::AuditEvent::append(event);
    }

    std::shared_ptr<Upload> createUpload(const std::shared_ptr<Upload>& upload) override {
        return db::query::share::Upload::create(upload);
    }

    std::shared_ptr<Upload> getUpload(const std::string& uploadId) override {
        return db::query::share::Upload::get(uploadId);
    }

    void addUploadReceivedBytes(const std::string& uploadId, const uint64_t bytes) override {
        db::query::share::Upload::addReceivedBytes(uploadId, bytes);
    }

    void completeUpload(
        const std::string& uploadId,
        const uint32_t entryId,
        const std::string& contentHash,
        const std::string& mimeType
    ) override {
        db::query::share::Upload::complete(uploadId, entryId, contentHash, mimeType);
    }

    void failUpload(const std::string& uploadId, const std::string& error) override {
        db::query::share::Upload::fail(uploadId, error);
    }

    void cancelUpload(const std::string& uploadId) override {
        db::query::share::Upload::cancel(uploadId);
    }

    uint64_t sumCompletedUploadBytes(const std::string& shareId) override {
        return db::query::share::Upload::sumCompletedBytes(shareId);
    }

    uint64_t countCompletedUploadFiles(const std::string& shareId) override {
        return db::query::share::Upload::countCompletedFiles(shareId);
    }

    std::vector<std::shared_ptr<Upload>> listStaleActiveUploads(
        const std::time_t olderThanSeconds,
        const uint64_t limit
    ) override {
        return db::query::share::Upload::listStaleActive(olderThanSeconds, limit);
    }
};

[[nodiscard]] AuthorizationDecision allow() { return {true, "allowed"}; }
[[nodiscard]] AuthorizationDecision deny(std::string reason) { return {false, std::move(reason)}; }

[[nodiscard]] std::shared_ptr<identities::User> humanUser(const rbac::Actor& actor) {
    if (!actor.isHuman() || !actor.canUseHumanPrivileges()) return nullptr;
    return actor.user();
}

// Share roots are vault-relative; the filesystem evaluator takes FUSE paths (as every other caller passes them).
// Evaluating the raw vault path resolved "/x" against the FUSE root, so only "/" ever matched (#178).
[[nodiscard]] std::optional<std::filesystem::path> fusePathFor(const uint32_t vaultId, const std::string& vaultPath) {
    const auto& storage = runtime::Deps::get().storageManager;
    if (!storage) return std::nullopt;
    const auto engine = storage->getEngine(vaultId);
    if (!engine) return std::nullopt;
    return engine->vaultPathToFusePath(std::filesystem::path{Scope::normalizeVaultPath(vaultPath)});
}

[[nodiscard]] bool hasFsPermission(
    const std::shared_ptr<identities::User>& user,
    const uint32_t vaultId,
    const std::string& path,
    const FilesystemAction action
) {
    const auto fusePath = fusePathFor(vaultId, path);
    if (!fusePath) return false;
    return rbac::resolver::Vault::has<FilesystemAction>({
        .user = user,
        .permission = action,
        .vault_id = vaultId,
        .path = *fusePath
    });
}

[[nodiscard]] bool hasMetadataPermission(
    const std::shared_ptr<identities::User>& user,
    const uint32_t vaultId,
    const std::string& path
) {
    const auto fusePath = fusePathFor(vaultId, path);
    if (!fusePath) return false;
    return rbac::resolver::Vault::hasAny(
        rbac::resolver::vault::Context<FilesystemAction>{
            .user = user,
            .permission = FilesystemAction::Lookup,
            .vault_id = vaultId,
            .path = *fusePath
        },
        rbac::resolver::vault::Context<FilesystemAction>{
            .user = user,
            .permission = FilesystemAction::Preview,
            .vault_id = vaultId,
            .path = *fusePath
        }
    );
}

[[nodiscard]] bool forEachOperation(const uint32_t ops, const std::function<bool(Operation)>& fn) {
    constexpr Operation all[] = {
        Operation::Metadata,
        Operation::List,
        Operation::Preview,
        Operation::Download,
        Operation::Upload,
        Operation::Mkdir,
        Operation::Overwrite
    };

    for (const auto op : all)
        if ((ops & bit(op)) != 0 && !fn(op)) return false;
    return true;
}

// The create payload names the root twice (root_entry_id and root_path). A link only resolves while both name the
// same durable entry (TargetResolver re-checks on every access), so a mismatch is refused when it is created.
[[nodiscard]] AuthorizationDecision shareRootEntryMatchesLink(const Link& link) {
    const auto entry = db::query::fs::Entry::getFSEntryById(link.root_entry_id);
    if (!entry || !entry->vault_id || static_cast<uint32_t>(*entry->vault_id) != link.vault_id)
        return deny("root_entry_not_in_vault");
    if (Scope::normalizeVaultPath(entry->path.string()) != Scope::normalizeVaultPath(link.root_path))
        return deny("root_entry_path_mismatch");
    const auto type = entry->isDirectory() ? TargetType::Directory : TargetType::File;
    if (type != link.target_type) return deny("root_entry_type_mismatch");
    return allow();
}

class DefaultShareAuthorizer final : public ShareAuthorizer {
public:
    AuthorizationDecision canCreateLink(const rbac::Actor& actor, const Link& link) const override {
        if (auto granted = canGrant(actor, link); !granted.allowed) return granted;
        return shareRootEntryMatchesLink(link);
    }

    AuthorizationDecision canUpdateLink(
        const rbac::Actor& actor,
        const Link& existing,
        const Link& updated
    ) const override {
        if (const auto user = humanUser(actor); user && user->id == existing.created_by)
            return canGrant(actor, updated);
        return canGrant(actor, updated);
    }

    AuthorizationDecision canManageLink(const rbac::Actor& actor, const Link& link) const override {
        const auto user = humanUser(actor);
        if (!user) return deny("share_management_requires_human_user");
        if (user->id == link.created_by) return allow();
        return hasShareMode(actor, link);
    }

    AuthorizationDecision canListVaultLinks(const rbac::Actor& actor, const uint32_t vaultId) const override {
        const auto user = humanUser(actor);
        if (!user) return deny("share_management_requires_human_user");
        if (hasFsPermission(user, vaultId, "/", FilesystemAction::SharePublic) ||
            hasFsPermission(user, vaultId, "/", FilesystemAction::SharePublicValidated))
            return allow();
        return deny("missing_share_management_permission");
    }

private:
    [[nodiscard]] AuthorizationDecision hasShareMode(const rbac::Actor& actor, const Link& link) const {
        const auto user = humanUser(actor);
        if (!user) return deny("share_management_requires_human_user");

        const auto required = link.access_mode == AccessMode::EmailValidated
                                  ? FilesystemAction::SharePublicValidated
                                  : FilesystemAction::SharePublic;
        if (!hasFsPermission(user, link.vault_id, link.root_path, required))
            return deny(link.access_mode == AccessMode::EmailValidated
                            ? "missing_share_public_validated_permission"
                            : "missing_share_public_permission");

        return allow();
    }

    [[nodiscard]] AuthorizationDecision canGrant(const rbac::Actor& actor, const Link& link) const {
        if (auto mode = hasShareMode(actor, link); !mode.allowed) return mode;

        const auto user = humanUser(actor);
        if (!user) return deny("share_management_requires_human_user");

        const bool ok = forEachOperation(link.allowed_ops, [&](const Operation op) {
            switch (op) {
                case Operation::Metadata: return hasMetadataPermission(user, link.vault_id, link.root_path);
                case Operation::List: return hasFsPermission(user, link.vault_id, link.root_path, FilesystemAction::List);
                case Operation::Preview: return hasFsPermission(user, link.vault_id, link.root_path, FilesystemAction::Preview);
                case Operation::Download: return hasFsPermission(user, link.vault_id, link.root_path, FilesystemAction::Read);
                case Operation::Upload: return hasFsPermission(user, link.vault_id, link.root_path, FilesystemAction::Write);
                case Operation::Mkdir: return hasFsPermission(user, link.vault_id, link.root_path, FilesystemAction::Touch);
                case Operation::Overwrite: return hasFsPermission(user, link.vault_id, link.root_path, FilesystemAction::Overwrite);
            }
            return false;
        });

        if (!ok) return deny("delegated_operation_not_grantable");
        return allow();
    }
};

[[nodiscard]] std::shared_ptr<AuditEvent> auditEvent(
    std::string eventType,
    const AuditStatus status,
    const std::optional<std::string>& shareId = std::nullopt,
    const std::optional<std::string>& sessionId = std::nullopt
) {
    auto event = std::make_shared<AuditEvent>();
    event->share_id = shareId;
    event->share_session_id = sessionId;
    event->actor_type = AuditActorType::System;
    event->event_type = std::move(eventType);
    event->status = status;
    return event;
}

void attachHuman(AuditEvent& event, const rbac::Actor& actor) {
    if (const auto user = humanUser(actor)) {
        event.actor_type = AuditActorType::OwnerUser;
        event.actor_user_id = user->id;
    }
}

void attachLink(AuditEvent& event, const Link& link) {
    event.share_id = link.id.empty() ? std::nullopt : std::make_optional(link.id);
    event.vault_id = link.vault_id;
    event.target_entry_id = link.root_entry_id;
    event.target_path = link.root_path;
}

void attachPrincipal(AuditEvent& event, const Principal& principal) {
    event.share_id = principal.share_id;
    event.share_session_id = principal.share_session_id;
    event.actor_type = AuditActorType::SharePrincipal;
    event.vault_id = principal.vault_id;
    event.target_entry_id = principal.root_entry_id;
}

void setDenied(AuditEvent& event, std::string code, std::string message = {}) {
    event.status = AuditStatus::Denied;
    event.error_code = std::move(code);
    if (!message.empty()) event.error_message = std::move(message);
}

[[nodiscard]] std::time_t now(const ManagerOptions& options) {
    if (!options.clock) throw std::runtime_error("Share manager clock is unavailable");
    return options.clock();
}

[[nodiscard]] std::string challengeCode(const ManagerOptions& options) {
    return options.challenge_code_generator ? options.challenge_code_generator() : EmailChallenge::generateCode();
}

void requireAllowed(const AuthorizationDecision& decision, const std::string_view operation) {
    if (!decision.allowed)
        throw ops::Denied("Share " + std::string(operation) + " denied: " + decision.reason);
}

template<typename T>
[[nodiscard]] std::shared_ptr<T> requirePtr(const std::shared_ptr<T>& value, const std::string_view reason) {
    if (!value) throw ops::NotFound(std::string(reason));
    return value;
}

void normalizeAndValidate(Link& link) {
    link.root_path = Scope::normalizeVaultPath(link.root_path);
    link.grant().requireValid();
}

[[nodiscard]] std::shared_ptr<rbac::role::Vault> roleTemplateForAssignment(
    ShareStore& store,
    const std::optional<RoleAssignmentRequest>& request
) {
    std::shared_ptr<rbac::role::Vault> role;

    if (request && request->vault_role_id)
        role = store.getVaultRoleTemplate(*request->vault_role_id);
    else if (request && request->vault_role_name)
        role = store.getVaultRoleTemplateByName(*request->vault_role_name);
    else
        role = store.getVaultRoleTemplateByName(rbac::role::Vault::ImplicitDeny().name);

    if (!role)
        throw std::runtime_error("Share vault role template is missing from the database");
    if (role->id == 0)
        throw std::runtime_error("Share vault role template is not persisted");
    return role;
}

void persistPublicAssignment(
    ShareStore& store,
    const Link& link,
    const std::optional<RoleAssignmentRequest>& request
) {
    if (link.id.empty()) throw std::runtime_error("Share link id is required for role assignment persistence");
    const auto role = roleTemplateForAssignment(store, request);
    store.upsertPublicVaultRoleAssignment(
        link.id,
        link.vault_id,
        role->id,
        request ? request->overrides : std::vector<rbac::permission::Override>{}
    );
}

std::vector<ShareStore::RecipientAssignmentInput> recipientAssignmentInputs(
    ShareStore& store,
    const std::vector<RecipientRoleAssignmentRequest>& recipients
) {
    std::vector<ShareStore::RecipientAssignmentInput> inputs;
    inputs.reserve(recipients.size());
    for (const auto& recipient : recipients) {
        const auto normalizedEmail = EmailChallenge::normalizeEmail(recipient.email);
        const auto emailHash = EmailChallenge::hashEmail(normalizedEmail);
        const auto role = roleTemplateForAssignment(store, std::make_optional(recipient.role));
        inputs.push_back({
            .email_hash = emailHash,
            .vault_role_id = role->id,
            .overrides = recipient.role.overrides
        });
    }
    return inputs;
}

void persistRecipientAssignments(
    ShareStore& store,
    const Link& link,
    const std::vector<RecipientRoleAssignmentRequest>& recipients
) {
    if (link.id.empty()) throw std::runtime_error("Share link id is required for recipient assignment persistence");
    for (const auto& recipient : recipientAssignmentInputs(store, recipients)) {
        const auto recipientId = store.upsertValidatedRecipient(link.id, recipient.email_hash);
        store.upsertRecipientVaultRoleAssignment(
            link.id,
            link.vault_id,
            recipientId,
            recipient.vault_role_id,
            recipient.overrides
        );
    }
}

void replaceRecipientAssignments(
    ShareStore& store,
    const Link& link,
    const std::vector<RecipientRoleAssignmentRequest>& recipients
) {
    if (link.id.empty()) throw std::runtime_error("Share link id is required for recipient assignment persistence");
    store.replaceRecipientVaultRoleAssignments(link.id, link.vault_id, recipientAssignmentInputs(store, recipients));
}

void persistRoleAssignments(
    ShareStore& store,
    const Link& link,
    const std::optional<RoleAssignmentRequest>& publicRole,
    const std::vector<RecipientRoleAssignmentRequest>& recipients
) {
    persistPublicAssignment(store, link, publicRole);
    persistRecipientAssignments(store, link, recipients);
}

void attachScopedVaultRole(ShareStore& store, const Link& link, const Session& session, Principal& principal) {
    std::shared_ptr<rbac::role::Vault> role;
    if (link.requiresEmail() && session.email_hash) {
        role = store.getRecipientVaultRoleForShare(link.id, *session.email_hash);
        if (!role) {
            auto legacy = store.getVaultRoleForShare(link.id);
            if (legacy && !legacy->assignment) role = std::move(legacy);
        }
    } else if (link.requiresEmail()) {
        throw ops::Denied("Share recipient is not verified");
    } else {
        role = store.getVaultRoleForShare(link.id);
    }
    if (!role)
        throw std::runtime_error("Share vault role assignment is missing");
    principal.scoped_vault_role = std::move(role);
}

[[nodiscard]] std::string toLower(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

[[nodiscard]] std::string normalizeExtension(std::string value) {
    value = toLower(std::move(value));
    if (value.empty()) return value;
    if (value.front() != '.') value.insert(value.begin(), '.');
    return value;
}

[[nodiscard]] bool containsInsensitive(const std::vector<std::string>& values, const std::string& needle) {
    const auto normalizedNeedle = toLower(needle);
    return std::ranges::any_of(values, [&](const std::string& item) {
        return toLower(item) == normalizedNeedle;
    });
}

[[nodiscard]] bool containsExtension(const std::vector<std::string>& values, const std::string& extension) {
    const auto normalizedNeedle = normalizeExtension(extension);
    return std::ranges::any_of(values, [&](const std::string& item) {
        return normalizeExtension(item) == normalizedNeedle;
    });
}

[[nodiscard]] std::string extensionOf(const std::string& filename) {
    return normalizeExtension(std::filesystem::path(filename).extension().string());
}

[[nodiscard]] std::pair<std::shared_ptr<Link>, std::shared_ptr<Session>> requireActiveShareContext(
    ShareStore& store,
    const Principal& principal,
    const ManagerOptions& options
) {
    if (!principal.isActive(now(options))) throw ops::Denied("Share principal is inactive");

    auto link = requirePtr(store.getLink(principal.share_id), "Share link not found");
    if (!link->isActive(now(options))) throw ops::Denied("Share link is inactive");
    if (link->vault_id != principal.vault_id || link->root_entry_id != principal.root_entry_id)
        throw ops::Denied("Share principal link mismatch");

    auto session = requirePtr(store.getSession(principal.share_session_id), "Share session not found");
    if (!session->isActive(now(options))) throw ops::Denied("Share session is inactive");
    if (session->share_id != link->id) throw ops::Denied("Share session link mismatch");

    return {link, session};
}

void requireUploadAllowedByGrant(const Link& link, const StartUploadRequest& request, const ManagerOptions& options) {
    if (!link.grant().allows(Operation::Upload)) throw ops::Denied("Share upload denied: missing_upload_operation");
    if (link.target_type != TargetType::Directory)
        throw ops::Denied("Share upload denied: target is not directory-compatible");
    if (request.target_parent_entry_id == 0) throw std::invalid_argument("Share upload target parent is required");
    if (request.target_path.empty() || request.target_path.front() != '/')
        throw std::invalid_argument("Share upload target path must be absolute");
    if (request.original_filename.empty()) throw std::invalid_argument("Share upload original filename is required");
    if (request.resolved_filename.empty()) throw std::invalid_argument("Share upload resolved filename is required");

    const auto maxSize = link.max_upload_size_bytes.value_or(options.default_max_upload_size_bytes);
    if (request.expected_size_bytes > maxSize)
        throw ops::Denied("Share upload denied: file size exceeds maximum");

    if (!request.mime_type && !link.allowed_mime_types.empty())
        throw ops::Denied("Share upload denied: MIME type is required");
    if (request.mime_type && containsInsensitive(link.blocked_mime_types, *request.mime_type))
        throw ops::Denied("Share upload denied: MIME type is blocked");
    if (request.mime_type && !link.allowed_mime_types.empty() &&
        !containsInsensitive(link.allowed_mime_types, *request.mime_type))
        throw ops::Denied("Share upload denied: MIME type is not allowed");

    const auto ext = extensionOf(request.resolved_filename);
    if (!ext.empty() && containsExtension(link.blocked_extensions, ext))
        throw ops::Denied("Share upload denied: extension is blocked");
    if (!link.allowed_extensions.empty()) {
        if (ext.empty()) throw ops::Denied("Share upload denied: extension is required");
        if (!containsExtension(link.allowed_extensions, ext))
            throw ops::Denied("Share upload denied: extension is not allowed");
    }
}

void requireUploadQuota(ShareStore& store, const Link& link, const uint64_t expectedSize) {
    if (link.max_upload_files && store.countCompletedUploadFiles(link.id) >= *link.max_upload_files)
        throw ops::Denied("Share upload denied: file count limit reached");
    if (link.max_upload_total_bytes) {
        const auto completedBytes = store.sumCompletedUploadBytes(link.id);
        if (expectedSize > *link.max_upload_total_bytes ||
            completedBytes > *link.max_upload_total_bytes - expectedSize)
            throw ops::Denied("Share upload denied: total byte limit exceeded");
    }
}

[[nodiscard]] std::shared_ptr<Upload> requireUploadForPrincipal(
    ShareStore& store,
    const Principal& principal,
    const std::string& uploadId
) {
    if (uploadId.empty()) throw std::invalid_argument("Share upload id is required");
    auto upload = requirePtr(store.getUpload(uploadId), "Share upload not found");
    if (upload->share_id != principal.share_id || upload->share_session_id != principal.share_session_id)
        throw ops::Denied("Share upload does not belong to this share session");
    return upload;
}

[[nodiscard]] std::shared_ptr<Link> linkFromPublicToken(
    ShareStore& store,
    const std::string_view publicToken,
    const std::time_t current
) {
    policy::requireEnabled();
    const auto parsed = Token::parse(publicToken);
    if (parsed.kind != TokenKind::PublicShare) throw std::invalid_argument("Expected public share token");

    auto link = store.getLinkByLookupId(parsed.lookup_id);
    if (!link || !Token::verify(link->token_hash, TokenKind::PublicShare, parsed.secret))
        throw ops::Denied("Invalid public share token");
    if (!link->isActive(current)) throw ops::Denied("Share link is inactive");
    policy::requireEnabled(link->access_mode);

    return link;
}

[[nodiscard]] std::pair<std::shared_ptr<Session>, std::string> createSessionForLink(
    ShareStore& store,
    const Link& link,
    const ManagerOptions& options,
    const std::optional<std::string>& ipAddress,
    const std::optional<std::string>& userAgent
) {
    const auto token = Token::generate(TokenKind::ShareSession);
    auto session = std::make_shared<Session>();
    session->share_id = link.id;
    session->session_token_lookup_id = token.lookup_id;
    session->session_token_hash = token.hash;
    session->expires_at = now(options) + options.session_ttl_seconds;
    session->ip_address = ipAddress;
    session->user_agent = userAgent;
    return {store.createSession(session), token.raw};
}

[[nodiscard]] std::shared_ptr<Session> sessionFromToken(
    ShareStore& store,
    const std::string_view sessionToken,
    const std::time_t current
) {
    const auto parsed = Token::parse(sessionToken);
    if (parsed.kind != TokenKind::ShareSession) throw std::invalid_argument("Expected share session token");

    auto session = store.getSessionByLookupId(parsed.lookup_id);
    if (!session || !Token::verify(session->session_token_hash, TokenKind::ShareSession, parsed.secret))
        throw ops::Denied("Invalid share session token");
    if (!session->isActive(current)) throw ops::Denied("Share session is inactive");

    return session;
}
}

Manager::Manager()
    : Manager(std::make_shared<QueryShareStore>(), std::make_shared<DefaultShareAuthorizer>(), {}) {}

Manager::Manager(
    std::shared_ptr<ShareStore> store,
    std::shared_ptr<ShareAuthorizer> authorizer,
    ManagerOptions options
) : store_(std::move(store)), authorizer_(std::move(authorizer)), options_(std::move(options)) {
    if (!store_) throw std::invalid_argument("Share manager store is required");
    if (!authorizer_) throw std::invalid_argument("Share manager authorizer is required");
}

CreateLinkResult Manager::createLink(const rbac::Actor& actor, CreateLinkRequest request) {
    auto link = std::make_shared<Link>(std::move(request.link));
    if (const auto user = humanUser(actor)) link->created_by = user->id;

    normalizeAndValidate(*link);

    auto audit = auditEvent("share.link.create", AuditStatus::Success);
    attachHuman(*audit, actor);
    attachLink(*audit, *link);

    try {
        policy::requireEnabled(link->access_mode);
        requireAllowed(authorizer_->canCreateLink(actor, *link), "create");
        const auto token = Token::generate(TokenKind::PublicShare);
        link->token_lookup_id = token.lookup_id;
        link->token_hash = token.hash;
        auto created = store_->createLink(link);
        try {
            persistRoleAssignments(*store_, *created, request.public_role, request.recipients);
        } catch (...) {
            store_->revokeLink(created->id, created->created_by);
            throw;
        }
        attachLink(*audit, *created);
        store_->appendAuditEvent(audit);
        return {
            .link = created,
            .public_token = token.raw,
            .public_url_path = "/share/" + token.raw
        };
    } catch (...) {
        setDenied(*audit, "share_create_denied");
        store_->appendAuditEvent(audit);
        throw;
    }
}

std::shared_ptr<Link> Manager::getLinkForManagement(const rbac::Actor& actor, const std::string& id) {
    auto link = requirePtr(store_->getLink(id), "Share link not found");
    requireAllowed(authorizer_->canManageLink(actor, *link), "get");
    return link;
}

std::vector<std::shared_ptr<Link>> Manager::listLinksForUser(
    const rbac::Actor& actor,
    const db::model::ListQueryParams& params
) {
    const auto user = humanUser(actor);
    if (!user) throw ops::Denied("Share list denied: share_management_requires_human_user");
    return store_->listLinksForUser(user->id, params);
}

std::vector<std::shared_ptr<Link>> Manager::listLinksForVault(
    const rbac::Actor& actor,
    const uint32_t vaultId,
    const db::model::ListQueryParams& params
) {
    requireAllowed(authorizer_->canListVaultLinks(actor, vaultId), "list vault");
    return store_->listLinksForVault(vaultId, params);
}

std::shared_ptr<Link> Manager::updateLink(const rbac::Actor& actor, UpdateLinkRequest request) {
    if (!request.link) throw std::invalid_argument("Share link update payload is required");
    auto existing = requirePtr(store_->getLink(request.link->id), "Share link not found");
    auto updated = std::make_shared<Link>(*request.link);

    updated->id = existing->id;
    updated->token_lookup_id = existing->token_lookup_id;
    updated->token_hash = existing->token_hash;
    updated->created_by = existing->created_by;
    updated->vault_id = existing->vault_id;
    updated->root_entry_id = existing->root_entry_id;
    updated->root_path = existing->root_path;
    updated->target_type = existing->target_type;
    if (const auto user = humanUser(actor)) updated->updated_by = user->id;

    normalizeAndValidate(*updated);

    auto audit = auditEvent("share.link.update", AuditStatus::Success, existing->id);
    attachHuman(*audit, actor);
    attachLink(*audit, *existing);

    try {
        // An update can't move a link into a kind the operator turned off (or touch links while sharing is off).
        policy::requireEnabled(updated->access_mode);
        requireAllowed(authorizer_->canUpdateLink(actor, *existing, *updated), "update");
        if (request.public_role) persistPublicAssignment(*store_, *updated, request.public_role);
        if (request.recipients) replaceRecipientAssignments(*store_, *updated, *request.recipients);
        auto saved = store_->updateLink(updated);
        rbac::bumpPolicyEpoch();
        store_->appendAuditEvent(audit);
        return saved;
    } catch (...) {
        setDenied(*audit, "share_update_denied");
        store_->appendAuditEvent(audit);
        throw;
    }
}

void Manager::revokeLink(const rbac::Actor& actor, const std::string& id) {
    auto link = getLinkForManagement(actor, id);
    auto audit = auditEvent("share.link.revoke", AuditStatus::Success, link->id);
    attachHuman(*audit, actor);
    attachLink(*audit, *link);

    const auto user = humanUser(actor);
    store_->revokeLink(link->id, user ? user->id : 0);
    rbac::bumpPolicyEpoch();
    store_->revokeSessionsForShare(link->id);
    store_->removeVaultRoleForShare(link->id);
    store_->appendAuditEvent(audit);
}

RotateLinkTokenResult Manager::rotateLinkToken(const rbac::Actor& actor, const std::string& id) {
    auto link = getLinkForManagement(actor, id);
    auto audit = auditEvent("share.link.rotate_token", AuditStatus::Success, link->id);
    attachHuman(*audit, actor);
    attachLink(*audit, *link);

    const auto user = humanUser(actor);
    const auto token = Token::generate(TokenKind::PublicShare);
    store_->rotateLinkToken(link->id, token.lookup_id, token.hash, user ? user->id : 0);
    rbac::bumpPolicyEpoch();
    store_->revokeSessionsForShare(link->id);
    auto rotated = requirePtr(store_->getLink(link->id), "Share link not found after token rotation");
    store_->appendAuditEvent(audit);

    return {
        .link = rotated,
        .public_token = token.raw,
        .public_url_path = "/share/" + token.raw
    };
}

std::shared_ptr<Link> Manager::resolvePublicLink(const std::string_view publicToken) {
    return linkFromPublicToken(*store_, publicToken, now(options_));
}

OpenSessionResult Manager::openPublicSession(
    const std::string_view publicToken,
    const std::optional<std::string> ipAddress,
    const std::optional<std::string> userAgent
) {
    auto audit = auditEvent(std::string(kSessionOpen), AuditStatus::Success);
    audit->ip_address = ipAddress;
    audit->user_agent = userAgent;

    try {
        auto link = linkFromPublicToken(*store_, publicToken, now(options_));
        attachLink(*audit, *link);
        const auto [session, rawSessionToken] = createSessionForLink(*store_, *link, options_, ipAddress, userAgent);
        audit->share_id = link->id;
        audit->share_session_id = session->id;
        audit->actor_type = AuditActorType::SharePrincipal;
        store_->touchLinkAccess(link->id);
        store_->appendAuditEvent(audit);
        return {
            .status = link->requiresEmail() ? OpenSessionStatus::EmailRequired : OpenSessionStatus::Ready,
            .link = link,
            .session = session,
            .session_token = rawSessionToken
        };
    } catch (...) {
        setDenied(*audit, "share_session_open_denied");
        store_->appendAuditEvent(audit);
        throw;
    }
}

StartEmailChallengeResult Manager::startEmailChallenge(StartEmailChallengeRequest request) {
    if (!request.public_token && !request.session_token)
        throw std::invalid_argument("Public token or share session token is required");

    std::shared_ptr<Link> link;
    std::shared_ptr<Session> session;
    std::string rawSessionToken;

    if (request.session_token) {
        policy::requireEnabled();
        session = sessionFromToken(*store_, *request.session_token, now(options_));
        link = requirePtr(store_->getLink(session->share_id), "Share link not found");
        policy::requireEnabled(link->access_mode);
    } else {
        link = linkFromPublicToken(*store_, *request.public_token, now(options_));
        auto created = createSessionForLink(*store_, *link, options_, request.ip_address, request.user_agent);
        session = std::move(created.first);
        rawSessionToken = std::move(created.second);

        auto sessionAudit = auditEvent(std::string(kSessionOpen), AuditStatus::Success, link->id, session->id);
        sessionAudit->actor_type = AuditActorType::SharePrincipal;
        sessionAudit->ip_address = request.ip_address;
        sessionAudit->user_agent = request.user_agent;
        attachLink(*sessionAudit, *link);
        store_->appendAuditEvent(sessionAudit);
    }

    if (!link->requiresEmail()) throw ops::Conflict("Share link does not require email verification");
    if (!link->isActive(now(options_))) throw ops::Denied("Share link is inactive");
    if (!session->isActive(now(options_))) throw ops::Denied("Share session is inactive");

    const auto normalizedEmail = EmailChallenge::normalizeEmail(request.email);
    const auto emailHash = EmailChallenge::hashEmail(normalizedEmail);
    const auto code = challengeCode(options_);

    auto challenge = std::make_shared<EmailChallenge>();
    challenge->share_id = link->id;
    challenge->share_session_id = session->id;
    challenge->email_hash = emailHash;
    challenge->code_hash = EmailChallenge::hashCode(code);
    challenge->max_attempts = options_.challenge_max_attempts;
    challenge->expires_at = now(options_) + options_.challenge_ttl_seconds;
    challenge->ip_address = request.ip_address;
    challenge->user_agent = request.user_agent;

    auto created = store_->createEmailChallenge(challenge);
    auto audit = auditEvent(std::string(kChallengeCreated), AuditStatus::Success, link->id, session->id);
    audit->actor_type = AuditActorType::SharePrincipal;
    audit->ip_address = request.ip_address;
    audit->user_agent = request.user_agent;
    attachLink(*audit, *link);
    store_->appendAuditEvent(audit);

    return {
        .link = link,
        .session = session,
        .challenge = created,
        .session_token = rawSessionToken,
        .verification_code = code
    };
}

ConfirmEmailChallengeResult Manager::confirmEmailChallenge(ConfirmEmailChallengeRequest request) {
    auto loadedChallenge = store_->getEmailChallenge(request.challenge_id);
    if (!loadedChallenge) throw ops::NotFound("Share email challenge not found");

    if (request.session_id.empty()) throw std::invalid_argument("Share session id is required");
    if (request.session_token.empty()) throw std::invalid_argument("Share session token is required");

    auto loadedSession = sessionFromToken(*store_, request.session_token, now(options_));
    if (loadedSession->id != request.session_id)
        throw ops::Denied("Share session token does not match session");

    auto link = requirePtr(store_->getLink(loadedChallenge->share_id), "Share link not found");
    auto audit = auditEvent(std::string(kChallengeConfirm), AuditStatus::Success, link->id, loadedSession->id);
    audit->actor_type = AuditActorType::SharePrincipal;
    audit->ip_address = loadedChallenge->ip_address;
    audit->user_agent = loadedChallenge->user_agent;
    attachLink(*audit, *link);

    try {
        policy::requireEnabled(link->access_mode);
        if (!link->requiresEmail()) throw ops::Conflict("Share link does not require email verification");
        if (!link->isActive(now(options_))) throw ops::Denied("Share link is inactive");
        if (!loadedSession->isActive(now(options_))) throw ops::Denied("Share session is inactive");
        if (loadedChallenge->share_id != loadedSession->share_id)
            throw ops::Denied("Share email challenge does not belong to session share");
        if (loadedChallenge->share_session_id && *loadedChallenge->share_session_id != loadedSession->id)
            throw ops::Denied("Share email challenge session mismatch");
        if (!store_->getRecipientVaultRoleForShare(link->id, loadedChallenge->email_hash))
            throw ops::Denied("Share email recipient is not authorized");
        if (!loadedChallenge->canAttempt(now(options_)))
            throw ops::Conflict("Share email challenge cannot be attempted");

        if (!EmailChallenge::verifyCode(loadedChallenge->code_hash, request.code)) {
            store_->recordEmailChallengeAttempt(loadedChallenge->id);
            setDenied(*audit, "share_email_code_invalid");
            throw ops::Denied("Share email challenge code is invalid");
        }

        store_->consumeEmailChallenge(loadedChallenge->id);
        store_->verifySession(loadedSession->id, loadedChallenge->email_hash);
        auto reloaded = store_->getSession(loadedSession->id);
        if (!reloaded) throw std::runtime_error("Share session not found after verification");
        store_->appendAuditEvent(audit);
        return {.session = reloaded, .verified = true};
    } catch (...) {
        if (!audit->error_code) setDenied(*audit, "share_email_verification_denied");
        store_->appendAuditEvent(audit);
        throw;
    }
}

std::shared_ptr<Principal> Manager::resolvePrincipal(
    const std::string_view sessionToken,
    const std::optional<std::string> ipAddress,
    const std::optional<std::string> userAgent
) {
    auto audit = auditEvent(std::string(kPrincipalResolve), AuditStatus::Success);
    audit->ip_address = ipAddress;
    audit->user_agent = userAgent;

    try {
        policy::requireEnabled();
        auto session = sessionFromToken(*store_, sessionToken, now(options_));
        audit->share_session_id = session->id;
        auto link = requirePtr(store_->getLink(session->share_id), "Share link not found");
        attachLink(*audit, *link);
        policy::requireEnabled(link->access_mode);
        auto principal = PrincipalResolver::resolve(*link, *session, now(options_));
        attachScopedVaultRole(*store_, *link, *session, *principal);
        store_->touchSession(session->id);
        store_->appendAuditEvent(audit);
        return principal;
    } catch (...) {
        setDenied(*audit, "share_principal_resolution_denied");
        store_->appendAuditEvent(audit);
        throw;
    }
}

ScopeDecision Manager::authorize(
    const Principal& principal,
    const Operation operation,
    const std::string_view requestedPath,
    const std::optional<TargetType> targetType,
    const std::optional<uint32_t> vaultId
) {
    auto audit = auditEvent(std::string(kScopeAuthorize), AuditStatus::Success, principal.share_id, principal.share_session_id);
    attachPrincipal(*audit, principal);
    audit->target_path = std::string(requestedPath);

    try {
        auto decision = Scope::authorize(principal, {
            .vault_id = vaultId.value_or(principal.vault_id),
            .path = std::string(requestedPath),
            .operation = operation,
            .target_type = targetType
        });
        audit->target_path = decision.normalized_path;
        if (!decision.allowed) {
            setDenied(*audit, "share_scope_denied", decision.reason);
            store_->appendAuditEvent(audit);
            return decision;
        }

        const auto rbacDecision = rbac::fs::policy::Share::evaluate(principal, {
            .vault_id = vaultId.value_or(principal.vault_id),
            .vault_path = decision.normalized_path,
            .operation = operation,
            .target_type = targetType.value_or(operation == Operation::List || operation == Operation::Mkdir
                                                   ? TargetType::Directory
                                                   : principal.grant.target_type),
            .target_exists = operation != Operation::Upload && operation != Operation::Mkdir
        });
        if (!rbacDecision.allowed) {
            decision.allowed = false;
            decision.reason = "rbac_policy_denied:" + rbac::fs::policy::reasonToString(rbacDecision.reason);
            setDenied(*audit, "share_rbac_denied", decision.reason);
        }
        store_->appendAuditEvent(audit);
        return decision;
    } catch (...) {
        setDenied(*audit, "share_scope_denied");
        store_->appendAuditEvent(audit);
        throw;
    }
}

ScopeDecision Manager::authorize(
    const rbac::Actor& actor,
    const Operation operation,
    const std::string_view requestedPath,
    const std::optional<TargetType> targetType,
    const std::optional<uint32_t> vaultId
) {
    if (!actor.isShare() || actor.canUseHumanPrivileges() || !actor.sharePrincipal())
        throw std::runtime_error("Share actor is required");

    return authorize(*actor.sharePrincipal(), operation, requestedPath, targetType, vaultId);
}

void Manager::appendAccessAuditEvent(const Principal& principal, ShareAccessAuditRequest request) {
    if (request.event_type.empty()) throw std::invalid_argument("Share access audit event type is required");
    if (request.target.vault_id == 0) throw std::invalid_argument("Share access audit vault is required");
    if (request.target.target_entry_id == 0) throw std::invalid_argument("Share access audit target is required");
    if (request.target.target_path.empty()) throw std::invalid_argument("Share access audit target path is required");

    auto audit = auditEvent(std::move(request.event_type), request.status, principal.share_id, principal.share_session_id);
    attachPrincipal(*audit, principal);
    audit->vault_id = request.target.vault_id;
    audit->target_entry_id = request.target.target_entry_id;
    audit->target_path = std::move(request.target.target_path);
    audit->bytes_transferred = request.bytes_transferred;
    audit->error_code = std::move(request.error_code);
    audit->error_message = std::move(request.error_message);
    audit->ip_address = principal.ip_address;
    audit->user_agent = principal.user_agent;
    store_->appendAuditEvent(audit);
}

bool Manager::consumeDownload(const Principal& principal) {
    if (principal.share_id.empty()) throw std::runtime_error("Share principal has no share id");
    if (store_->consumeDownload(principal.share_id)) return true;
    auto audit = auditEvent("share.download.limit", AuditStatus::Denied);
    audit->share_id = principal.share_id;
    audit->share_session_id = principal.share_session_id;
    audit->error_code = "max_downloads_reached";
    audit->ip_address = principal.ip_address;
    audit->user_agent = principal.user_agent;
    store_->appendAuditEvent(audit);
    return false;
}

void Manager::incrementDownloadCount(const Principal& principal) {
    if (principal.share_id.empty()) throw std::runtime_error("Share principal has no share id");
    store_->incrementDownload(principal.share_id);
}

StartUploadResult Manager::startUpload(StartUploadRequest request) {
    auto [link, session] = requireActiveShareContext(*store_, request.principal, options_);
    auto audit = auditEvent(std::string(kUploadStart), AuditStatus::Success, link->id, session->id);
    attachPrincipal(*audit, request.principal);
    audit->target_entry_id = request.target_parent_entry_id;
    audit->target_path = request.target_path;

    try {
        requireUploadAllowedByGrant(*link, request, options_);
        requireUploadQuota(*store_, *link, request.expected_size_bytes);

        auto upload = std::make_shared<Upload>();
        upload->share_id = link->id;
        upload->share_session_id = session->id;
        upload->target_parent_entry_id = request.target_parent_entry_id;
        upload->target_path = Scope::normalizeVaultPath(request.target_path);
        upload->original_filename = std::move(request.original_filename);
        upload->resolved_filename = std::move(request.resolved_filename);
        upload->expected_size_bytes = request.expected_size_bytes;
        upload->mime_type = std::move(request.mime_type);
        upload->status = UploadStatus::Pending;

        auto created = store_->createUpload(upload);
        audit->target_path = created->target_path;
        store_->appendAuditEvent(audit);

        return {
            .upload = created,
            .max_chunk_size_bytes = options_.max_upload_chunk_size_bytes,
            .max_transfer_size_bytes = link->max_upload_size_bytes.value_or(options_.default_max_upload_size_bytes),
            .duplicate_policy = link->duplicate_policy
        };
    } catch (...) {
        setDenied(*audit, "share_upload_start_denied");
        store_->appendAuditEvent(audit);
        throw;
    }
}

void Manager::recordUploadChunk(const Principal& principal, const std::string& uploadId, const uint64_t bytes) {
    if (bytes == 0) throw std::invalid_argument("Share upload chunk bytes are required");
    auto [link, session] = requireActiveShareContext(*store_, principal, options_);
    auto upload = requireUploadForPrincipal(*store_, principal, uploadId);
    if (upload->isTerminal()) throw ops::Conflict("Share upload is already complete");
    if (upload->exceedsExpectedSize(bytes)) throw ops::Invalid("Share upload exceeds expected size");

    auto audit = auditEvent(std::string(kUploadChunk), AuditStatus::Success, link->id, session->id);
    attachPrincipal(*audit, principal);
    if (upload->target_parent_entry_id) audit->target_entry_id = upload->target_parent_entry_id;
    audit->target_path = upload->target_path;
    audit->bytes_transferred = bytes;

    try {
        store_->addUploadReceivedBytes(uploadId, bytes);
        store_->appendAuditEvent(audit);
    } catch (...) {
        setDenied(*audit, "share_upload_chunk_denied");
        store_->appendAuditEvent(audit);
        throw;
    }
}

void Manager::finishUpload(FinishUploadRequest request) {
    auto [link, session] = requireActiveShareContext(*store_, request.principal, options_);
    auto upload = requireUploadForPrincipal(*store_, request.principal, request.upload_id);
    if (upload->isTerminal()) throw ops::Conflict("Share upload is already complete");
    if (upload->received_size_bytes != upload->expected_size_bytes)
        throw ops::Invalid("Share upload size mismatch");
    if (request.created_entry_id == 0) throw std::invalid_argument("Share upload created entry id is required");

    auto audit = auditEvent(std::string(kUploadFinish), AuditStatus::Success, link->id, session->id);
    attachPrincipal(*audit, request.principal);
    audit->target_entry_id = request.created_entry_id;
    audit->target_path = upload->target_path;
    audit->bytes_transferred = upload->received_size_bytes;

    try {
        store_->completeUpload(
            request.upload_id,
            request.created_entry_id,
            request.content_hash,
            request.mime_type.value_or(upload->mime_type.value_or(""))
        );
        store_->incrementUpload(link->id);
        store_->appendAuditEvent(audit);
    } catch (...) {
        setDenied(*audit, "share_upload_finish_denied");
        store_->appendAuditEvent(audit);
        throw;
    }
}

void Manager::cancelUpload(const Principal& principal, const std::string& uploadId) {
    auto [link, session] = requireActiveShareContext(*store_, principal, options_);
    auto upload = requireUploadForPrincipal(*store_, principal, uploadId);

    auto audit = auditEvent(std::string(kUploadCancel), AuditStatus::Success, link->id, session->id);
    attachPrincipal(*audit, principal);
    if (upload->target_parent_entry_id) audit->target_entry_id = upload->target_parent_entry_id;
    audit->target_path = upload->target_path;
    audit->bytes_transferred = upload->received_size_bytes;

    try {
        store_->cancelUpload(uploadId);
        store_->appendAuditEvent(audit);
    } catch (...) {
        setDenied(*audit, "share_upload_cancel_denied");
        store_->appendAuditEvent(audit);
        throw;
    }
}

void Manager::failUpload(const Principal& principal, const std::string& uploadId, std::string error) {
    auto upload = requireUploadForPrincipal(*store_, principal, uploadId);
    auto audit = auditEvent(std::string(kUploadFail), AuditStatus::Failed, principal.share_id, principal.share_session_id);
    attachPrincipal(*audit, principal);
    if (upload->target_parent_entry_id) audit->target_entry_id = upload->target_parent_entry_id;
    audit->target_path = upload->target_path;
    audit->bytes_transferred = upload->received_size_bytes;
    audit->error_code = "share_upload_failed";
    audit->error_message = error;

    store_->failUpload(uploadId, std::move(error));
    store_->appendAuditEvent(audit);
}

StaleUploadSweepResult Manager::sweepStaleUploads(StaleUploadSweepRequest request) {
    const auto olderThan = request.older_than_seconds > 0
                               ? request.older_than_seconds
                               : options_.stale_upload_ttl_seconds;
    const auto limit = request.limit > 0 ? request.limit : options_.stale_upload_sweep_limit;
    if (olderThan <= 0) throw std::invalid_argument("Share stale upload sweep age must be positive");
    if (limit == 0) return {};

    StaleUploadSweepResult result;
    const auto uploads = store_->listStaleActiveUploads(olderThan, limit);
    result.scanned = uploads.size();

    for (const auto& upload : uploads) {
        if (!upload || upload->isTerminal()) continue;

        auto audit = auditEvent(std::string(kUploadStaleSweep), AuditStatus::Failed, upload->share_id, upload->share_session_id);
        if (upload->target_parent_entry_id) audit->target_entry_id = upload->target_parent_entry_id;
        audit->target_path = upload->target_path;
        audit->bytes_transferred = upload->received_size_bytes;
        audit->error_code = "stale_upload_sweep";
        audit->error_message = "stale_upload_sweep";

        try {
            store_->failUpload(upload->id, "stale_upload_sweep");
            ++result.failed;
        } catch (...) {
            setDenied(*audit, "stale_upload_sweep_failed");
            store_->appendAuditEvent(audit);
            throw;
        }
        store_->appendAuditEvent(audit);
    }

    return result;
}

}
