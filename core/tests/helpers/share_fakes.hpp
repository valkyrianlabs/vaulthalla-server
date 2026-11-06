#pragma once

// In-memory link-sharing fakes for the share unit suites: a ShareStore and ShareAuthorizer over maps, a
// TargetEntryProvider tree, entry/link builders, and a fixture base that runs a share::Manager over them and opens
// ready share sessions.

#include "db/encoding/bytea.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/role/Vault.hpp"
#include "share/AuditEvent.hpp"
#include "share/EmailChallenge.hpp"
#include "share/Manager.hpp"
#include "share/TargetResolver.hpp"
#include "share/Token.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace vh::test::shares {

constexpr std::time_t kNow = 1'800'000'000;

inline std::string uuidFor(const uint32_t value) {
    return std::format("00000000-0000-4000-8000-{:012d}", value);
}

// Allows human actors only; each allow_* switch denies one kind of call.
class FakeAuthorizer final : public vh::share::ShareAuthorizer {
public:
    bool allow_create{true};
    bool allow_update{true};
    bool allow_manage{true};
    bool allow_list_vault{true};

    vh::share::AuthorizationDecision canCreateLink(
        const vh::rbac::Actor& actor,
        const vh::share::Link&
    ) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_create, allow_create ? "allowed" : "create_denied"};
    }

    vh::share::AuthorizationDecision canUpdateLink(
        const vh::rbac::Actor& actor,
        const vh::share::Link&,
        const vh::share::Link&
    ) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_update, allow_update ? "allowed" : "update_denied"};
    }

    vh::share::AuthorizationDecision canManageLink(
        const vh::rbac::Actor& actor,
        const vh::share::Link&
    ) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_manage, allow_manage ? "allowed" : "manage_denied"};
    }

    vh::share::AuthorizationDecision canListVaultLinks(const vh::rbac::Actor& actor, uint32_t) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_list_vault, allow_list_vault ? "allowed" : "list_denied"};
    }
};

// Records codes instead of mailing them (#317).
class RecordingCodeSender final : public vh::share::ChallengeCodeSender {
public:
    bool canSend = true;
    bool failSends = false;
    std::vector<vh::share::ChallengeCodeMessage> sent;
    [[nodiscard]] bool available() const override { return canSend; }
    void send(const vh::share::ChallengeCodeMessage& message) override {
        if (failSends) throw std::runtime_error("provider down");
        sent.push_back(message);
    }
};

// The whole ShareStore over maps, stamped with kNow. Role templates 1-3 are implicit_deny, reader and contributor.
class FakeStore final : public vh::share::ShareStore {
public:
    using Role = vh::rbac::role::Vault;

    std::unordered_map<std::string, std::shared_ptr<vh::share::Link>> links;
    std::unordered_map<std::string, std::string> link_by_lookup;
    std::unordered_map<std::string, std::shared_ptr<vh::share::Session>> sessions;
    std::unordered_map<std::string, std::string> session_by_lookup;
    std::unordered_map<std::string, std::shared_ptr<vh::share::EmailChallenge>> challenges;
    std::unordered_map<std::string, std::shared_ptr<vh::share::Upload>> uploads;
    std::unordered_map<std::string, std::shared_ptr<Role>> vault_roles;
    std::unordered_map<uint32_t, std::shared_ptr<Role>> role_templates;
    std::unordered_map<std::string, uint32_t> role_template_by_name;
    std::unordered_map<std::string, uint32_t> recipients_by_hash;
    std::unordered_map<std::string, std::shared_ptr<Role>> recipient_roles;
    std::vector<std::shared_ptr<vh::share::AuditEvent>> audits;

    uint32_t next_link{100};
    uint32_t next_session{200};
    uint32_t next_challenge{300};
    uint32_t next_upload{400};
    uint32_t next_recipient{500};

    FakeStore() {
        addTemplate(1, Role::ImplicitDeny());
        addTemplate(2, Role::Reader());
        addTemplate(3, Role::Contributor());
    }

    void addTemplate(const uint32_t id, Role role) {
        role.id = id;
        role_templates[id] = std::make_shared<Role>(std::move(role));
        role_template_by_name[role_templates[id]->name] = id;
    }

    std::shared_ptr<vh::share::Link> createLink(const std::shared_ptr<vh::share::Link>& link) override {
        auto stored = std::make_shared<vh::share::Link>(*link);
        if (stored->id.empty()) stored->id = uuidFor(next_link++);
        stored->created_at = kNow;
        stored->updated_at = kNow;
        links[stored->id] = stored;
        link_by_lookup[stored->token_lookup_id] = stored->id;
        return stored;
    }

    std::shared_ptr<vh::share::Link> getLink(const std::string& id) override {
        if (!links.contains(id)) return nullptr;
        return links.at(id);
    }

    std::shared_ptr<vh::share::Link> getLinkByLookupId(const std::string& lookupId) override {
        if (!link_by_lookup.contains(lookupId)) return nullptr;
        return getLink(link_by_lookup.at(lookupId));
    }

    std::vector<std::shared_ptr<vh::share::Link>> listLinksForUser(
        uint32_t userId,
        const vh::db::model::ListQueryParams&
    ) override {
        std::vector<std::shared_ptr<vh::share::Link>> out;
        for (auto& [_, link] : links)
            if (link->created_by == userId) out.push_back(link);
        return out;
    }

    std::vector<std::shared_ptr<vh::share::Link>> listLinksForVault(
        uint32_t vaultId,
        const vh::db::model::ListQueryParams&
    ) override {
        std::vector<std::shared_ptr<vh::share::Link>> out;
        for (auto& [_, link] : links)
            if (link->vault_id == vaultId) out.push_back(link);
        return out;
    }

    std::shared_ptr<vh::share::Link> updateLink(const std::shared_ptr<vh::share::Link>& link) override {
        auto stored = std::make_shared<vh::share::Link>(*link);
        stored->updated_at = kNow + 1;
        links[stored->id] = stored;
        link_by_lookup[stored->token_lookup_id] = stored->id;
        return stored;
    }

    void revokeLink(const std::string& id, uint32_t revokedBy) override {
        auto link = requireLink(id);
        link->revoked_at = kNow;
        link->revoked_by = revokedBy;
    }

    void rotateLinkToken(
        const std::string& id,
        const std::string& lookupId,
        const std::vector<uint8_t>& tokenHash,
        uint32_t updatedBy
    ) override {
        auto link = requireLink(id);
        link_by_lookup.erase(link->token_lookup_id);
        link->token_lookup_id = lookupId;
        link->token_hash = tokenHash;
        link->updated_by = updatedBy;
        link_by_lookup[lookupId] = id;
    }

    void touchLinkAccess(const std::string& id) override {
        auto link = requireLink(id);
        link->last_accessed_at = kNow;
        ++link->access_count;
    }

    void incrementDownload(const std::string& id) override { ++requireLink(id)->download_count; }
    void incrementUpload(const std::string& id) override { ++requireLink(id)->upload_count; }

    void upsertVaultRoleForShare(const std::string& shareId, uint32_t, const std::shared_ptr<Role>& role) override {
        if (!role) vault_roles.erase(shareId);
        else vault_roles[shareId] = std::make_shared<Role>(*role);
    }

    std::shared_ptr<Role> getVaultRoleForShare(const std::string& shareId) override {
        if (!vault_roles.contains(shareId)) return nullptr;
        return vault_roles.at(shareId);
    }

    std::shared_ptr<Role> getRecipientVaultRoleForShare(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        const auto key = recipientKey(shareId, emailHash);
        if (!recipient_roles.contains(key)) return nullptr;
        return recipient_roles.at(key);
    }

    std::shared_ptr<Role> getVaultRoleTemplate(const uint32_t id) override {
        if (!role_templates.contains(id)) return nullptr;
        return role_templates.at(id);
    }

    std::shared_ptr<Role> getVaultRoleTemplateByName(const std::string& name) override {
        if (!role_template_by_name.contains(name)) return nullptr;
        return getVaultRoleTemplate(role_template_by_name.at(name));
    }

    void upsertPublicVaultRoleAssignment(
        const std::string& shareId,
        const uint32_t vaultId,
        const uint32_t roleId,
        const std::vector<vh::rbac::permission::Override>& overrides
    ) override {
        auto assigned = assignedTemplate(roleId, overrides);
        assigned->assignment_id = 900 + static_cast<uint32_t>(vault_roles.size());
        assigned->assign(assigned->assignment_id, "public", vaultId);
        vault_roles[shareId] = assigned;
    }

    uint32_t upsertValidatedRecipient(const std::string& shareId, const std::vector<uint8_t>& emailHash) override {
        const auto key = recipientKey(shareId, emailHash);
        if (recipients_by_hash.contains(key)) return recipients_by_hash.at(key);
        const auto id = next_recipient++;
        recipients_by_hash[key] = id;
        return id;
    }

    void upsertRecipientVaultRoleAssignment(
        const std::string& shareId,
        const uint32_t vaultId,
        const uint32_t recipientId,
        const uint32_t roleId,
        const std::vector<vh::rbac::permission::Override>& overrides
    ) override {
        auto assigned = assignedTemplate(roleId, overrides);
        assigned->assignment_id = 1000 + recipientId;
        assigned->assign(recipientId, "actor", vaultId);
        for (const auto& [key, id] : recipients_by_hash)
            if (id == recipientId && key.starts_with(shareId + ":"))
                recipient_roles[key] = assigned;
    }

    void replaceRecipientVaultRoleAssignments(
        const std::string& shareId,
        const uint32_t vaultId,
        const std::vector<RecipientAssignmentInput>& assignments
    ) override {
        std::vector<std::string> activeKeys;
        for (const auto& assignment : assignments) {
            const auto recipientId = upsertValidatedRecipient(shareId, assignment.email_hash);
            activeKeys.push_back(recipientKey(shareId, assignment.email_hash));
            upsertRecipientVaultRoleAssignment(
                shareId, vaultId, recipientId, assignment.vault_role_id, assignment.overrides);
        }
        std::erase_if(recipient_roles, [&](const auto& entry) {
            return entry.first.starts_with(shareId + ":") &&
                   std::ranges::find(activeKeys, entry.first) == activeKeys.end();
        });
    }

    void removeVaultRoleForShare(const std::string& shareId) override {
        vault_roles.erase(shareId);
        std::erase_if(recipient_roles, [&](const auto& entry) { return entry.first.starts_with(shareId + ":"); });
    }

    std::shared_ptr<vh::share::Session> createSession(const std::shared_ptr<vh::share::Session>& session) override {
        auto stored = std::make_shared<vh::share::Session>(*session);
        if (stored->id.empty()) stored->id = uuidFor(next_session++);
        stored->created_at = kNow;
        stored->last_seen_at = kNow;
        sessions[stored->id] = stored;
        session_by_lookup[stored->session_token_lookup_id] = stored->id;
        return stored;
    }

    std::shared_ptr<vh::share::Session> getSession(const std::string& id) override {
        if (!sessions.contains(id)) return nullptr;
        return sessions.at(id);
    }

    std::shared_ptr<vh::share::Session> getSessionByLookupId(const std::string& lookupId) override {
        if (!session_by_lookup.contains(lookupId)) return nullptr;
        return getSession(session_by_lookup.at(lookupId));
    }

    void verifySession(const std::string& sessionId, const std::vector<uint8_t>& emailHash) override {
        auto session = requireSession(sessionId);
        session->email_hash = emailHash;
        session->verified_at = kNow;
    }

    void touchSession(const std::string& sessionId) override { requireSession(sessionId)->last_seen_at = kNow + 1; }
    void revokeSession(const std::string& sessionId) override { requireSession(sessionId)->revoked_at = kNow; }

    void revokeSessionsForShare(const std::string& shareId) override {
        for (auto& [_, session] : sessions)
            if (session->share_id == shareId && !session->revoked_at) session->revoked_at = kNow;
    }

    std::shared_ptr<vh::share::EmailChallenge> createEmailChallenge(
        const std::shared_ptr<vh::share::EmailChallenge>& challenge
    ) override {
        auto stored = std::make_shared<vh::share::EmailChallenge>(*challenge);
        if (stored->id.empty()) stored->id = uuidFor(next_challenge++);
        stored->created_at = kNow;
        challenges[stored->id] = stored;
        return stored;
    }

    std::shared_ptr<vh::share::EmailChallenge> getEmailChallenge(const std::string& id) override {
        if (!challenges.contains(id)) return nullptr;
        return challenges.at(id);
    }

    std::shared_ptr<vh::share::EmailChallenge> getActiveEmailChallenge(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        std::shared_ptr<vh::share::EmailChallenge> best;
        for (auto& [_, challenge] : challenges) {
            if (challenge->share_id != shareId || challenge->email_hash != emailHash) continue;
            if (!challenge->canAttempt(kNow)) continue;
            if (!best || challenge->created_at > best->created_at) best = challenge;
        }
        return best;
    }

    void recordEmailChallengeAttempt(const std::string& challengeId) override {
        ++requireChallenge(challengeId)->attempts;
    }

    void consumeEmailChallenge(const std::string& challengeId) override {
        auto challenge = requireChallenge(challengeId);
        if (challenge->consumed_at) throw std::runtime_error("challenge consumed");
        challenge->consumed_at = kNow;
    }

    void appendAuditEvent(const std::shared_ptr<vh::share::AuditEvent>& event) override {
        audits.push_back(std::make_shared<vh::share::AuditEvent>(*event));
    }

    std::shared_ptr<vh::share::Upload> createUpload(const std::shared_ptr<vh::share::Upload>& upload) override {
        auto stored = std::make_shared<vh::share::Upload>(*upload);
        if (stored->id.empty()) stored->id = uuidFor(next_upload++);
        stored->started_at = kNow;
        uploads[stored->id] = stored;
        return stored;
    }

    std::shared_ptr<vh::share::Upload> getUpload(const std::string& uploadId) override {
        if (!uploads.contains(uploadId)) return nullptr;
        return uploads.at(uploadId);
    }

    void addUploadReceivedBytes(const std::string& uploadId, const uint64_t bytes) override {
        auto upload = requireUpload(uploadId);
        if (upload->isTerminal()) throw std::runtime_error("terminal upload");
        if (upload->exceedsExpectedSize(bytes)) throw std::runtime_error("upload too large");
        upload->received_size_bytes += bytes;
        upload->status = vh::share::UploadStatus::Receiving;
    }

    void completeUpload(
        const std::string& uploadId,
        const uint32_t entryId,
        const std::string& contentHash,
        const std::string& mimeType
    ) override {
        auto upload = requireUpload(uploadId);
        if (upload->isTerminal()) throw std::runtime_error("terminal upload");
        upload->created_entry_id = entryId;
        upload->content_hash = contentHash;
        upload->mime_type = mimeType;
        finish(*upload, vh::share::UploadStatus::Complete);
    }

    void failUpload(const std::string& uploadId, const std::string& error) override {
        auto upload = requireUpload(uploadId);
        upload->error = error;
        finish(*upload, vh::share::UploadStatus::Failed);
    }

    void cancelUpload(const std::string& uploadId) override {
        finish(*requireUpload(uploadId), vh::share::UploadStatus::Cancelled);
    }

    uint64_t sumCompletedUploadBytes(const std::string& shareId) override {
        uint64_t total = 0;
        for (const auto& [_, upload] : uploads)
            if (upload->share_id == shareId && upload->status == vh::share::UploadStatus::Complete)
                total += upload->received_size_bytes;
        return total;
    }

    uint64_t countCompletedUploadFiles(const std::string& shareId) override {
        uint64_t total = 0;
        for (const auto& [_, upload] : uploads)
            if (upload->share_id == shareId && upload->status == vh::share::UploadStatus::Complete) ++total;
        return total;
    }

    std::vector<std::shared_ptr<vh::share::Upload>> listStaleActiveUploads(
        const std::time_t olderThanSeconds,
        const uint64_t limit
    ) override {
        std::vector<std::shared_ptr<vh::share::Upload>> out;
        const auto cutoff = kNow - olderThanSeconds;
        for (auto& [_, upload] : uploads) {
            if (out.size() >= limit) break;
            if (upload->isTerminal() || upload->started_at >= cutoff) continue;
            out.push_back(upload);
        }
        return out;
    }

private:
    static std::string recipientKey(const std::string& shareId, const std::vector<uint8_t>& emailHash) {
        return shareId + ":" + vh::db::encoding::to_hex_bytea(emailHash);
    }

    std::shared_ptr<Role> assignedTemplate(
        const uint32_t roleId,
        const std::vector<vh::rbac::permission::Override>& overrides
    ) {
        auto role = getVaultRoleTemplate(roleId);
        if (!role) throw std::runtime_error("missing role template");
        auto assigned = std::make_shared<Role>(*role);
        assigned->fs.overrides = overrides;
        return assigned;
    }

    static void finish(vh::share::Upload& upload, const vh::share::UploadStatus status) {
        upload.status = status;
        upload.completed_at = kNow + 2;
    }

    std::shared_ptr<vh::share::Link> requireLink(const std::string& id) {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        return link;
    }

    std::shared_ptr<vh::share::Session> requireSession(const std::string& id) {
        auto session = getSession(id);
        if (!session) throw std::runtime_error("missing session");
        return session;
    }

    std::shared_ptr<vh::share::EmailChallenge> requireChallenge(const std::string& id) {
        auto challenge = getEmailChallenge(id);
        if (!challenge) throw std::runtime_error("missing challenge");
        return challenge;
    }

    std::shared_ptr<vh::share::Upload> requireUpload(const std::string& id) {
        auto upload = getUpload(id);
        if (!upload) throw std::runtime_error("missing upload");
        return upload;
    }
};

// Entries by id and by vault path, with children in insertion order.
class FakeEntryProvider final : public vh::share::TargetEntryProvider {
public:
    std::unordered_map<uint32_t, std::shared_ptr<vh::fs::model::Entry>> by_id;
    std::unordered_map<std::string, std::shared_ptr<vh::fs::model::Entry>> by_path;
    std::unordered_map<uint32_t, std::vector<std::shared_ptr<vh::fs::model::Entry>>> children;

    void add(const std::shared_ptr<vh::fs::model::Entry>& entry) {
        by_id[entry->id] = entry;
        by_path[key(*entry->vault_id, entry->path.string())] = entry;
        if (entry->parent_id) children[*entry->parent_id].push_back(entry);
    }

    std::shared_ptr<vh::fs::model::Entry> getEntryById(const uint32_t entryId) override {
        if (!by_id.contains(entryId)) return nullptr;
        return by_id.at(entryId);
    }

    std::shared_ptr<vh::fs::model::Entry> getEntryByVaultPath(
        const uint32_t vaultId,
        const std::string_view vaultPath
    ) override {
        const auto k = key(vaultId, std::string(vaultPath));
        if (!by_path.contains(k)) return nullptr;
        return by_path.at(k);
    }

    std::vector<std::shared_ptr<vh::fs::model::Entry>> listChildren(const uint32_t parentEntryId) override {
        if (!children.contains(parentEntryId)) return {};
        return children.at(parentEntryId);
    }

private:
    static std::string key(const uint32_t vaultId, const std::string& path) {
        return std::to_string(vaultId) + ":" + path;
    }
};

inline std::shared_ptr<vh::fs::model::Directory> makeDir(
    const uint32_t id,
    const uint32_t vaultId,
    const std::string& path,
    const std::optional<int32_t> parentId = std::nullopt
) {
    auto entry = std::make_shared<vh::fs::model::Directory>();
    entry->id = id;
    entry->vault_id = vaultId;
    entry->parent_id = parentId;
    entry->path = path;
    entry->name = path == "/" ? "" : std::filesystem::path(path).filename().string();
    entry->created_at = entry->updated_at = kNow;
    return entry;
}

inline std::shared_ptr<vh::fs::model::File> makeFile(
    const uint32_t id,
    const uint32_t vaultId,
    const std::string& path,
    const std::optional<int32_t> parentId = std::nullopt,
    const std::string& mimeType = "text/plain",
    const uintmax_t sizeBytes = 0
) {
    auto entry = std::make_shared<vh::fs::model::File>();
    entry->id = id;
    entry->vault_id = vaultId;
    entry->parent_id = parentId;
    entry->path = path;
    entry->name = std::filesystem::path(path).filename().string();
    entry->mime_type = mimeType;
    entry->size_bytes = sizeBytes;
    entry->created_at = entry->updated_at = kNow;
    return entry;
}

// A directory link on vault 42 entry 77 (/reports), live for an hour.
inline vh::share::Link makeLink(const uint32_t ops, const vh::share::AccessMode mode = vh::share::AccessMode::Public) {
    vh::share::Link link;
    link.vault_id = 42;
    link.root_entry_id = 77;
    link.root_path = "/reports";
    link.target_type = vh::share::TargetType::Directory;
    link.link_type = vh::share::LinkType::Access;
    link.access_mode = mode;
    link.allowed_ops = ops;
    link.expires_at = kNow + 3600;
    return link;
}

// A public link gives `roleName` to the public; an email-validated one denies the public and gives `roleName` to
// recipient@example.com and email@example.com.
inline vh::share::CreateLinkRequest linkRequest(vh::share::Link link, const std::string& roleName) {
    const auto role = [](const std::string& name) { return vh::share::RoleAssignmentRequest{.vault_role_name = name}; };
    if (link.access_mode != vh::share::AccessMode::EmailValidated)
        return {.link = std::move(link), .public_role = role(roleName)};
    return {
        .link = std::move(link),
        .public_role = role(vh::rbac::role::Vault::ImplicitDeny().name),
        .recipients = {{.email = "recipient@example.com", .role = role(roleName)},
                       {.email = "email@example.com", .role = role(roleName)}}
    };
}

inline std::shared_ptr<vh::protocols::ws::Session> publicSession() {
    auto session = std::make_shared<vh::protocols::ws::Session>(std::make_shared<vh::protocols::ws::Router>());
    session->ipAddress = "127.0.0.1";
    session->userAgent = "ws-share-test";
    return session;
}

inline std::shared_ptr<vh::protocols::ws::Session> humanSession() {
    auto session = publicSession();
    vh::identities::UserState userState;
    userState.name = "human";
    session->user = vh::identities::User::detached(9, std::move(userState));
    return session;
}

inline void expectNoSecretOrInternalFields(const nlohmann::json& value) {
    const auto dump = value.dump();
    for (const auto* field : {"token", "hash", "email", "challenge", "vault_id", "abs_path", "backing", "inode",
                              "owner_uid", "group_gid", "mode"})
        EXPECT_FALSE(dump.contains(field)) << field;
}

// A share::Manager over the fakes on kNow, owned by user 7, and ready public share sessions on `link`.
class Harness : public ::testing::Test {
protected:
    std::shared_ptr<FakeStore> store = std::make_shared<FakeStore>();
    std::shared_ptr<FakeAuthorizer> authorizer = std::make_shared<FakeAuthorizer>();
    std::shared_ptr<vh::share::Manager> manager;
    std::shared_ptr<FakeEntryProvider> provider = std::make_shared<FakeEntryProvider>();
    std::shared_ptr<vh::share::TargetResolver> resolver = std::make_shared<vh::share::TargetResolver>(provider);
    std::shared_ptr<vh::identities::User> user = owner();
    vh::share::Link link = makeLink(0);                         // create() sets its allowed_ops
    std::string publicRole = vh::rbac::role::Vault::Reader().name;
    uint32_t readyOps = 0;                                      // readySession()'s ops

    // Sets the token pepper; `options` gets the fixed clock and 10-minute sessions.
    void startManager(vh::share::ManagerOptions options = {}) {
        vh::share::Token::setPepperForTesting(std::vector<uint8_t>(32, 0x61));
        options.clock = [] { return kNow; };
        options.session_ttl_seconds = 600;
        manager = std::make_shared<vh::share::Manager>(store, authorizer, std::move(options));
    }

    void TearDown() override { vh::share::Token::clearPepperForTesting(); }

    vh::share::CreateLinkResult create(const uint32_t ops) {
        auto requested = link;
        requested.allowed_ops = ops;
        return manager->createLink(vh::rbac::Actor::human(user), linkRequest(std::move(requested), publicRole));
    }

    std::shared_ptr<vh::protocols::ws::Session> readySession(const uint32_t ops) {
        const auto created = create(ops);
        auto opened = manager->openPublicSession(created.public_token);
        auto principal = manager->resolvePrincipal(opened.session_token);
        auto session = publicSession();
        session->setSharePrincipal(std::move(principal), opened.session_token);
        return session;
    }

    std::shared_ptr<vh::protocols::ws::Session> readySession() { return readySession(readyOps); }

private:
    static std::shared_ptr<vh::identities::User> owner() {
        vh::identities::UserState userState;
        userState.name = "share-owner";
        return vh::identities::User::detached(7, std::move(userState));
    }
};

}
