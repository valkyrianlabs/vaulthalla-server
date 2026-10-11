#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "identities/User.hpp"
#include "db/encoding/bytea.hpp"
#include "ops/Error.hpp"
#include "share/Policy.hpp"
#include "rbac/Actor.hpp"
#include "share/AuditEvent.hpp"
#include "share/EmailChallenge.hpp"
#include "share/Manager.hpp"
#include "share/Token.hpp"
#include "rbac/role/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <format>
#include <functional>
#include <memory>
#include <stdexcept>
#include <unordered_map>

using namespace vh;
using namespace vh::share;

namespace vh::share::test_manager {
constexpr std::time_t kManagerNow = 1'800'000'000;

std::string uuidFor(const uint32_t value) {
    return std::format("00000000-0000-4000-8000-{:012d}", value);
}

class FakeAuthorizer final : public ShareAuthorizer {
public:
    bool allow_create{true};
    bool allow_update{true};
    bool allow_manage{true};
    bool allow_list_vault{true};

    AuthorizationDecision canCreateLink(const rbac::Actor& actor, const Link&) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_create, allow_create ? "allowed" : "create_denied"};
    }

    AuthorizationDecision canUpdateLink(const rbac::Actor& actor, const Link&, const Link&) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_update, allow_update ? "allowed" : "update_denied"};
    }

    AuthorizationDecision canManageLink(const rbac::Actor& actor, const Link&) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_manage, allow_manage ? "allowed" : "manage_denied"};
    }

    AuthorizationDecision canListVaultLinks(const rbac::Actor& actor, uint32_t) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_list_vault, allow_list_vault ? "allowed" : "list_denied"};
    }
};

class FakeStore final : public ShareStore {
public:
    std::unordered_map<std::string, std::shared_ptr<Link>> links;
    std::unordered_map<std::string, std::string> link_by_lookup;
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions;
    std::unordered_map<std::string, std::string> session_by_lookup;
    std::unordered_map<std::string, std::shared_ptr<EmailChallenge>> challenges;
    std::unordered_map<std::string, std::shared_ptr<Upload>> uploads;
    std::unordered_map<std::string, std::shared_ptr<rbac::role::Vault>> vault_roles;
    std::unordered_map<uint32_t, std::shared_ptr<rbac::role::Vault>> role_templates;
    std::unordered_map<std::string, uint32_t> role_template_by_name;
    std::unordered_map<std::string, uint32_t> recipients_by_hash;
    std::unordered_map<std::string, std::shared_ptr<rbac::role::Vault>> recipient_roles;
    std::vector<std::shared_ptr<AuditEvent>> audits;

    uint32_t next_link{100};
    uint32_t next_session{200};
    uint32_t next_challenge{300};
    uint32_t next_upload{400};
    uint32_t next_recipient{500};

    FakeStore() {
        addTemplate(1, rbac::role::Vault::ImplicitDeny());
        addTemplate(2, rbac::role::Vault::Reader());
        addTemplate(3, rbac::role::Vault::Contributor());
    }

    void addTemplate(const uint32_t id, rbac::role::Vault role) {
        role.id = id;
        role_templates[id] = std::make_shared<rbac::role::Vault>(std::move(role));
        role_template_by_name[role_templates[id]->name] = id;
    }

    std::shared_ptr<Link> createLink(const std::shared_ptr<Link>& link) override {
        auto stored = std::make_shared<Link>(*link);
        if (stored->id.empty()) stored->id = uuidFor(next_link++);
        stored->created_at = kManagerNow;
        stored->updated_at = kManagerNow;
        links[stored->id] = stored;
        link_by_lookup[stored->token_lookup_id] = stored->id;
        return stored;
    }

    std::shared_ptr<Link> getLink(const std::string& id) override {
        if (!links.contains(id)) return nullptr;
        return links.at(id);
    }

    std::shared_ptr<Link> getLinkByLookupId(const std::string& lookupId) override {
        if (!link_by_lookup.contains(lookupId)) return nullptr;
        return getLink(link_by_lookup.at(lookupId));
    }

    std::vector<std::shared_ptr<Link>> listLinksForUser(uint32_t userId, const db::model::ListQueryParams&) override {
        std::vector<std::shared_ptr<Link>> out;
        for (auto& [_, link] : links)
            if (link->created_by == userId) out.push_back(link);
        return out;
    }

    std::vector<std::shared_ptr<Link>> listLinksForVault(uint32_t vaultId, const db::model::ListQueryParams&) override {
        std::vector<std::shared_ptr<Link>> out;
        for (auto& [_, link] : links)
            if (link->vault_id == vaultId) out.push_back(link);
        return out;
    }

    std::shared_ptr<Link> updateLink(const std::shared_ptr<Link>& link) override {
        auto stored = std::make_shared<Link>(*link);
        stored->updated_at = kManagerNow + 1;
        links[stored->id] = stored;
        link_by_lookup[stored->token_lookup_id] = stored->id;
        return stored;
    }

    void revokeLink(const std::string& id, uint32_t revokedBy) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        link->revoked_at = kManagerNow;
        link->revoked_by = revokedBy;
    }

    void rotateLinkToken(
        const std::string& id,
        const std::string& lookupId,
        const std::vector<uint8_t>& tokenHash,
        uint32_t updatedBy
    ) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        link_by_lookup.erase(link->token_lookup_id);
        link->token_lookup_id = lookupId;
        link->token_hash = tokenHash;
        link->updated_by = updatedBy;
        link_by_lookup[lookupId] = id;
    }

    void touchLinkAccess(const std::string& id) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        link->last_accessed_at = kManagerNow;
        ++link->access_count;
    }

    void incrementDownload(const std::string& id) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        ++link->download_count;
    }

    void incrementUpload(const std::string& id) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        ++link->upload_count;
    }

    void upsertVaultRoleForShare(
        const std::string& shareId,
        uint32_t,
        const std::shared_ptr<rbac::role::Vault>& role
    ) override {
        vault_roles[shareId] = std::make_shared<rbac::role::Vault>(*role);
    }

    std::shared_ptr<rbac::role::Vault> getVaultRoleForShare(const std::string& shareId) override {
        if (!vault_roles.contains(shareId)) return nullptr;
        return vault_roles.at(shareId);
    }

    std::shared_ptr<rbac::role::Vault> getRecipientVaultRoleForShare(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        const auto key = shareId + ":" + db::encoding::to_hex_bytea(emailHash);
        if (!recipient_roles.contains(key)) return nullptr;
        return recipient_roles.at(key);
    }

    std::shared_ptr<rbac::role::Vault> getVaultRoleTemplate(const uint32_t id) override {
        if (!role_templates.contains(id)) return nullptr;
        return role_templates.at(id);
    }

    std::shared_ptr<rbac::role::Vault> getVaultRoleTemplateByName(const std::string& name) override {
        if (!role_template_by_name.contains(name)) return nullptr;
        return getVaultRoleTemplate(role_template_by_name.at(name));
    }

    void upsertPublicVaultRoleAssignment(
        const std::string& shareId,
        const uint32_t vaultId,
        const uint32_t roleId,
        const std::vector<rbac::permission::Override>& overrides
    ) override {
        auto role = getVaultRoleTemplate(roleId);
        if (!role) throw std::runtime_error("missing role template");
        auto assigned = std::make_shared<rbac::role::Vault>(*role);
        assigned->assignment_id = 900 + static_cast<uint32_t>(vault_roles.size());
        assigned->assign(assigned->assignment_id, "public", vaultId);
        assigned->fs.overrides = overrides;
        vault_roles[shareId] = assigned;
    }

    uint32_t upsertValidatedRecipient(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        const auto key = shareId + ":" + db::encoding::to_hex_bytea(emailHash);
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
        const std::vector<rbac::permission::Override>& overrides
    ) override {
        auto role = getVaultRoleTemplate(roleId);
        if (!role) throw std::runtime_error("missing role template");
        auto assigned = std::make_shared<rbac::role::Vault>(*role);
        assigned->assignment_id = 1000 + recipientId;
        assigned->assign(recipientId, "actor", vaultId);
        assigned->fs.overrides = overrides;
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
        activeKeys.reserve(assignments.size());
        for (const auto& assignment : assignments) {
            const auto key = shareId + ":" + db::encoding::to_hex_bytea(assignment.email_hash);
            const auto recipientId = upsertValidatedRecipient(shareId, assignment.email_hash);
            activeKeys.push_back(key);
            upsertRecipientVaultRoleAssignment(
                shareId,
                vaultId,
                recipientId,
                assignment.vault_role_id,
                assignment.overrides
            );
        }

        for (auto it = recipient_roles.begin(); it != recipient_roles.end();) {
            const auto active = std::find(activeKeys.begin(), activeKeys.end(), it->first) != activeKeys.end();
            if (it->first.starts_with(shareId + ":") && !active) it = recipient_roles.erase(it);
            else ++it;
        }
    }

    void removeVaultRoleForShare(const std::string& shareId) override {
        vault_roles.erase(shareId);
        for (auto it = recipient_roles.begin(); it != recipient_roles.end();)
            if (it->first.starts_with(shareId + ":")) it = recipient_roles.erase(it);
            else ++it;
    }

    std::shared_ptr<Session> createSession(const std::shared_ptr<Session>& session) override {
        auto stored = std::make_shared<Session>(*session);
        if (stored->id.empty()) stored->id = uuidFor(next_session++);
        stored->created_at = kManagerNow;
        stored->last_seen_at = kManagerNow;
        sessions[stored->id] = stored;
        session_by_lookup[stored->session_token_lookup_id] = stored->id;
        return stored;
    }

    std::shared_ptr<Session> getSession(const std::string& id) override {
        if (!sessions.contains(id)) return nullptr;
        return sessions.at(id);
    }

    std::shared_ptr<Session> getSessionByLookupId(const std::string& lookupId) override {
        if (!session_by_lookup.contains(lookupId)) return nullptr;
        return getSession(session_by_lookup.at(lookupId));
    }

    void verifySession(const std::string& sessionId, const std::vector<uint8_t>& emailHash) override {
        auto session = getSession(sessionId);
        if (!session) throw std::runtime_error("missing session");
        session->email_hash = emailHash;
        session->verified_at = kManagerNow;
    }

    void touchSession(const std::string& sessionId) override {
        auto session = getSession(sessionId);
        if (!session) throw std::runtime_error("missing session");
        session->last_seen_at = kManagerNow + 1;
    }

    void revokeSession(const std::string& sessionId) override {
        auto session = getSession(sessionId);
        if (!session) throw std::runtime_error("missing session");
        session->revoked_at = kManagerNow;
    }

    void revokeSessionsForShare(const std::string& shareId) override {
        for (auto& [_, session] : sessions)
            if (session->share_id == shareId && !session->revoked_at) session->revoked_at = kManagerNow;
    }

    std::shared_ptr<EmailChallenge> createEmailChallenge(const std::shared_ptr<EmailChallenge>& challenge) override {
        auto stored = std::make_shared<EmailChallenge>(*challenge);
        if (stored->id.empty()) stored->id = uuidFor(next_challenge++);
        stored->created_at = kManagerNow;
        challenges[stored->id] = stored;
        return stored;
    }

    std::shared_ptr<EmailChallenge> getEmailChallenge(const std::string& id) override {
        if (!challenges.contains(id)) return nullptr;
        return challenges.at(id);
    }

    std::shared_ptr<EmailChallenge> getActiveEmailChallenge(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        std::shared_ptr<EmailChallenge> best;
        for (auto& [_, challenge] : challenges) {
            if (challenge->share_id != shareId) continue;
            if (challenge->email_hash != emailHash) continue;
            if (!challenge->canAttempt(kManagerNow)) continue;
            if (!best || challenge->created_at > best->created_at) best = challenge;
        }
        return best;
    }

    void recordEmailChallengeAttempt(const std::string& challengeId) override {
        auto challenge = getEmailChallenge(challengeId);
        if (!challenge) throw std::runtime_error("missing challenge");
        ++challenge->attempts;
    }

    void consumeEmailChallenge(const std::string& challengeId) override {
        auto challenge = getEmailChallenge(challengeId);
        if (!challenge) throw std::runtime_error("missing challenge");
        if (challenge->consumed_at) throw std::runtime_error("challenge consumed");
        challenge->consumed_at = kManagerNow;
    }

    void appendAuditEvent(const std::shared_ptr<AuditEvent>& event) override {
        audits.push_back(std::make_shared<AuditEvent>(*event));
    }

    std::shared_ptr<Upload> createUpload(const std::shared_ptr<Upload>& upload) override {
        auto stored = std::make_shared<Upload>(*upload);
        if (stored->id.empty()) stored->id = uuidFor(next_upload++);
        stored->started_at = kManagerNow;
        uploads[stored->id] = stored;
        return stored;
    }

    std::shared_ptr<Upload> getUpload(const std::string& uploadId) override {
        if (!uploads.contains(uploadId)) return nullptr;
        return uploads.at(uploadId);
    }

    void addUploadReceivedBytes(const std::string& uploadId, const uint64_t bytes) override {
        auto upload = getUpload(uploadId);
        if (!upload) throw std::runtime_error("missing upload");
        if (upload->isTerminal()) throw std::runtime_error("terminal upload");
        if (upload->exceedsExpectedSize(bytes)) throw std::runtime_error("upload too large");
        upload->received_size_bytes += bytes;
        upload->status = UploadStatus::Receiving;
    }

    void completeUpload(
        const std::string& uploadId,
        const uint32_t entryId,
        const std::string& contentHash,
        const std::string& mimeType
    ) override {
        auto upload = getUpload(uploadId);
        if (!upload) throw std::runtime_error("missing upload");
        if (upload->isTerminal()) throw std::runtime_error("terminal upload");
        upload->created_entry_id = entryId;
        upload->content_hash = contentHash;
        upload->mime_type = mimeType;
        upload->status = UploadStatus::Complete;
        upload->completed_at = kManagerNow + 2;
    }

    void failUpload(const std::string& uploadId, const std::string& error) override {
        auto upload = getUpload(uploadId);
        if (!upload) throw std::runtime_error("missing upload");
        upload->error = error;
        upload->status = UploadStatus::Failed;
        upload->completed_at = kManagerNow + 2;
    }

    void cancelUpload(const std::string& uploadId) override {
        auto upload = getUpload(uploadId);
        if (!upload) throw std::runtime_error("missing upload");
        upload->status = UploadStatus::Cancelled;
        upload->completed_at = kManagerNow + 2;
    }

    uint64_t sumCompletedUploadBytes(const std::string& shareId) override {
        uint64_t total = 0;
        for (const auto& [_, upload] : uploads)
            if (upload->share_id == shareId && upload->status == UploadStatus::Complete)
                total += upload->received_size_bytes;
        return total;
    }

    uint64_t countCompletedUploadFiles(const std::string& shareId) override {
        uint64_t total = 0;
        for (const auto& [_, upload] : uploads)
            if (upload->share_id == shareId && upload->status == UploadStatus::Complete)
                ++total;
        return total;
    }

    std::vector<std::shared_ptr<Upload>> listStaleActiveUploads(
        const std::time_t olderThanSeconds,
        const uint64_t limit
    ) override {
        std::vector<std::shared_ptr<Upload>> out;
        const auto cutoff = kManagerNow - olderThanSeconds;
        for (auto& [_, upload] : uploads) {
            if (out.size() >= limit) break;
            if (upload->isTerminal()) continue;
            if (upload->started_at >= cutoff) continue;
            out.push_back(upload);
        }
        return out;
    }
};

Link makeManagerLink(const AccessMode mode = AccessMode::Public) {
    Link link;
    link.vault_id = 42;
    link.root_entry_id = 77;
    link.root_path = "/reports";
    link.target_type = TargetType::Directory;
    link.link_type = LinkType::Access;
    link.access_mode = mode;
    link.allowed_ops = bit(Operation::Metadata) |
                       bit(Operation::List) |
                       bit(Operation::Download) |
                       bit(Operation::Upload) |
                       bit(Operation::Mkdir);
    link.expires_at = kManagerNow + 3600;
    link.duplicate_policy = DuplicatePolicy::Reject;
    link.metadata = R"({"test":true})";
    return link;
}

class ShareManagerTest : public ::testing::Test {
protected:
    std::shared_ptr<FakeStore> store;
    std::shared_ptr<FakeAuthorizer> authorizer;
    std::unique_ptr<Manager> manager;
    std::shared_ptr<identities::User> user;

    void SetUp() override {
        Token::setPepperForTesting(std::vector<uint8_t>(32, 0x61));
        store = std::make_shared<FakeStore>();
        authorizer = std::make_shared<FakeAuthorizer>();
        ManagerOptions options;
        options.clock = [] { return kManagerNow; };
        options.session_ttl_seconds = 600;
        options.challenge_ttl_seconds = 300;
        options.challenge_max_attempts = 3;
        manager = std::make_unique<Manager>(store, authorizer, options);

        vh::identities::UserState userState;
        userState.name = "share-manager-user";
        user = vh::identities::User::detached(7, std::move(userState));
    }

    void TearDown() override {
        Token::clearPepperForTesting();
    }

    [[nodiscard]] rbac::Actor humanActor() const { return rbac::Actor::human(user); }

    [[nodiscard]] CreateLinkResult create(
        const AccessMode mode = AccessMode::Public,
        const std::string& roleName = rbac::role::Vault::Reader().name
    ) {
        std::vector<RecipientRoleAssignmentRequest> recipients;
        if (mode == AccessMode::EmailValidated) {
            recipients.push_back({
                .email = "recipient@example.com",
                .role = RoleAssignmentRequest{.vault_role_name = roleName}
            });
            recipients.push_back({
                .email = "email@example.com",
                .role = RoleAssignmentRequest{.vault_role_name = roleName}
            });
        }
        return manager->createLink(humanActor(), {
            .link = makeManagerLink(mode),
            .public_role = mode == AccessMode::EmailValidated
                               ? RoleAssignmentRequest{.vault_role_name = rbac::role::Vault::ImplicitDeny().name}
                               : RoleAssignmentRequest{.vault_role_name = roleName},
            .recipients = std::move(recipients)
        });
    }

    [[nodiscard]] std::string wrongSecret(const std::string& token) const {
        auto parsed = Token::parse(token);
        parsed.secret.back() = parsed.secret.back() == 'a' ? 'b' : 'a';
        return (parsed.kind == TokenKind::PublicShare ? "vhs_" : "vhss_") + parsed.lookup_id + "_" + parsed.secret;
    }
};
}

using namespace vh::share::test_manager;

TEST_F(ShareManagerTest, CreatePublicShareSucceedsWhenAuthorizerAllows) {
    const auto result = create();

    ASSERT_NE(result.link, nullptr);
    EXPECT_EQ(result.link->created_by, user->id);
    EXPECT_TRUE(result.public_token.starts_with("vhs_"));
    EXPECT_EQ(result.public_url_path, "/share/" + result.public_token);
    EXPECT_TRUE(Token::verify(result.link->token_hash, TokenKind::PublicShare, Token::parse(result.public_token).secret));
    EXPECT_FALSE(result.link->toManagementJson().dump().contains(Token::parse(result.public_token).secret));
    EXPECT_FALSE(store->audits.empty());
}

TEST_F(ShareManagerTest, CreatePersistsScopedVaultRoleAndResolvedPrincipalUsesIt) {
    const auto result = create();
    ASSERT_TRUE(store->vault_roles.contains(result.link->id));
    const auto role = store->vault_roles.at(result.link->id);
    ASSERT_NE(role, nullptr);
    EXPECT_EQ(role->name, rbac::role::Vault::Reader().name);
    ASSERT_TRUE(role->assignment);
    EXPECT_EQ(role->assignment->subject_type, "public");

    auto opened = manager->openPublicSession(result.public_token);
    auto principal = manager->resolvePrincipal(opened.session_token);
    ASSERT_NE(principal, nullptr);
    ASSERT_NE(principal->scoped_vault_role, nullptr);
    EXPECT_EQ(principal->scoped_vault_role->name, role->name);

    auto decision = manager->authorize(*principal, Operation::Download, "/reports/file.txt", TargetType::File);
    EXPECT_TRUE(decision.allowed);

    decision = manager->authorize(*principal, Operation::Preview, "/reports/file.txt", TargetType::File);
    EXPECT_FALSE(decision.allowed);
}

TEST_F(ShareManagerTest, CreateWithoutPublicRoleDefaultsToPersistedImplicitDenyTemplate) {
    const auto result = manager->createLink(humanActor(), {.link = makeManagerLink()});
    ASSERT_TRUE(store->vault_roles.contains(result.link->id));
    const auto role = store->vault_roles.at(result.link->id);
    ASSERT_NE(role, nullptr);
    EXPECT_EQ(role->name, rbac::role::Vault::ImplicitDeny().name);

    auto opened = manager->openPublicSession(result.public_token);
    auto principal = manager->resolvePrincipal(opened.session_token);
    ASSERT_NE(principal, nullptr);
    auto decision = manager->authorize(*principal, Operation::Download, "/reports/file.txt", TargetType::File);
    EXPECT_FALSE(decision.allowed);
}

TEST_F(ShareManagerTest, CreatePublicShareFailsWhenAuthorizerDenies) {
    authorizer->allow_create = false;
    EXPECT_THROW({ (void)create(); }, std::runtime_error);
    EXPECT_TRUE(store->links.empty());
    ASSERT_FALSE(store->audits.empty());
    EXPECT_EQ(store->audits.back()->status, AuditStatus::Denied);
}

TEST_F(ShareManagerTest, CreateEmailValidatedShareSucceedsWhenAuthorizerAllows) {
    const auto result = create(AccessMode::EmailValidated);

    ASSERT_NE(result.link, nullptr);
    EXPECT_EQ(result.link->access_mode, AccessMode::EmailValidated);
    EXPECT_TRUE(result.public_token.starts_with("vhs_"));
}

TEST_F(ShareManagerTest, InvalidGrantFailsBeforePersistence) {
    auto link = makeManagerLink();
    link.root_entry_id = 0;
    const CreateLinkRequest request{.link = link};

    EXPECT_THROW({ (void)manager->createLink(humanActor(), request); }, std::invalid_argument);
    EXPECT_TRUE(store->links.empty());
}

TEST_F(ShareManagerTest, RevokeLinkMarksInactiveAndRevokesSessions) {
    auto created = create();
    auto opened = manager->openPublicSession(created.public_token);
    ASSERT_TRUE(opened.session->isActive(kManagerNow));
    ASSERT_TRUE(store->vault_roles.contains(created.link->id));

    manager->revokeLink(humanActor(), created.link->id);

    EXPECT_TRUE(created.link->isRevoked());
    EXPECT_FALSE(created.link->isActive(kManagerNow));
    EXPECT_TRUE(opened.session->isRevoked());
    EXPECT_FALSE(store->vault_roles.contains(created.link->id));
}

TEST_F(ShareManagerTest, RotateTokenChangesLookupHashAndInvalidatesOldTokenAndSessions) {
    auto created = create();
    const auto oldToken = created.public_token;
    const auto oldLookup = created.link->token_lookup_id;
    auto opened = manager->openPublicSession(oldToken);

    const auto rotated = manager->rotateLinkToken(humanActor(), created.link->id);

    EXPECT_NE(rotated.link->token_lookup_id, oldLookup);
    EXPECT_TRUE(opened.session->isRevoked());
    EXPECT_THROW({ (void)manager->openPublicSession(oldToken); }, std::runtime_error);
    EXPECT_NO_THROW({ (void)manager->openPublicSession(rotated.public_token); });
}

TEST_F(ShareManagerTest, ValidPublicTokenOpensReadySession) {
    const auto created = create();
    const auto opened = manager->openPublicSession(created.public_token, "127.0.0.1", "test-agent");

    ASSERT_NE(opened.session, nullptr);
    EXPECT_TRUE(opened.ready());
    EXPECT_TRUE(opened.session_token.starts_with("vhss_"));
    EXPECT_EQ(opened.session->share_id, created.link->id);
    EXPECT_EQ(opened.session->ip_address, "127.0.0.1");
    EXPECT_FALSE(opened.link->toPublicJson().dump().contains(Token::parse(opened.session_token).secret));
}

TEST_F(ShareManagerTest, PublicSessionRejectsMalformedWrongOrInactiveTokens) {
    const auto created = create();
    EXPECT_THROW({ (void)manager->openPublicSession("not-a-share-token"); }, std::exception);
    EXPECT_THROW({ (void)manager->openPublicSession(wrongSecret(created.public_token)); }, std::runtime_error);

    created.link->expires_at = kManagerNow - 1;
    EXPECT_THROW({ (void)manager->openPublicSession(created.public_token); }, std::runtime_error);

    created.link->expires_at = kManagerNow + 3600;
    created.link->revoked_at = kManagerNow;
    EXPECT_THROW({ (void)manager->openPublicSession(created.public_token); }, std::runtime_error);

    created.link->revoked_at.reset();
    created.link->disabled_at = kManagerNow;
    EXPECT_THROW({ (void)manager->openPublicSession(created.public_token); }, std::runtime_error);
}

TEST_F(ShareManagerTest, EmailValidatedShareDoesNotResolveBeforeVerification) {
    const auto created = create(AccessMode::EmailValidated);
    const auto opened = manager->openPublicSession(created.public_token);

    EXPECT_FALSE(opened.ready());
    EXPECT_EQ(opened.status, OpenSessionStatus::EmailRequired);
    EXPECT_THROW({ (void)manager->resolvePrincipal(opened.session_token); }, std::runtime_error);
}

TEST_F(ShareManagerTest, EmailChallengeStoresHashesAndRejectsWrongExpiredOrConsumedCodes) {
    const auto created = create(AccessMode::EmailValidated);
    auto challenge = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = created.public_token,
        .session_token = std::nullopt,
        .email = " Recipient@Example.COM ",
        .ip_address = "127.0.0.1",
        .user_agent = "test"
    });

    ASSERT_NE(challenge.challenge, nullptr);
    ASSERT_NE(challenge.session, nullptr);
    EXPECT_FALSE(challenge.verification_code.empty());
    EXPECT_FALSE(challenge.challenge->email_hash.empty());
    EXPECT_FALSE(challenge.challenge->code_hash.empty());
    EXPECT_NE(challenge.challenge->code_hash, std::vector<uint8_t>(challenge.verification_code.begin(), challenge.verification_code.end()));
    EXPECT_EQ(challenge.challenge->attempts, 0u);

    EXPECT_THROW({ (void)manager->confirmEmailChallenge(ConfirmEmailChallengeRequest{
        .challenge_id = challenge.challenge->id,
        .session_id = challenge.session->id,
        .session_token = challenge.session_token,
        .code = "000000"
    }); }, std::runtime_error);
    EXPECT_EQ(challenge.challenge->attempts, 1u);

    challenge.challenge->expires_at = kManagerNow - 1;
    EXPECT_THROW({ (void)manager->confirmEmailChallenge(ConfirmEmailChallengeRequest{
        .challenge_id = challenge.challenge->id,
        .session_id = challenge.session->id,
        .session_token = challenge.session_token,
        .code = challenge.verification_code
    }); }, std::runtime_error);

    auto consumed = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = std::nullopt,
        .session_token = challenge.session_token,
        .email = "recipient@example.com",
        .ip_address = std::nullopt,
        .user_agent = std::nullopt
    });
    store->consumeEmailChallenge(consumed.challenge->id);
    EXPECT_THROW({ (void)manager->confirmEmailChallenge(ConfirmEmailChallengeRequest{
        .challenge_id = consumed.challenge->id,
        .session_id = consumed.session->id,
        .session_token = challenge.session_token,
        .code = consumed.verification_code
    }); }, std::runtime_error);
}

TEST_F(ShareManagerTest, ConfirmEmailChallengeVerifiesSessionAndPreventsReuse) {
    const auto created = create(AccessMode::EmailValidated);
    auto challenge = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = created.public_token,
        .session_token = std::nullopt,
        .email = "recipient@example.com",
        .ip_address = std::nullopt,
        .user_agent = std::nullopt
    });

    auto confirmed = manager->confirmEmailChallenge({
        .challenge_id = challenge.challenge->id,
        .session_id = challenge.session->id,
        .session_token = challenge.session_token,
        .code = challenge.verification_code
    });

    ASSERT_NE(confirmed.session, nullptr);
    EXPECT_TRUE(confirmed.verified);
    EXPECT_TRUE(confirmed.session->isVerified());
    EXPECT_TRUE(challenge.challenge->consumed_at.has_value());
    EXPECT_THROW({ (void)manager->confirmEmailChallenge(ConfirmEmailChallengeRequest{
        .challenge_id = challenge.challenge->id,
        .session_id = challenge.session->id,
        .session_token = challenge.session_token,
        .code = challenge.verification_code
    }); }, std::runtime_error);
}

TEST_F(ShareManagerTest, EmailRecipientAssignmentTakesPrecedenceOverPublicImplicitDeny) {
    const auto created = create(AccessMode::EmailValidated);
    auto challenge = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = created.public_token,
        .session_token = std::nullopt,
        .email = "recipient@example.com",
        .ip_address = std::nullopt,
        .user_agent = std::nullopt
    });

    auto confirmed = manager->confirmEmailChallenge({
        .challenge_id = challenge.challenge->id,
        .session_id = challenge.session->id,
        .session_token = challenge.session_token,
        .code = challenge.verification_code
    });
    ASSERT_TRUE(confirmed.verified);

    auto principal = manager->resolvePrincipal(challenge.session_token);
    ASSERT_NE(principal, nullptr);
    ASSERT_NE(principal->scoped_vault_role, nullptr);
    ASSERT_TRUE(principal->scoped_vault_role->assignment);
    EXPECT_EQ(principal->scoped_vault_role->assignment->subject_type, "actor");

    auto decision = manager->authorize(*principal, Operation::Download, "/reports/file.txt", TargetType::File);
    EXPECT_TRUE(decision.allowed);
}

TEST_F(ShareManagerTest, UpdateRecipientAssignmentsReplacesSetAndPreservesPublicAssignment) {
    const auto created = create(AccessMode::EmailValidated);
    const auto keptHash = EmailChallenge::hashEmail(EmailChallenge::normalizeEmail("recipient@example.com"));
    const auto removedHash = EmailChallenge::hashEmail(EmailChallenge::normalizeEmail("email@example.com"));
    const auto keptKey = created.link->id + ":" + db::encoding::to_hex_bytea(keptHash);
    const auto removedKey = created.link->id + ":" + db::encoding::to_hex_bytea(removedHash);

    ASSERT_TRUE(store->vault_roles.contains(created.link->id));
    ASSERT_TRUE(store->recipient_roles.contains(keptKey));
    ASSERT_TRUE(store->recipient_roles.contains(removedKey));

    auto update = std::make_shared<Link>(*created.link);
    const std::vector<RecipientRoleAssignmentRequest> replacementRecipients{
        RecipientRoleAssignmentRequest{
            .email = "recipient@example.com",
            .role = RoleAssignmentRequest{.vault_role_name = rbac::role::Vault::Reader().name}
        }
    };
    auto updated = manager->updateLink(humanActor(), {
        .link = update,
        .public_role = std::nullopt,
        .recipients = replacementRecipients
    });
    ASSERT_NE(updated, nullptr);

    ASSERT_TRUE(store->vault_roles.contains(created.link->id));
    ASSERT_TRUE(store->vault_roles.at(created.link->id)->assignment.has_value());
    EXPECT_EQ(store->vault_roles.at(created.link->id)->assignment->subject_type, "public");
    EXPECT_TRUE(store->recipient_roles.contains(keptKey));
    EXPECT_FALSE(store->recipient_roles.contains(removedKey));

    auto keptChallenge = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = created.public_token,
        .session_token = std::nullopt,
        .email = "recipient@example.com",
        .ip_address = std::nullopt,
        .user_agent = std::nullopt
    });
    auto keptConfirmed = manager->confirmEmailChallenge({
        .challenge_id = keptChallenge.challenge->id,
        .session_id = keptChallenge.session->id,
        .session_token = keptChallenge.session_token,
        .code = keptChallenge.verification_code
    });
    EXPECT_TRUE(keptConfirmed.verified);
    EXPECT_NO_THROW({ (void)manager->resolvePrincipal(keptChallenge.session_token); });

    auto removedChallenge = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = created.public_token,
        .session_token = std::nullopt,
        .email = "email@example.com",
        .ip_address = std::nullopt,
        .user_agent = std::nullopt
    });
    EXPECT_THROW({ (void)manager->confirmEmailChallenge(ConfirmEmailChallengeRequest{
        .challenge_id = removedChallenge.challenge->id,
        .session_id = removedChallenge.session->id,
        .session_token = removedChallenge.session_token,
        .code = removedChallenge.verification_code
    }); }, std::runtime_error);
    EXPECT_FALSE(removedChallenge.session->isVerified());
    EXPECT_FALSE(removedChallenge.challenge->consumed_at.has_value());
    EXPECT_THROW({ (void)manager->resolvePrincipal(removedChallenge.session_token); }, std::runtime_error);
}

TEST_F(ShareManagerTest, UnmatchedEmailRecipientFailsClosedBeforeVerification) {
    const auto created = create(AccessMode::EmailValidated);
    auto challenge = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = created.public_token,
        .session_token = std::nullopt,
        .email = "unmatched@example.com",
        .ip_address = std::nullopt,
        .user_agent = std::nullopt
    });

    EXPECT_THROW({ (void)manager->confirmEmailChallenge(ConfirmEmailChallengeRequest{
        .challenge_id = challenge.challenge->id,
        .session_id = challenge.session->id,
        .session_token = challenge.session_token,
        .code = challenge.verification_code
    }); }, std::runtime_error);
    EXPECT_FALSE(challenge.session->isVerified());
    EXPECT_FALSE(challenge.challenge->consumed_at.has_value());
    EXPECT_THROW({ (void)manager->resolvePrincipal(challenge.session_token); }, std::runtime_error);
}

TEST_F(ShareManagerTest, ConfirmEmailChallengeRequiresMatchingSessionTokenBeforeMutation) {
    const auto created = create(AccessMode::EmailValidated);
    auto challenge = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = created.public_token,
        .session_token = std::nullopt,
        .email = "recipient@example.com",
        .ip_address = std::nullopt,
        .user_agent = std::nullopt
    });

    EXPECT_THROW({ (void)manager->confirmEmailChallenge(ConfirmEmailChallengeRequest{
        .challenge_id = challenge.challenge->id,
        .session_id = challenge.session->id,
        .session_token = "",
        .code = challenge.verification_code
    }); }, std::invalid_argument);
    EXPECT_FALSE(challenge.session->isVerified());
    EXPECT_FALSE(challenge.challenge->consumed_at.has_value());
    EXPECT_EQ(challenge.challenge->attempts, 0u);

    try {
        (void)manager->confirmEmailChallenge(ConfirmEmailChallengeRequest{
            .challenge_id = challenge.challenge->id,
            .session_id = challenge.session->id,
            .session_token = wrongSecret(challenge.session_token),
            .code = challenge.verification_code
        });
        FAIL() << "Expected wrong share session token to be rejected";
    } catch (const std::exception& ex) {
        const std::string message = ex.what();
        EXPECT_EQ(message.find(challenge.session_token), std::string::npos);
        EXPECT_EQ(message.find(challenge.verification_code), std::string::npos);
        EXPECT_EQ(message.find("recipient@example.com"), std::string::npos);
    }
    EXPECT_FALSE(challenge.session->isVerified());
    EXPECT_FALSE(challenge.challenge->consumed_at.has_value());
    EXPECT_EQ(challenge.challenge->attempts, 0u);

    const auto other = create(AccessMode::EmailValidated);
    auto otherChallenge = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = other.public_token,
        .session_token = std::nullopt,
        .email = "recipient@example.com",
        .ip_address = std::nullopt,
        .user_agent = std::nullopt
    });
    EXPECT_THROW({ (void)manager->confirmEmailChallenge(ConfirmEmailChallengeRequest{
        .challenge_id = challenge.challenge->id,
        .session_id = challenge.session->id,
        .session_token = otherChallenge.session_token,
        .code = challenge.verification_code
    }); }, std::runtime_error);
    EXPECT_FALSE(challenge.session->isVerified());
    EXPECT_FALSE(challenge.challenge->consumed_at.has_value());
    EXPECT_EQ(challenge.challenge->attempts, 0u);

    auto confirmed = manager->confirmEmailChallenge({
        .challenge_id = challenge.challenge->id,
        .session_id = challenge.session->id,
        .session_token = challenge.session_token,
        .code = challenge.verification_code
    });
    EXPECT_TRUE(confirmed.verified);
    EXPECT_TRUE(confirmed.session->isVerified());
}

TEST_F(ShareManagerTest, SessionTokenResolvesPrincipalAndRejectsInactiveSessions) {
    const auto created = create();
    auto opened = manager->openPublicSession(created.public_token);

    auto principal = manager->resolvePrincipal(opened.session_token);
    ASSERT_NE(principal, nullptr);
    EXPECT_EQ(principal->share_id, created.link->id);
    EXPECT_EQ(principal->share_session_id, opened.session->id);

    opened.session->expires_at = kManagerNow - 1;
    EXPECT_THROW({ (void)manager->resolvePrincipal(opened.session_token); }, std::runtime_error);

    opened.session->expires_at = kManagerNow + 600;
    opened.session->revoked_at = kManagerNow;
    EXPECT_THROW({ (void)manager->resolvePrincipal(opened.session_token); }, std::runtime_error);
}

TEST_F(ShareManagerTest, AuthorizeUsesScopeForOperationsAndContainment) {
    const auto created = create();
    auto opened = manager->openPublicSession(created.public_token);
    auto principal = manager->resolvePrincipal(opened.session_token);

    auto decision = manager->authorize(*principal, Operation::Download, "//reports//2026///summary.pdf", TargetType::File);
    EXPECT_TRUE(decision.allowed);
    EXPECT_EQ(decision.normalized_path, "/reports/2026/summary.pdf");

    decision = manager->authorize(*principal, Operation::Preview, "/reports/2026/summary.pdf", TargetType::File);
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "operation_not_granted");

    decision = manager->authorize(*principal, Operation::Download, "/reports/summary.pdf", TargetType::File, 999);
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "vault_mismatch");

    decision = manager->authorize(*principal, Operation::Download, "../reports/summary.pdf", TargetType::File);
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "path_escape");

    principal->root_path = "/shared";
    principal->grant.root_path = "/shared";
    decision = manager->authorize(*principal, Operation::Download, "/shared_evil/summary.pdf", TargetType::File);
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "outside_scope");
}

TEST_F(ShareManagerTest, ShareActorCannotUseManagementAuthorizationOrHumanPrivileges) {
    const auto created = create();
    auto opened = manager->openPublicSession(created.public_token);
    auto principal = manager->resolvePrincipal(opened.session_token);
    const auto shareActor = rbac::Actor::share(principal);

    EXPECT_FALSE(shareActor.canUseHumanPrivileges());
    EXPECT_EQ(shareActor.user(), nullptr);
    const CreateLinkRequest request{.link = makeManagerLink()};
    EXPECT_THROW({ (void)manager->createLink(shareActor, request); }, std::runtime_error);
    EXPECT_THROW({ (void)manager->listLinksForUser(shareActor, {}); }, std::runtime_error);
}

TEST_F(ShareManagerTest, UploadLifecycleRecordsBytesCompletesAndIncrementsCounter) {
    const auto created = create();
    auto opened = manager->openPublicSession(created.public_token);
    auto principal = manager->resolvePrincipal(opened.session_token);

    auto started = manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/new.txt",
        .original_filename = "new.txt",
        .resolved_filename = "new.txt",
        .expected_size_bytes = 11,
        .mime_type = "text/plain"
    });

    ASSERT_NE(started.upload, nullptr);
    EXPECT_EQ(started.upload->status, UploadStatus::Pending);
    EXPECT_EQ(started.upload->target_path, "/reports/new.txt");
    EXPECT_EQ(started.max_chunk_size_bytes, 256u * 1024u);

    manager->recordUploadChunk(*principal, started.upload->id, 5);
    manager->recordUploadChunk(*principal, started.upload->id, 6);
    EXPECT_EQ(store->getUpload(started.upload->id)->received_size_bytes, 11u);
    EXPECT_EQ(store->getUpload(started.upload->id)->status, UploadStatus::Receiving);
    EXPECT_THROW({ manager->recordUploadChunk(*principal, started.upload->id, 1); }, std::runtime_error);

    manager->finishUpload({
        .principal = *principal,
        .upload_id = started.upload->id,
        .created_entry_id = 88,
        .content_hash = "safe-created-content-hash",
        .mime_type = "text/plain"
    });

    const auto upload = store->getUpload(started.upload->id);
    EXPECT_EQ(upload->status, UploadStatus::Complete);
    EXPECT_EQ(upload->created_entry_id, 88u);
    EXPECT_EQ(created.link->upload_count, 1u);
}

TEST_F(ShareManagerTest, UploadStartFailsForMissingGrantFileTargetAndInactiveState) {
    auto noUpload = makeManagerLink();
    noUpload.allowed_ops = bit(Operation::Metadata);
    const auto createdNoUpload = manager->createLink(humanActor(), {.link = noUpload});
    auto openedNoUpload = manager->openPublicSession(createdNoUpload.public_token);
    auto principalNoUpload = manager->resolvePrincipal(openedNoUpload.session_token);
    EXPECT_THROW({ (void)manager->startUpload({
        .principal = *principalNoUpload,
        .target_parent_entry_id = 77,
        .target_path = "/reports/new.txt",
        .original_filename = "new.txt",
        .resolved_filename = "new.txt",
        .expected_size_bytes = 1
    }); }, std::runtime_error);

    auto fileTarget = makeManagerLink();
    fileTarget.target_type = TargetType::File;
    fileTarget.allowed_ops = bit(Operation::Upload);
    const auto createdFileTarget = manager->createLink(humanActor(), {.link = fileTarget});
    auto openedFileTarget = manager->openPublicSession(createdFileTarget.public_token);
    auto principalFileTarget = manager->resolvePrincipal(openedFileTarget.session_token);
    EXPECT_THROW({ (void)manager->startUpload({
        .principal = *principalFileTarget,
        .target_parent_entry_id = 77,
        .target_path = "/reports/new.txt",
        .original_filename = "new.txt",
        .resolved_filename = "new.txt",
        .expected_size_bytes = 1
    }); }, std::runtime_error);

    createdFileTarget.link->revoked_at = kManagerNow;
    EXPECT_THROW({ (void)manager->startUpload({
        .principal = *principalFileTarget,
        .target_parent_entry_id = 77,
        .target_path = "/reports/new.txt",
        .original_filename = "new.txt",
        .resolved_filename = "new.txt",
        .expected_size_bytes = 1
    }); }, std::runtime_error);
}

TEST_F(ShareManagerTest, UploadStartEnforcesSizeCountTotalMimeAndExtensionLimits) {
    auto limited = makeManagerLink();
    limited.max_upload_size_bytes = 10;
    limited.max_upload_files = 1;
    limited.max_upload_total_bytes = 20;
    limited.allowed_mime_types = {"text/plain"};
    limited.blocked_extensions = {".exe"};
    const auto created = manager->createLink(humanActor(), {.link = limited});
    auto opened = manager->openPublicSession(created.public_token);
    auto principal = manager->resolvePrincipal(opened.session_token);

    EXPECT_THROW({ (void)manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/large.txt",
        .original_filename = "large.txt",
        .resolved_filename = "large.txt",
        .expected_size_bytes = 11,
        .mime_type = "text/plain"
    }); }, std::runtime_error);

    EXPECT_THROW({ (void)manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/new.exe",
        .original_filename = "new.exe",
        .resolved_filename = "new.exe",
        .expected_size_bytes = 1,
        .mime_type = "text/plain"
    }); }, std::runtime_error);

    EXPECT_THROW({ (void)manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/new.txt",
        .original_filename = "new.txt",
        .resolved_filename = "new.txt",
        .expected_size_bytes = 1,
        .mime_type = "application/pdf"
    }); }, std::runtime_error);

    auto started = manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/ok.txt",
        .original_filename = "ok.txt",
        .resolved_filename = "ok.txt",
        .expected_size_bytes = 10,
        .mime_type = "text/plain"
    });
    manager->recordUploadChunk(*principal, started.upload->id, 10);
    manager->finishUpload({
        .principal = *principal,
        .upload_id = started.upload->id,
        .created_entry_id = 90,
        .content_hash = "hash",
        .mime_type = "text/plain"
    });

    EXPECT_THROW({ (void)manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/second.txt",
        .original_filename = "second.txt",
        .resolved_filename = "second.txt",
        .expected_size_bytes = 1,
        .mime_type = "text/plain"
    }); }, std::runtime_error);
}

TEST_F(ShareManagerTest, UploadCancelAndFailRecordTerminalStatusWithoutLeakingSecrets) {
    const auto created = create();
    auto opened = manager->openPublicSession(created.public_token);
    auto principal = manager->resolvePrincipal(opened.session_token);

    auto cancelled = manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/cancel.txt",
        .original_filename = "cancel.txt",
        .resolved_filename = "cancel.txt",
        .expected_size_bytes = 4,
        .mime_type = "text/plain"
    });
    manager->cancelUpload(*principal, cancelled.upload->id);
    EXPECT_EQ(store->getUpload(cancelled.upload->id)->status, UploadStatus::Cancelled);

    auto failed = manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/fail.txt",
        .original_filename = "fail.txt",
        .resolved_filename = "fail.txt",
        .expected_size_bytes = 4,
        .mime_type = "text/plain"
    });
    manager->failUpload(*principal, failed.upload->id, "write_failed");
    EXPECT_EQ(store->getUpload(failed.upload->id)->status, UploadStatus::Failed);
    EXPECT_EQ(store->getUpload(failed.upload->id)->error, "write_failed");
    EXPECT_FALSE(store->getUpload(failed.upload->id)->tmp_path.has_value());
}

TEST_F(ShareManagerTest, SweepStaleUploadsFailsOnlyOldActiveRecords) {
    const auto created = create();
    auto opened = manager->openPublicSession(created.public_token);
    auto principal = manager->resolvePrincipal(opened.session_token);

    auto stalePending = manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/stale-pending.txt",
        .original_filename = "stale-pending.txt",
        .resolved_filename = "stale-pending.txt",
        .expected_size_bytes = 4,
        .mime_type = "text/plain"
    });
    auto staleReceiving = manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/stale-receiving.txt",
        .original_filename = "stale-receiving.txt",
        .resolved_filename = "stale-receiving.txt",
        .expected_size_bytes = 4,
        .mime_type = "text/plain"
    });
    auto fresh = manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/fresh.txt",
        .original_filename = "fresh.txt",
        .resolved_filename = "fresh.txt",
        .expected_size_bytes = 4,
        .mime_type = "text/plain"
    });
    auto completed = manager->startUpload({
        .principal = *principal,
        .target_parent_entry_id = 77,
        .target_path = "/reports/complete.txt",
        .original_filename = "complete.txt",
        .resolved_filename = "complete.txt",
        .expected_size_bytes = 4,
        .mime_type = "text/plain"
    });

    manager->recordUploadChunk(*principal, staleReceiving.upload->id, 1);
    manager->recordUploadChunk(*principal, completed.upload->id, 4);
    manager->finishUpload({
        .principal = *principal,
        .upload_id = completed.upload->id,
        .created_entry_id = 101,
        .content_hash = "complete-hash",
        .mime_type = "text/plain"
    });

    store->getUpload(stalePending.upload->id)->started_at = kManagerNow - 7200;
    store->getUpload(staleReceiving.upload->id)->started_at = kManagerNow - 7200;

    const auto result = manager->sweepStaleUploads({.older_than_seconds = 3600, .limit = 10});
    EXPECT_EQ(result.scanned, 2u);
    EXPECT_EQ(result.failed, 2u);
    EXPECT_EQ(store->getUpload(stalePending.upload->id)->status, UploadStatus::Failed);
    EXPECT_EQ(store->getUpload(staleReceiving.upload->id)->status, UploadStatus::Failed);
    EXPECT_EQ(store->getUpload(stalePending.upload->id)->error, "stale_upload_sweep");
    EXPECT_EQ(store->getUpload(fresh.upload->id)->status, UploadStatus::Pending);
    EXPECT_EQ(store->getUpload(completed.upload->id)->status, UploadStatus::Complete);

    const auto second = manager->sweepStaleUploads({.older_than_seconds = 3600, .limit = 10});
    EXPECT_EQ(second.failed, 0u);
}

// ── sharing.* switches (#164) ─────────────────────────────────────────────────────────────────────────────────

namespace vh::share::test_manager {
// Swaps config::Registry's sharing section for one test and puts the previous config back.
struct SharingSwitches {
    config::Config previous = config::Registry::get();
    explicit SharingSwitches(const std::function<void(config::SharingConfig&)>& edit) {
        auto next = previous;
        edit(next.sharing);
        config::Registry::set(next);
    }
    ~SharingSwitches() { config::Registry::set(previous); }
};
}

TEST_F(ShareManagerTest, SharingDisabledRefusesCreateOpenAndUseButNotManagement) {
    const auto created = create();
    const auto opened = manager->openPublicSession(created.public_token);
    {
        SharingSwitches off([](auto& s) { s.enabled = false; });
        EXPECT_THROW({ (void)create(); }, ops::Denied);
        EXPECT_THROW({ (void)create(AccessMode::EmailValidated); }, ops::Denied);
        EXPECT_THROW({ (void)manager->resolvePublicLink(created.public_token); }, ops::Denied);
        EXPECT_THROW({ (void)manager->openPublicSession(created.public_token); }, ops::Denied);
        EXPECT_THROW({ (void)manager->resolvePrincipal(opened.session_token); }, ops::Denied);
        ASSERT_FALSE(store->audits.empty());
        EXPECT_EQ(store->audits.back()->status, AuditStatus::Denied);
        // Links can still be found and cleaned up.
        EXPECT_NO_THROW({ (void)manager->getLinkForManagement(humanActor(), created.link->id); });
    }
    // Turning it back on restores the existing link and session.
    EXPECT_NO_THROW({ (void)manager->resolvePrincipal(opened.session_token); });
    EXPECT_EQ(store->links.size(), 1u);
}

TEST_F(ShareManagerTest, AnonymousSwitchGatesOnlyPublicLinks) {
    const auto publicLink = create();
    const auto publicSession = manager->openPublicSession(publicLink.public_token);
    SharingSwitches off([](auto& s) { s.enable_anonymous = false; });

    EXPECT_THROW({ (void)create(); }, ops::Denied);
    EXPECT_THROW({ (void)manager->openPublicSession(publicLink.public_token); }, ops::Denied);
    EXPECT_THROW({ (void)manager->resolvePrincipal(publicSession.session_token); }, ops::Denied);

    const auto emailLink = create(AccessMode::EmailValidated);
    const auto pending = manager->openPublicSession(emailLink.public_token);
    EXPECT_EQ(pending.status, OpenSessionStatus::EmailRequired);
}

TEST_F(ShareManagerTest, EmailValidatedSwitchGatesOnlyEmailLinks) {
    const auto emailLink = create(AccessMode::EmailValidated);
    auto challenge = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = emailLink.public_token,
        .session_token = std::nullopt,
        .email = "recipient@example.com",
        .ip_address = std::nullopt,
        .user_agent = std::nullopt
    });
    SharingSwitches off([](auto& s) { s.enable_email_validated = false; });

    EXPECT_THROW({ (void)create(AccessMode::EmailValidated); }, ops::Denied);
    EXPECT_THROW({ (void)manager->openPublicSession(emailLink.public_token); }, ops::Denied);
    EXPECT_THROW({ (void)manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = std::nullopt,
        .session_token = challenge.session_token,
        .email = "recipient@example.com",
        .ip_address = std::nullopt,
        .user_agent = std::nullopt
    }); }, ops::Denied);
    EXPECT_THROW({ (void)manager->confirmEmailChallenge({
        .challenge_id = challenge.challenge->id,
        .session_id = challenge.session->id,
        .session_token = challenge.session_token,
        .code = challenge.verification_code
    }); }, ops::Denied);
    EXPECT_FALSE(challenge.challenge->consumed_at.has_value());

    EXPECT_NO_THROW({ (void)create(); });
}

TEST_F(ShareManagerTest, UpdateCannotMoveALinkIntoADisabledKind) {
    const auto created = create();
    SharingSwitches off([](auto& s) { s.enable_email_validated = false; });

    auto changed = std::make_shared<Link>(*created.link);
    changed->access_mode = AccessMode::EmailValidated;
    EXPECT_THROW({ (void)manager->updateLink(humanActor(), {.link = changed, .public_role = std::nullopt, .recipients = std::nullopt}); }, ops::Denied);
    EXPECT_EQ(store->getLink(created.link->id)->access_mode, AccessMode::Public);

    auto renamed = std::make_shared<Link>(*created.link);
    renamed->name = "still public";
    EXPECT_NO_THROW({ (void)manager->updateLink(humanActor(), {.link = renamed, .public_role = std::nullopt, .recipients = std::nullopt}); });
}

TEST(SharePolicy, RefusalNamesTheSwitchThatIsOff) {
    config::SharingConfig sharing;
    EXPECT_FALSE(policy::refusal(sharing));
    EXPECT_FALSE(policy::refusal(sharing, AccessMode::Public));
    EXPECT_FALSE(policy::refusal(sharing, AccessMode::EmailValidated));

    sharing.enable_anonymous = false;
    EXPECT_EQ(policy::refusal(sharing, AccessMode::Public), "Anonymous share links are disabled on this server");
    EXPECT_FALSE(policy::refusal(sharing, AccessMode::EmailValidated));

    sharing.enable_anonymous = true;
    sharing.enable_email_validated = false;
    EXPECT_EQ(policy::refusal(sharing, AccessMode::EmailValidated),
              "Email-verified share links are disabled on this server");

    sharing.enable_email_validated = true;
    EXPECT_FALSE(policy::refusal(sharing, AccessMode::Public));

    sharing.enabled = false;
    EXPECT_EQ(policy::refusal(sharing), "Sharing is disabled on this server");
    EXPECT_EQ(policy::refusal(sharing, AccessMode::Public), "Sharing is disabled on this server");
}
