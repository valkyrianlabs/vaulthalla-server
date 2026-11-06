#include "../helpers/share_fakes.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
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

#include <functional>
#include <memory>
#include <stdexcept>

using namespace vh;
using namespace vh::share;

namespace vh::share::test_manager {
using vh::test::shares::RecordingCodeSender;
constexpr std::time_t kManagerNow = vh::test::shares::kNow;

Link makeManagerLink(const AccessMode mode = AccessMode::Public) {
    auto link = vh::test::shares::makeLink(
        bit(Operation::Metadata) | bit(Operation::List) | bit(Operation::Download) | bit(Operation::Upload) |
            bit(Operation::Mkdir),
        mode
    );
    link.metadata = R"({"test":true})";
    return link;
}

class ShareManagerTest : public vh::test::shares::Harness {
protected:
    std::shared_ptr<RecordingCodeSender> sender = std::make_shared<RecordingCodeSender>();

    void SetUp() override {
        startManager({.challenge_ttl_seconds = 300, .challenge_max_attempts = 3, .challenge_code_sender = sender});
    }

    [[nodiscard]] rbac::Actor humanActor() const { return rbac::Actor::human(user); }

    [[nodiscard]] CreateLinkResult create(
        const AccessMode mode = AccessMode::Public,
        const std::string& roleName = rbac::role::Vault::Reader().name
    ) {
        return manager->createLink(humanActor(), vh::test::shares::linkRequest(makeManagerLink(mode), roleName));
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
    EXPECT_EQ(result.public_url_path, "/share#" + result.public_token);
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

// #317: codes were generated and returned internally but never sent, so email-validated links could not be opened.
TEST_F(ShareManagerTest, EmailChallengeSendsTheCodeToTheListedRecipientOnly) {
    const auto created = create(AccessMode::EmailValidated);
    const auto listed = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = created.public_token, .session_token = std::nullopt, .email = " Recipient@Example.COM ",
        .ip_address = "127.0.0.1", .user_agent = "test"});
    ASSERT_EQ(sender->sent.size(), 1u);
    EXPECT_EQ(sender->sent.front().to, "recipient@example.com");
    EXPECT_EQ(sender->sent.front().code, listed.verification_code);
    EXPECT_EQ(sender->sent.front().challenge_id, listed.challenge->id);
    EXPECT_EQ(sender->sent.front().expires_at, kManagerNow + 300);

    // The code that was mailed opens the session.
    const auto confirmed = manager->confirmEmailChallenge({
        .challenge_id = listed.challenge->id, .session_id = listed.session->id,
        .session_token = listed.session_token, .code = sender->sent.front().code});
    EXPECT_TRUE(confirmed.verified);

    // An address the link doesn't name gets the same kind of result and no email.
    const auto stranger = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = created.public_token, .session_token = std::nullopt, .email = "stranger@example.com",
        .ip_address = "127.0.0.1", .user_agent = "test"});
    ASSERT_NE(stranger.challenge, nullptr);
    ASSERT_NE(stranger.session, nullptr);
    EXPECT_EQ(sender->sent.size(), 1u) << "no email to an address the link doesn't name";
    EXPECT_EQ(store->audits.back()->error_code.value_or(""), "share_email_recipient_not_listed");
}

TEST_F(ShareManagerTest, EmailValidatedLinksNeedEmailDelivery) {
    sender->canSend = false;
    try {
        (void)create(AccessMode::EmailValidated);
        FAIL() << "created an email-validated link that could never be opened";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, kShareEmailUnavailableCode);
    }
    EXPECT_NO_THROW((void)create(AccessMode::Public)) << "other links don't need email";

    // A link created while email worked: its challenge is refused with the same clear error, nothing is created.
    sender->canSend = true;
    const auto created = create(AccessMode::EmailValidated);
    sender->canSend = false;
    const auto challengesBefore = store->challenges.size();
    try {
        (void)manager->startEmailChallenge(StartEmailChallengeRequest{
            .public_token = created.public_token, .session_token = std::nullopt, .email = "recipient@example.com",
            .ip_address = std::nullopt, .user_agent = std::nullopt});
        FAIL() << "started a challenge whose code can't be delivered";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, kShareEmailUnavailableCode);
    }
    EXPECT_EQ(store->challenges.size(), challengesBefore);
    EXPECT_TRUE(sender->sent.empty());
}

TEST_F(ShareManagerTest, AFailedSendIsAuditedNotReported) {
    const auto created = create(AccessMode::EmailValidated);
    sender->failSends = true;
    const auto result = manager->startEmailChallenge(StartEmailChallengeRequest{
        .public_token = created.public_token, .session_token = std::nullopt, .email = "recipient@example.com",
        .ip_address = std::nullopt, .user_agent = std::nullopt});
    ASSERT_NE(result.challenge, nullptr) << "the reply must not differ for listed recipients";
    EXPECT_EQ(store->audits.back()->error_code.value_or(""), "share_email_delivery_failed");
}

TEST(ShareCodeEmail, CarriesTheCodeAndNothingAboutTheShare) {
    const ChallengeCodeMessage message{.to = "r@example.com", .code = "042917", .expires_at = 1000 + 900, .challenge_id = "c1"};
    const auto email = renderChallengeCodeEmail(message, 1000);
    EXPECT_NE(email.text.find("042917"), std::string::npos);
    EXPECT_NE(email.html.find("042917"), std::string::npos);
    EXPECT_NE(email.text.find("15 minutes"), std::string::npos);
    EXPECT_EQ(email.subject.find("042917"), std::string::npos) << "keep the code out of subject lines (notifications)";
    EXPECT_THROW((void)renderChallengeCodeEmail({.to = "r@example.com", .code = "<b>1</b>", .expires_at = 0, .challenge_id = "c"}, 0),
                 std::invalid_argument);
}

