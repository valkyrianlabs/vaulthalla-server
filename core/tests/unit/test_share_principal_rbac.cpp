#include "identities/User.hpp"
#include "rbac/Actor.hpp"
#include "rbac/fs/policy/Share.hpp"
#include "share/Link.hpp"
#include "share/PrincipalResolver.hpp"
#include "share/Scope.hpp"
#include "share/Session.hpp"
#include "share/Types.hpp"

#include <gtest/gtest.h>

#include <ctime>
#include <memory>
#include <stdexcept>
#include <typeindex>

using namespace vh::share;

namespace {

constexpr std::time_t kNow = 1'800'000'000;

Link makeLink() {
    Link link;
    link.id = "00000000-0000-4000-8000-000000000101";
    link.token_lookup_id = "00000000-0000-4000-8000-000000000102";
    link.created_by = 1;
    link.vault_id = 42;
    link.root_entry_id = 77;
    link.root_path = "/reports";
    link.target_type = TargetType::Directory;
    link.link_type = LinkType::Access;
    link.access_mode = AccessMode::Public;
    link.allowed_ops = bit(Operation::Metadata) |
                       bit(Operation::List) |
                       bit(Operation::Download) |
                       bit(Operation::Upload) |
                       bit(Operation::Mkdir);
    link.created_at = kNow - 60;
    link.updated_at = kNow - 60;
    link.expires_at = kNow + 3600;
    return link;
}

vh::share::Session makeSession(const std::string& shareId) {
    vh::share::Session session;
    session.id = "00000000-0000-4000-8000-000000000201";
    session.share_id = shareId;
    session.session_token_lookup_id = "00000000-0000-4000-8000-000000000202";
    session.created_at = kNow - 60;
    session.last_seen_at = kNow - 30;
    session.expires_at = kNow + 1800;
    session.ip_address = "203.0.113.10";
    session.user_agent = "share-test";
    return session;
}

std::shared_ptr<Principal> makePrincipal() {
    auto link = makeLink();
    auto session = makeSession(link.id);
    return PrincipalResolver::resolve(link, session, kNow);
}

}

TEST(SharePrincipalRbacTest, ResolvesActivePublicShareSession) {
    auto link = makeLink();
    auto session = makeSession(link.id);

    const auto principal = PrincipalResolver::resolve(link, session, kNow);

    ASSERT_NE(principal, nullptr);
    EXPECT_EQ(principal->share_id, link.id);
    EXPECT_EQ(principal->share_session_id, session.id);
    EXPECT_EQ(principal->vault_id, link.vault_id);
    EXPECT_EQ(principal->root_entry_id, link.root_entry_id);
    EXPECT_EQ(principal->root_path, "/reports");
    EXPECT_TRUE(principal->allows(Operation::Download));
    EXPECT_FALSE(principal->email_verified);
    EXPECT_EQ(principal->expires_at, session.expires_at);
    EXPECT_TRUE(principal->isActive(kNow));
}

TEST(SharePrincipalRbacTest, ResolvesVerifiedEmailValidatedShareSession) {
    auto link = makeLink();
    link.access_mode = AccessMode::EmailValidated;
    link.expires_at = kNow + 900;

    auto session = makeSession(link.id);
    session.verified_at = kNow - 10;
    session.expires_at = kNow + 1800;

    const auto principal = PrincipalResolver::resolve(link, session, kNow);

    ASSERT_NE(principal, nullptr);
    EXPECT_TRUE(principal->email_verified);
    EXPECT_EQ(principal->expires_at, *link.expires_at);
}

TEST(SharePrincipalRbacTest, RejectsUnverifiedEmailValidatedSession) {
    auto link = makeLink();
    link.access_mode = AccessMode::EmailValidated;
    auto session = makeSession(link.id);

    EXPECT_THROW(PrincipalResolver::resolve(link, session, kNow), std::runtime_error);
}

TEST(SharePrincipalRbacTest, RejectsInactiveSharesAndSessions) {
    auto link = makeLink();
    auto session = makeSession(link.id);

    auto expiredLink = link;
    expiredLink.expires_at = kNow;
    EXPECT_THROW(PrincipalResolver::resolve(expiredLink, session, kNow), std::runtime_error);

    auto revokedLink = link;
    revokedLink.revoked_at = kNow - 1;
    EXPECT_THROW(PrincipalResolver::resolve(revokedLink, session, kNow), std::runtime_error);

    auto disabledLink = link;
    disabledLink.disabled_at = kNow - 1;
    EXPECT_THROW(PrincipalResolver::resolve(disabledLink, session, kNow), std::runtime_error);

    auto expiredSession = session;
    expiredSession.expires_at = kNow;
    EXPECT_THROW(PrincipalResolver::resolve(link, expiredSession, kNow), std::runtime_error);

    auto revokedSession = session;
    revokedSession.revoked_at = kNow - 1;
    EXPECT_THROW(PrincipalResolver::resolve(link, revokedSession, kNow), std::runtime_error);
}

TEST(SharePrincipalRbacTest, RejectsSessionForDifferentShare) {
    auto link = makeLink();
    auto session = makeSession("00000000-0000-4000-8000-000000000999");

    EXPECT_THROW(PrincipalResolver::resolve(link, session, kNow), std::runtime_error);
}

TEST(SharePrincipalRbacTest, AuthorizesAllowedOperationsInsideScope) {
    const auto principal = makePrincipal();

    auto decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports/2026/summary.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File
    });

    EXPECT_TRUE(decision.allowed);
    EXPECT_EQ(decision.reason, "allowed");
    EXPECT_EQ(decision.normalized_path, "/reports/2026/summary.pdf");

    decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "reports/2026",
        .operation = Operation::List,
        .target_type = TargetType::Directory
    });

    EXPECT_TRUE(decision.allowed);
    EXPECT_EQ(decision.normalized_path, "/reports/2026");

    decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports",
        .operation = Operation::Metadata,
        .target_type = TargetType::Directory
    });

    EXPECT_TRUE(decision.allowed);
    EXPECT_EQ(decision.normalized_path, "/reports");
}

TEST(SharePrincipalRbacTest, DeniesMissingOperationAndVaultMismatch) {
    auto principal = makePrincipal();

    auto decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports/2026/summary.pdf",
        .operation = Operation::Preview,
        .target_type = TargetType::File
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "operation_not_granted");

    decision = Scope::authorize(*principal, {
        .vault_id = 43,
        .path = "/reports/2026/summary.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "vault_mismatch");
}

TEST(SharePrincipalRbacTest, AuthorizesNormalizedDescendantPath) {
    const auto principal = makePrincipal();

    const auto decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "//reports//2026///summary.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File
    });

    EXPECT_TRUE(decision.allowed);
    EXPECT_EQ(decision.reason, "allowed");
    EXPECT_EQ(decision.normalized_path, "/reports/2026/summary.pdf");
}

TEST(SharePrincipalRbacTest, DeniesPathEscapeAndSiblingPrefix) {
    const auto principal = makePrincipal();

    auto decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports/../secret.txt",
        .operation = Operation::Download,
        .target_type = TargetType::File
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "outside_scope");
    EXPECT_EQ(decision.normalized_path, "/secret.txt");

    decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "../reports/summary.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "path_escape");

    decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports2/summary.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "outside_scope");

    auto sharedRoot = makePrincipal();
    sharedRoot->root_path = "/shared";
    sharedRoot->grant.root_path = "/shared";

    decision = Scope::authorize(*sharedRoot, {
        .vault_id = 42,
        .path = "/shared_evil/summary.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "outside_scope");

    decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/",
        .operation = Operation::List,
        .target_type = TargetType::Directory
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "outside_scope");
}

TEST(SharePrincipalRbacTest, EnforcesUploadOverwriteAndMkdirGrantRules) {
    auto principal = makePrincipal();

    auto decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports/new.pdf",
        .operation = Operation::Upload,
        .target_type = TargetType::File
    });
    EXPECT_TRUE(decision.allowed);

    decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports/new.pdf",
        .operation = Operation::Overwrite,
        .target_type = TargetType::File
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "operation_not_granted");

    decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports/new-dir",
        .operation = Operation::Mkdir,
        .target_type = TargetType::Directory
    });
    EXPECT_TRUE(decision.allowed);

    decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports/not-a-dir",
        .operation = Operation::Mkdir,
        .target_type = TargetType::File
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "invalid_mkdir_target");
}

TEST(SharePrincipalRbacTest, ReadOperationsRequireMatchingGrantBits) {
    auto principal = makePrincipal();

    auto decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports/2026/summary.pdf",
        .operation = Operation::Preview,
        .target_type = TargetType::File
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "operation_not_granted");

    principal->grant.allowed_ops |= bit(Operation::Preview);
    decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports/2026/summary.pdf",
        .operation = Operation::Preview,
        .target_type = TargetType::File
    });
    EXPECT_TRUE(decision.allowed);

    principal->grant.allowed_ops &= ~bit(Operation::List);
    decision = Scope::authorize(*principal, {
        .vault_id = 42,
        .path = "/reports/2026",
        .operation = Operation::List,
        .target_type = TargetType::Directory
    });
    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(decision.reason, "operation_not_granted");
}

TEST(SharePrincipalRbacTest, ShareActorDoesNotInheritHumanPrivileges) {
    const auto principal = makePrincipal();
    const auto actor = vh::rbac::Actor::share(principal);

    EXPECT_TRUE(actor.isShare());
    EXPECT_FALSE(actor.isHuman());
    EXPECT_FALSE(actor.canUseHumanPrivileges());
    EXPECT_EQ(actor.user(), nullptr);
    EXPECT_EQ(actor.sharePrincipal(), principal);

    vh::identities::UserState userState;
    userState.name = "human";
    auto user = vh::identities::User::detached(123, std::move(userState));

    const auto human = vh::rbac::Actor::human(user);
    EXPECT_TRUE(human.isHuman());
    EXPECT_FALSE(human.isShare());
    EXPECT_TRUE(human.canUseHumanPrivileges());
    EXPECT_EQ(human.user(), user);
    EXPECT_EQ(human.sharePrincipal(), nullptr);

    EXPECT_THROW(vh::rbac::Actor::share(nullptr), std::invalid_argument);
    EXPECT_THROW(vh::rbac::Actor::human(nullptr), std::invalid_argument);
}

TEST(SharePrincipalRbacTest, ShareGrantHasNoDeleteRenameMoveOrCopyOperation) {
    EXPECT_THROW({ (void)operation_from_string("delete"); }, std::invalid_argument);
    EXPECT_THROW({ (void)operation_from_string("rename"); }, std::invalid_argument);
    EXPECT_THROW({ (void)operation_from_string("move"); }, std::invalid_argument);
    EXPECT_THROW({ (void)operation_from_string("copy"); }, std::invalid_argument);
}

TEST(SharePrincipalRbacTest, EffectiveShareVaultRoleIsInMemoryAndImplicitDenyBased) {
    const auto principal = makePrincipal();

    const auto role = vh::rbac::fs::policy::Share::effectiveVaultRole(*principal, Operation::Download);

    ASSERT_TRUE(role.assignment.has_value());
    EXPECT_EQ(role.assignment->subject_type, "share");
    EXPECT_EQ(role.assignment->vault_id, principal->vault_id);
    EXPECT_EQ(role.assignment->subject_id, principal->root_entry_id);
    EXPECT_FALSE(role.fs.files.canDownload());
    EXPECT_FALSE(role.fs.directories.canDownload());
    EXPECT_FALSE(role.fs.overrides.empty());
    for (const auto& override : role.fs.overrides) {
        EXPECT_NE(override.permission.enumType, std::type_index(typeid(void)));
        EXPECT_NE(override.permission.rawValue, 0u);
        EXPECT_FALSE(override.permission.qualified_name.empty());
        EXPECT_FALSE(override.permission.description.empty());
    }
}

TEST(SharePrincipalRbacTest, RbacSharePolicyAllowsScopedGrantedOperation) {
    const auto principal = makePrincipal();
    const auto actor = vh::rbac::Actor::share(principal);

    auto decision = vh::rbac::fs::policy::Share::evaluate(actor, {
        .vault_id = 42,
        .vault_path = "/reports/2026/summary.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File,
        .target_exists = true
    });
    EXPECT_TRUE(decision.allowed);

    decision = vh::rbac::fs::policy::Share::evaluate(actor, {
        .vault_id = 42,
        .vault_path = "/reports",
        .operation = Operation::List,
        .target_type = TargetType::Directory,
        .target_exists = true
    });
    EXPECT_TRUE(decision.allowed);
}

TEST(SharePrincipalRbacTest, RbacSharePolicyDeniesOutsideRootAndPrefixTricks) {
    const auto principal = makePrincipal();

    auto decision = vh::rbac::fs::policy::Share::evaluate(*principal, {
        .vault_id = 42,
        .vault_path = "/secret/summary.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File,
        .target_exists = true
    });
    EXPECT_FALSE(decision.allowed);

    auto sharedRoot = *principal;
    sharedRoot.root_path = "/shared";
    sharedRoot.grant.root_path = "/shared";

    decision = vh::rbac::fs::policy::Share::evaluate(sharedRoot, {
        .vault_id = 42,
        .vault_path = "/shared_evil/summary.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File,
        .target_exists = true
    });
    EXPECT_FALSE(decision.allowed);
}

TEST(SharePrincipalRbacTest, RbacSharePolicyDoesNotLetMetadataGrantPreview) {
    auto principal = makePrincipal();
    principal->grant.allowed_ops = bit(Operation::Metadata);

    auto decision = vh::rbac::fs::policy::Share::evaluate(*principal, {
        .vault_id = 42,
        .vault_path = "/reports/summary.pdf",
        .operation = Operation::Metadata,
        .target_type = TargetType::File,
        .target_exists = true
    });
    EXPECT_TRUE(decision.allowed);

    decision = vh::rbac::fs::policy::Share::evaluate(*principal, {
        .vault_id = 42,
        .vault_path = "/reports/summary.pdf",
        .operation = Operation::Preview,
        .target_type = TargetType::File,
        .target_exists = true
    });
    EXPECT_FALSE(decision.allowed);
}

TEST(SharePrincipalRbacTest, RbacSharePolicyKeepsUploadIndependentFromReadOperations) {
    auto principal = makePrincipal();
    principal->grant.allowed_ops = bit(Operation::Upload);

    auto decision = vh::rbac::fs::policy::Share::evaluate(*principal, {
        .vault_id = 42,
        .vault_path = "/reports/incoming/new.pdf",
        .operation = Operation::Upload,
        .target_type = TargetType::File,
        .target_exists = false
    });
    EXPECT_TRUE(decision.allowed);

    decision = vh::rbac::fs::policy::Share::evaluate(*principal, {
        .vault_id = 42,
        .vault_path = "/reports/incoming",
        .operation = Operation::List,
        .target_type = TargetType::Directory,
        .target_exists = true
    });
    EXPECT_FALSE(decision.allowed);

    decision = vh::rbac::fs::policy::Share::evaluate(*principal, {
        .vault_id = 42,
        .vault_path = "/reports/incoming/new.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File,
        .target_exists = true
    });
    EXPECT_FALSE(decision.allowed);
}

TEST(SharePrincipalRbacTest, RbacSharePolicyKeepsOverwriteDeferred) {
    auto principal = makePrincipal();
    principal->grant.allowed_ops |= bit(Operation::Overwrite);

    const auto decision = vh::rbac::fs::policy::Share::evaluate(*principal, {
        .vault_id = 42,
        .vault_path = "/reports/summary.pdf",
        .operation = Operation::Overwrite,
        .target_type = TargetType::File,
        .target_exists = true
    });
    EXPECT_FALSE(decision.allowed);
}

TEST(SharePrincipalRbacTest, RbacSharePolicyRejectsHumanActors) {
    vh::identities::UserState userState;
    userState.name = "human";
    auto user = vh::identities::User::detached(123, std::move(userState));

    const auto actor = vh::rbac::Actor::human(user);
    const auto decision = vh::rbac::fs::policy::Share::evaluate(actor, {
        .vault_id = 42,
        .vault_path = "/reports/summary.pdf",
        .operation = Operation::Download,
        .target_type = TargetType::File,
        .target_exists = true
    });

    EXPECT_FALSE(decision.allowed);
}
