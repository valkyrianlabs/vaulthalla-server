// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "db/query/share/AuditEvent.hpp"
#include "db/query/share/EmailChallenge.hpp"
#include "db/query/share/Link.hpp"
#include "db/query/share/Session.hpp"
#include "db/query/share/Upload.hpp"
#include "db/query/share/VaultRole.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/model/ListQueryParams.hpp"
#include "fs/model/Entry.hpp"
#include "rbac/fs/policy/Share.hpp"
#include "rbac/role/Vault.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "share/AuditEvent.hpp"
#include "share/EmailChallenge.hpp"
#include "share/Link.hpp"
#include "share/Principal.hpp"
#include "share/Session.hpp"
#include "share/Token.hpp"
#include "share/Upload.hpp"

#include <paths.h>
#include <gtest/gtest.h>

using namespace vh;

class ShareQueryTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static uint32_t userId = 0;
    inline static uint32_t vaultId = 0;
    inline static uint32_t rootEntryId = 0;

    static bool hasDbEnv() {
        return std::getenv("VH_TEST_DB_USER") &&
               std::getenv("VH_TEST_DB_PASS") &&
               std::getenv("VH_TEST_DB_HOST") &&
               std::getenv("VH_TEST_DB_PORT") &&
               std::getenv("VH_TEST_DB_NAME");
    }

    static void SetUpTestSuite() {
        if (!hasDbEnv()) {
            skipTests = true;
            std::cout << "[test_share_queries] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }

        paths::enableTestMode();
        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::initPermissions();
        seed::initRoles();
        share::Token::setPepperForTesting(std::vector<uint8_t>(32, 0x51));

        db::Transactions::exec("ShareQueryTest::seed", [&](pqxx::work& txn) {
            userId = txn.exec(
                "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
                pqxx::params{"share_foundation_user", "share-foundation@vaulthalla.test", "hash"}
            ).one_field_ref().as<uint32_t>();

            vaultId = txn.exec(
                "INSERT INTO vault (type, name, owner_id, mount_point) VALUES ($1, $2, $3, $4) RETURNING id",
                pqxx::params{"local", "Share Foundation Vault", userId, "0123456789ABCDEFGHJKMNPQRSTVWXYZ"}
            ).one_field_ref().as<uint32_t>();

            rootEntryId = txn.exec(
                "INSERT INTO fs_entry (vault_id, parent_id, name, created_by, path) VALUES ($1, NULL, $2, $3, $4) RETURNING id",
                pqxx::params{vaultId, "/", userId, "/"}
            ).one_field_ref().as<uint32_t>();

            txn.exec("INSERT INTO directories (fs_entry_id) VALUES ($1)", pqxx::params{rootEntryId});
        });
    }

    static void TearDownTestSuite() {
        share::Token::clearPepperForTesting();
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static std::shared_ptr<share::Link> makeLink() {
        const auto token = share::Token::generate(share::TokenKind::PublicShare);
        auto link = std::make_shared<share::Link>();
        link->token_lookup_id = token.lookup_id;
        link->token_hash = token.hash;
        link->created_by = userId;
        link->vault_id = vaultId;
        link->root_entry_id = rootEntryId;
        link->root_path = "/";
        link->target_type = share::TargetType::Directory;
        link->link_type = share::LinkType::Access;
        link->access_mode = share::AccessMode::Public;
        link->allowed_ops = share::bit(share::Operation::Metadata) |
                            share::bit(share::Operation::List) |
                            share::bit(share::Operation::Download) |
                            share::bit(share::Operation::Upload);
        link->name = "Foundation share";
        link->public_label = "Foundation";
        link->description = "query test";
        link->expires_at = std::time(nullptr) + 3600;
        link->duplicate_policy = share::DuplicatePolicy::Reject;
        link->metadata = R"({"purpose":"test"})";
        return link;
    }

    static std::shared_ptr<share::Session> makeSession(const std::string& shareId) {
        const auto token = share::Token::generate(share::TokenKind::ShareSession);
        auto session = std::make_shared<share::Session>();
        session->share_id = shareId;
        session->session_token_lookup_id = token.lookup_id;
        session->session_token_hash = token.hash;
        session->expires_at = std::time(nullptr) + 3600;
        session->ip_address = "127.0.0.1";
        session->user_agent = "unit-test";
        return session;
    }
};

TEST_F(ShareQueryTest, EntryPathLookupPreservesLegacyVaultMountSegment) {
    struct SeededPath {
        uint32_t vaultId{};
        uint32_t fileEntryId{};
    };

    const auto seeded = db::Transactions::exec("ShareQueryTest::legacyPathSeed", [&](pqxx::work& txn) {
        SeededPath out;
        out.vaultId = txn.exec(
            "INSERT INTO vault (type, name, owner_id, mount_point) VALUES ($1, $2, $3, $4) RETURNING id",
            pqxx::params{"local", "Legacy Mount Vault", userId, "legacy_mount_alias"}
        ).one_field_ref().as<uint32_t>();

        const auto vaultRootId = txn.exec(
            "INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, inode) "
            "VALUES ($1, NULL, $2, $3, $4, $4, $5, $6) RETURNING id",
            pqxx::params{out.vaultId, "legacy_mount", "legacy-mount-root", userId, "/", 9100}
        ).one_field_ref().as<uint32_t>();
        txn.exec("INSERT INTO directories (fs_entry_id) VALUES ($1)", pqxx::params{vaultRootId});

        const auto miscId = txn.exec(
            "INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, inode) "
            "VALUES ($1, $2, $3, $4, $5, $5, $6, $7) RETURNING id",
            pqxx::params{out.vaultId, vaultRootId, "misc", "legacy-mount-misc", userId, "/misc", 9101}
        ).one_field_ref().as<uint32_t>();
        txn.exec("INSERT INTO directories (fs_entry_id) VALUES ($1)", pqxx::params{miscId});

        out.fileEntryId = txn.exec(
            "INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, inode) "
            "VALUES ($1, $2, $3, $4, $5, $5, $6, $7) RETURNING id",
            pqxx::params{out.vaultId, miscId, "test.jpg", "legacy-mount-file", userId, "/misc/test.jpg", 9102}
        ).one_field_ref().as<uint32_t>();
        txn.exec(
            "INSERT INTO files (fs_entry_id, size_bytes, mime_type, content_hash, encryption_iv) "
            "VALUES ($1, $2, $3, $4, $5)",
            pqxx::params{out.fileEntryId, 5, "image/jpeg", "hash", ""}
        );

        return out;
    });

    const auto entry = db::query::fs::Entry::getFSEntryByPath(seeded.vaultId, "/misc/test.jpg");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->id, seeded.fileEntryId);
    EXPECT_EQ(entry->path.string(), "/misc/test.jpg");
    EXPECT_EQ(entry->fuse_path.string(), "/legacy_mount/misc/test.jpg");
}

TEST_F(ShareQueryTest, ShareLinkRoundTripAndCounters) {
    auto created = db::query::share::Link::create(makeLink());
    ASSERT_NE(created, nullptr);
    EXPECT_TRUE(share::Token::verify(created->token_hash, share::TokenKind::PublicShare, share::Token::parse("vhs_" + created->token_lookup_id + "_" + share::Token::generate(share::TokenKind::PublicShare).secret).secret) == false);

    auto byId = db::query::share::Link::get(created->id);
    ASSERT_NE(byId, nullptr);
    EXPECT_EQ(byId->token_hash, created->token_hash);

    auto byLookup = db::query::share::Link::getByLookupId(created->token_lookup_id);
    ASSERT_NE(byLookup, nullptr);
    EXPECT_EQ(byLookup->id, created->id);

    db::model::ListQueryParams params;
    params.limit = 10;
    EXPECT_FALSE(db::query::share::Link::listForUser(userId, params).empty());
    EXPECT_FALSE(db::query::share::Link::listForVault(vaultId, params).empty());
    EXPECT_FALSE(db::query::share::Link::listForTarget(rootEntryId, params).empty());

    created->name = "Updated foundation share";
    created->updated_by = userId;
    auto updated = db::query::share::Link::update(created);
    ASSERT_NE(updated, nullptr);
    ASSERT_TRUE(updated->name);
    EXPECT_EQ(*updated->name, "Updated foundation share");

    const auto rotated = share::Token::generate(share::TokenKind::PublicShare);
    db::query::share::Link::rotateToken(created->id, rotated.lookup_id, rotated.hash, userId);
    auto afterRotate = db::query::share::Link::get(created->id);
    ASSERT_NE(afterRotate, nullptr);
    EXPECT_EQ(afterRotate->token_lookup_id, rotated.lookup_id);
    EXPECT_TRUE(share::Token::verify(afterRotate->token_hash, share::TokenKind::PublicShare, rotated.secret));

    db::query::share::Link::touchAccess(created->id);
    db::query::share::Link::incrementDownload(created->id);
    db::query::share::Link::incrementUpload(created->id);
    auto counted = db::query::share::Link::get(created->id);
    ASSERT_NE(counted, nullptr);
    EXPECT_EQ(counted->access_count, afterRotate->access_count + 1);
    EXPECT_EQ(counted->download_count, afterRotate->download_count + 1);
    EXPECT_EQ(counted->upload_count, afterRotate->upload_count + 1);

    db::query::share::Link::revoke(created->id, userId);
    auto revoked = db::query::share::Link::get(created->id);
    ASSERT_NE(revoked, nullptr);
    EXPECT_TRUE(revoked->isRevoked());
}

TEST_F(ShareQueryTest, DuplicateLookupIdFails) {
    auto link = makeLink();
    auto created = db::query::share::Link::create(link);
    ASSERT_NE(created, nullptr);
    link->token_hash = share::Token::hashSecret(share::TokenKind::PublicShare, "different-secret");
    EXPECT_THROW(db::query::share::Link::create(link), std::exception);
}

TEST_F(ShareQueryTest, ShareVaultRoleMappingRoundTripsScopedOverrides) {
    auto link = db::query::share::Link::create(makeLink());
    ASSERT_NE(link, nullptr);

    auto role = db::query::rbac::role::Vault::get(rbac::role::Vault::ImplicitDeny().name);
    ASSERT_NE(role, nullptr);
    role->fs.overrides = rbac::fs::policy::Share::scopedVaultRoleForGrant(link->id, link->grant()).fs.overrides;
    ASSERT_GT(role->fs.overrides.size(), 0u);
    const auto persistedRoleId = role->id;

    const auto mappingId = db::query::share::VaultRole::upsertForShare(link->id, link->vault_id, role);
    EXPECT_GT(mappingId, 0u);

    auto loaded = db::query::share::VaultRole::getForShare(link->id);
    ASSERT_NE(loaded, nullptr);
    EXPECT_EQ(loaded->id, persistedRoleId);
    EXPECT_EQ(loaded->name, rbac::role::Vault::ImplicitDeny().name);
    ASSERT_TRUE(loaded->assignment);
    EXPECT_EQ(loaded->assignment->subject_type, "public");
    EXPECT_EQ(loaded->assignment->vault_id, link->vault_id);
    EXPECT_EQ(loaded->fs.files.toBitString(), rbac::role::Vault::ImplicitDeny().fs.files.toBitString());
    EXPECT_EQ(loaded->fs.directories.toBitString(), rbac::role::Vault::ImplicitDeny().fs.directories.toBitString());
    EXPECT_GT(loaded->fs.overrides.size(), 0u);

    share::Principal principal;
    principal.share_id = link->id;
    principal.share_session_id = "00000000-0000-4000-8000-000000000901";
    principal.vault_id = link->vault_id;
    principal.root_entry_id = link->root_entry_id;
    principal.root_path = link->root_path;
    principal.grant = link->grant();
    principal.scoped_vault_role = loaded;

    auto decision = rbac::fs::policy::Share::evaluate(principal, {
        .vault_id = link->vault_id,
        .vault_path = "/roundtrip.txt",
        .operation = share::Operation::Download,
        .target_type = share::TargetType::File,
        .target_exists = true
    });
    EXPECT_TRUE(decision.allowed);

    decision = rbac::fs::policy::Share::evaluate(principal, {
        .vault_id = link->vault_id,
        .vault_path = "/roundtrip.txt",
        .operation = share::Operation::Preview,
        .target_type = share::TargetType::File,
        .target_exists = true
    });
    EXPECT_FALSE(decision.allowed);

    db::query::share::VaultRole::removeForShare(link->id);
    EXPECT_EQ(db::query::share::VaultRole::getForShare(link->id), nullptr);
    EXPECT_TRUE(db::query::rbac::role::Vault::exists(persistedRoleId));
}

TEST_F(ShareQueryTest, ShareRecipientRoleReplacementDisablesAbsentRecipientsAndPreservesPublicAssignment) {
    auto link = db::query::share::Link::create(makeLink());
    ASSERT_NE(link, nullptr);

    const auto reader = db::query::rbac::role::Vault::get(rbac::role::Vault::Reader().name);
    const auto contributor = db::query::rbac::role::Vault::get(rbac::role::Vault::Contributor().name);
    ASSERT_NE(reader, nullptr);
    ASSERT_NE(contributor, nullptr);

    db::query::share::VaultRole::upsertPublicAssignment(link->id, link->vault_id, reader->id);
    const auto keptHash = share::EmailChallenge::hashEmail("kept@vaulthalla.test");
    const auto removedHash = share::EmailChallenge::hashEmail("removed@vaulthalla.test");

    db::query::share::VaultRole::replaceRecipientAssignments(link->id, link->vault_id, {
        db::query::share::VaultRole::RecipientAssignmentInput{
            .email_hash = keptHash,
            .vault_role_id = reader->id,
            .overrides = {}
        },
        db::query::share::VaultRole::RecipientAssignmentInput{
            .email_hash = removedHash,
            .vault_role_id = contributor->id,
            .overrides = {}
        }
    });
    ASSERT_NE(db::query::share::VaultRole::getPublicAssignment(link->id), nullptr);
    ASSERT_NE(db::query::share::VaultRole::getRecipientAssignment(link->id, keptHash), nullptr);
    ASSERT_NE(db::query::share::VaultRole::getRecipientAssignment(link->id, removedHash), nullptr);

    db::query::share::VaultRole::replaceRecipientAssignments(link->id, link->vault_id, {
        db::query::share::VaultRole::RecipientAssignmentInput{
            .email_hash = keptHash,
            .vault_role_id = reader->id,
            .overrides = {}
        }
    });
    EXPECT_NE(db::query::share::VaultRole::getPublicAssignment(link->id), nullptr);
    EXPECT_NE(db::query::share::VaultRole::getRecipientAssignment(link->id, keptHash), nullptr);
    EXPECT_EQ(db::query::share::VaultRole::getRecipientAssignment(link->id, removedHash), nullptr);

    db::query::share::VaultRole::replaceRecipientAssignments(link->id, link->vault_id, {});
    EXPECT_NE(db::query::share::VaultRole::getPublicAssignment(link->id), nullptr);
    EXPECT_EQ(db::query::share::VaultRole::getRecipientAssignment(link->id, keptHash), nullptr);
}

TEST_F(ShareQueryTest, SessionChallengeUploadAndAuditRoundTrips) {
    auto link = db::query::share::Link::create(makeLink());
    ASSERT_NE(link, nullptr);

    auto session = db::query::share::Session::create(makeSession(link->id));
    ASSERT_NE(session, nullptr);
    auto sessionByLookup = db::query::share::Session::getByLookupId(session->session_token_lookup_id);
    ASSERT_NE(sessionByLookup, nullptr);
    EXPECT_EQ(sessionByLookup->session_token_hash, session->session_token_hash);

    const auto emailHash = share::EmailChallenge::hashEmail("recipient@vaulthalla.test");
    db::query::share::Session::verify(session->id, emailHash);
    db::query::share::Session::touch(session->id);
    auto verified = db::query::share::Session::get(session->id);
    ASSERT_NE(verified, nullptr);
    ASSERT_TRUE(verified->email_hash);
    EXPECT_EQ(*verified->email_hash, emailHash);
    EXPECT_TRUE(verified->isVerified());

    auto challenge = std::make_shared<share::EmailChallenge>();
    challenge->share_id = link->id;
    challenge->share_session_id = session->id;
    challenge->email_hash = emailHash;
    challenge->code_hash = share::EmailChallenge::hashCode("123456");
    challenge->max_attempts = 3;
    challenge->expires_at = std::time(nullptr) + 3600;
    auto createdChallenge = db::query::share::EmailChallenge::create(challenge);
    ASSERT_NE(createdChallenge, nullptr);
    EXPECT_TRUE(share::EmailChallenge::verifyCode(createdChallenge->code_hash, "123456"));
    auto activeChallenge = db::query::share::EmailChallenge::getActive(link->id, emailHash);
    ASSERT_NE(activeChallenge, nullptr);
    db::query::share::EmailChallenge::recordAttempt(createdChallenge->id);
    db::query::share::EmailChallenge::consume(createdChallenge->id);
    EXPECT_GE(db::query::share::EmailChallenge::purgeExpired(), 1u);

    auto upload = std::make_shared<share::Upload>();
    upload->share_id = link->id;
    upload->share_session_id = session->id;
    upload->target_parent_entry_id = rootEntryId;
    upload->target_path = "/uploaded.txt";
    upload->original_filename = "uploaded.txt";
    upload->resolved_filename = "uploaded.txt";
    upload->expected_size_bytes = 100;
    upload->status = share::UploadStatus::Pending;
    auto createdUpload = db::query::share::Upload::create(upload);
    ASSERT_NE(createdUpload, nullptr);
    db::query::share::Upload::addReceivedBytes(createdUpload->id, 25);
    auto receiving = db::query::share::Upload::get(createdUpload->id);
    ASSERT_NE(receiving, nullptr);
    EXPECT_EQ(receiving->received_size_bytes, 25u);
    EXPECT_EQ(receiving->status, share::UploadStatus::Receiving);
    EXPECT_THROW(db::query::share::Upload::addReceivedBytes(createdUpload->id, 1000), std::runtime_error);
    db::query::share::Upload::complete(createdUpload->id, rootEntryId, "content-hash", "text/plain");
    auto complete = db::query::share::Upload::get(createdUpload->id);
    ASSERT_NE(complete, nullptr);
    EXPECT_TRUE(complete->isTerminal());
    EXPECT_EQ(db::query::share::Upload::sumCompletedBytes(link->id), 25u);
    EXPECT_EQ(db::query::share::Upload::countCompletedFiles(link->id), 1u);

    db::model::ListQueryParams params;
    params.limit = 10;
    EXPECT_FALSE(db::query::share::Upload::listForShare(link->id, params).empty());

    auto event = std::make_shared<share::AuditEvent>();
    event->share_id = link->id;
    event->share_session_id = session->id;
    event->actor_type = share::AuditActorType::OwnerUser;
    event->actor_user_id = userId;
    event->event_type = "share.create";
    event->vault_id = vaultId;
    event->target_entry_id = rootEntryId;
    event->target_path = "/";
    event->status = share::AuditStatus::Success;
    db::query::share::AuditEvent::append(event);
    EXPECT_FALSE(db::query::share::AuditEvent::listForShare(link->id, params).empty());
    EXPECT_FALSE(db::query::share::AuditEvent::listForVault(vaultId, params).empty());

    db::query::share::Session::revoke(session->id);
    auto revoked = db::query::share::Session::get(session->id);
    ASSERT_NE(revoked, nullptr);
    EXPECT_TRUE(revoked->isRevoked());
    db::query::share::Session::revokeForShare(link->id);
}

TEST_F(ShareQueryTest, PurgesExpiredSessions) {
    auto link = db::query::share::Link::create(makeLink());
    ASSERT_NE(link, nullptr);

    auto expired = makeSession(link->id);
    expired->expires_at = std::time(nullptr) - 10;
    auto created = db::query::share::Session::create(expired);
    ASSERT_NE(created, nullptr);
    EXPECT_GE(db::query::share::Session::purgeExpired(), 1u);
    EXPECT_EQ(db::query::share::Session::get(created->id), nullptr);
}
