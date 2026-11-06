#include "../helpers/share_fakes.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "protocols/ws/handler/share/Filesystem.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <stdexcept>

namespace vh::protocols::ws::handler::share::test_fs {
namespace ws_fs = vh::protocols::ws::handler::fs;
using namespace vh::test::shares;

class WsShareFsTest : public Harness {
protected:
    void SetUp() override {
        startManager();
        publicRole = rbac::role::Vault::Contributor().name;
        const auto counted = [](auto entry) {
            entry->file_count = 1;
            entry->subdirectory_count = 1;
            return entry;
        };
        provider->add(counted(makeDir(77, 42, "/reports")));
        provider->add(makeFile(78, 42, "/reports/q1.pdf", 77, "application/pdf", 1234));
        provider->add(counted(makeDir(79, 42, "/reports/team", 77)));
        provider->add(makeFile(80, 42, "/reports/team/notes.pdf", 79, "application/pdf", 1234));
        provider->add(counted(makeDir(99, 42, "/reports_evil")));
        Filesystem::setManagerFactoryForTesting([this] { return manager; });
        Filesystem::setResolverFactoryForTesting([this] { return resolver; });
    }

    void TearDown() override {
        Filesystem::resetManagerFactoryForTesting();
        Filesystem::resetResolverFactoryForTesting();
        Harness::TearDown();
    }
};

TEST_F(WsShareFsTest, RouterAllowsShareFsOnlyForReadyShareMode) {
    auto unauth = publicSession();
    auto human = humanSession();
    auto pending = publicSession();
    pending->setPendingShareSession(uuidFor(10), "vhss_pending");
    auto share = readySession(vh::share::bit(vh::share::Operation::Metadata));

    using Decision = Router::CommandAuthDecision;
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.fs.metadata", *unauth));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.metadata", *unauth));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.list", *unauth));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.fs.list", *human));
    EXPECT_EQ(Decision::RequireHumanAuth, Router::classifyCommand("fs.metadata", *human));
    EXPECT_EQ(Decision::RequireHumanAuth, Router::classifyCommand("fs.list", *human));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.fs.metadata", *pending));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.metadata", *pending));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.list", *pending));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("share.fs.metadata", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.metadata", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.list", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.dir.list", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.upload.start", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.upload.finish", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.upload.cancel", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.link.create", *share));
}

TEST_F(WsShareFsTest, NativeMetadataUsesShareActorWithoutSessionUser) {
    auto session = readySession(vh::share::bit(vh::share::Operation::Metadata));
    ASSERT_EQ(session->user, nullptr);
    ASSERT_NE(session->sharePrincipal(), nullptr);
    ASSERT_NE(session->sharePrincipal()->scoped_vault_role, nullptr);
    const auto actor = session->rbacActor();
    EXPECT_TRUE(actor.isShare());
    EXPECT_EQ(actor.user(), nullptr);

    const auto response = ws_fs::Storage::metadata({{"path", "/q1.pdf"}}, session);

    EXPECT_EQ(session->user, nullptr);
    EXPECT_EQ(response.at("path").get<std::string>(), "/q1.pdf");
    const auto& entry = response.at("entry");
    EXPECT_EQ(entry.at("id").get<uint32_t>(), 78u);
    EXPECT_EQ(entry.at("path").get<std::string>(), "/q1.pdf");
    EXPECT_EQ(entry.at("type").get<std::string>(), "file");
    EXPECT_FALSE(response.contains("vault"));
    expectNoSecretOrInternalFields(response);
}

TEST_F(WsShareFsTest, NativeMetadataAcceptsExplicitVaultRelativePath) {
    auto session = readySession(vh::share::bit(vh::share::Operation::Metadata));

    const auto response = ws_fs::Storage::metadata({{"vault_id", 42}, {"path", "/reports/q1.pdf"}}, session);

    EXPECT_EQ(response.at("path").get<std::string>(), "/q1.pdf");
    EXPECT_EQ(response.at("entry").at("id").get<uint32_t>(), 78u);
}

TEST_F(WsShareFsTest, NativeListReturnsNativeShapeUnderShareRoot) {
    auto session = readySession(
        vh::share::bit(vh::share::Operation::Metadata) |
        vh::share::bit(vh::share::Operation::List)
    );

    const auto response = ws_fs::Storage::list({{"path", "/"}}, session);

    EXPECT_EQ(response.at("path").get<std::string>(), "/");
    EXPECT_EQ(response.at("entry").at("path").get<std::string>(), "/");
    ASSERT_TRUE(response.contains("files"));
    ASSERT_FALSE(response.contains("entries"));
    ASSERT_EQ(response.at("files").size(), 2u);
    EXPECT_EQ(response.at("files").at(0).at("path").get<std::string>(), "/q1.pdf");
    EXPECT_EQ(response.at("files").at(1).at("path").get<std::string>(), "/team");
    expectNoSecretOrInternalFields(response);
}

TEST_F(WsShareFsTest, NativeReadDeniesMissingGrantScopeEscapePrefixAndDuplicateSlashes) {
    auto metadataOnly = readySession(vh::share::bit(vh::share::Operation::Metadata));
    EXPECT_THROW({ (void)ws_fs::Storage::list({{"path", "/"}}, metadataOnly); }, std::runtime_error);

    auto session = readySession(
        vh::share::bit(vh::share::Operation::Metadata) |
        vh::share::bit(vh::share::Operation::List)
    );

    EXPECT_THROW({ (void)ws_fs::Storage::metadata({{"path", "/../secret.txt"}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)ws_fs::Storage::metadata({{"path", "//q1.pdf"}}, session); }, std::runtime_error);
    EXPECT_THROW({
        (void)ws_fs::Storage::metadata({{"vault_id", 42}, {"path", "/reports_evil"}}, session);
    }, std::runtime_error);
    EXPECT_THROW({
        (void)ws_fs::Storage::metadata({{"vault_id", 99}, {"path", "/reports/q1.pdf"}}, session);
    }, std::runtime_error);
}

TEST_F(WsShareFsTest, MetadataReturnsSafeShareRelativeEntry) {
    auto session = readySession(vh::share::bit(vh::share::Operation::Metadata));

    const auto response = Filesystem::metadata({{"path", "/reports/q1.pdf"}}, session);

    const auto& entry = response.at("entry");
    EXPECT_EQ(entry.at("id").get<uint32_t>(), 78u);
    EXPECT_EQ(entry.at("path").get<std::string>(), "/q1.pdf");
    EXPECT_EQ(entry.at("type").get<std::string>(), "file");
    EXPECT_EQ(entry.at("mime_type").get<std::string>(), "application/pdf");
    // Share recipients get the same preview plan as console listings (without it the sheet could only fall back to
    // MIME and showed "no preview" for media, 3D and text even on download-capable links).
    ASSERT_TRUE(entry.contains("preview"));
    EXPECT_EQ(entry.at("preview").at("renderer").get<std::string>(), "pdf");
    EXPECT_EQ(entry.at("preview").at("requires").get<std::string>(), "preview");
    expectNoSecretOrInternalFields(response);
}

TEST_F(WsShareFsTest, ListReturnsSafeChildrenUnderShareRoot) {
    auto session = readySession(
        vh::share::bit(vh::share::Operation::Metadata) |
        vh::share::bit(vh::share::Operation::List)
    );

    const auto response = Filesystem::list({{"path", "/"}}, session);

    EXPECT_EQ(response.at("path").get<std::string>(), "/");
    ASSERT_EQ(response.at("entries").size(), 2u);
    EXPECT_EQ(response.at("entries").at(0).at("path").get<std::string>(), "/q1.pdf");
    EXPECT_EQ(response.at("entries").at(1).at("path").get<std::string>(), "/team");
    EXPECT_TRUE(response.at("entries").at(0).contains("preview"));
    EXPECT_FALSE(response.at("entries").at(1).contains("preview"));
    expectNoSecretOrInternalFields(response);
}

TEST_F(WsShareFsTest, ShareCompatibilityWrappersKeepLegacyResponseShape) {
    auto session = readySession(
        vh::share::bit(vh::share::Operation::Metadata) |
        vh::share::bit(vh::share::Operation::List)
    );

    const auto metadata = Filesystem::metadata({{"path", "/reports/q1.pdf"}}, session);
    EXPECT_TRUE(metadata.contains("entry"));
    EXPECT_FALSE(metadata.contains("path"));

    const auto listing = Filesystem::list({{"path", "/"}}, session);
    EXPECT_EQ(listing.at("path").get<std::string>(), "/");
    EXPECT_TRUE(listing.contains("entries"));
    EXPECT_FALSE(listing.contains("files"));
}

TEST_F(WsShareFsTest, DeniesMissingGrantEscapeAndPrefixTrick) {
    auto session = readySession(vh::share::bit(vh::share::Operation::Metadata));

    EXPECT_THROW({ (void)Filesystem::list({{"path", "/reports"}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)Filesystem::metadata({{"path", "/reports/../secret.txt"}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)Filesystem::metadata({{"path", "/reports_evil"}}, session); }, std::runtime_error);
}

TEST_F(WsShareFsTest, RejectsUnauthenticatedHumanAndPendingSessions) {
    auto pending = publicSession();
    pending->setPendingShareSession(uuidFor(10), "vhss_pending");

    EXPECT_THROW({ (void)Filesystem::metadata({{"path", "/reports"}}, publicSession()); }, std::runtime_error);
    EXPECT_THROW({ (void)Filesystem::metadata({{"path", "/reports"}}, humanSession()); }, std::runtime_error);
    EXPECT_THROW({ (void)Filesystem::metadata({{"path", "/reports"}}, pending); }, std::runtime_error);
}

}
