#include "../helpers/share_fakes.hpp"
#include "protocols/ws/handler/share/Download.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace vh::protocols::ws::handler::share::test_download {
using namespace vh::test::shares;

class FakeDownloadReader final : public DownloadReader {
public:
    std::unordered_map<uint32_t, std::vector<uint8_t>> bytes_by_entry;

    std::vector<uint8_t> readFile(const vh::share::ResolvedTarget& target) const override {
        if (!target.entry) throw std::runtime_error("missing target");
        if (!bytes_by_entry.contains(target.entry->id)) throw std::runtime_error("missing file bytes");
        return bytes_by_entry.at(target.entry->id);
    }
};

class WsShareDownloadTest : public Harness {
protected:
    std::shared_ptr<FakeDownloadReader> reader = std::make_shared<FakeDownloadReader>();

    void SetUp() override {
        startManager();
        readyOps = vh::share::bit(vh::share::Operation::Download);
        const auto text = [](uint32_t id, const std::string& path, int32_t parent, uintmax_t size = 11) {
            auto entry = makeFile(id, 42, path, parent, "text/plain", size);
            entry->content_hash = "safe-content-digest";
            return entry;
        };
        provider->add(makeDir(77, 42, "/reports"));
        provider->add(text(78, "/reports/q1.txt", 77));
        provider->add(makeDir(79, 42, "/reports/team", 77));
        provider->add(text(80, "/reports/team/notes.txt", 79));
        provider->add(text(81, "/reports/empty.txt", 77, 0));
        provider->add(makeDir(99, 42, "/reports_evil"));
        provider->add(text(100, "/reports_evil/q1.txt", 99));

        reader->bytes_by_entry[78] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
        reader->bytes_by_entry[80] = {'n', 'o', 't', 'e', 's'};
        reader->bytes_by_entry[81] = {};

        Download::setManagerFactoryForTesting([this] { return manager; });
        Download::setResolverFactoryForTesting([this] { return resolver; });
        Download::setReaderFactoryForTesting([this] { return reader; });
        Download::resetTransfersForTesting();
    }

    void TearDown() override {
        Download::resetTransfersForTesting();
        Download::resetManagerFactoryForTesting();
        Download::resetResolverFactoryForTesting();
        Download::resetReaderFactoryForTesting();
        Harness::TearDown();
    }
};

TEST_F(WsShareDownloadTest, RouterAllowsDownloadOnlyForReadyShareMode) {
    auto unauth = publicSession();
    auto human = humanSession();
    auto pending = publicSession();
    pending->setPendingShareSession(uuidFor(10), "vhss_pending");
    auto share = readySession();

    using Decision = Router::CommandAuthDecision;
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.download.start", *unauth));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.download.start", *human));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.download.start", *pending));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("share.download.start", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("share.download.chunk", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("share.download.cancel", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.download.start", *unauth));
    EXPECT_EQ(Decision::RequireHumanAuth, Router::classifyCommand("fs.download.start", *human));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.download.start", *pending));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.download.start", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.download.chunk", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.download.cancel", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.dir.list", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.upload.start", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.upload.finish", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.upload.cancel", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.entry.delete", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.link.create", *share));
}

TEST_F(WsShareDownloadTest, StartAndChunksCompleteDownloadWithGrant) {
    const auto session = readySession();
    const auto shareId = session->sharePrincipal()->share_id;

    const auto start = Download::start({{"path", "/reports/q1.txt"}}, session);

    EXPECT_TRUE(start.at("transfer_id").get<std::string>().size() > 20);
    EXPECT_EQ(start.at("filename"), "q1.txt");
    EXPECT_EQ(start.at("path"), "/q1.txt");
    EXPECT_EQ(start.at("size_bytes"), 11u);
    EXPECT_EQ(start.at("chunk_size"), 65536u);
    expectNoSecretOrInternalFields(start);

    const auto first = Download::chunk({
        {"transfer_id", start.at("transfer_id").get<std::string>()},
        {"offset", 0},
        {"length", 5}
    }, session);
    EXPECT_EQ(first.at("bytes"), 5u);
    EXPECT_EQ(first.at("next_offset"), 5u);
    EXPECT_FALSE(first.at("complete").get<bool>());
    EXPECT_FALSE(first.at("data_base64").get<std::string>().empty());
    expectNoSecretOrInternalFields(first);

    const auto second = Download::chunk({
        {"transfer_id", start.at("transfer_id").get<std::string>()},
        {"offset", 5},
        {"length", 6}
    }, session);
    EXPECT_EQ(second.at("bytes"), 6u);
    EXPECT_EQ(second.at("next_offset"), 11u);
    EXPECT_TRUE(second.at("complete").get<bool>());
    EXPECT_EQ(store->getLink(shareId)->download_count, 1u);
    EXPECT_THROW({ (void)Download::chunk({
        {"transfer_id", start.at("transfer_id").get<std::string>()},
        {"offset", 11},
        {"length", 1}
    }, session); }, std::runtime_error);
}

TEST_F(WsShareDownloadTest, NativeStartUsesShareActorAndDurableScopedRole) {
    const auto session = readySession();
    ASSERT_EQ(session->user, nullptr);
    ASSERT_TRUE(session->sharePrincipal());
    ASSERT_TRUE(session->sharePrincipal()->scoped_vault_role);

    const auto actor = session->rbacActor();
    EXPECT_TRUE(actor.isShare());
    EXPECT_FALSE(actor.canUseHumanPrivileges());

    const auto start = Download::nativeStart({{"path", "/q1.txt"}}, session);

    EXPECT_TRUE(start.at("transfer_id").get<std::string>().size() > 20);
    EXPECT_EQ(start.at("filename"), "q1.txt");
    EXPECT_EQ(start.at("path"), "/q1.txt");
    EXPECT_EQ(start.at("size_bytes"), 11u);
    expectNoSecretOrInternalFields(start);
    EXPECT_EQ(session->user, nullptr);

    const auto explicitVaultPath = Download::nativeStart({
        {"vault_id", 42},
        {"path", "/reports/q1.txt"}
    }, session);
    EXPECT_EQ(explicitVaultPath.at("path"), "/q1.txt");
}

TEST_F(WsShareDownloadTest, DeniesMissingGrantDirectoryEscapeAndPrefixTrick) {
    auto noGrant = readySession(vh::share::bit(vh::share::Operation::Metadata));
    EXPECT_THROW({ (void)Download::start({{"path", "/reports/q1.txt"}}, noGrant); }, std::runtime_error);
    EXPECT_THROW({ (void)Download::nativeStart({{"path", "/q1.txt"}}, noGrant); }, std::runtime_error);

    auto session = readySession();
    EXPECT_THROW({ (void)Download::start({{"path", "/reports"}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)Download::start({{"path", "/reports/../secret.txt"}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)Download::start({{"path", "/reports_evil/q1.txt"}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)Download::nativeStart({{"path", "/"}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)Download::nativeStart({{"path", "/../secret.txt"}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)Download::nativeStart({{"path", "/team//notes.txt"}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)Download::nativeStart({
        {"vault_id", 42},
        {"path", "/reports_evil/q1.txt"}
    }, session); }, std::runtime_error);
}

TEST_F(WsShareDownloadTest, TransferIdIsSessionBoundAndChunkCannotChangePath) {
    auto session = readySession();
    const auto start = Download::nativeStart({{"path", "/q1.txt"}}, session);
    const auto transferId = start.at("transfer_id").get<std::string>();

    auto otherSession = publicSession();
    otherSession->setSharePrincipal(session->sharePrincipal(), session->shareSessionToken());
    EXPECT_THROW({ (void)Download::nativeChunk({
        {"transfer_id", transferId},
        {"offset", 0},
        {"length", 1}
    }, otherSession); }, std::runtime_error);

    EXPECT_THROW({ (void)Download::nativeChunk({
        {"transfer_id", transferId},
        {"offset", 0},
        {"length", 1},
        {"path", "/reports/team/notes.txt"}
    }, session); }, std::runtime_error);
}

TEST_F(WsShareDownloadTest, ChunkBoundsAndMaxChunkSizeAreEnforced) {
    auto session = readySession();
    const auto wrongOffsetStart = Download::nativeStart({{"path", "/q1.txt"}}, session);
    const auto wrongOffsetId = wrongOffsetStart.at("transfer_id").get<std::string>();

    EXPECT_THROW({ (void)Download::nativeChunk({
        {"transfer_id", wrongOffsetId},
        {"offset", 1},
        {"length", 1}
    }, session); }, std::runtime_error);

    const auto tooLargeStart = Download::nativeStart({{"path", "/q1.txt"}}, session);
    const auto tooLargeId = tooLargeStart.at("transfer_id").get<std::string>();
    EXPECT_THROW({ (void)Download::nativeChunk({
        {"transfer_id", tooLargeId},
        {"offset", 0},
        {"length", 300000}
    }, session); }, std::runtime_error);

    const auto clampedStart = Download::nativeStart({{"path", "/q1.txt"}}, session);
    const auto clamped = Download::nativeChunk({
        {"transfer_id", clampedStart.at("transfer_id").get<std::string>()},
        {"offset", 0},
        {"length", 12}
    }, session);
    EXPECT_EQ(clamped.at("bytes"), 11u);
    EXPECT_EQ(clamped.at("next_offset"), 11u);
    EXPECT_TRUE(clamped.at("complete").get<bool>());
}

TEST_F(WsShareDownloadTest, NativeZeroSizeFileCompletesEmptyChunkSafely) {
    auto session = readySession();
    const auto start = Download::nativeStart({{"path", "/empty.txt"}}, session);
    EXPECT_EQ(start.at("size_bytes"), 0u);

    const auto chunk = Download::nativeChunk({
        {"transfer_id", start.at("transfer_id").get<std::string>()},
        {"offset", 0},
        {"length", 1}
    }, session);

    EXPECT_EQ(chunk.at("bytes"), 0u);
    EXPECT_EQ(chunk.at("data_base64"), "");
    EXPECT_EQ(chunk.at("next_offset"), 0u);
    EXPECT_TRUE(chunk.at("complete").get<bool>());
}

TEST_F(WsShareDownloadTest, RevokedSessionFailsClosedDuringChunkRevalidation) {
    auto session = readySession();
    const auto start = Download::start({{"path", "/reports/q1.txt"}}, session);
    store->revokeSession(session->shareSessionId());

    EXPECT_THROW({ (void)Download::chunk({
        {"transfer_id", start.at("transfer_id").get<std::string>()},
        {"offset", 0},
        {"length", 5}
    }, session); }, std::runtime_error);

    EXPECT_THROW({ (void)Download::chunk({
        {"transfer_id", start.at("transfer_id").get<std::string>()},
        {"offset", 0},
        {"length", 5}
    }, session); }, std::runtime_error);
}

TEST_F(WsShareDownloadTest, CancelClearsTransferContext) {
    auto session = readySession();
    const auto start = Download::nativeStart({{"path", "/q1.txt"}}, session);
    const auto transferId = start.at("transfer_id").get<std::string>();

    const auto cancelled = Download::nativeCancel({{"transfer_id", transferId}}, session);

    EXPECT_TRUE(cancelled.at("cancelled").get<bool>());
    expectNoSecretOrInternalFields(cancelled);
    EXPECT_THROW({ (void)Download::nativeChunk({
        {"transfer_id", transferId},
        {"offset", 0},
        {"length", 1}
    }, session); }, std::runtime_error);

    const auto compatibilityStart = Download::start({{"path", "/reports/q1.txt"}}, session);
    const auto compatibilityCancelled = Download::cancel({
        {"transfer_id", compatibilityStart.at("transfer_id").get<std::string>()}
    }, session);
    EXPECT_TRUE(compatibilityCancelled.at("cancelled").get<bool>());
}

}
