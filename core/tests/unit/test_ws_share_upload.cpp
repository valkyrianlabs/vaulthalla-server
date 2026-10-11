#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "identities/User.hpp"
#include "protocols/http/upload/Coordinator.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Upload.hpp"
#include "protocols/ws/handler/share/Upload.hpp"
#include "rbac/fs/policy/Share.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/seed_db.hpp"
#include "share/AuditEvent.hpp"
#include "share/EmailChallenge.hpp"
#include "share/Manager.hpp"
#include "share/TargetResolver.hpp"
#include "share/Token.hpp"
#include "stats/model/FuseStats.hpp"
#include "storage/Engine.hpp"
#include "vault/model/Vault.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <format>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using WsShareUploadHandler = vh::protocols::ws::handler::share::Upload;

namespace vh::protocols::ws::handler::share::test_upload {
constexpr std::time_t kNow = 1'800'000'000;

std::string uuidFor(const uint32_t value) {
    return std::format("00000000-0000-4000-8000-{:012d}", value);
}

class FakeAuthorizer final : public vh::share::ShareAuthorizer {
public:
    vh::share::AuthorizationDecision canCreateLink(const rbac::Actor& actor, const vh::share::Link&) const override {
        return {actor.isHuman(), actor.isHuman() ? "allowed" : "not_human"};
    }

    vh::share::AuthorizationDecision canUpdateLink(
        const rbac::Actor& actor,
        const vh::share::Link&,
        const vh::share::Link&
    ) const override {
        return {actor.isHuman(), actor.isHuman() ? "allowed" : "not_human"};
    }

    vh::share::AuthorizationDecision canManageLink(const rbac::Actor& actor, const vh::share::Link&) const override {
        return {actor.isHuman(), actor.isHuman() ? "allowed" : "not_human"};
    }

    vh::share::AuthorizationDecision canListVaultLinks(const rbac::Actor& actor, uint32_t) const override {
        return {actor.isHuman(), actor.isHuman() ? "allowed" : "not_human"};
    }
};

class FakeStore final : public vh::share::ShareStore {
public:
    std::unordered_map<std::string, std::shared_ptr<vh::share::Link>> links;
    std::unordered_map<std::string, std::string> link_by_lookup;
    std::unordered_map<std::string, std::shared_ptr<vh::share::Session>> sessions;
    std::unordered_map<std::string, std::string> session_by_lookup;
    std::unordered_map<std::string, std::shared_ptr<vh::share::EmailChallenge>> challenges;
    std::unordered_map<std::string, std::shared_ptr<vh::share::Upload>> uploads;
    std::unordered_map<std::string, std::shared_ptr<vh::rbac::role::Vault>> vault_roles;
    std::vector<std::shared_ptr<vh::share::AuditEvent>> audits;
    uint32_t next_link{100};
    uint32_t next_session{200};
    uint32_t next_challenge{300};
    uint32_t next_upload{400};

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

    std::vector<std::shared_ptr<vh::share::Link>> listLinksForUser(uint32_t userId, const db::model::ListQueryParams&) override {
        std::vector<std::shared_ptr<vh::share::Link>> out;
        for (auto& [_, link] : links)
            if (link->created_by == userId) out.push_back(link);
        return out;
    }

    std::vector<std::shared_ptr<vh::share::Link>> listLinksForVault(uint32_t vaultId, const db::model::ListQueryParams&) override {
        std::vector<std::shared_ptr<vh::share::Link>> out;
        for (auto& [_, link] : links)
            if (link->vault_id == vaultId) out.push_back(link);
        return out;
    }

    std::shared_ptr<vh::share::Link> updateLink(const std::shared_ptr<vh::share::Link>& link) override {
        links[link->id] = link;
        link_by_lookup[link->token_lookup_id] = link->id;
        return link;
    }

    void revokeLink(const std::string& id, uint32_t revokedBy) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        link->revoked_at = kNow;
        link->revoked_by = revokedBy;
    }

    void rotateLinkToken(const std::string& id, const std::string& lookupId, const std::vector<uint8_t>& tokenHash, uint32_t updatedBy) override {
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
        ++link->access_count;
        link->last_accessed_at = kNow;
    }

    void incrementDownload(const std::string&) override {}

    void incrementUpload(const std::string& id) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        ++link->upload_count;
    }

    void upsertVaultRoleForShare(
        const std::string& shareId,
        uint32_t,
        const std::shared_ptr<vh::rbac::role::Vault>& role
    ) override {
        if (!role) {
            vault_roles.erase(shareId);
            return;
        }
        vault_roles[shareId] = std::make_shared<vh::rbac::role::Vault>(*role);
    }

    std::shared_ptr<vh::rbac::role::Vault> getVaultRoleForShare(const std::string& shareId) override {
        if (!vault_roles.contains(shareId)) return nullptr;
        return std::make_shared<vh::rbac::role::Vault>(*vault_roles.at(shareId));
    }

    void removeVaultRoleForShare(const std::string& shareId) override {
        vault_roles.erase(shareId);
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
        auto session = getSession(sessionId);
        if (!session) throw std::runtime_error("missing session");
        session->email_hash = emailHash;
        session->verified_at = kNow;
    }

    void touchSession(const std::string& sessionId) override {
        auto session = getSession(sessionId);
        if (!session) throw std::runtime_error("missing session");
        session->last_seen_at = kNow + 1;
    }

    void revokeSession(const std::string& sessionId) override {
        auto session = getSession(sessionId);
        if (!session) throw std::runtime_error("missing session");
        session->revoked_at = kNow;
    }

    void revokeSessionsForShare(const std::string& shareId) override {
        for (auto& [_, session] : sessions)
            if (session->share_id == shareId && !session->revoked_at) session->revoked_at = kNow;
    }

    std::shared_ptr<vh::share::EmailChallenge> createEmailChallenge(const std::shared_ptr<vh::share::EmailChallenge>& challenge) override {
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

    std::shared_ptr<vh::share::EmailChallenge> getActiveEmailChallenge(const std::string&, const std::vector<uint8_t>&) override {
        return nullptr;
    }

    void recordEmailChallengeAttempt(const std::string&) override {}
    void consumeEmailChallenge(const std::string&) override {}

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
        auto upload = getUpload(uploadId);
        if (!upload) throw std::runtime_error("missing upload");
        if (upload->exceedsExpectedSize(bytes)) throw std::runtime_error("too large");
        upload->received_size_bytes += bytes;
        upload->status = vh::share::UploadStatus::Receiving;
    }

    void completeUpload(const std::string& uploadId, uint32_t entryId, const std::string& contentHash, const std::string& mimeType) override {
        auto upload = getUpload(uploadId);
        if (!upload) throw std::runtime_error("missing upload");
        upload->created_entry_id = entryId;
        upload->content_hash = contentHash;
        upload->mime_type = mimeType;
        upload->status = vh::share::UploadStatus::Complete;
        upload->completed_at = kNow + 2;
    }

    void failUpload(const std::string& uploadId, const std::string& error) override {
        auto upload = getUpload(uploadId);
        if (!upload) throw std::runtime_error("missing upload");
        upload->error = error;
        upload->status = vh::share::UploadStatus::Failed;
        upload->completed_at = kNow + 2;
    }

    void cancelUpload(const std::string& uploadId) override {
        auto upload = getUpload(uploadId);
        if (!upload) throw std::runtime_error("missing upload");
        upload->status = vh::share::UploadStatus::Cancelled;
        upload->completed_at = kNow + 2;
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
            if (upload->share_id == shareId && upload->status == vh::share::UploadStatus::Complete)
                ++total;
        return total;
    }
};

class FakeEntryProvider final : public vh::share::TargetEntryProvider {
public:
    std::unordered_map<uint32_t, std::shared_ptr<vh::fs::model::Entry>> by_id;
    std::unordered_map<std::string, std::shared_ptr<vh::fs::model::Entry>> by_path;

    void add(const std::shared_ptr<vh::fs::model::Entry>& entry) {
        by_id[entry->id] = entry;
        by_path[key(*entry->vault_id, entry->path.string())] = entry;
    }

    std::shared_ptr<vh::fs::model::Entry> getEntryById(uint32_t entryId) override {
        if (!by_id.contains(entryId)) return nullptr;
        return by_id.at(entryId);
    }

    std::shared_ptr<vh::fs::model::Entry> getEntryByVaultPath(uint32_t vaultId, std::string_view vaultPath) override {
        const auto k = key(vaultId, std::string(vaultPath));
        if (!by_path.contains(k)) return nullptr;
        return by_path.at(k);
    }

    std::vector<std::shared_ptr<vh::fs::model::Entry>> listChildren(uint32_t) override { return {}; }

private:
    static std::string key(const uint32_t vaultId, const std::string& path) {
        return std::to_string(vaultId) + ":" + path;
    }
};

class FakeUploadWriter final : public UploadWriter {
public:
    std::unordered_map<std::string, std::vector<uint8_t>> bytes_by_path;
    uint32_t next_entry{500};

    std::shared_ptr<vh::fs::model::File> createFile(
        const vh::share::ResolvedTarget& parent,
        const std::shared_ptr<vh::identities::User>&,
        const std::string& finalVaultPath,
        const std::vector<uint8_t>& bytes
    ) const override {
        auto file = std::make_shared<vh::fs::model::File>();
        file->id = const_cast<FakeUploadWriter*>(this)->next_entry++;
        file->vault_id = parent.vault_id;
        file->parent_id = static_cast<int32_t>(parent.entry->id);
        file->path = finalVaultPath;
        file->name = std::filesystem::path(finalVaultPath).filename().string();
        file->size_bytes = bytes.size();
        file->mime_type = "text/plain";
        file->content_hash = "safe-upload-content-digest";
        file->created_at = file->updated_at = kNow;
        const_cast<FakeUploadWriter*>(this)->bytes_by_path[finalVaultPath] = bytes;
        return file;
    }
};

std::shared_ptr<vh::fs::model::Directory> dir(
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

std::shared_ptr<vh::fs::model::File> file(
    const uint32_t id,
    const uint32_t vaultId,
    const std::string& path,
    const std::optional<int32_t> parentId = std::nullopt
) {
    auto entry = std::make_shared<vh::fs::model::File>();
    entry->id = id;
    entry->vault_id = vaultId;
    entry->parent_id = parentId;
    entry->path = path;
    entry->name = std::filesystem::path(path).filename().string();
    entry->mime_type = "text/plain";
    entry->size_bytes = 3;
    entry->created_at = entry->updated_at = kNow;
    return entry;
}

vh::share::Link makeLink(const uint32_t ops) {
    vh::share::Link link;
    link.vault_id = 42;
    link.root_entry_id = 77;
    link.root_path = "/reports";
    link.target_type = vh::share::TargetType::Directory;
    link.link_type = vh::share::LinkType::Access;
    link.access_mode = vh::share::AccessMode::Public;
    link.allowed_ops = ops;
    link.expires_at = kNow + 3600;
    link.max_upload_size_bytes = 1024;
    link.duplicate_policy = vh::share::DuplicatePolicy::Reject;
    return link;
}

std::shared_ptr<Session> publicSession() {
    auto session = std::make_shared<Session>(std::make_shared<Router>());
    session->ipAddress = "127.0.0.1";
    session->userAgent = "ws-share-upload-test";
    return session;
}

std::shared_ptr<Session> humanSession() {
    auto session = publicSession();
    vh::identities::UserState userState;
    userState.name = "human";
    auto user = vh::identities::User::detached(9, std::move(userState));
    session->user = user;
    return session;
}

boost::beast::flat_buffer binaryBuffer(const std::vector<uint8_t>& bytes) {
    boost::beast::flat_buffer buffer;
    auto prepared = buffer.prepare(bytes.size());
    boost::asio::buffer_copy(prepared, boost::asio::buffer(bytes));
    buffer.commit(bytes.size());
    return buffer;
}

void expectNoSecretOrInternalFields(const nlohmann::json& value) {
    const auto dump = value.dump();
    EXPECT_FALSE(dump.contains("token"));
    EXPECT_FALSE(dump.contains("hash"));
    EXPECT_FALSE(dump.contains("email"));
    EXPECT_FALSE(dump.contains("challenge"));
    EXPECT_FALSE(dump.contains("backing"));
    EXPECT_FALSE(dump.contains("tmp_path"));
    EXPECT_FALSE(dump.contains("abs_path"));
    EXPECT_FALSE(dump.contains("vault_id"));
}

class FuseStatsRuntimeGuard {
public:
    explicit FuseStatsRuntimeGuard(std::shared_ptr<vh::stats::model::FuseStats> stats)
        : previous(vh::runtime::Deps::get().fuseStats) {
        vh::runtime::Deps::get().fuseStats = std::move(stats);
    }

    ~FuseStatsRuntimeGuard() {
        vh::runtime::Deps::get().fuseStats = std::move(previous);
    }

private:
    std::shared_ptr<vh::stats::model::FuseStats> previous;
};

class WsShareUploadTest : public ::testing::Test {
protected:
    std::shared_ptr<FakeStore> store;
    std::shared_ptr<FakeAuthorizer> authorizer;
    std::shared_ptr<vh::share::Manager> manager;
    std::shared_ptr<FakeEntryProvider> provider;
    std::shared_ptr<vh::share::TargetResolver> resolver;
    std::shared_ptr<FakeUploadWriter> writer;
    std::shared_ptr<identities::User> user;
    std::shared_ptr<vh::storage::Engine> httpEngine;
    std::filesystem::path oldBackingPath;
    std::filesystem::path oldMountPath;
    std::filesystem::path testRoot;

    void SetUp() override {
        vh::share::Token::setPepperForTesting(std::vector<uint8_t>(32, 0x61));
        oldBackingPath = vh::paths::backingPath;
        oldMountPath = vh::paths::mountPath;
        testRoot = std::filesystem::temp_directory_path() / "vh_http_share_upload_unit";
        std::filesystem::remove_all(testRoot);
        vh::paths::backingPath = testRoot / "backing";
        vh::paths::mountPath = testRoot / "mount";
        std::filesystem::create_directories(vh::paths::backingPath);
        std::filesystem::create_directories(vh::paths::mountPath);

        store = std::make_shared<FakeStore>();
        authorizer = std::make_shared<FakeAuthorizer>();
        vh::share::ManagerOptions options;
        options.clock = [] { return kNow; };
        options.session_ttl_seconds = 600;
        options.default_max_upload_size_bytes = 1024;
        options.max_upload_chunk_size_bytes = 8;
        manager = std::make_shared<vh::share::Manager>(store, authorizer, options);

        provider = std::make_shared<FakeEntryProvider>();
        provider->add(dir(77, 42, "/reports"));
        provider->add(dir(78, 42, "/reports/team", 77));
        provider->add(file(79, 42, "/reports/existing.txt", 77));
        provider->add(dir(99, 42, "/reports_evil"));
        resolver = std::make_shared<vh::share::TargetResolver>(provider);

        writer = std::make_shared<FakeUploadWriter>();
        WsShareUploadHandler::setManagerFactoryForTesting([this] { return manager; });
        WsShareUploadHandler::setResolverFactoryForTesting([this] { return resolver; });
        WsShareUploadHandler::setWriterFactoryForTesting([this] { return writer; });

        auto vault = std::make_shared<vh::vault::model::Vault>();
        vault->id = 42;
        vault->mount_point = "http-share-upload-test";
        vault->quota = 1024ull * 1024ull * 1024ull;
        httpEngine = std::make_shared<vh::storage::Engine>();
        httpEngine->vault = vault;
        httpEngine->paths = std::make_shared<vh::fs::model::Path>("http-share-upload-test", "http-share-upload-test");
        std::filesystem::create_directories(httpEngine->paths->vaultRoot);
        std::filesystem::create_directories(httpEngine->paths->backingVaultRoot);
        std::filesystem::create_directories(httpEngine->paths->cacheRoot);

        vh::protocols::http::upload::Coordinator::setShareManagerFactoryForTesting([this] { return manager; });
        vh::protocols::http::upload::Coordinator::setShareResolverFactoryForTesting([this] { return resolver; });
        vh::protocols::http::upload::Coordinator::setEngineResolverForTesting([this](const uint32_t vaultId) {
            return vaultId == 42 ? httpEngine : nullptr;
        });

        vh::identities::UserState userState;
        userState.name = "share-owner";
        user = vh::identities::User::detached(7, std::move(userState));
    }

    void TearDown() override {
        WsShareUploadHandler::resetManagerFactoryForTesting();
        WsShareUploadHandler::resetResolverFactoryForTesting();
        WsShareUploadHandler::resetWriterFactoryForTesting();
        vh::protocols::http::upload::Coordinator::clearForTesting();
        vh::protocols::http::upload::Coordinator::resetSessionResolverForTesting();
        vh::protocols::http::upload::Coordinator::resetShareManagerFactoryForTesting();
        vh::protocols::http::upload::Coordinator::resetShareResolverFactoryForTesting();
        vh::protocols::http::upload::Coordinator::resetEngineResolverForTesting();
        vh::protocols::http::upload::Coordinator::resetClockForTesting();
        std::filesystem::remove_all(testRoot);
        vh::paths::backingPath = oldBackingPath;
        vh::paths::mountPath = oldMountPath;
        vh::share::Token::clearPepperForTesting();
    }

    vh::share::CreateLinkResult create(const uint32_t ops) {
        return manager->createLink(rbac::Actor::human(user), {
            .link = makeLink(ops),
            .public_role = vh::share::RoleAssignmentRequest{.vault_role_name = rbac::role::Vault::Contributor().name}
        });
    }

    std::shared_ptr<Session> readySession(const uint32_t ops = vh::share::bit(vh::share::Operation::Upload)) {
        const auto created = create(ops);
        auto opened = manager->openPublicSession(created.public_token);
        auto principal = manager->resolvePrincipal(opened.session_token);
        auto session = publicSession();
        session->setSharePrincipal(std::move(principal), opened.session_token);
        return session;
    }
};
}

using namespace vh::protocols::ws::handler::share::test_upload;
using vh::protocols::ws::Router;

namespace {
vh::protocols::http::request httpRequest(
    const vh::protocols::http::verb method,
    const std::string& target
) {
    return vh::protocols::http::request{method, target, 11};
}

std::string readOnlyRegularFileUnder(const std::filesystem::path& root) {
    std::string content;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;
        std::ifstream in(entry.path(), std::ios::binary);
        content.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    return content;
}
}

TEST_F(WsShareUploadTest, RouterAllowsUploadOnlyForReadyShareMode) {
    auto unauth = publicSession();
    auto human = humanSession();
    auto pending = publicSession();
    pending->setPendingShareSession(uuidFor(10), "vhss_pending");
    auto share = readySession();

    using Decision = Router::CommandAuthDecision;
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.upload.start", *unauth));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.upload.start", *human));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.upload.start", *pending));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("share.upload.start", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("share.upload.finish", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("share.upload.cancel", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.upload.start", *unauth));
    EXPECT_EQ(Decision::RequireHumanAuth, Router::classifyCommand("fs.upload.start", *human));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.upload.start", *pending));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.upload.start", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.upload.finish", *share));
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("fs.upload.cancel", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.entry.copy", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.entry.move", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.entry.delete", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.link.create", *share));
}

TEST_F(WsShareUploadTest, StartRejectsUnauthHumanAndUnsafeFilenames) {
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "new.txt"}, {"size_bytes", 4}}, publicSession()); }, std::runtime_error);
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "new.txt"}, {"size_bytes", 4}}, humanSession()); }, std::runtime_error);

    auto session = readySession();
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports"}, {"filename", ""}, {"size_bytes", 4}}, session); }, std::exception);
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "."}, {"size_bytes", 4}}, session); }, std::exception);
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "../x.txt"}, {"size_bytes", 4}}, session); }, std::exception);
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "nested/x.txt"}, {"size_bytes", 4}}, session); }, std::exception);
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "nested\\x.txt"}, {"size_bytes", 4}}, session); }, std::exception);
}

TEST_F(WsShareUploadTest, NativeStartUsesShareActorDurableRoleAndActiveContext) {
    auto session = readySession();
    ASSERT_EQ(session->user, nullptr);
    ASSERT_TRUE(session->sharePrincipal());
    ASSERT_TRUE(session->sharePrincipal()->scoped_vault_role);

    const auto actor = session->rbacActor();
    EXPECT_TRUE(actor.isShare());
    EXPECT_FALSE(actor.canUseHumanPrivileges());

    const auto start = WsShareUploadHandler::nativeStart({
        {"path", "/native.txt"},
        {"size", 4},
        {"mime_type", "text/plain"}
    }, session);

    EXPECT_TRUE(start.at("upload_id").get<std::string>().size() > 20);
    EXPECT_EQ(start.at("transfer_id"), start.at("upload_id"));
    EXPECT_EQ(start.at("path"), "/native.txt");
    EXPECT_EQ(session->getUploadHandler()->activeShareUploadId(), start.at("upload_id").get<std::string>());
    expectNoSecretOrInternalFields(start);
    EXPECT_EQ(session->user, nullptr);

    const auto cancelled = WsShareUploadHandler::nativeCancel(nlohmann::json::object(), session);
    EXPECT_TRUE(cancelled.at("cancelled").get<bool>());
}

TEST_F(WsShareUploadTest, NativeAndCompatibilityStartUseSameShareUploadContext) {
    auto session = readySession();

    const auto native = WsShareUploadHandler::nativeStart({
        {"path", "/team/native.txt"},
        {"size_bytes", 1}
    }, session);
    EXPECT_EQ(native.at("path"), "/team/native.txt");
    EXPECT_TRUE(session->getUploadHandler()->shareUploadInProgress());
    EXPECT_EQ(session->getUploadHandler()->activeShareUploadId(), native.at("upload_id").get<std::string>());
    (void)WsShareUploadHandler::nativeCancel({{"transfer_id", native.at("transfer_id").get<std::string>()}}, session);

    const auto compatibility = WsShareUploadHandler::start({
        {"path", "/reports/team"},
        {"filename", "compat.txt"},
        {"size_bytes", 1}
    }, session);
    EXPECT_EQ(compatibility.at("path"), "/team/compat.txt");
    EXPECT_TRUE(session->getUploadHandler()->shareUploadInProgress());
    EXPECT_EQ(session->getUploadHandler()->activeShareUploadId(), compatibility.at("upload_id").get<std::string>());
    (void)WsShareUploadHandler::cancel({{"upload_id", compatibility.at("upload_id").get<std::string>()}}, session);
}

TEST_F(WsShareUploadTest, HttpShareUploadStreamsBodyToTempFileAndRecordsBytes) {
    namespace http_upload = vh::protocols::http::upload;

    auto session = readySession();
    http_upload::Coordinator::setSessionResolverForTesting([session](const vh::protocols::http::request&) {
        return session;
    });

    const auto created = http_upload::Coordinator::instance().createSession(
        httpRequest(vh::protocols::http::verb::post, "/upload/session?share=1"),
        {
            {"files", nlohmann::json::array({
                {
                    {"file_id", "f0"},
                    {"path", "/http.txt"},
                    {"size_bytes", 5},
                    {"mime_type", "text/plain"}
                }
            })}
        }
    );

    const auto batchId = created.at("upload_id").get<std::string>();
    const auto transferId = created.at("files").at(0).at("transfer_id").get<std::string>();
    const auto tempPath = httpEngine->paths->vaultRoot / "reports" / (".upload-http-" + batchId + "-f0.part");

    auto stream = http_upload::Coordinator::instance().beginFile(
        httpRequest(vh::protocols::http::verb::put, "/upload/" + batchId + "/files/f0?share=1"),
        5
    );
    stream.write("he", 2);
    stream.write("llo", 3);
    const auto fileDone = stream.finish();

    EXPECT_TRUE(fileDone.at("complete").get<bool>());
    EXPECT_EQ(fileDone.at("received_size"), 5u);
    EXPECT_TRUE(std::filesystem::exists(tempPath));
    ASSERT_NE(store->getUpload(transferId), nullptr);
    EXPECT_EQ(store->getUpload(transferId)->received_size_bytes, 5u);
    EXPECT_TRUE(writer->bytes_by_path.empty());
    EXPECT_EQ(readOnlyRegularFileUnder(vh::paths::mountPath), "hello");

    const auto cancelled = http_upload::Coordinator::instance().cancelSession(
        httpRequest(vh::protocols::http::verb::delete_, "/upload/" + batchId + "?share=1"),
        batchId
    );
    EXPECT_TRUE(cancelled.at("cancelled").get<bool>());
    EXPECT_FALSE(std::filesystem::exists(tempPath));
    EXPECT_EQ(store->getUpload(transferId)->status, vh::share::UploadStatus::Cancelled);

    const auto recreated = http_upload::Coordinator::instance().createSession(
        httpRequest(vh::protocols::http::verb::post, "/upload/session?share=1"),
        {
            {"files", nlohmann::json::array({
                {
                    {"file_id", "f0"},
                    {"path", "/http.txt"},
                    {"size_bytes", 5},
                    {"mime_type", "text/plain"}
                }
            })}
        }
    );
    const auto recreatedBatchId = recreated.at("upload_id").get<std::string>();
    EXPECT_NE(recreatedBatchId, batchId);
    const auto recreatedTempPath = httpEngine->paths->vaultRoot / "reports" / (".upload-http-" + recreatedBatchId + "-f0.part");

    auto recreatedStream = http_upload::Coordinator::instance().beginFile(
        httpRequest(vh::protocols::http::verb::put, "/upload/" + recreatedBatchId + "/files/f0?share=1"),
        5
    );
    recreatedStream.write("again", 5);
    EXPECT_TRUE(recreatedStream.finish().at("complete").get<bool>());
    EXPECT_TRUE(std::filesystem::exists(recreatedTempPath));

    const auto recreatedCancelled = http_upload::Coordinator::instance().cancelSession(
        httpRequest(vh::protocols::http::verb::delete_, "/upload/" + recreatedBatchId + "?share=1"),
        recreatedBatchId
    );
    EXPECT_TRUE(recreatedCancelled.at("cancelled").get<bool>());
    EXPECT_FALSE(std::filesystem::exists(recreatedTempPath));
}

TEST_F(WsShareUploadTest, HttpShareUploadAbortAllFailsActiveStreamsAndClearsTempState) {
    namespace http_upload = vh::protocols::http::upload;

    auto session = readySession();
    http_upload::Coordinator::setSessionResolverForTesting([session](const vh::protocols::http::request&) {
        return session;
    });

    const auto created = http_upload::Coordinator::instance().createSession(
        httpRequest(vh::protocols::http::verb::post, "/upload/session?share=1"),
        {
            {"files", nlohmann::json::array({
                {
                    {"file_id", "f0"},
                    {"path", "/shutdown.txt"},
                    {"size_bytes", 5},
                    {"mime_type", "text/plain"}
                }
            })}
        }
    );

    const auto batchId = created.at("upload_id").get<std::string>();
    const auto transferId = created.at("files").at(0).at("transfer_id").get<std::string>();
    const auto tempPath = httpEngine->paths->vaultRoot / "reports" / (".upload-http-" + batchId + "-f0.part");

    auto stream = http_upload::Coordinator::instance().beginFile(
        httpRequest(vh::protocols::http::verb::put, "/upload/" + batchId + "/files/f0?share=1"),
        5
    );
    stream.write("he", 2);

    ASSERT_TRUE(std::filesystem::exists(tempPath));
    ASSERT_NE(store->getUpload(transferId), nullptr);
    EXPECT_EQ(store->getUpload(transferId)->status, vh::share::UploadStatus::Receiving);

    http_upload::Coordinator::instance().abortAll("http_service_stopping");

    EXPECT_FALSE(std::filesystem::exists(tempPath));
    EXPECT_EQ(store->getUpload(transferId)->status, vh::share::UploadStatus::Failed);
    EXPECT_EQ(store->getUpload(transferId)->error, "http_service_stopping");
    EXPECT_THROW({ stream.write("llo", 3); }, std::runtime_error);
    EXPECT_THROW({
        (void)http_upload::Coordinator::instance().beginFile(
            httpRequest(vh::protocols::http::verb::put, "/upload/" + batchId + "/files/f0?share=1"),
            5
        );
    }, std::runtime_error);

    const auto recreated = http_upload::Coordinator::instance().createSession(
        httpRequest(vh::protocols::http::verb::post, "/upload/session?share=1"),
        {
            {"files", nlohmann::json::array({
                {
                    {"file_id", "f0"},
                    {"path", "/shutdown.txt"},
                    {"size_bytes", 5},
                    {"mime_type", "text/plain"}
                }
            })}
        }
    );
    const auto recreatedBatchId = recreated.at("upload_id").get<std::string>();
    auto recreatedStream = http_upload::Coordinator::instance().beginFile(
        httpRequest(vh::protocols::http::verb::put, "/upload/" + recreatedBatchId + "/files/f0?share=1"),
        5
    );
    recreatedStream.write("again", 5);
    EXPECT_TRUE(recreatedStream.finish().at("complete").get<bool>());
}

TEST_F(WsShareUploadTest, HttpShareUploadRejectsDuplicatesScopeDenialAndSizeMismatch) {
    namespace http_upload = vh::protocols::http::upload;

    auto session = readySession();
    http_upload::Coordinator::setSessionResolverForTesting([session](const vh::protocols::http::request&) {
        return session;
    });

    EXPECT_THROW({
        (void)http_upload::Coordinator::instance().createSession(
            httpRequest(vh::protocols::http::verb::post, "/upload/session?share=1"),
            {
                {"files", nlohmann::json::array({
                    {{"file_id", "f0"}, {"path", "/dupe.txt"}, {"size_bytes", 1}},
                    {{"file_id", "f1"}, {"path", "/dupe.txt"}, {"size_bytes", 1}}
                })}
            }
        );
    }, std::runtime_error);

    auto denied = readySession(vh::share::bit(vh::share::Operation::Metadata));
    http_upload::Coordinator::setSessionResolverForTesting([denied](const vh::protocols::http::request&) {
        return denied;
    });
    EXPECT_THROW({
        (void)http_upload::Coordinator::instance().createSession(
            httpRequest(vh::protocols::http::verb::post, "/upload/session?share=1"),
            {
                {"files", nlohmann::json::array({
                    {{"file_id", "f0"}, {"path", "/denied.txt"}, {"size_bytes", 1}}
                })}
            }
        );
    }, std::runtime_error);

    http_upload::Coordinator::setSessionResolverForTesting([session](const vh::protocols::http::request&) {
        return session;
    });
    const auto created = http_upload::Coordinator::instance().createSession(
        httpRequest(vh::protocols::http::verb::post, "/upload/session?share=1"),
        {
            {"files", nlohmann::json::array({
                {{"file_id", "f0"}, {"path", "/mismatch.txt"}, {"size_bytes", 2}}
            })}
        }
    );
    const auto batchId = created.at("upload_id").get<std::string>();
    EXPECT_THROW({
        (void)http_upload::Coordinator::instance().beginFile(
            httpRequest(vh::protocols::http::verb::put, "/upload/" + batchId + "/files/f0?share=1"),
            3
        );
    }, std::runtime_error);
    (void)http_upload::Coordinator::instance().cancelSession(
        httpRequest(vh::protocols::http::verb::delete_, "/upload/" + batchId + "?share=1"),
        batchId
    );
}

TEST_F(WsShareUploadTest, HttpShareUploadRejectsAggregateQuotaOverflow) {
    namespace http_upload = vh::protocols::http::upload;

    auto session = readySession();
    http_upload::Coordinator::setSessionResolverForTesting([session](const vh::protocols::http::request&) {
        return session;
    });

    httpEngine->vault->quota = vh::storage::Engine::MIN_FREE_SPACE + 100;

    EXPECT_THROW({
        (void)http_upload::Coordinator::instance().createSession(
            httpRequest(vh::protocols::http::verb::post, "/upload/session?share=1"),
            {
                {"files", nlohmann::json::array({
                    {{"file_id", "f0"}, {"path", "/quota-a.txt"}, {"size_bytes", 60}},
                    {{"file_id", "f1"}, {"path", "/quota-b.txt"}, {"size_bytes", 60}}
                })}
            }
        );
    }, std::runtime_error);
}

TEST_F(WsShareUploadTest, BinaryUploadFinishesThroughWriterAndManager) {
    auto session = readySession();
    const auto shareId = session->sharePrincipal()->share_id;
    const auto start = WsShareUploadHandler::start({
        {"path", "/reports"},
        {"filename", "new.txt"},
        {"size_bytes", 5},
        {"mime_type", "text/plain"}
    }, session);

    EXPECT_TRUE(start.at("upload_id").get<std::string>().size() > 20);
    EXPECT_EQ(start.at("transfer_id"), start.at("upload_id"));
    EXPECT_EQ(start.at("path"), "/new.txt");
    EXPECT_EQ(start.at("chunk_size"), 8u);
    expectNoSecretOrInternalFields(start);

    auto buffer = binaryBuffer({'h', 'e', 'l', 'l', 'o'});
    session->getUploadHandler()->handleBinaryFrame(buffer);
    EXPECT_EQ(store->getUpload(start.at("upload_id").get<std::string>())->received_size_bytes, 5u);

    const auto finish = WsShareUploadHandler::finish({{"upload_id", start.at("upload_id").get<std::string>()}}, session);
    EXPECT_TRUE(finish.at("complete").get<bool>());
    EXPECT_EQ(finish.at("entry").at("path"), "/new.txt");
    expectNoSecretOrInternalFields(finish);
    EXPECT_EQ(writer->bytes_by_path.at("/reports/new.txt"), std::vector<uint8_t>({'h', 'e', 'l', 'l', 'o'}));
    EXPECT_EQ(store->getLink(shareId)->upload_count, 1u);
    EXPECT_EQ(store->getUpload(start.at("upload_id").get<std::string>())->status, vh::share::UploadStatus::Complete);
}

TEST_F(WsShareUploadTest, NativeBinaryUploadFinishesThroughSharedUploadHandler) {
    auto session = readySession();
    const auto start = WsShareUploadHandler::nativeStart({
        {"path", "/native-finish.txt"},
        {"size", 2},
        {"mime_type", "text/plain"}
    }, session);

    auto buffer = binaryBuffer({'o', 'k'});
    session->getUploadHandler()->handleBinaryFrame(buffer);

    const auto finish = WsShareUploadHandler::nativeFinish(nlohmann::json::object(), session);

    EXPECT_TRUE(finish.at("complete").get<bool>());
    EXPECT_EQ(finish.at("entry").at("path"), "/native-finish.txt");
    EXPECT_EQ(writer->bytes_by_path.at("/reports/native-finish.txt"), std::vector<uint8_t>({'o', 'k'}));
    EXPECT_EQ(store->getUpload(start.at("upload_id").get<std::string>())->status, vh::share::UploadStatus::Complete);
}

TEST_F(WsShareUploadTest, ShareUploadDoesNotRecordFuseOperationCounters) {
    auto fuseStats = std::make_shared<vh::stats::model::FuseStats>();
    FuseStatsRuntimeGuard fuseStatsGuard(fuseStats);

    auto session = readySession();
    const auto start = WsShareUploadHandler::start({
        {"path", "/reports"},
        {"filename", "direct-writer.txt"},
        {"size_bytes", 2},
        {"mime_type", "text/plain"}
    }, session);

    auto buffer = binaryBuffer({'o', 'k'});
    session->getUploadHandler()->handleBinaryFrame(buffer);
    const auto finish = WsShareUploadHandler::finish({{"upload_id", start.at("upload_id").get<std::string>()}}, session);

    EXPECT_TRUE(finish.at("complete").get<bool>());
    EXPECT_EQ(fuseStats->snapshot().totalOps, 0u);
}

TEST_F(WsShareUploadTest, MissingGrantPathEscapePrefixAndDuplicateAreDenied) {
    auto noGrant = readySession(vh::share::bit(vh::share::Operation::Metadata));
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "new.txt"}, {"size_bytes", 1}}, noGrant); }, std::runtime_error);
    EXPECT_THROW({ (void)WsShareUploadHandler::nativeStart({{"path", "/new.txt"}, {"size_bytes", 1}}, noGrant); }, std::runtime_error);

    auto session = readySession();
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports/../secret"}, {"filename", "new.txt"}, {"size_bytes", 1}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports_evil"}, {"filename", "new.txt"}, {"size_bytes", 1}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "existing.txt"}, {"size_bytes", 1}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)WsShareUploadHandler::nativeStart({{"path", "/../secret/new.txt"}, {"size_bytes", 1}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)WsShareUploadHandler::nativeStart({{"path", "/team//new.txt"}, {"size_bytes", 1}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)WsShareUploadHandler::nativeStart({
        {"vault_id", 42},
        {"path", "/reports_evil/new.txt"},
        {"size_bytes", 1}
    }, session); }, std::runtime_error);
    EXPECT_THROW({ (void)WsShareUploadHandler::nativeStart({{"path", "/existing.txt"}, {"size_bytes", 1}}, session); }, std::runtime_error);
    EXPECT_THROW({ (void)WsShareUploadHandler::start({
        {"path", "/reports"},
        {"filename", "new.txt"},
        {"size_bytes", 1},
        {"duplicate_policy", "overwrite"}
    }, session); }, std::runtime_error);
}

TEST_F(WsShareUploadTest, ChunkBoundsSessionBindingAndCancelAreEnforced) {
    auto session = readySession();
    const auto start = WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "small.txt"}, {"size_bytes", 2}}, session);
    const auto uploadId = start.at("upload_id").get<std::string>();

    auto tooLarge = binaryBuffer({'a', 'b', 'c'});
    EXPECT_THROW({ session->getUploadHandler()->handleBinaryFrame(tooLarge); }, std::runtime_error);
    EXPECT_EQ(store->getUpload(uploadId)->status, vh::share::UploadStatus::Failed);

    auto second = readySession();
    EXPECT_THROW({ (void)second->getUploadHandler()->finishShareUpload(uploadId, session->shareSessionId()); }, std::runtime_error);

    auto ownerChanged = readySession();
    const auto ownedStart = WsShareUploadHandler::nativeStart({{"path", "/owned.txt"}, {"size_bytes", 1}}, ownerChanged);
    const auto ownedUploadId = ownedStart.at("upload_id").get<std::string>();
    auto differentShareSession = readySession();
    ownerChanged->setSharePrincipal(differentShareSession->sharePrincipal(), differentShareSession->shareSessionToken());
    auto ownedFrame = binaryBuffer({'x'});
    EXPECT_THROW({ ownerChanged->getUploadHandler()->handleBinaryFrame(ownedFrame); }, std::runtime_error);
    EXPECT_EQ(store->getUpload(ownedUploadId)->status, vh::share::UploadStatus::Failed);

    auto cancelStart = WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "cancel.txt"}, {"size_bytes", 2}}, session);
    const auto cancelId = cancelStart.at("upload_id").get<std::string>();
    const auto cancelled = WsShareUploadHandler::cancel({{"upload_id", cancelId}}, session);
    EXPECT_TRUE(cancelled.at("cancelled").get<bool>());
    expectNoSecretOrInternalFields(cancelled);
    EXPECT_EQ(store->getUpload(cancelId)->status, vh::share::UploadStatus::Cancelled);
    EXPECT_THROW({ (void)WsShareUploadHandler::finish({{"upload_id", cancelId}}, session); }, std::runtime_error);
}

TEST_F(WsShareUploadTest, SessionCloseFailsAbandonedShareUpload) {
    auto session = readySession();
    const auto start = WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "abandoned.txt"}, {"size_bytes", 2}}, session);
    const auto uploadId = start.at("upload_id").get<std::string>();

    EXPECT_TRUE(session->getUploadHandler()->shareUploadInProgress());
    session->close();

    EXPECT_FALSE(session->getUploadHandler()->shareUploadInProgress());
    const auto upload = store->getUpload(uploadId);
    ASSERT_NE(upload, nullptr);
    EXPECT_EQ(upload->status, vh::share::UploadStatus::Failed);
    EXPECT_EQ(upload->error, "websocket_session_closed");
}

TEST_F(WsShareUploadTest, RevokedSessionFailsClosedDuringChunkRevalidation) {
    auto session = readySession();
    const auto start = WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "new.txt"}, {"size_bytes", 2}}, session);
    const auto uploadId = start.at("upload_id").get<std::string>();
    store->revokeSession(session->shareSessionId());

    auto buffer = binaryBuffer({'o', 'k'});
    EXPECT_THROW({ session->getUploadHandler()->handleBinaryFrame(buffer); }, std::runtime_error);
    EXPECT_EQ(store->getUpload(uploadId)->status, vh::share::UploadStatus::Failed);
}

namespace {
std::string httpUploadErrorOf(const std::function<void()>& fn) {
    try {
        fn();
    } catch (const std::exception& e) {
        return e.what();
    }
    return {};
}
}

// #142: sessions used to expire 30 minutes after creation, so any longer upload failed at finish ("Upload session
// not found") and lost its staged parts. The TTL now slides with activity, under a hard ceiling.
TEST_F(WsShareUploadTest, HttpUploadSessionTtlSlidesWithActivityUnderAHardCeiling) {
    namespace http_upload = vh::protocols::http::upload;
    using namespace std::chrono_literals;

    auto now = std::make_shared<std::chrono::steady_clock::time_point>(std::chrono::steady_clock::now());
    http_upload::Coordinator::setClockForTesting([now] { return *now; });

    auto session = readySession();
    http_upload::Coordinator::setSessionResolverForTesting([session](const vh::protocols::http::request&) {
        return session;
    });

    const auto create = [&](const std::string& prefix, const uint64_t size) {
        return http_upload::Coordinator::instance().createSession(
            httpRequest(vh::protocols::http::verb::post, "/upload/session?share=1"),
            {
                {"files", nlohmann::json::array({
                    {{"file_id", "f0"}, {"path", "/" + prefix + "-0.txt"}, {"size_bytes", size}},
                    {{"file_id", "f1"}, {"path", "/" + prefix + "-1.txt"}, {"size_bytes", size}}
                })}
            }
        ).at("upload_id").get<std::string>();
    };
    const auto begin = [&](const std::string& batchId, const std::string& fileId, const uint64_t size) {
        return http_upload::Coordinator::instance().beginFile(
            httpRequest(vh::protocols::http::verb::put, "/upload/" + batchId + "/files/" + fileId + "?share=1"), size);
    };

    // Active for well over 30 minutes since creation: every chunk and request keeps it alive.
    const auto slow = create("slow", 4);
    *now += 25min;
    auto first = begin(slow, "f0", 4);
    first.write("ab", 2);
    *now += 20min;
    first.write("cd", 2);
    EXPECT_TRUE(first.finish().at("complete").get<bool>());
    *now += 29min;  // 74 minutes after creation, 29 idle
    auto second = begin(slow, "f1", 4);
    second.write("efgh", 4);
    EXPECT_TRUE(second.finish().at("complete").get<bool>());

    // Idle past the TTL: gone.
    *now += 31min;
    EXPECT_EQ(httpUploadErrorOf([&] { (void)begin(slow, "f1", 4); }), "Upload session not found");

    // A session that keeps trickling still ends at the hard ceiling.
    const auto trickle = create("trickle", 100);
    auto stream = begin(trickle, "f0", 100);
    for (int i = 0; i < 73; ++i) {  // 24h20m of one byte every 20 minutes
        *now += 20min;
        stream.write("x", 1);
    }
    EXPECT_EQ(httpUploadErrorOf([&] { (void)begin(trickle, "f1", 100); }), "Upload session not found");
}

// #151: a dropbox link is upload-only. Uploads need nothing but the upload op and the role's Upload bits; the
// seeded share_upload_dropbox role no longer grants List, so recipients can't see each other's submissions.
TEST_F(WsShareUploadTest, UploadOnlyDropboxUploadsWithoutListOrMetadata) {
    namespace http_upload = vh::protocols::http::upload;

    const auto created = create(vh::share::bit(vh::share::Operation::Upload));
    auto dropbox = vh::seed::shareUploadDropboxRole();
    dropbox.id = 99;
    dropbox.assign(99, "public", 42);
    store->vault_roles[created.link->id] = std::make_shared<vh::rbac::role::Vault>(dropbox);
    auto opened = manager->openPublicSession(created.public_token);
    auto principal = manager->resolvePrincipal(opened.session_token);
    ASSERT_TRUE(principal->scoped_vault_role);
    EXPECT_EQ(principal->scoped_vault_role->name, "share_upload_dropbox");
    auto session = publicSession();
    session->setSharePrincipal(std::move(principal), opened.session_token);
    http_upload::Coordinator::setSessionResolverForTesting([session](const vh::protocols::http::request&) {
        return session;
    });

    const auto batch = http_upload::Coordinator::instance().createSession(
        httpRequest(vh::protocols::http::verb::post, "/upload/session?share=1"),
        {{"files", nlohmann::json::array({{{"file_id", "f0"}, {"path", "/drop.txt"}, {"size_bytes", 4}}})}}
    ).at("upload_id").get<std::string>();
    auto stream = http_upload::Coordinator::instance().beginFile(
        httpRequest(vh::protocols::http::verb::put, "/upload/" + batch + "/files/f0?share=1"), 4);
    stream.write("drop", 4);
    EXPECT_TRUE(stream.finish().at("complete").get<bool>());
    (void)http_upload::Coordinator::instance().cancelSession(
        httpRequest(vh::protocols::http::verb::delete_, "/upload/" + batch + "?share=1"), batch);

    // The ws lane takes the same path.
    const auto ws = WsShareUploadHandler::start({{"path", "/reports"}, {"filename", "ws-drop.txt"}, {"size_bytes", 2}}, session);
    (void)WsShareUploadHandler::cancel({{"upload_id", ws.at("upload_id").get<std::string>()}}, session);

    const auto actor = session->rbacActor();
    EXPECT_FALSE(manager->authorize(actor, vh::share::Operation::List, "/reports", vh::share::TargetType::Directory, 42).allowed);
    EXPECT_FALSE(manager->authorize(actor, vh::share::Operation::Metadata, "/reports", vh::share::TargetType::Directory, 42).allowed);
    EXPECT_FALSE(manager->authorize(actor, vh::share::Operation::Download, "/reports/existing.txt", vh::share::TargetType::File, 42).allowed);

    // Even a link that asks for list can't list through the seeded role.
    const auto rbac = vh::rbac::fs::policy::Share::evaluate(*session->sharePrincipal(), {
        .vault_id = 42,
        .vault_path = "/reports",
        .operation = vh::share::Operation::Upload,
        .target_type = vh::share::TargetType::Directory,
        .target_exists = true
    });
    EXPECT_TRUE(rbac.allowed);
    EXPECT_FALSE(dropbox.fs.directories.canList());
}
