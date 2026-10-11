#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/share/Download.hpp"
#include "rbac/role/Vault.hpp"
#include "share/AuditEvent.hpp"
#include "share/EmailChallenge.hpp"
#include "share/Manager.hpp"
#include "share/TargetResolver.hpp"
#include "share/Token.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace vh::protocols::ws::handler::share::test_download {
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
    std::unordered_map<std::string, std::shared_ptr<vh::rbac::role::Vault>> vault_roles;
    std::vector<std::shared_ptr<vh::share::AuditEvent>> audits;
    uint32_t next_link{100};
    uint32_t next_session{200};
    uint32_t next_challenge{300};

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
        const db::model::ListQueryParams&
    ) override {
        std::vector<std::shared_ptr<vh::share::Link>> out;
        for (auto& [_, link] : links)
            if (link->created_by == userId) out.push_back(link);
        return out;
    }

    std::vector<std::shared_ptr<vh::share::Link>> listLinksForVault(
        uint32_t vaultId,
        const db::model::ListQueryParams&
    ) override {
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
        ++link->access_count;
        link->last_accessed_at = kNow;
    }

    void incrementDownload(const std::string& id) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        ++link->download_count;
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
            if (challenge->share_id != shareId) continue;
            if (challenge->email_hash != emailHash) continue;
            if (!challenge->canAttempt(kNow)) continue;
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
        challenge->consumed_at = kNow;
    }

    void appendAuditEvent(const std::shared_ptr<vh::share::AuditEvent>& event) override {
        audits.push_back(std::make_shared<vh::share::AuditEvent>(*event));
    }
};

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

class FakeDownloadReader final : public DownloadReader {
public:
    std::unordered_map<uint32_t, std::vector<uint8_t>> bytes_by_entry;

    std::vector<uint8_t> readFile(const vh::share::ResolvedTarget& target) const override {
        if (!target.entry) throw std::runtime_error("missing target");
        if (!bytes_by_entry.contains(target.entry->id)) throw std::runtime_error("missing file bytes");
        return bytes_by_entry.at(target.entry->id);
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
    entry->content_hash = "safe-content-digest";
    entry->size_bytes = 11;
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
    return link;
}

std::shared_ptr<Session> publicSession() {
    auto session = std::make_shared<Session>(std::make_shared<Router>());
    session->ipAddress = "127.0.0.1";
    session->userAgent = "ws-share-download-test";
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

void expectNoSecretOrInternalFields(const nlohmann::json& value) {
    const auto dump = value.dump();
    EXPECT_FALSE(dump.contains("token"));
    EXPECT_FALSE(dump.contains("hash"));
    EXPECT_FALSE(dump.contains("email"));
    EXPECT_FALSE(dump.contains("challenge"));
    EXPECT_FALSE(dump.contains("vault_id"));
    EXPECT_FALSE(dump.contains("abs_path"));
    EXPECT_FALSE(dump.contains("backing"));
    EXPECT_FALSE(dump.contains("inode"));
    EXPECT_FALSE(dump.contains("owner_uid"));
    EXPECT_FALSE(dump.contains("group_gid"));
    EXPECT_FALSE(dump.contains("mode"));
}

class WsShareDownloadTest : public ::testing::Test {
protected:
    std::shared_ptr<FakeStore> store;
    std::shared_ptr<FakeAuthorizer> authorizer;
    std::shared_ptr<vh::share::Manager> manager;
    std::shared_ptr<FakeEntryProvider> provider;
    std::shared_ptr<vh::share::TargetResolver> resolver;
    std::shared_ptr<FakeDownloadReader> reader;
    std::shared_ptr<identities::User> user;

    void SetUp() override {
        vh::share::Token::setPepperForTesting(std::vector<uint8_t>(32, 0x61));
        store = std::make_shared<FakeStore>();
        authorizer = std::make_shared<FakeAuthorizer>();
        vh::share::ManagerOptions options;
        options.clock = [] { return kNow; };
        options.session_ttl_seconds = 600;
        manager = std::make_shared<vh::share::Manager>(store, authorizer, options);

        provider = std::make_shared<FakeEntryProvider>();
        provider->add(dir(77, 42, "/reports"));
        provider->add(file(78, 42, "/reports/q1.txt", 77));
        provider->add(dir(79, 42, "/reports/team", 77));
        provider->add(file(80, 42, "/reports/team/notes.txt", 79));
        auto empty = file(81, 42, "/reports/empty.txt", 77);
        empty->size_bytes = 0;
        provider->add(empty);
        provider->add(dir(99, 42, "/reports_evil"));
        provider->add(file(100, 42, "/reports_evil/q1.txt", 99));
        resolver = std::make_shared<vh::share::TargetResolver>(provider);

        reader = std::make_shared<FakeDownloadReader>();
        reader->bytes_by_entry[78] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
        reader->bytes_by_entry[80] = {'n', 'o', 't', 'e', 's'};
        reader->bytes_by_entry[81] = {};

        Download::setManagerFactoryForTesting([this] { return manager; });
        Download::setResolverFactoryForTesting([this] { return resolver; });
        Download::setReaderFactoryForTesting([this] { return reader; });
        Download::resetTransfersForTesting();

        vh::identities::UserState userState;
        userState.name = "share-owner";
        user = vh::identities::User::detached(7, std::move(userState));
    }

    void TearDown() override {
        Download::resetTransfersForTesting();
        Download::resetManagerFactoryForTesting();
        Download::resetResolverFactoryForTesting();
        Download::resetReaderFactoryForTesting();
        vh::share::Token::clearPepperForTesting();
    }

    vh::share::CreateLinkResult create(const uint32_t ops) {
        return manager->createLink(rbac::Actor::human(user), {
            .link = makeLink(ops),
            .public_role = vh::share::RoleAssignmentRequest{.vault_role_name = rbac::role::Vault::Reader().name}
        });
    }

    std::shared_ptr<Session> readySession(
        const uint32_t ops = vh::share::bit(vh::share::Operation::Download)
    ) {
        const auto created = create(ops);
        auto opened = manager->openPublicSession(created.public_token);
        auto principal = manager->resolvePrincipal(opened.session_token);
        auto session = publicSession();
        session->setSharePrincipal(std::move(principal), opened.session_token);
        return session;
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
