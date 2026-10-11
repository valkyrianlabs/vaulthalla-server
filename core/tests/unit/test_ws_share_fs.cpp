#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "protocols/ws/handler/share/Filesystem.hpp"
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
#include <unordered_map>

namespace vh::protocols::ws::handler::share::test_fs {
namespace ws_fs = vh::protocols::ws::handler::fs;

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
    entry->file_count = 1;
    entry->subdirectory_count = 1;
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
    entry->mime_type = "application/pdf";
    entry->size_bytes = 1234;
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
    session->userAgent = "ws-share-fs-test";
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

class WsShareFsTest : public ::testing::Test {
protected:
    std::shared_ptr<FakeStore> store;
    std::shared_ptr<FakeAuthorizer> authorizer;
    std::shared_ptr<vh::share::Manager> manager;
    std::shared_ptr<FakeEntryProvider> provider;
    std::shared_ptr<vh::share::TargetResolver> resolver;
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
        provider->add(file(78, 42, "/reports/q1.pdf", 77));
        provider->add(dir(79, 42, "/reports/team", 77));
        provider->add(file(80, 42, "/reports/team/notes.pdf", 79));
        provider->add(dir(99, 42, "/reports_evil"));
        resolver = std::make_shared<vh::share::TargetResolver>(provider);

        Filesystem::setManagerFactoryForTesting([this] { return manager; });
        Filesystem::setResolverFactoryForTesting([this] { return resolver; });

        vh::identities::UserState userState;
        userState.name = "share-owner";
        user = vh::identities::User::detached(7, std::move(userState));
    }

    void TearDown() override {
        Filesystem::resetManagerFactoryForTesting();
        Filesystem::resetResolverFactoryForTesting();
        vh::share::Token::clearPepperForTesting();
    }

    vh::share::CreateLinkResult create(const uint32_t ops) {
        return manager->createLink(rbac::Actor::human(user), {
            .link = makeLink(ops),
            .public_role = vh::share::RoleAssignmentRequest{.vault_role_name = rbac::role::Vault::Contributor().name}
        });
    }

    std::shared_ptr<Session> readySession(const uint32_t ops) {
        const auto created = create(ops);
        auto opened = manager->openPublicSession(created.public_token);
        auto principal = manager->resolvePrincipal(opened.session_token);
        auto session = publicSession();
        session->setSharePrincipal(std::move(principal), opened.session_token);
        return session;
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
