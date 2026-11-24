// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Vault read grants (ops/ReadGrants.hpp, migration 155) against the test DB, the in-memory provider account of the
// upstream control-plane tests (with read keys) and throwaway OpenPGP keys made with the system gpg:
//  - pinning refuses a fingerprint mismatch, an expired, a revoked and a sign-only key, an agent and a non-super-admin;
//    a keyserver key must hash to the pinned fingerprint;
//  - issuing is refused without the permission, for an unpinned recipient, for a local vault without --gateway-only,
//    for a vault that encrypts upstream, and past the per-vault limit;
//  - the grant decrypts with the recipient's secret key (and with each of two), and with nothing else; its gateway
//    credential authenticates and reads only that vault; its upstream key was asked for exactly the vault's bucket;
//  - no plaintext secret appears in the stored rows, the audit trail or the log output;
//  - an upstream failure rolls the gateway credential back; revoke deletes both, and an upstream failure leaves the
//    grant revocation_incomplete until a retry succeeds;
//  - `vh vault read-grant` decides and reports the same.

#include "../helpers/db_suite.hpp"
#include "../helpers/identities.hpp"
#include "../helpers/openpgp_keys.hpp"
#include "../helpers/upstream_admin_fakes.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/s3/Gateway.hpp"
#include "db/query/vault/ReadGrants.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/APIKeys.hpp"
#include "ops/Error.hpp"
#include "ops/ReadGrants.hpp"
#include "ops/S3Gateway.hpp"
#include "ops/Upstream.hpp"
#include "protocols/s3/Auth.hpp"
#include "protocols/s3/CredentialManager.hpp"
#include "protocols/s3/ObjectStore.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "rbac/permission/vault/sync/Action.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/vault/Base.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/curl/Http.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "UsageManager.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <spdlog/sinks/ringbuffer_sink.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace vh::test_read_grants_db {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using namespace test_support::upstream_admin;
namespace rg = ops::read_grants;
namespace gw = ops::s3_gateway;
namespace up = ops::upstream;
namespace s3 = protocols::s3;
using test::openpgp::Keyring;

std::string rgdTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

class ReadGrantsDb : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser;
    inline static std::unique_ptr<Keyring> keys;     // the recipients' secret keys (Sentinel and a client)
    inline static std::unique_ptr<Keyring> other;    // a key no grant is encrypted to
    inline static std::string sentinel, client, stranger, expired, revoked, signOnly;
    std::shared_ptr<FakeCloud> cloud;
    std::optional<vh::config::Config> savedConfig;

    static constexpr const char* kB2Host = "s3.us-west-004.backblazeb2.com";

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_read_grants_db")) return;
        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerAllCommands(router);
        superUser = test::identities::createUser("rgd_super_" + rgdTag(), db::query::rbac::role::Admin::get("super_admin"),
                                                 "rgd-super-" + rgdTag() + "@vaulthalla.test");
        keys = std::make_unique<Keyring>();
        other = std::make_unique<Keyring>();
        if (!keys->available()) return;
        sentinel = keys->generate("Sentinel test (credential handoff) <sentinel@example.test>");
        client = keys->generate("Client test <client@example.test>");
        stranger = other->generate("Stranger <stranger@example.test>");
        expired = keys->generate("Expired <expired@example.test>", "1d", std::string("20200101T000000"));
        signOnly = keys->generateSignOnly("Sign only <signonly@example.test>");
        revoked = keys->generate("Revoked <revoked@example.test>");
        keys->revoke(revoked);
    }

    static void TearDownTestSuite() {
        keys.reset();
        other.reset();
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        if (!keys || !keys->available()) GTEST_SKIP() << "gpg is not installed";
        savedConfig = vh::config::Registry::get();
        cloud = std::make_shared<FakeCloud>();
        padmin::setFactoryForTesting(padmin::Factory{
            .admin = [c = cloud](const std::shared_ptr<vault::model::APIKey>&) -> std::unique_ptr<padmin::AdminClient> {
                return std::make_unique<FakeAdmin>(c);
            },
            .events = nullptr});
        storage::upstream::guard::clearForTesting();
        storage::upstream::guard::reload();
        // Pins persist across tests of the suite (one schema); each test pins what it needs if it isn't yet.
        pinned(sentinel);
        pinned(client);
    }

    void TearDown() override {
        padmin::setFactoryForTesting(std::nullopt);
        storage::s3::curl::http::setTransportForTesting(std::nullopt);
        if (savedConfig) vh::config::Registry::set(*savedConfig);
    }

    // ---- fixtures ----------------------------------------------------------------------------------------------

    static void pinned(const std::string& fpr) {
        if (db::query::vault::ReadGrants::liveRecipient(fpr)) return;
        (void)rg::pinRecipient(superUser, {.fingerprint = fpr, .public_key = keys->publicKey(fpr), .keyserver = {},
                                           .label = std::string("test")});
    }

    static unsigned b2Key() {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "rgd_b2_" + rgdTag(),
                                                          vault::model::S3Provider::BackblazeB2,
                                                          "0041234567890ab0000000001", "K004account-secret-0000000000rgd",
                                                          "us-west-004", std::string("https://") + kB2Host);
        const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        (void)up::enableAdmin(superUser, id, {});
        return id;
    }

    static gw::Credential credentialFor(const UserPtr& principal) {
        return gw::createCredential(superUser, {.name = "rgd_cred_" + rgdTag(), .principal_id = principal->id}).credential;
    }

    static s3::AuthContext authFor(const gw::Credential& credential) {
        const auto fresh = db::query::s3::Gateway::getCredentialById(credential.id);
        return {.user = vh::identities::manager().user(credential.principal_user_id),
                .credential = fresh.value_or(credential),
                .credential_id = credential.id,
                .access_key = credential.access_key,
                .scope_mode = credential.scope_mode,
                .enforce_budget_for_local_requests = false,
                .dev_context = false,
                .signing_region = "us-east-1"};
    }

    // A gateway bucket over a fresh B2 bucket: an S3 vault created from an upstream profile (mirror; objects stored
    // readable unless `encrypt`), bound to the gateway. Returns the vault.
    std::shared_ptr<vault::model::Vault> s3Vault(const bool encrypt = false) {
        const auto profile = gw::createUpstreamProfile(superUser, {.name = "rgd-" + rgdTag(),
                                                                   .api_key = b2Key(),
                                                                   .encrypt_upstream = encrypt,
                                                                   .sync_strategy = std::string("mirror"),
                                                                   .conflict_policy = std::string("keep_local"),
                                                                   .bucket_prefix = {}});
        const auto credential = gw::setCredentialUpstream(superUser, gw::Ref{credentialFor(superUser).id},
                                                          {.profile = gw::ProfileRef{profile.id}});
        const auto bucket = "rgd-bkt-" + rgdTag();
        (void)s3::ObjectStore{}.createBucket(bucket, authFor(credential), "local", 0, "");
        const auto binding = db::query::s3::Gateway::resolveBucket(bucket);
        if (!binding) throw std::runtime_error("the gateway bucket was not bound");
        return runtime::Deps::get().storageManager->getVault(binding->vault_id);
    }

    // A local vault bound to the gateway.
    static std::shared_ptr<vault::model::Vault> localVault() {
        const auto bucket = "rgd-local-" + rgdTag();
        (void)s3::ObjectStore{}.createBucket(bucket, authFor(credentialFor(superUser)), "local", 0, "");
        const auto binding = db::query::s3::Gateway::resolveBucket(bucket);
        return runtime::Deps::get().storageManager->getVault(binding->vault_id);
    }

    static uint32_t vaultRole(const std::string& name, const rbac::role::vault::Base& base) {
        const auto role = rbac::role::Vault::Custom(name, "test", base);
        return db::Transactions::exec("ReadGrantsDb::vaultRole", [&](pqxx::work& txn) {
            return txn.exec(R"SQL(
                INSERT INTO vault_role (name, description, files_permissions, directories_permissions, sync_permissions,
                                        roles_permissions)
                VALUES ($1, 'test', $2::bit(32), $3::bit(32), $4::bit(32), $5::bit(16)) RETURNING id
            )SQL", pqxx::params{name, role.fs.files.toBitString(), role.fs.directories.toBitString(),
                                role.sync.toBitString(), role.roles.toBitString()}).one_field_ref().as<uint32_t>();
        });
    }

    // An unprivileged account holding `base` on the vault.
    static UserPtr memberWith(const uint32_t vaultId, const rbac::role::vault::Base& base, const std::string& prefix) {
        const auto name = prefix + "_" + rgdTag();
        const auto user = test::identities::createUser(name, db::query::rbac::role::Admin::get("unprivileged"),
                                                       name + "@vaulthalla.test");
        const auto roleId = vaultRole(name + "_role", base);
        db::Transactions::exec("ReadGrantsDb::assign", [&](pqxx::work& txn) {
            txn.exec("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) "
                     "VALUES ($1, 'user', $2, $3)", pqxx::params{vaultId, user->id, roleId});
        });
        (void)vh::identities::manager().reconcile();
        return vh::identities::manager().user(user->id);
    }

    static rbac::role::vault::Base readerWithGrants() {
        auto base = rbac::role::vault::Base::Reader();
        base.sync.action.grant(rbac::permission::vault::sync::SyncActionPermissions::ReadGrants);
        return base;
    }

    static std::string refusalCode(const std::function<void()>& fn) {
        try {
            fn();
        } catch (const ops::Refused& e) {
            return e.code;
        } catch (const ops::Denied&) {
            return "denied";
        } catch (const ops::NotFound&) {
            return "not_found";
        } catch (const ops::Invalid&) {
            return "invalid";
        } catch (const ops::Conflict&) {
            return "conflict";
        }
        return "ok";
    }

    static std::pair<int, std::string> cli(const std::string& line, const UserPtr& user) {
        try {
            const auto res = router->executeLine(line, user, nullptr);
            return {res.exit_code, res.stdout_text + res.stderr_text};
        } catch (const std::exception& e) {
            return {1, e.what()};
        }
    }

    // Everything the database holds about read grants and their audit trail, as text.
    static std::string storedText() {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("ReadGrantsDb::storedText", [&](pqxx::work& txn) {
            std::string out;
            for (const auto* q : {"SELECT row_to_json(g)::text FROM vault_read_grant g",
                                  "SELECT row_to_json(r)::text FROM read_grant_recipient r",
                                  "SELECT row_to_json(r)::text FROM vault_read_grant_recipient r",
                                  "SELECT row_to_json(c)::text FROM s3_gateway_credentials c",
                                  "SELECT coalesce(message, '') || ' ' || coalesce(details::text, '') FROM audit_event"})
                for (const auto& row : txn.exec(q)) out += row[0].as<std::string>("") + "\n";
            return out;
        });
    }

    static json opened(const std::string& message, Keyring& ring) {
        const auto plain = ring.decrypt(message);
        if (!plain) return nullptr;
        return json::parse(*plain);
    }
};

// ---- recipients --------------------------------------------------------------------------------------------------

TEST_F(ReadGrantsDb, PinningRefusesAMismatchAndUnusableKeysAndSaysWhich) {
    const auto pin = [&](const std::string& expected, const std::string& keyOf) {
        return refusalCode([&] {
            (void)rg::pinRecipient(superUser, {.fingerprint = expected, .public_key = keys->publicKey(keyOf),
                                               .keyserver = {}, .label = {}});
        });
    };
    EXPECT_EQ(pin(stranger.substr(0, 39) + (stranger.back() == 'A' ? "B" : "A"), client), "fingerprint_mismatch");
    // A key that carries another key's name is never pinned under it: the fingerprint decides.
    EXPECT_EQ(pin(stranger, client), "fingerprint_mismatch");
    EXPECT_EQ(pin(expired, expired), "recipient_unusable");
    EXPECT_EQ(pin(revoked, revoked), "recipient_unusable");
    EXPECT_EQ(pin(signOnly, signOnly), "recipient_unusable");
    EXPECT_EQ(pin("2096C49D7A8F000A", client), "invalid") << "a key id is not a fingerprint";
    try {
        (void)rg::pinRecipient(superUser, {.fingerprint = signOnly, .public_key = keys->publicKey(signOnly)});
    } catch (const ops::Refused& e) {
        EXPECT_NE(std::string(e.what()).find("no valid encryption-capable subkey"), std::string::npos) << e.what();
    }
    try {
        (void)rg::pinRecipient(superUser, {.fingerprint = expired, .public_key = keys->publicKey(expired)});
    } catch (const ops::Refused& e) {
        EXPECT_NE(std::string(e.what()).find("expired"), std::string::npos) << e.what();
    }
    for (const auto& fpr : {expired, revoked, signOnly})
        EXPECT_FALSE(db::query::vault::ReadGrants::liveRecipient(fpr)) << fpr;
    EXPECT_EQ(pin(sentinel, sentinel), "conflict") << "already pinned";
}

TEST_F(ReadGrantsDb, PinningIsAHumanStepForSuperAdmins) {
    Keyring ring;
    const auto fpr = ring.generate("Agent target <agent@example.test>");
    const rg::PinRequest req{.fingerprint = fpr, .public_key = ring.publicKey(fpr)};
    {
        // An agent (vh mcp, /mcp) can never produce the step-up of family secrets.
        const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
        EXPECT_THROW((void)rg::pinRecipient(superUser, req), ops::StepUpRequired);
    }
    EXPECT_FALSE(db::query::vault::ReadGrants::liveRecipient(fpr));
    const auto vault = localVault();
    const auto member = memberWith(vault->id, readerWithGrants(), "rgd_member");
    EXPECT_THROW((void)rg::pinRecipient(member, req), ops::Denied) << "issuing grants is not pinning recipients";
    {
        const auth::stepup::Scope host(auth::stepup::Channel::Host);
        const auto pinnedKey = rg::pinRecipient(superUser, req);
        EXPECT_EQ(pinnedKey.fingerprint, fpr);
        EXPECT_EQ(pinnedKey.algorithm, "ed25519/cv25519");
    }
    // Removing is the same human step.
    {
        const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
        EXPECT_THROW((void)rg::removeRecipient(superUser, fpr), ops::StepUpRequired);
    }
    EXPECT_THROW((void)rg::removeRecipient(member, fpr), ops::Denied);
    EXPECT_EQ(rg::removeRecipient(superUser, fpr).live_grants, 0u);
    EXPECT_FALSE(db::query::vault::ReadGrants::liveRecipient(fpr));
}

TEST_F(ReadGrantsDb, AKeyserverKeyMustHashToThePinnedFingerprint) {
    Keyring ring;
    const auto fpr = ring.generate("Keyserver <keyserver@example.test>");
    const auto good = ring.publicKey(fpr);
    std::string served = good;
    std::vector<std::string> urls;
    storage::s3::curl::http::setTransportForTesting([&](const storage::s3::curl::http::Request& r) {
        urls.push_back(r.url);
        storage::s3::curl::http::Response resp;
        resp.status = 200;
        resp.body = served;
        return resp;
    });
    // The keyserver answers with another key: refused, whatever user IDs it carries.
    served = keys->publicKey(client);
    EXPECT_EQ(refusalCode([&] {
                  (void)rg::pinRecipient(superUser, {.fingerprint = fpr, .keyserver = std::string("https://keys.example.test")});
              }),
              "fingerprint_mismatch");
    ASSERT_EQ(urls.size(), 1u);
    EXPECT_EQ(urls[0], "https://keys.example.test/vks/v1/by-fingerprint/" + fpr) << "looked up by fingerprint only";
    EXPECT_EQ(refusalCode([&] {
                  (void)rg::pinRecipient(superUser, {.fingerprint = fpr, .keyserver = std::string("http://keys.example.test")});
              }),
              "invalid") << "https only";

    served = good;
    const auto pinnedKey = rg::pinRecipient(superUser, {.fingerprint = fpr, .keyserver = std::string("https://keys.example.test/")});
    EXPECT_EQ(pinnedKey.source, "keyserver");
    EXPECT_EQ(pinnedKey.source_url, "https://keys.example.test/vks/v1/by-fingerprint/" + fpr);
    (void)rg::removeRecipient(superUser, fpr);
}

// ---- issuing -----------------------------------------------------------------------------------------------------

TEST_F(ReadGrantsDb, AGrantDecryptsForItsRecipientAndCarriesBothWorkingCredentials) {
    const auto vault = s3Vault();
    const auto s3v = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    ASSERT_TRUE(s3v);
    const auto issued = rg::issue(superUser, {.vault_id = vault->id, .recipients = {sentinel}});
    EXPECT_EQ(issued.grant.state, "active");
    EXPECT_TRUE(issued.ciphertext.starts_with("-----BEGIN PGP MESSAGE-----"));

    // Only the recipient opens it.
    EXPECT_TRUE(opened(issued.ciphertext, *other).is_null()) << "a key it isn't encrypted to";
    const auto doc = opened(issued.ciphertext, *keys);
    ASSERT_TRUE(doc.is_object());
    EXPECT_EQ(doc["type"], rg::kDocumentType);
    EXPECT_EQ(doc["version"], 1);
    EXPECT_EQ(doc["grant_id"], issued.grant.grant_id);
    EXPECT_EQ(doc["vault"]["id"], vault->id);
    EXPECT_EQ(doc["vault"]["name"], vault->name);
    EXPECT_EQ(doc["recipients"], json::array({sentinel}));

    // The gateway half: a vault-allowlist reader credential whose secret authenticates.
    const auto& g = doc["gateway"];
    EXPECT_EQ(g["bucket"], issued.grant.gateway_bucket.value());
    EXPECT_EQ(g["addressing_style"], "path");
    const auto secret = s3::CredentialManager{}.findEnabledSecret(g["access_key_id"].get<std::string>());
    ASSERT_TRUE(secret);
    EXPECT_EQ(secret->secret_access_key, g["secret_access_key"].get<std::string>());
    EXPECT_EQ(secret->credential.scope_mode, "vault_allowlist");
    EXPECT_EQ(secret->credential.principal_user_id, superUser->id);
    const auto selected = db::query::s3::Gateway::listCredentialSelectedVaults(secret->credential.id);
    ASSERT_EQ(selected.size(), 1u);
    EXPECT_EQ(selected[0].vault_id, vault->id);
    const auto role = db::query::s3::Gateway::getEffectiveCredentialVaultRole(secret->credential.id, vault->id,
                                                                              "vault_allowlist");
    ASSERT_TRUE(role);
    EXPECT_TRUE(role->files().canDownload());
    EXPECT_FALSE(role->files().canUpload() || role->files().canDelete() || role->files().canOverwrite());

    // The upstream half: the key created for exactly the vault's bucket, read-only.
    const auto& u = doc["upstream"];
    ASSERT_TRUE(u.is_object());
    EXPECT_EQ(u["bucket"], s3v->bucket);
    EXPECT_EQ(u["endpoint"], "https://s3.us-west-004.backblazeb2.com");
    EXPECT_EQ(u["region"], "us-west-004");
    EXPECT_EQ(u["capabilities"], json::array({"listBuckets", "listFiles", "readFiles"}));
    EXPECT_EQ(u["objects_readable"], true);
    EXPECT_EQ(u["storage_layout"], "transparent");
    {
        std::scoped_lock lock(cloud->mutex);
        ASSERT_EQ(cloud->readKeyRequests.size(), 1u);
        EXPECT_EQ(cloud->readKeyRequests[0].bucket, s3v->bucket);
        ASSERT_TRUE(cloud->readKeys.contains(u["access_key_id"].get<std::string>()));
    }
    EXPECT_EQ(issued.grant.upstream_key_id, u["access_key_id"].get<std::string>());

    // The stored message is the same one.
    EXPECT_EQ(rg::get(superUser, issued.grant.grant_id).ciphertext, issued.ciphertext);
}

TEST_F(ReadGrantsDb, TwoRecipientsBothDecryptOneMessage) {
    Keyring second;
    const auto secondFpr = second.generate("Second <second@example.test>");
    (void)rg::pinRecipient(superUser, {.fingerprint = secondFpr, .public_key = second.publicKey(secondFpr)});
    const auto vault = s3Vault();
    const auto issued = rg::issue(superUser, {.vault_id = vault->id, .recipients = {sentinel, secondFpr}});
    const auto a = opened(issued.ciphertext, *keys);
    const auto b = opened(issued.ciphertext, second);
    ASSERT_TRUE(a.is_object());
    ASSERT_TRUE(b.is_object());
    EXPECT_EQ(a, b);
    EXPECT_TRUE(opened(issued.ciphertext, *other).is_null());
    EXPECT_EQ(refusalCode([&] {
                  (void)rg::issue(superUser, {.vault_id = vault->id, .recipients = {sentinel, client, secondFpr}});
              }),
              "invalid") << "one or two recipients";
    EXPECT_EQ(refusalCode([&] { (void)rg::issue(superUser, {.vault_id = vault->id, .recipients = {sentinel, sentinel}}); }),
              "invalid");
}

TEST_F(ReadGrantsDb, IssuingIsRefusedWhereItMustBe) {
    const auto vault = s3Vault();
    // Without the permission (a plain reader), and with it but without reading the vault.
    const auto reader = memberWith(vault->id, rbac::role::vault::Base::Reader(), "rgd_reader");
    EXPECT_EQ(refusalCode([&] { (void)rg::issue(reader, {.vault_id = vault->id, .recipients = {sentinel}}); }), "denied");
    auto grantsOnly = rbac::role::vault::Base::None();
    grantsOnly.sync.action.grant(rbac::permission::vault::sync::SyncActionPermissions::ReadGrants);
    const auto blind = memberWith(vault->id, grantsOnly, "rgd_blind");
    EXPECT_EQ(refusalCode([&] { (void)rg::issue(blind, {.vault_id = vault->id, .recipients = {sentinel}}); }), "denied")
        << "a grant never reaches further than its issuer";

    // An unpinned recipient, or none.
    EXPECT_EQ(refusalCode([&] { (void)rg::issue(superUser, {.vault_id = vault->id, .recipients = {stranger}}); }),
              "recipient_not_pinned");
    EXPECT_EQ(refusalCode([&] { (void)rg::issue(superUser, {.vault_id = vault->id, .recipients = {}}); }), "invalid");

    // A local vault: only with --gateway-only.
    const auto local = localVault();
    EXPECT_EQ(refusalCode([&] { (void)rg::issue(superUser, {.vault_id = local->id, .recipients = {sentinel}}); }),
              "local_vault");
    const auto gatewayOnly = rg::issue(superUser, {.vault_id = local->id, .recipients = {sentinel}, .gateway_only = true});
    EXPECT_TRUE(gatewayOnly.grant.gateway_only);
    const auto doc = opened(gatewayOnly.ciphertext, *keys);
    EXPECT_TRUE(doc["upstream"].is_null());
    EXPECT_EQ(doc["upstream_omitted"], "local_vault");

    // A vault that encrypts upstream: the upstream half would be useless.
    const auto encrypted = s3Vault(true);
    EXPECT_EQ(refusalCode([&] { (void)rg::issue(superUser, {.vault_id = encrypted->id, .recipients = {sentinel}}); }),
              "upstream_encrypted");
    {
        std::scoped_lock lock(cloud->mutex);
        EXPECT_TRUE(cloud->readKeyRequests.empty()) << "no provider key was asked for";
    }

    // A provider without read keys (AWS S3, Cloudflare R2 today).
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->readKeysSupported = false;
    }
    EXPECT_EQ(refusalCode([&] { (void)rg::issue(superUser, {.vault_id = vault->id, .recipients = {sentinel}}); }),
              "upstream_unsupported");
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->readKeysSupported = true;
    }

    // The per-vault limit.
    auto cfg = vh::config::Registry::get();
    cfg.vaults.read_grants.max_per_vault = 2;
    vh::config::Registry::set(cfg);
    const auto member = memberWith(vault->id, readerWithGrants(), "rgd_issuer");
    (void)rg::issue(member, {.vault_id = vault->id, .recipients = {sentinel}});
    (void)rg::issue(member, {.vault_id = vault->id, .recipients = {client}});
    EXPECT_EQ(refusalCode([&] { (void)rg::issue(member, {.vault_id = vault->id, .recipients = {sentinel}}); }),
              "read_grant_limit");
    {
        std::scoped_lock lock(cloud->mutex);
        EXPECT_EQ(cloud->readKeys.size(), 2u) << "no third key was minted";
    }
    EXPECT_EQ(rg::list(member, vault->id).size(), 2u);
    EXPECT_EQ(refusalCode([&] { (void)rg::list(reader, vault->id); }), "denied");
}

TEST_F(ReadGrantsDb, AnUpstreamFailureRollsTheGatewayCredentialBack) {
    const auto vault = s3Vault();
    const auto credentialsBefore = db::query::s3::Gateway::listCredentials().size();
    for (const bool missing : {true, false}) {
        {
            std::scoped_lock lock(cloud->mutex);
            cloud->writeKeysMissing = missing;
            cloud->createReadKeyFails = !missing;
        }
        const auto code = refusalCode([&] { (void)rg::issue(superUser, {.vault_id = vault->id, .recipients = {sentinel}}); });
        EXPECT_EQ(code, missing ? "upstream_key_refused" : "upstream_key_failed");
        EXPECT_EQ(db::query::s3::Gateway::listCredentials().size(), credentialsBefore) << "the gateway credential is gone";
        EXPECT_TRUE(db::query::vault::ReadGrants::list(vault->id, true).empty()) << "no half grant is recorded";
    }
    try {
        {
            std::scoped_lock lock(cloud->mutex);
            cloud->writeKeysMissing = true;
            cloud->createReadKeyFails = false;
        }
        (void)rg::issue(superUser, {.vault_id = vault->id, .recipients = {sentinel}});
    } catch (const ops::Refused& e) {
        EXPECT_NE(std::string(e.what()).find("writeKeys"), std::string::npos) << e.what();
    }
}

// ---- revoking ----------------------------------------------------------------------------------------------------

TEST_F(ReadGrantsDb, RevokeDeletesBothAndAnUpstreamFailureStaysIncompleteUntilRetried) {
    const auto vault = s3Vault();
    const auto issued = rg::issue(superUser, {.vault_id = vault->id, .recipients = {sentinel}});
    const auto accessKey = *issued.grant.gateway_access_key;
    const auto keyId = *issued.grant.upstream_key_id;

    {
        std::scoped_lock lock(cloud->mutex);
        cloud->deleteReadKeyFails = true;
    }
    EXPECT_EQ(refusalCode([&] { (void)rg::revoke(superUser, issued.grant.grant_id); }), "revocation_incomplete");
    auto row = rg::get(superUser, issued.grant.grant_id);
    EXPECT_EQ(row.state, "revocation_incomplete");
    ASSERT_TRUE(row.revocation_error);
    EXPECT_NE(row.revocation_error->find(keyId), std::string::npos);
    EXPECT_FALSE(s3::CredentialManager{}.findEnabledSecret(accessKey)) << "the gateway half is gone already";
    {
        std::scoped_lock lock(cloud->mutex);
        EXPECT_TRUE(cloud->readKeys.contains(keyId)) << "the provider still has the key";
    }
    // It still counts against the limit, and the API key that made it can't be removed meanwhile.
    EXPECT_EQ(db::query::vault::ReadGrants::liveCount(vault->id), 1u);

    {
        std::scoped_lock lock(cloud->mutex);
        cloud->deleteReadKeyFails = false;
    }
    const auto revokedGrant = rg::revoke(superUser, issued.grant.grant_id);
    EXPECT_EQ(revokedGrant.state, "revoked");
    EXPECT_TRUE(revokedGrant.revoked_at.has_value());
    EXPECT_FALSE(revokedGrant.revocation_error.has_value());
    {
        std::scoped_lock lock(cloud->mutex);
        EXPECT_FALSE(cloud->readKeys.contains(keyId));
        EXPECT_EQ(cloud->deleteReadKeyCalls, (std::vector<std::string>{keyId, keyId}));
    }
    EXPECT_EQ(db::query::vault::ReadGrants::liveCount(vault->id), 0u);
    EXPECT_EQ(refusalCode([&] { (void)rg::revoke(superUser, issued.grant.grant_id); }), "conflict");
}

TEST_F(ReadGrantsDb, AnApiKeyWithLiveGrantsIsNotRemoved) {
    const auto vault = s3Vault();
    const auto s3v = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    const auto issued = rg::issue(superUser, {.vault_id = vault->id, .recipients = {sentinel}});
    EXPECT_EQ(db::query::vault::ReadGrants::liveCountForApiKey(s3v->api_key_id), 1u);
    (void)rg::revoke(superUser, issued.grant.grant_id);
    EXPECT_EQ(db::query::vault::ReadGrants::liveCountForApiKey(s3v->api_key_id), 0u);
}

// ---- secrets never at rest, in the audit trail or in logs ---------------------------------------------------------

TEST_F(ReadGrantsDb, NoPlaintextSecretIsStoredAuditedOrLogged) {
    auto sink = std::make_shared<spdlog::sinks::ringbuffer_sink_mt>(4096);
    sink->set_level(spdlog::level::trace);
    std::vector<std::pair<std::shared_ptr<spdlog::logger>, spdlog::level::level_enum>> loggers;
    spdlog::apply_all([&](const std::shared_ptr<spdlog::logger>& l) {
        loggers.emplace_back(l, l->level());
        l->set_level(spdlog::level::trace);
        l->sinks().push_back(sink);
    });

    const auto vault = s3Vault();
    const auto issued = rg::issue(superUser, {.vault_id = vault->id, .recipients = {sentinel}});
    const auto [code, out] = cli("vault read-grant issue " + std::to_string(vault->id) + " --recipient " + sentinel +
                                     " --json", superUser);
    ASSERT_EQ(code, 0) << out;
    const auto viaCli = json::parse(out);
    (void)rg::revoke(superUser, issued.grant.grant_id);

    for (const auto& [l, level] : loggers) {
        std::erase(l->sinks(), std::static_pointer_cast<spdlog::sinks::sink>(sink));
        l->set_level(level);
    }

    std::vector<std::string> secrets;
    for (const auto* message : {&issued.ciphertext, &viaCli["ciphertext"].get_ref<const std::string&>()}) {
        const auto doc = opened(*message, *keys);
        ASSERT_TRUE(doc.is_object());
        secrets.push_back(doc["gateway"]["secret_access_key"].get<std::string>());
        secrets.push_back(doc["upstream"]["secret_access_key"].get<std::string>());
    }
    std::string logs;
    for (const auto& line : sink->last_formatted()) logs += line;
    EXPECT_NE(logs.find("read grant"), std::string::npos) << "the issue was logged (without secrets)";
    const auto stored = storedText();
    EXPECT_NE(stored.find(issued.grant.grant_id), std::string::npos);
    for (const auto& secret : secrets) {
        ASSERT_GE(secret.size(), 16u);
        EXPECT_EQ(stored.find(secret), std::string::npos) << "a secret is stored or audited";
        EXPECT_EQ(logs.find(secret), std::string::npos) << "a secret was logged";
        EXPECT_EQ(out.find(secret), std::string::npos) << "a secret was printed";
    }
    EXPECT_EQ(stored.find(rg::kDocumentType), std::string::npos) << "no plaintext grant document is stored";
}

// ---- the CLI ------------------------------------------------------------------------------------------------------

TEST_F(ReadGrantsDb, TheCliIssuesListsShowsAndRevokes) {
    const auto vault = s3Vault();
    const auto member = memberWith(vault->id, readerWithGrants(), "rgd_cli");
    const auto vid = std::to_string(vault->id);

    // Plain output: the armored message alone on stdout (pipe it to gpg --decrypt), the grant id on stderr.
    const auto plain = router->executeLine("vault read-grant issue " + vid + " --recipient " + sentinel, member, nullptr);
    ASSERT_EQ(plain.exit_code, 0) << plain.stdout_text << plain.stderr_text;
    EXPECT_TRUE(plain.stdout_text.starts_with("-----BEGIN PGP MESSAGE-----"));
    EXPECT_TRUE(opened(plain.stdout_text, *keys).is_object());
    EXPECT_NE(plain.stderr_text.find("Issued read grant"), std::string::npos);

    auto [code, out] = cli("vault read-grant list --vault " + vid + " --json", member);
    ASSERT_EQ(code, 0) << out;
    const auto listed = json::parse(out)["grants"];
    ASSERT_EQ(listed.size(), 1u);
    const auto grantId = listed[0]["grant_id"].get<std::string>();
    EXPECT_FALSE(listed[0].contains("ciphertext"));
    EXPECT_EQ(listed[0]["upstream"]["provider"], "aws-s3") << "the fake account's provider id";

    std::tie(code, out) = cli("vault read-grant show " + grantId + " --ciphertext", member);
    ASSERT_EQ(code, 0) << out;
    EXPECT_EQ(out, plain.stdout_text);

    // Refusals carry their code.
    std::tie(code, out) = cli("vault read-grant issue " + vid + " --recipient " + stranger + " --json", member);
    EXPECT_NE(code, 0);
    EXPECT_EQ(json::parse(out)["error"], "recipient_not_pinned") << out;
    std::tie(code, out) = cli("vault read-grant recipient add --fingerprint " + stranger + " --keyserver https://k.example.test",
                              member);
    EXPECT_NE(code, 0);
    EXPECT_NE(out.find("super admins"), std::string::npos) << out;

    std::tie(code, out) = cli("vault read-grant recipient list --json", member);
    ASSERT_EQ(code, 0) << out;
    bool sawSentinel = false;
    const auto recipientList = json::parse(out);
    for (const auto& r : recipientList["recipients"])
        if (r["fingerprint"] == sentinel) sawSentinel = true;
    EXPECT_TRUE(sawSentinel);

    std::tie(code, out) = cli("vault read-grant revoke " + grantId + " --json", member);
    ASSERT_EQ(code, 0) << out;
    EXPECT_EQ(json::parse(out)["state"], "revoked");
    std::tie(code, out) = cli("vault read-grant list --json", member);
    ASSERT_EQ(code, 0) << out;
    EXPECT_TRUE(json::parse(out)["grants"].empty());
}

}
