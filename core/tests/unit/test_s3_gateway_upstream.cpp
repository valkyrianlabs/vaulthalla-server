// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// S3 gateway upstream profiles (migration 154): what a gateway CreateBucket creates. Against the test DB and an
// in-memory provider account (the fake AdminClient of the upstream control-plane tests):
//  - a credential without an upstream source still creates a local vault, with no provider call;
//  - a credential with a profile creates the upstream bucket (or adopts this account's own while it is empty), an S3
//    vault with the profile's settings, and binds it;
//  - a bucket that holds objects, a name another account holds, and a key without bucket administration are refused
//    with an S3 error, and nothing is created, deleted or silently made local;
//  - the server default applies only to credentials that opted in; a request selects a profile with its
//    LocationConstraint or its signing region, and "local" forces a local vault;
//  - a request may only name the credential's own profile or one on its allowlist;
//  - who may set it: credential management plus provision + the key's Consume, for the setter and for the principal,
//    and the principal again on every CreateBucket;
//  - a profile's changed sync settings follow to the buckets created from it, per credential and server setting;
//  - `vh s3-gateway` and ws s3.gateway.* decide and report the same.

#include "../helpers/db_suite.hpp"
#include "../helpers/identities.hpp"
#include "../helpers/s3_gateway.hpp"
#include "../helpers/upstream_admin_fakes.hpp"

#include "config/Registry.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/recovery/Policy.hpp"
#include "db/query/s3/Gateway.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/APIKeys.hpp"
#include "ops/Config.hpp"
#include "ops/Error.hpp"
#include "ops/Roles.hpp"
#include "ops/S3Gateway.hpp"
#include "ops/Upstream.hpp"
#include "ops/Vaults.hpp"
#include "protocols/s3/Auth.hpp"
#include "protocols/s3/CredentialManager.hpp"
#include "protocols/s3/Error.hpp"
#include "protocols/s3/ObjectStore.hpp"
#include "protocols/s3/Router.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/S3Gateway.hpp"
#include "recovery/Model.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/s3/provider/admin/Internal.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Provisioner.hpp"
#include "storage/upstream/model/Bucket.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "UsageManager.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <vl/sigv4/canonical.hpp>
#include <vl/sigv4/crypto.hpp>
#include <vl/sigv4/signer.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace vh::test_s3_gateway_upstream {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using namespace test_support::upstream_admin;
namespace gw = ops::s3_gateway;
namespace up = ops::upstream;
namespace s3 = protocols::s3;
namespace http = boost::beast::http;
namespace umodel = storage::upstream::model;

std::string gwuTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

class GatewayUpstreamTest : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser;
    std::shared_ptr<FakeCloud> cloud;
    std::optional<vh::config::Config> savedConfig;

    static constexpr const char* kB2Host = "s3.us-west-004.backblazeb2.com";

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_s3_gateway_upstream")) return;
        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerS3GatewayCommands(router);
        superUser = test::identities::createUser("gwu_super_" + gwuTag(), db::query::rbac::role::Admin::get("super_admin"),
                                                 "gwu-super-" + gwuTag() + "@vaulthalla.test");
    }

    static void TearDownTestSuite() { tearDownDbSuite(); }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        savedConfig = vh::config::Registry::get();
        cloud = std::make_shared<FakeCloud>();
        padmin::setFactoryForTesting(padmin::Factory{
            .admin = [c = cloud](const std::shared_ptr<vault::model::APIKey>&) -> std::unique_ptr<padmin::AdminClient> {
                return std::make_unique<FakeAdmin>(c);
            },
            .events = nullptr});
        storage::upstream::guard::clearForTesting();   // an earlier suite's own protection set, if it left one
        storage::upstream::guard::reload();
    }

    void TearDown() override {
        padmin::setFactoryForTesting(std::nullopt);
        if (savedConfig) vh::config::Registry::set(*savedConfig);
    }

    // ---- fixtures ----------------------------------------------------------------------------------------------

    // A Backblaze B2 application key over the fake account, enabled for provider administration unless told not to.
    static unsigned b2Key(const bool enable = true) {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "gwu_b2_" + gwuTag(), vault::model::S3Provider::BackblazeB2,
                                                          "0041234567890ab0000000001", "K004secret-value-000000000000000",
                                                          "us-west-004", std::string("https://") + kB2Host);
        const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        if (enable) (void)up::enableAdmin(superUser, id, {});
        return id;
    }

    static std::string profileName() { return "gwu-" + gwuTag(); }
    static std::string bucketName() { return "gwu-bkt-" + gwuTag(); }

    // The first consumer's settings: no upstream encryption, mirror + keep_local.
    static gw::UpstreamProfile mirrorProfile(const unsigned keyId, const std::string& prefix = {}) {
        return gw::createUpstreamProfile(superUser, {.name = profileName(),
                                                     .api_key = keyId,
                                                     .encrypt_upstream = false,
                                                     .sync_strategy = std::string("mirror"),
                                                     .conflict_policy = std::string("keep_local"),
                                                     .bucket_prefix = prefix});
    }

    static gw::Credential credentialFor(const UserPtr& principal) {
        return gw::createCredential(superUser, {.name = "gwu_cred_" + gwuTag(), .principal_id = principal->id}).credential;
    }

    static gw::Credential withProfile(const gw::Credential& credential, const gw::UpstreamProfile& profile) {
        return gw::setCredentialUpstream(superUser, gw::Ref{credential.id}, {.profile = gw::ProfileRef{profile.id}});
    }

    // Lets requests made with the credential name these profiles (what `--allow-upstream` does).
    static gw::Credential allow(const gw::Credential& credential, const std::vector<gw::UpstreamProfile>& profiles) {
        std::vector<gw::ProfileRef> refs;
        for (const auto& profile : profiles) refs.emplace_back(profile.id);
        return gw::setCredentialUpstream(superUser, gw::Ref{credential.id}, {.allowed = refs});
    }

    // The request context the gateway builds for a signed request of this credential.
    static s3::AuthContext authFor(const gw::Credential& credential, const std::string& signingRegion = "us-east-1") {
        const auto fresh = db::query::s3::Gateway::getCredentialById(credential.id);
        return {.user = vh::identities::manager().user(credential.principal_user_id),
                .credential = fresh.value_or(credential),
                .credential_id = credential.id,
                .access_key = credential.access_key,
                .scope_mode = credential.scope_mode,
                .enforce_budget_for_local_requests = false,
                .dev_context = false,
                .signing_region = signingRegion};
    }

    static s3::ResolvedBucket createBucket(const std::string& bucket, const s3::AuthContext& auth,
                                           const std::string& locationConstraint = {}) {
        return s3::ObjectStore{}.createBucket(bucket, auth, "local", 0, locationConstraint);
    }

    // The S3 error a CreateBucket answers with ("" when it succeeds).
    static std::pair<std::string, http::status> refusal(const std::string& bucket, const s3::AuthContext& auth,
                                                        const std::string& locationConstraint = {}) {
        try {
            (void)createBucket(bucket, auth, locationConstraint);
        } catch (const s3::S3Error& e) {
            return {e.code, e.status};
        }
        return {"", http::status::ok};
    }

    static std::shared_ptr<vault::model::Vault> vaultOf(const std::string& bucket) {
        const auto binding = db::query::s3::Gateway::resolveBucket(bucket);
        return binding ? runtime::Deps::get().storageManager->getVault(binding->vault_id) : nullptr;
    }

    static std::shared_ptr<sync::model::RemotePolicy> policyOf(const std::string& bucket) {
        const auto binding = db::query::s3::Gateway::resolveBucket(bucket);
        if (!binding) return nullptr;
        const auto engine = std::dynamic_pointer_cast<storage::CloudEngine>(
            runtime::Deps::get().storageManager->getEngine(binding->vault_id));
        return engine ? engine->remote_policy() : nullptr;
    }

    static std::optional<umodel::Bucket> upstreamRow(const std::string& name) {
        return db::query::upstream::Bucket::getByIdentity("backblaze-b2", kB2Host, name);
    }

    void seedBucket(const std::string& name, std::map<std::string, uint64_t> objects = {}) {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets[name].objects = std::move(objects);
    }

    bool existsUpstream(const std::string& name) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->buckets.contains(name);
    }

    unsigned providerCalls() {
        std::scoped_lock lock(cloud->mutex);
        return cloud->calls;
    }

    static size_t vaultCount() { return db::query::vault::Vault::listVaults().size(); }

    static void setServerDefaults(const std::string& profile, const bool reapply = true) {
        auto cfg = vh::config::Registry::get();
        cfg.s3_gateway.default_upstream_profile = profile;
        cfg.s3_gateway.reapply_upstream_profile_changes = reapply;
        vh::config::Registry::set(cfg);
    }

    // An admin with exactly these permissions.
    static UserPtr adminWith(const std::string& prefix, const std::vector<std::pair<std::string, bool>>& permissions) {
        const auto roleName = prefix + "_role_" + gwuTag();
        (void)ops::roles::createAdminRole(superUser, {.name = roleName, .permissions = {.changes = permissions}}, "test");
        const auto name = prefix + "_" + gwuTag();
        return test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName), name + "@vaulthalla.test");
    }

    static std::pair<int, std::string> cli(const std::string& line, const UserPtr& user) {
        try {
            const auto res = router->executeLine(line, user, nullptr);
            return {res.exit_code, res.stdout_text + res.stderr_text};
        } catch (const std::exception& e) {
            return {1, e.what()};
        }
    }

    static std::shared_ptr<protocols::ws::Session> ws(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }
};

// ---- the unchanged path --------------------------------------------------------------------------------------------

TEST_F(GatewayUpstreamTest, ACredentialWithoutAnUpstreamSourceStillCreatesALocalVault) {
    const auto keyId = b2Key();
    (void)mirrorProfile(keyId);   // a profile nobody selected changes nothing
    const auto credential = credentialFor(superUser);
    const auto before = providerCalls();

    const auto name = bucketName();
    const auto bucket = createBucket(name, authFor(credential));
    EXPECT_EQ(bucket.mode, "local");
    const auto vault = vaultOf(name);
    ASSERT_TRUE(vault);
    EXPECT_EQ(vault->type, vault::model::VaultType::Local);
    const auto binding = db::query::s3::Gateway::resolveBucket(name);
    ASSERT_TRUE(binding);
    EXPECT_FALSE(binding->upstream_profile_id);
    EXPECT_FALSE(binding->created_by_credential_id);
    EXPECT_EQ(providerCalls(), before) << "a local bucket never calls the provider";
    EXPECT_FALSE(existsUpstream(name));

    const auto upstream = gw::upstreamOf(*db::query::s3::Gateway::getCredentialById(credential.id));
    EXPECT_EQ(upstream.source, "local");
    EXPECT_FALSE(upstream.profile);
}

// ---- creating upstream ---------------------------------------------------------------------------------------------

TEST_F(GatewayUpstreamTest, AProfileCreatesTheUpstreamBucketAndBindsAVaultWithItsSettings) {
    const auto keyId = b2Key();
    const auto profile = mirrorProfile(keyId, "vlp-");
    const auto credential = withProfile(credentialFor(superUser), profile);

    const auto name = bucketName();
    ASSERT_FALSE(existsUpstream("vlp-" + name));
    const auto bucket = createBucket(name, authFor(credential));
    EXPECT_EQ(bucket.mode, "remote_cache");

    // The upstream bucket: created by Vaulthalla under the prefixed name, in the key's region.
    ASSERT_TRUE(existsUpstream("vlp-" + name));
    EXPECT_FALSE(existsUpstream(name));
    const auto row = upstreamRow("vlp-" + name);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->ownership, umodel::Ownership::Managed);
    EXPECT_TRUE(row->created_by_vaulthalla);
    EXPECT_EQ(row->provisioning_state, umodel::ProvisioningState::Ready);

    // The vault: an S3 vault named after the gateway bucket, with the profile's key, encryption and sync settings.
    const auto vault = std::dynamic_pointer_cast<vault::model::S3Vault>(vaultOf(name));
    ASSERT_TRUE(vault);
    EXPECT_EQ(vault->name, name);
    EXPECT_EQ(vault->owner_id, superUser->id);
    EXPECT_EQ(vault->api_key_id, keyId);
    EXPECT_EQ(vault->bucket, "vlp-" + name);
    EXPECT_FALSE(vault->encrypt_upstream);
    EXPECT_EQ(row->vault_id.value_or(0), vault->id);
    const auto policy = policyOf(name);
    ASSERT_TRUE(policy);
    EXPECT_EQ(policy->strategy, sync::model::RemotePolicy::Strategy::Mirror);
    EXPECT_EQ(policy->conflict_policy, sync::model::RemotePolicy::ConflictPolicy::KeepLocal);

    // The binding records who made it and from what, so the bucket can follow its profile.
    const auto binding = db::query::s3::Gateway::resolveBucket(name);
    ASSERT_TRUE(binding);
    EXPECT_EQ(binding->created_by_credential_id.value_or(0), credential.id);
    EXPECT_EQ(binding->upstream_profile_id.value_or(0), profile.id);

    // CreateBucket again is the client's "make sure it exists": the same bucket, nothing new anywhere.
    const auto vaults = vaultCount();
    const auto calls = providerCalls();
    EXPECT_EQ(createBucket(name, authFor(credential)).vault_id, bucket.vault_id);
    EXPECT_EQ(vaultCount(), vaults);
    EXPECT_EQ(providerCalls(), calls);
}

TEST_F(GatewayUpstreamTest, ThisAccountsOwnEmptyBucketIsAdopted) {
    const auto keyId = b2Key();
    const auto credential = withProfile(credentialFor(superUser), mirrorProfile(keyId));
    const auto name = bucketName();
    seedBucket(name);

    EXPECT_EQ(createBucket(name, authFor(credential)).mode, "remote_cache");
    const auto row = upstreamRow(name);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->ownership, umodel::Ownership::Adopted);
    EXPECT_FALSE(row->created_by_vaulthalla) << "an adopted bucket is never recorded as created by Vaulthalla";
    const auto vault = std::dynamic_pointer_cast<vault::model::S3Vault>(vaultOf(name));
    ASSERT_TRUE(vault);
    EXPECT_EQ(vault->bucket, name);
    std::scoped_lock lock(cloud->mutex);
    EXPECT_EQ(cloud->deleteBucketCalls, 0u);
}

TEST_F(GatewayUpstreamTest, ABucketThatHoldsObjectsIsRefusedAndLeftAlone) {
    const auto keyId = b2Key();
    const auto credential = withProfile(credentialFor(superUser), mirrorProfile(keyId));   // mirror + keep_local
    const auto name = bucketName();
    seedBucket(name, {{"backups/2026-11-22.tar.gpg", 4096}});
    const auto vaults = vaultCount();

    const auto [code, status] = refusal(name, authFor(credential));
    EXPECT_EQ(code, "BucketAlreadyExists");
    EXPECT_EQ(status, http::status::conflict);

    // Nothing was taken over: no vault, no gateway bucket, no claim, and every object is still there.
    EXPECT_EQ(vaultCount(), vaults);
    EXPECT_FALSE(db::query::s3::Gateway::resolveBucket(name));
    const auto row = upstreamRow(name);
    EXPECT_FALSE(row && (row->vault_id || row->created_by_vaulthalla || row->ownership != umodel::Ownership::Unmanaged));
    {
        std::scoped_lock lock(cloud->mutex);
        EXPECT_EQ(cloud->buckets.at(name).objects.size(), 1u);
        EXPECT_EQ(cloud->deleteBucketCalls, 0u);
    }

    // Empty means no object version at all: a bucket whose objects are all hidden or non-current (Backblaze keeps
    // every version) lists nothing, and is still not empty.
    const auto hidden = bucketName();
    seedBucket(hidden);
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets.at(hidden).history.push_back({.key = "old.tar.gpg", .size = 1, .etag = "e", .last_modified = {},
                                                     .version_id = std::string("v1"), .delete_marker = false,
                                                     .latest = false});
    }
    EXPECT_EQ(refusal(hidden, authFor(credential)).first, "BucketAlreadyExists");
    EXPECT_FALSE(db::query::s3::Gateway::resolveBucket(hidden));
    EXPECT_EQ(vaultCount(), vaults);
}

TEST_F(GatewayUpstreamTest, ANameAnotherAccountHoldsIsRefused) {
    const auto keyId = b2Key();
    const auto credential = withProfile(credentialFor(superUser), mirrorProfile(keyId));
    // Backblaze names are global: HeadBucket answers 403 for one, and hides the other until CreateBucket collides.
    const auto forbidden = bucketName(), hidden = bucketName();
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->otherAccount.insert(forbidden);
        cloud->takenElsewhere.insert(hidden);
    }
    const auto vaults = vaultCount();
    for (const auto& name : {forbidden, hidden}) {
        const auto [code, status] = refusal(name, authFor(credential));
        EXPECT_EQ(code, "BucketAlreadyExists") << name;
        EXPECT_EQ(status, http::status::conflict) << name;
        EXPECT_FALSE(db::query::s3::Gateway::resolveBucket(name)) << name;
        EXPECT_FALSE(existsUpstream(name)) << name;
        const auto row = upstreamRow(name);
        EXPECT_FALSE(row && row->created_by_vaulthalla) << name;
    }
    EXPECT_EQ(vaultCount(), vaults) << "a refused CreateBucket never falls back to a local vault";
}

TEST_F(GatewayUpstreamTest, AKeyWithoutBucketAdministrationIsRefused) {
    // No profile over a key that can't administer buckets.
    const auto plainKey = b2Key(/*enable=*/false);
    EXPECT_THROW((void)mirrorProfile(plainKey), ops::Invalid);

    // A key that lost administration after its profile was set up: the CreateBucket fails, it is not made local.
    const auto keyId = b2Key();
    const auto credential = withProfile(credentialFor(superUser), mirrorProfile(keyId));
    (void)up::disableAdmin(superUser, keyId);
    const auto name = bucketName();
    const auto vaults = vaultCount();
    const auto before = providerCalls();
    const auto [code, status] = refusal(name, authFor(credential));
    EXPECT_EQ(code, "InvalidArgument");
    EXPECT_EQ(status, http::status::bad_request);
    EXPECT_EQ(vaultCount(), vaults);
    EXPECT_FALSE(db::query::s3::Gateway::resolveBucket(name));
    EXPECT_EQ(providerCalls(), before) << "nothing is sent to a provider the key may not administer";
}

TEST_F(GatewayUpstreamTest, AProviderFailureIsAnswered503AndLeavesNothingBehind) {
    const auto keyId = b2Key();
    const auto credential = withProfile(credentialFor(superUser), mirrorProfile(keyId));
    const auto name = bucketName();
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->headFails.insert(name);
    }
    const auto vaults = vaultCount();
    const auto [code, status] = refusal(name, authFor(credential));
    EXPECT_EQ(code, "ServiceUnavailable");
    EXPECT_EQ(status, http::status::service_unavailable);
    EXPECT_EQ(vaultCount(), vaults);
    EXPECT_FALSE(db::query::s3::Gateway::resolveBucket(name));

    // The same request works once the provider answers again.
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->headFails.clear();
    }
    EXPECT_EQ(createBucket(name, authFor(credential)).mode, "remote_cache");
}

// ---- which profile -------------------------------------------------------------------------------------------------

TEST_F(GatewayUpstreamTest, TheServerDefaultAppliesOnlyToCredentialsThatOptedIn) {
    const auto keyId = b2Key();
    const auto profile = mirrorProfile(keyId);
    setServerDefaults(profile.name);

    // Not opted in: a server default never changes what an existing credential creates.
    const auto plain = credentialFor(superUser);
    const auto localName = bucketName();
    EXPECT_EQ(createBucket(localName, authFor(plain)).mode, "local");

    const auto follower = gw::setCredentialUpstream(superUser, gw::Ref{credentialFor(superUser).id},
                                                    {.source = std::string("server_default")});
    EXPECT_TRUE(follower.upstream_server_default);
    const auto upstream = gw::upstreamOf(follower);
    EXPECT_EQ(upstream.source, "server_default");
    ASSERT_TRUE(upstream.profile);
    EXPECT_EQ(upstream.profile->id, profile.id);
    const auto name = bucketName();
    EXPECT_EQ(createBucket(name, authFor(follower)).mode, "remote_cache");
    EXPECT_TRUE(existsUpstream(name));

    // The default goes away: the follower's CreateBucket fails loudly instead of creating a local vault.
    setServerDefaults("");
    const auto vaults = vaultCount();
    const auto orphan = bucketName();
    const auto [code, status] = refusal(orphan, authFor(follower));
    EXPECT_EQ(code, "InvalidArgument");
    EXPECT_EQ(vaultCount(), vaults);
    EXPECT_FALSE(gw::upstreamOf(follower).problem.empty());

    // A default that names no profile is refused where it is set.
    auto settings = json(vh::config::Registry::get());
    const auto complaint = [&](const std::string& name) {
        settings["s3_gateway"]["default_upstream_profile"] = name;
        try {
            ops::config::validateSettings(settings);
        } catch (const ops::Invalid& e) {
            return std::string(e.what());
        }
        return std::string{};
    };
    EXPECT_NE(complaint("no-such-profile").find("default_upstream_profile"), std::string::npos);
    EXPECT_EQ(complaint(profile.name).find("default_upstream_profile"), std::string::npos);
}

TEST_F(GatewayUpstreamTest, ARequestSelectsAProfileWithItsLocationConstraintOrSigningRegion) {
    const auto keyId = b2Key();
    const auto profile = mirrorProfile(keyId);
    const auto other = mirrorProfile(keyId, "alt-");
    const auto plain = allow(credentialFor(superUser), {profile});
    const auto bound = allow(withProfile(credentialFor(superUser), profile), {other});

    // LocationConstraint names a profile the credential may select: that profile, whatever its own is.
    const auto byConstraint = bucketName();
    EXPECT_EQ(createBucket(byConstraint, authFor(plain), profile.name).mode, "remote_cache");
    EXPECT_TRUE(existsUpstream(byConstraint));
    const auto overridden = bucketName();
    EXPECT_EQ(createBucket(overridden, authFor(bound), other.name).mode, "remote_cache");
    EXPECT_TRUE(existsUpstream("alt-" + overridden));
    EXPECT_EQ(db::query::s3::Gateway::resolveBucket(overridden)->upstream_profile_id.value_or(0), other.id);

    // The region the client signs with names a profile: no CreateBucketConfiguration needed.
    const auto byRegion = bucketName();
    EXPECT_EQ(createBucket(byRegion, authFor(plain, profile.name)).mode, "remote_cache");
    EXPECT_TRUE(existsUpstream(byRegion));

    // "local" forces a local vault; a real region is what every S3 client sends and selects nothing.
    const auto forcedLocal = bucketName();
    EXPECT_EQ(createBucket(forcedLocal, authFor(bound), "local").mode, "local");
    EXPECT_FALSE(existsUpstream(forcedLocal));
    const auto region = bucketName();
    EXPECT_EQ(createBucket(region, authFor(plain, "eu-central-1"), "eu-central-1").mode, "local");
    const auto regionBound = bucketName();
    EXPECT_EQ(createBucket(regionBound, authFor(bound, "us-west-2"), "us-west-2").mode, "remote_cache");
}

// The whole request path: a signed PUT /bucket whose body is a CreateBucketConfiguration, and one signed with the
// profile as its region.
TEST_F(GatewayUpstreamTest, TheGatewayReadsTheLocationConstraintAndTheSigningRegionOfASignedRequest) {
    test::s3gw::ConfigRestore restoreConfig(vh::config::Registry::get());
    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.require_sigv4 = true;
    cfg.s3_gateway.allow_path_style = true;
    vh::config::Registry::set(cfg);

    const auto keyId = b2Key();
    const auto profile = mirrorProfile(keyId);
    const s3::CredentialManager manager;
    const auto secret = manager.createCredential({.created_by = superUser->id,
                                                  .principal_user_id = superUser->id,
                                                  .name = "gwu_signed_" + gwuTag(),
                                                  .scope_mode = "user_access"});
    db::query::s3::Gateway::replaceCredentialAllowedProfiles(secret.credential.id, {profile.id}, superUser->id);

    const auto put = [&](const std::string& bucket, const std::string& body, const std::string& region) {
        s3::Router::Request request{http::verb::put, "/" + bucket, 11};
        request.set(http::field::host, "localhost:39000");
        request.body() = body;
        request.prepare_payload();
        const vl::sigv4::Request toSign{.method = "PUT",
                                        .host = "localhost:39000",
                                        .path = "/" + bucket,
                                        .query = {},
                                        .headers = {},
                                        .payload_hash = vl::sigv4::sha256Hex(body)};
        const auto s = vl::sigv4::sign(toSign, {.access_key = secret.credential.access_key,
                                                .secret_key = secret.secret_access_key,
                                                .session_token = {}},
                                       region, "s3", vl::sigv4::Clock::now());
        for (const auto& [name, value] : s.headers) request.set(name, value);
        const s3::Router gateway;
        return gateway.route(std::move(request));
    };
    const auto configuration = [](const std::string& constraint) {
        return "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>" +
               constraint + "</LocationConstraint></CreateBucketConfiguration>";
    };

    const auto byBody = bucketName();
    auto response = put(byBody, configuration(profile.name), "us-east-1");
    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_TRUE(existsUpstream(byBody));

    const auto byRegion = bucketName();
    response = put(byRegion, "", profile.name);
    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_TRUE(existsUpstream(byRegion));

    // What boto3 and the AWS CLI send by default: their region. A local vault, as before.
    const auto plain = bucketName();
    response = put(plain, configuration("us-west-2"), "us-west-2");
    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_FALSE(existsUpstream(plain));
    EXPECT_EQ(db::query::s3::Gateway::resolveBucket(plain)->mode, "local");

    // A taken name is the S3 error a client understands.
    const auto taken = bucketName();
    seedBucket(taken, {{"kept", 1}});
    response = put(taken, configuration(profile.name), "us-east-1");
    EXPECT_EQ(response.result(), http::status::conflict);
    EXPECT_NE(response.body().find("<Code>BucketAlreadyExists</Code>"), std::string::npos) << response.body();

    response = put(bucketName(), "<CreateBucketConfiguration><LocationConstraint>", "us-east-1");
    EXPECT_EQ(response.result(), http::status::bad_request);
    EXPECT_NE(response.body().find("<Code>MalformedXML</Code>"), std::string::npos) << response.body();
}

// ---- who may ---------------------------------------------------------------------------------------------------------

TEST_F(GatewayUpstreamTest, SettingAnUpstreamNeedsProvisionAndTheKeyForTheSetterAndThePrincipal) {
    const auto keyId = b2Key();
    const auto profile = mirrorProfile(keyId);

    // Profiles themselves: bucket management alone doesn't reach an upstream account.
    const auto bucketManager = adminWith("gwu_bktmgr", {{"admin.s3_gateway.view", true}, {"admin.s3_gateway.manage_buckets", true}});
    EXPECT_THROW((void)gw::createUpstreamProfile(bucketManager, {.name = profileName(), .api_key = keyId}), ops::Denied);
    EXPECT_THROW((void)gw::updateUpstreamProfile(bucketManager, gw::ProfileRef{profile.id},
                                                 {.sync_strategy = std::string("sync")}),
                 ops::Denied);
    const auto provisionerOnly = adminWith("gwu_prov", {{"admin.upstream.provision", true}, {"admin.keys.api.admin.consume", true}});
    EXPECT_THROW((void)gw::createUpstreamProfile(provisionerOnly, {.name = profileName(), .api_key = keyId}), ops::Denied);
    EXPECT_NO_THROW((void)gw::listUpstreamProfiles(provisionerOnly));
    const auto nobody = adminWith("gwu_nobody", {{"admin.vaults.self.view", true}});
    EXPECT_THROW((void)gw::listUpstreamProfiles(nobody), ops::Denied);

    // A credential manager who can't provision can't hand a credential an upstream account.
    const auto credential = credentialFor(superUser);
    const auto credentialManager = adminWith("gwu_credmgr", {{"admin.s3_gateway.manage_credentials", true},
                                                             {"admin.s3_gateway.assign_principal", true}});
    EXPECT_THROW((void)gw::setCredentialUpstream(credentialManager, gw::Ref{credential.id},
                                                 {.profile = gw::ProfileRef{profile.id}}),
                 ops::Denied);
    EXPECT_FALSE(db::query::s3::Gateway::getCredentialById(credential.id)->upstream_profile_id);

    // The principal has to be able to create that bucket too, or the credential would exceed it.
    const auto weakPrincipal = adminWith("gwu_weak", {{"admin.s3_gateway.manage_buckets", true}});
    const auto weak = credentialFor(weakPrincipal);
    try {
        (void)gw::setCredentialUpstream(superUser, gw::Ref{weak.id}, {.profile = gw::ProfileRef{profile.id}});
        ADD_FAILURE() << "a principal without provision was given an upstream profile";
    } catch (const ops::Invalid& e) {
        EXPECT_NE(std::string(e.what()).find("principal"), std::string::npos) << e.what();
    }
    EXPECT_FALSE(db::query::s3::Gateway::getCredentialById(weak.id)->upstream_profile_id);

    // Going back to local, and the re-apply choice, need only the credential.
    EXPECT_NO_THROW((void)gw::setCredentialUpstream(credentialManager, gw::Ref{credential.id},
                                                    {.source = std::string("local"), .reapply = std::optional<bool>{false}}));
    EXPECT_EQ(db::query::s3::Gateway::getCredentialById(credential.id)->upstream_reapply, std::optional<bool>{false});
}

TEST_F(GatewayUpstreamTest, ThePrincipalIsCheckedAgainOnEveryCreateBucket) {
    const auto keyId = b2Key();
    const auto profile = mirrorProfile(keyId);
    // A principal who may create gateway buckets and vaults but not provision upstream: the state after their
    // provision right was taken away (the profile is written straight to the row, as it would have been before).
    const auto principal = adminWith("gwu_demoted", {{"admin.s3_gateway.manage_buckets", true},
                                                     {"admin.vaults.self.create", true},
                                                     {"admin.keys.api.admin.consume", true}});
    const auto credential = credentialFor(principal);
    db::query::s3::Gateway::setCredentialUpstream(credential.id, profile.id, false, std::nullopt);

    const auto name = bucketName();
    const auto vaults = vaultCount();
    const auto before = providerCalls();
    const auto [code, status] = refusal(name, authFor(credential));
    EXPECT_EQ(code, "AccessDenied");
    EXPECT_EQ(status, http::status::forbidden);
    EXPECT_EQ(vaultCount(), vaults);
    EXPECT_FALSE(existsUpstream(name));
    EXPECT_EQ(providerCalls(), before);

    // A request can't reach past the principal either, even for a profile on the credential's allowlist.
    const auto plain = credentialFor(principal);
    db::query::s3::Gateway::replaceCredentialAllowedProfiles(plain.id, {profile.id}, superUser->id);
    EXPECT_EQ(refusal(bucketName(), authFor(plain), profile.name).first, "AccessDenied");
    EXPECT_EQ(refusal(bucketName(), authFor(plain, profile.name)).first, "AccessDenied");
}

// One key can reach several upstream accounts, and only those: a request names the credential's own profile or one
// on its allowlist. Any other profile is refused, by LocationConstraint and by signing region alike.
TEST_F(GatewayUpstreamTest, AKeyOnlyReachesTheProfilesItWasGiven) {
    const auto keyId = b2Key();
    const auto own = mirrorProfile(keyId);
    const auto listed = mirrorProfile(keyId, "lst-");
    const auto foreign = mirrorProfile(keyId, "frn-");

    // No allowlist: a key with no profile can't be steered to an upstream account by its client.
    const auto plain = credentialFor(superUser);
    const auto vaults = vaultCount();
    const auto before = providerCalls();
    for (const auto& [constraint, region] : {std::pair<std::string, std::string>{foreign.name, "us-east-1"},
                                             std::pair<std::string, std::string>{"", foreign.name}}) {
        const auto name = bucketName();
        const auto [code, status] = refusal(name, authFor(plain, region), constraint);
        EXPECT_EQ(code, "AccessDenied") << constraint << "/" << region;
        EXPECT_EQ(status, http::status::forbidden);
        EXPECT_FALSE(db::query::s3::Gateway::resolveBucket(name)) << "refused, not made local";
    }
    EXPECT_EQ(vaultCount(), vaults);
    EXPECT_EQ(providerCalls(), before);

    // Its own profile plus an allowlist: both work, the third stays out of reach.
    const auto key = allow(withProfile(credentialFor(superUser), own), {listed});
    const auto upstream = gw::upstreamOf(key);
    ASSERT_EQ(upstream.allowed.size(), 1u);
    EXPECT_EQ(upstream.allowed.front().id, listed.id);
    const auto byDefault = bucketName(), byName = bucketName(), ownByName = bucketName();
    EXPECT_EQ(createBucket(byDefault, authFor(key)).mode, "remote_cache");
    EXPECT_TRUE(existsUpstream(byDefault));
    EXPECT_EQ(createBucket(byName, authFor(key), listed.name).mode, "remote_cache");
    EXPECT_TRUE(existsUpstream("lst-" + byName));
    EXPECT_EQ(createBucket(ownByName, authFor(key, own.name)).mode, "remote_cache");
    EXPECT_EQ(refusal(bucketName(), authFor(key), foreign.name).first, "AccessDenied");
    EXPECT_EQ(refusal(bucketName(), authFor(key, foreign.name)).first, "AccessDenied");

    // Granting reach needs what pointing a credential at the profile needs; taking it away needs only the credential.
    const auto credentialManager = adminWith("gwu_allowmgr", {{"admin.s3_gateway.manage_credentials", true},
                                                              {"admin.s3_gateway.assign_principal", true}});
    EXPECT_THROW((void)gw::setCredentialUpstream(credentialManager, gw::Ref{key.id},
                                                 {.allowed = std::vector<gw::ProfileRef>{listed.id, foreign.id}}),
                 ops::Denied);
    EXPECT_EQ(gw::upstreamOf(key).allowed.size(), 1u);
    EXPECT_NO_THROW((void)gw::setCredentialUpstream(credentialManager, gw::Ref{key.id},
                                                    {.allowed = std::vector<gw::ProfileRef>{listed.id}}))
        << "keeping what it already had is no new grant";
    const auto weakPrincipal = adminWith("gwu_allowweak", {{"admin.s3_gateway.manage_buckets", true}});
    EXPECT_THROW((void)gw::setCredentialUpstream(superUser, gw::Ref{credentialFor(weakPrincipal).id},
                                                 {.allowed = std::vector<gw::ProfileRef>{listed.id}}),
                 ops::Invalid);

    // A profile on an allowlist is in use.
    EXPECT_THROW(gw::deleteUpstreamProfile(superUser, gw::ProfileRef{listed.id}), ops::Conflict);
    EXPECT_NO_THROW((void)gw::setCredentialUpstream(credentialManager, gw::Ref{key.id},
                                                    {.allowed = std::vector<gw::ProfileRef>{}}));
    EXPECT_TRUE(gw::upstreamOf(key).allowed.empty());
    EXPECT_EQ(refusal(bucketName(), authFor(key), listed.name).first, "AccessDenied");
    EXPECT_NO_THROW(gw::deleteUpstreamProfile(superUser, gw::ProfileRef{listed.id}));

    // Both surfaces set and report the same list.
    const auto a = credentialFor(superUser), b = credentialFor(superUser);
    auto [code, out] = cli("s3-gateway creds scope " + a.name + " set --upstream " + own.name + " --allow-upstream " +
                           foreign.name, superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_NE(out.find("may also select: " + foreign.name), std::string::npos) << out;
    const auto viaWs = protocols::ws::handler::S3Gateway::credentialsUpstreamSet(
        json{{"credential_id", b.id}, {"profile_id", own.id}, {"allowed_profile_ids", json::array({foreign.id})}}, ws(superUser))
        .at("credential").at("upstream");
    std::tie(code, out) = cli("s3-gateway creds scope " + a.name + " show --json", superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_EQ(json::parse(out).at("upstream"), viaWs);
    ASSERT_EQ(viaWs.at("allowed_profiles").size(), 1u);
    EXPECT_EQ(viaWs.at("allowed_profiles")[0].at("name"), foreign.name);
    std::tie(code, out) = cli("s3-gateway creds scope " + a.name + " set --allow-upstream none", superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_TRUE(gw::upstreamOf(a).allowed.empty());
    EXPECT_EQ(gw::upstreamOf(*db::query::s3::Gateway::getCredentialById(a.id)).source, "profile") << "its own profile stays";
    EXPECT_NE(cli("s3-gateway creds scope " + a.name + " set --allow-upstream no-such-profile", superUser).first, 0);
}

// ---- profiles ----------------------------------------------------------------------------------------------------------

TEST_F(GatewayUpstreamTest, ProfileNamesAreRegionShapedAndNeverARealRegion) {
    const auto keyId = b2Key();
    for (const auto* bad : {"", "local", "server-default", "us-east-1", "us-west-004", "eu-central-1", "auto", "wnam",
                            "Upper", "under_score", "-lead", "trail-", "dot.ted", "this-name-is-much-longer-than-thirty-two"})
        EXPECT_THROW((void)gw::createUpstreamProfile(superUser, {.name = bad, .api_key = keyId}), ops::Invalid) << bad;

    const auto name = profileName();
    const auto profile = gw::createUpstreamProfile(superUser, {.name = name, .api_key = keyId});
    EXPECT_TRUE(profile.encrypt_upstream) << "encryption is on unless turned off";
    const auto& defaults = vh::config::Registry::get().vaults.s3;
    EXPECT_EQ(profile.sync_strategy, defaults.default_remote_sync_strategy);
    EXPECT_EQ(profile.conflict_policy, defaults.default_remote_conflict_policy);
    EXPECT_THROW((void)gw::createUpstreamProfile(superUser, {.name = name, .api_key = keyId}), ops::Conflict);

    EXPECT_THROW((void)gw::updateUpstreamProfile(superUser, gw::ProfileRef{name}, {}), ops::Invalid);
    EXPECT_THROW((void)gw::updateUpstreamProfile(superUser, gw::ProfileRef{name}, {.sync_strategy = std::string("copy")}),
                 ops::Invalid);
    EXPECT_THROW((void)gw::updateUpstreamProfile(superUser, gw::ProfileRef{name}, {.bucket_prefix = std::string("Bad_")}),
                 ops::Invalid);
    const auto updated = gw::updateUpstreamProfile(superUser, gw::ProfileRef{name}, {.bucket_prefix = std::string("acme-")});
    EXPECT_EQ(updated.profile.bucket_prefix, "acme-");
    EXPECT_TRUE(updated.reapplied.empty());
}

TEST_F(GatewayUpstreamTest, AProfileInUseAndItsKeyCannotBeRemoved) {
    const auto keyId = b2Key();
    const auto profile = mirrorProfile(keyId);
    const auto credential = withProfile(credentialFor(superUser), profile);

    EXPECT_THROW(gw::deleteUpstreamProfile(superUser, gw::ProfileRef{profile.id}), ops::Conflict);
    EXPECT_THROW((void)ops::api_keys::remove(superUser, ops::api_keys::Ref{keyId}), ops::Conflict);
    EXPECT_TRUE(db::query::s3::Gateway::getUpstreamProfile(profile.id));

    (void)gw::setCredentialUpstream(superUser, gw::Ref{credential.id}, {.source = std::string("local")});
    setServerDefaults(profile.name);
    EXPECT_THROW(gw::deleteUpstreamProfile(superUser, gw::ProfileRef{profile.id}), ops::Conflict) << "the server default";
    setServerDefaults("");
    EXPECT_NO_THROW(gw::deleteUpstreamProfile(superUser, gw::ProfileRef{profile.id}));
    EXPECT_FALSE(db::query::s3::Gateway::getUpstreamProfile(profile.id));
}

TEST_F(GatewayUpstreamTest, ChangedSyncSettingsFollowToTheBucketsCreatedFromTheProfile) {
    const auto keyId = b2Key();
    const auto profile = mirrorProfile(keyId);
    const auto following = withProfile(credentialFor(superUser), profile);
    const auto pinned = gw::setCredentialUpstream(superUser, gw::Ref{credentialFor(superUser).id},
                                                  {.profile = gw::ProfileRef{profile.id}, .reapply = std::optional<bool>{false}});
    const auto followed = bucketName(), kept = bucketName();
    (void)createBucket(followed, authFor(following));
    (void)createBucket(kept, authFor(pinned));

    const auto updated = gw::updateUpstreamProfile(superUser, gw::ProfileRef{profile.id},
                                                   {.sync_strategy = std::string("sync"),
                                                    .conflict_policy = std::string("keep_newest")});
    ASSERT_EQ(updated.reapplied.size(), 2u);
    for (const auto& r : updated.reapplied) {
        EXPECT_EQ(r.applied, r.bucket_name == followed) << r.bucket_name << ": " << r.detail;
        if (!r.applied) {
            EXPECT_FALSE(r.detail.empty());
        }
    }
    EXPECT_EQ(policyOf(followed)->strategy, sync::model::RemotePolicy::Strategy::Sync);
    EXPECT_EQ(policyOf(followed)->conflict_policy, sync::model::RemotePolicy::ConflictPolicy::KeepNewest);
    EXPECT_EQ(policyOf(kept)->strategy, sync::model::RemotePolicy::Strategy::Mirror) << "its credential opted out";
    EXPECT_EQ(policyOf(kept)->conflict_policy, sync::model::RemotePolicy::ConflictPolicy::KeepLocal);

    // The server's setting decides for credentials with no choice of their own.
    setServerDefaults("", /*reapply=*/false);
    EXPECT_FALSE(gw::upstreamOf(*db::query::s3::Gateway::getCredentialById(following.id)).reapply_effective);
    const auto second = gw::updateUpstreamProfile(superUser, gw::ProfileRef{profile.id}, {.sync_strategy = std::string("cache")});
    for (const auto& r : second.reapplied) EXPECT_FALSE(r.applied) << r.bucket_name;
    EXPECT_EQ(policyOf(followed)->strategy, sync::model::RemotePolicy::Strategy::Sync);

    // Encryption, the key and the prefix are never re-applied: they only shape buckets created afterwards.
    const auto third = gw::updateUpstreamProfile(superUser, gw::ProfileRef{profile.id},
                                                 {.encrypt_upstream = true, .bucket_prefix = std::string("new-")});
    EXPECT_TRUE(third.reapplied.empty());
    const auto vault = std::dynamic_pointer_cast<vault::model::S3Vault>(vaultOf(followed));
    ASSERT_TRUE(vault);
    EXPECT_FALSE(vault->encrypt_upstream);
    EXPECT_EQ(vault->bucket, followed);
}

// ---- the two surfaces ------------------------------------------------------------------------------------------------

TEST_F(GatewayUpstreamTest, TheCliAndTheWebSetAndReportTheSameThing) {
    const auto keyId = b2Key();
    const auto key = db::query::vault::APIKey::getAPIKey(keyId);
    const auto cliProfile = profileName(), wsProfile = profileName();

    auto [code, out] = cli("s3-gateway upstream create " + cliProfile + " --api-key " + key->name +
                           " --no-encrypt --sync-strategy mirror --on-sync-conflict keep_local --bucket-prefix vlp- --json",
                           superUser);
    ASSERT_EQ(code, 0) << out;
    const auto viaCli = json::parse(out);
    const auto viaWs = protocols::ws::handler::S3Gateway::upstreamProfilesCreate(
        json{{"name", wsProfile}, {"api_key", key->name}, {"encrypt_upstream", false}, {"sync_strategy", "mirror"},
             {"conflict_policy", "keep_local"}, {"bucket_prefix", "vlp-"}},
        ws(superUser)).at("profile");
    for (const auto* field : {"api_key_id", "api_key_name", "provider", "encrypt_upstream", "sync_strategy",
                              "conflict_policy", "bucket_prefix", "server_default"})
        EXPECT_EQ(viaCli.at(field), viaWs.at(field)) << field;
    EXPECT_EQ(viaCli.at("provider"), "Backblaze B2");
    EXPECT_EQ(viaCli.at("encrypt_upstream"), false);

    // The same refusals.
    EXPECT_NE(cli("s3-gateway upstream create local --api-key " + key->name, superUser).first, 0);
    EXPECT_THROW((void)protocols::ws::handler::S3Gateway::upstreamProfilesCreate(
                     json{{"name", "local"}, {"api_key_id", keyId}}, ws(superUser)),
                 ops::Invalid);

    // A credential pointed at a profile on each surface reads back the same on both.
    const auto a = credentialFor(superUser), b = credentialFor(superUser);
    std::tie(code, out) = cli("s3-gateway creds scope " + a.name + " set --upstream " + cliProfile + " --reapply off", superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_NE(out.find("upstream profile " + cliProfile), std::string::npos) << out;
    const auto wsCredential = protocols::ws::handler::S3Gateway::credentialsUpstreamSet(
        json{{"credential_id", b.id}, {"profile", cliProfile}, {"reapply", false}}, ws(superUser)).at("credential");

    std::tie(code, out) = cli("s3-gateway creds scope " + a.name + " show --json", superUser);
    ASSERT_EQ(code, 0) << out;
    const auto shown = json::parse(out).at("upstream");
    EXPECT_EQ(shown, wsCredential.at("upstream"));
    EXPECT_EQ(shown.at("source"), "profile");
    EXPECT_EQ(shown.at("profile").at("name"), cliProfile);
    EXPECT_EQ(shown.at("profile").at("encrypt_upstream"), false);
    EXPECT_EQ(shown.at("profile").at("sync_strategy"), "mirror");
    EXPECT_EQ(shown.at("profile").at("conflict_policy"), "keep_local");
    EXPECT_EQ(shown.at("reapply"), false);
    EXPECT_EQ(shown.at("reapply_effective"), false);

    std::tie(code, out) = cli("s3-gateway creds scope " + a.name + " show", superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_NE(out.find("new buckets: upstream profile " + cliProfile), std::string::npos) << out;
    EXPECT_NE(out.find("upstream encryption off, mirror + keep_local"), std::string::npos) << out;

    // Back to local vaults, and inheriting the server's re-apply setting, on both.
    std::tie(code, out) = cli("s3-gateway creds scope " + a.name + " set --upstream local --reapply inherit", superUser);
    ASSERT_EQ(code, 0) << out;
    const auto cleared = protocols::ws::handler::S3Gateway::credentialsUpstreamSet(
        json{{"credential_id", b.id}, {"source", "local"}, {"reapply", nullptr}}, ws(superUser)).at("credential").at("upstream");
    std::tie(code, out) = cli("s3-gateway creds scope " + a.name + " show --json", superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_EQ(json::parse(out).at("upstream"), cleared);
    EXPECT_EQ(cleared.at("source"), "local");
    EXPECT_TRUE(cleared.at("profile").is_null());
    EXPECT_TRUE(cleared.at("reapply").is_null());

    // Unknown profiles and choices are refused on both, and change nothing.
    EXPECT_NE(cli("s3-gateway creds scope " + a.name + " set --upstream no-such-profile", superUser).first, 0);
    EXPECT_NE(cli("s3-gateway creds scope " + a.name + " set --reapply sometimes", superUser).first, 0);
    EXPECT_THROW((void)protocols::ws::handler::S3Gateway::credentialsUpstreamSet(
                     json{{"credential_id", b.id}, {"profile", "no-such-profile"}}, ws(superUser)),
                 ops::NotFound);
    EXPECT_THROW((void)protocols::ws::handler::S3Gateway::credentialsUpstreamSet(json{{"credential_id", b.id}}, ws(superUser)),
                 ops::Invalid);

    // Listing and deleting.
    std::tie(code, out) = cli("s3-gateway upstream list --json", superUser);
    ASSERT_EQ(code, 0) << out;
    const auto listed = protocols::ws::handler::S3Gateway::upstreamProfilesList(json::object(), ws(superUser));
    EXPECT_EQ(json::parse(out), listed);
    EXPECT_TRUE(listed.at("default_profile").is_null());
    EXPECT_EQ(listed.at("reapply_default"), true);

    std::tie(code, out) = cli("s3-gateway upstream update " + cliProfile + " --sync-strategy sync", superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_EQ(db::query::s3::Gateway::getUpstreamProfileByName(cliProfile)->sync_strategy, "sync");
    std::tie(code, out) = cli("s3-gateway upstream delete " + cliProfile, superUser);
    EXPECT_EQ(code, 0) << out;
    EXPECT_EQ(protocols::ws::handler::S3Gateway::upstreamProfilesDelete(json{{"profile", wsProfile}}, ws(superUser)),
              (json{{"deleted", true}}));
    EXPECT_NE(cli("s3-gateway upstream show " + cliProfile, superUser).first, 0);
}


// ---- the profile's versioning default (migration 156) --------------------------------------------------------------

TEST_F(GatewayUpstreamTest, AProfilesVersioningDefaultIsAppliedToEveryBucketItCreates) {
    const auto keyId = b2Key();
    // Without a versioning: off, the owner's default. The bucket keeps only the latest version.
    const auto plain = mirrorProfile(keyId);
    EXPECT_EQ(plain.versioning, "off");
    const auto plainCred = withProfile(credentialFor(superUser), plain);
    const auto first = bucketName();
    (void)createBucket(first, authFor(plainCred));
    const auto firstVault = vaultOf(first);
    ASSERT_TRUE(firstVault);
    EXPECT_EQ(db::query::recovery::Policy::get(firstVault->id).mode, vh::recovery::Mode::Off);
    {
        std::scoped_lock lock(cloud->mutex);
        const auto& lc = cloud->buckets.at(first).lifecycle;
        const auto owned = std::ranges::find(lc, std::string("vaulthalla-managed"), &padmin::LifecycleRule::id);
        ASSERT_NE(owned, lc.end()) << "versioning off is really off on B2";
        EXPECT_EQ(owned->expire_noncurrent_days.value_or(0), 1u);
        EXPECT_EQ(owned->prefix, "") << "an unencrypted (transparent) vault: the whole bucket";
    }

    // 30 days: asked for once, when the profile is set (the cost can't be estimated before the buckets exist).
    gw::CreateProfile req{.name = profileName(), .api_key = keyId, .encrypt_upstream = true,
                          .sync_strategy = std::string("cache"), .conflict_policy = std::string("keep_local"),
                          .versioning = std::string("30")};
    try {
        (void)gw::createUpstreamProfile(superUser, req);
        FAIL() << "a versioning default that bills old versions needs its acceptance";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, gw::PROFILE_VERSIONING);
    }
    req.accept_versioning = true;
    const auto keeping = gw::createUpstreamProfile(superUser, req);
    EXPECT_EQ(keeping.versioning, "30d");
    const auto cred = withProfile(credentialFor(superUser), keeping);
    const auto name = bucketName();
    (void)createBucket(name, authFor(cred));
    const auto vault = vaultOf(name);
    ASSERT_TRUE(vault);
    EXPECT_EQ(db::query::recovery::Policy::get(vault->id).mode, vh::recovery::Mode::ProviderVersioning);
    const auto row = upstreamRow(name);
    ASSERT_TRUE(row);
    const auto versioning = db::query::upstream::Bucket::getVersioning(row->id);
    ASSERT_TRUE(versioning);
    EXPECT_EQ(versioning->retention_mode, "days");
    EXPECT_EQ(versioning->retention_days.value_or(0), 30u);
    {
        std::scoped_lock lock(cloud->mutex);
        const auto& lc = cloud->buckets.at(name).lifecycle;
        const auto owned = std::ranges::find(lc, std::string("vaulthalla-managed"), &padmin::LifecycleRule::id);
        ASSERT_NE(owned, lc.end());
        EXPECT_EQ(owned->expire_noncurrent_days.value_or(0), 30u);
        EXPECT_EQ(owned->prefix, "o/") << "an encrypting vault's files only";
        EXPECT_TRUE(cloud->putVersioningCalls.empty());
    }

    // Changing the default asks again, for buckets created afterwards only.
    EXPECT_THROW((void)gw::updateUpstreamProfile(superUser, gw::ProfileRef{keeping.id}, {.versioning = std::string("indefinite")}),
                 ops::NeedsConfirmation);
    const auto changed = gw::updateUpstreamProfile(superUser, gw::ProfileRef{keeping.id},
                                                   {.versioning = std::string("indefinite"), .accept_versioning = true});
    EXPECT_EQ(changed.profile.versioning, "indefinite");
    EXPECT_EQ(db::query::upstream::Bucket::getVersioning(row->id)->retention_days.value_or(0), 30u)
        << "an existing bucket keeps its own";
    // Back to off needs nothing (it never keeps more than before for new buckets).
    EXPECT_EQ(gw::updateUpstreamProfile(superUser, gw::ProfileRef{keeping.id}, {.versioning = std::string("off")})
                  .profile.versioning, "off");
    EXPECT_THROW((void)gw::updateUpstreamProfile(superUser, gw::ProfileRef{keeping.id}, {.versioning = std::string("soon")}),
                 ops::Invalid);
}

TEST_F(GatewayUpstreamTest, AVersioningDefaultIsValidatedAgainstTheProvider) {
    const auto add = [&](const vault::model::S3Provider provider, const std::string& endpoint, const std::string& region) {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "gwu_k_" + gwuTag(), provider,
                                                          "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                          region, endpoint);
        const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        (void)up::enableAdmin(superUser, id, {});
        return id;
    };
    const auto r2 = add(vault::model::S3Provider::CloudflareR2,
                        "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com", "auto");
    const auto aws = add(vault::model::S3Provider::AWS, "https://s3.us-east-2.amazonaws.com", "us-east-2");
    for (const auto keyId : {r2, aws}) {
        for (const auto* value : {"30d", "indefinite"}) {
            try {
                (void)gw::createUpstreamProfile(superUser, {.name = profileName(), .api_key = keyId,
                                                            .versioning = std::string(value), .accept_versioning = true});
                FAIL() << value;
            } catch (const ops::Invalid& e) {
                EXPECT_NE(std::string(e.what()).find("can only be off"), std::string::npos) << e.what();
            }
        }
        EXPECT_EQ(gw::createUpstreamProfile(superUser, {.name = profileName(), .api_key = keyId,
                                                        .versioning = std::string("off")}).versioning, "off");
    }
    // A B2 profile with a retention can't move to a key of a provider without one.
    const auto b2 = gw::createUpstreamProfile(superUser, {.name = profileName(), .api_key = b2Key(),
                                                          .versioning = std::string("90d"), .accept_versioning = true});
    EXPECT_THROW((void)gw::updateUpstreamProfile(superUser, gw::ProfileRef{b2.id}, {.api_key = r2}), ops::Invalid);

    // The CLI and ws carry the same field.
    auto [code, out] = cli("s3-gateway upstream show " + b2.name + " --json", superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_EQ(json::parse(out).at("versioning"), "90d");
    const auto created = cli("s3-gateway upstream create " + profileName() + " --api-key " + std::to_string(b2Key()) +
                                 " --versioning 7d --accept-versioning --json", superUser);
    ASSERT_EQ(created.first, 0) << created.second;
    EXPECT_EQ(json::parse(created.second).at("versioning"), "7d");
    EXPECT_NE(cli("s3-gateway upstream create " + profileName() + " --api-key " + std::to_string(b2Key()) +
                      " --versioning 7d", superUser).first, 0) << "without the acceptance";
}

}
