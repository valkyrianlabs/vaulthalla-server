// Event-driven sync through the control-plane ops (#96, #237), against the test DB, an in-memory provider account
// (upstream_admin_fakes.hpp: buckets), an in-memory queue (upstream_event_fakes.hpp) and an in-memory bucket for the
// vault's data (sync-conflict harness FakeBucket):
//  - ops::upstream::{enable,disable,repair}Events / eventStatus: RBAC (admin.upstream bits + vault + key permission,
//    every seeded admin role), unsupported keys explained, audit rows, provider failures mapped to ops errors;
//  - vault creation with events: create mode subscribes, adoption holds events until its baseline listing, a failed
//    subscription leaves a working vault that repair fixes;
//  - keys operating a subscription can't be removed or demoted;
//  - end to end: external put / overwrite / delete, duplicates and stale events, Vaulthalla's own writes, a restart,
//    and a bucket lock that stops everything and an unlock that resumes it at once;
//  - vault deletion tears down only Vaulthalla's rule and keeps the bucket; a restore re-arms.

#include "../helpers/sync_conflict_harness.hpp"
#include "../helpers/upstream_event_fakes.hpp"
#include "../helpers/upstream_admin_fakes.hpp"

#include "db/query/upstream/Audit.hpp"
#include "db/query/upstream/Channel.hpp"
#include "db/query/upstream/Inbox.hpp"
#include "db/query/upstream/Subscription.hpp"
#include "db/query/vault/Vault.hpp"
#include "ops/APIKeys.hpp"
#include "ops/Upstream.hpp"
#include "ops/Vaults.hpp"
#include "rbac/permission/admin/Vaults.hpp"
#include "rbac/permission/admin/keys/API.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/Controller.hpp"
#include "sync/events/Applier.hpp"
#include "sync/events/Service.hpp"
#include "sync/events/Subscriptions.hpp"
#include "sync/model/Scope.hpp"

namespace vh::test_upstream_event_ops {

using namespace test_support::sync_conflicts;
namespace ue = test_support::upstream_events;
namespace uo = test_support::upstream_admin;
namespace padmin = storage::s3::provider::admin;
namespace umodel = storage::upstream::model;
namespace up = ops::upstream;
using ActionType = sync::model::ActionType;

class UpstreamEventOpsTest : public Harness {
protected:
    std::shared_ptr<uo::FakeCloud> cloud;

    void SetUp() override {
        Harness::SetUp();
        if (skipTests) return;
        cloud = std::make_shared<uo::FakeCloud>();
        ue::providerState() = std::make_shared<ue::FakeProviderState>();
        ue::providerState()->account = uo::kAccount;
        padmin::setFactoryForTesting(padmin::Factory{
            .admin = [c = cloud](const std::shared_ptr<vault::model::APIKey>&) -> std::unique_ptr<padmin::AdminClient> {
                return std::make_unique<uo::FakeAdmin>(c);
            },
            .events = [](const std::shared_ptr<vault::model::APIKey>&) -> std::unique_ptr<padmin::EventsClient> {
                if (const auto& missing = ue::providerState()->capabilityMissing)
                    throw padmin::CapabilityMissing("events.queues", *missing);
                return std::make_unique<ue::FakeEvents>(ue::providerState());
            }});
        storage::upstream::guard::clearForTesting();
        storage::upstream::guard::reload();
        sync::events::subscriptions::invalidateCache();
    }

    void TearDown() override {
        padmin::setFactoryForTesting(std::nullopt);
        storage::upstream::guard::clearForTesting();
        sync::Cloud::setPendingRemovalsProvider({});
        sync::Cloud::setEventHooks({});
    }

    struct EventVault {
        Fixture f;
        std::string bucket;
        unsigned keyId = 0;
    };

    static unsigned awsKey(const bool enable = true) {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "ev_key_" + tag(), vault::model::S3Provider::AWS,
                                                          "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                          "us-east-2", "https://s3.us-east-2.amazonaws.com");
        const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        if (enable) (void)up::enableAdmin(superUser, id, {});
        return id;
    }

    static std::string bucketName() { return "vh-ev-" + tag(); }

    void seedBucket(const std::string& name, std::map<std::string, uint64_t> objects = {}) {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets[name].objects = std::move(objects);
    }

    // The vault's data path goes to an in-memory bucket; sync the way the conflict harness does.
    static Fixture attach(const ops::vaults::VaultPtr& vault) {
        Fixture f;
        f.vault = vault;
        f.engine = std::static_pointer_cast<storage::CloudEngine>(runtime::Deps::get().storageManager->getEngine(vault->id));
        f.bucket = std::make_shared<FakeBucket>();
        f.engine->setS3ControllerForTesting(f.bucket);
        const auto rp = f.engine->remote_policy();
        rp->strategy = sync::model::RemotePolicy::Strategy::Sync;
        rp->conflict_policy = sync::model::RemotePolicy::ConflictPolicy::Ask;
        return f;
    }

    // An S3 vault (named bucket, no provisioning) on an admin key, not subscribed yet.
    EventVault vaultOn(const unsigned keyId, const std::optional<std::string>& region = std::nullopt) {
        EventVault v;
        v.keyId = keyId;
        v.bucket = bucketName();
        seedBucket(v.bucket);
        if (region) {
            std::scoped_lock lock(cloud->mutex);
            cloud->buckets[v.bucket].region = *region;
        }
        v.f = attach(ops::vaults::create(superUser, {.name = "ev_vault_" + tag(), .type = vault::model::VaultType::S3,
                                                     .owner_id = superUser->id,
                                                     .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = v.bucket}}));
        return v;
    }

    static umodel::Channel channelOf(const uint32_t vaultId) {
        const auto sub = db::query::upstream::Subscription::getLiveForVault(vaultId);
        EXPECT_TRUE(sub && sub->channel_id);
        return *db::query::upstream::Channel::get(*sub->channel_id);
    }

    static sync::events::PollOutcome poll(const uint32_t vaultId) {
        ue::FakeEvents client(ue::providerState());
        return sync::events::Service::pollOnce(channelOf(vaultId), client);
    }

    struct PassCounts {
        unsigned passes = 0;
        storage::s3::S3RequestMetrics last{};   // requests of the last scoped pass alone
    };

    // The applier with its scoped pass run inline (plan + transfers), measuring the pass's own requests.
    static sync::events::Applier inlineApplier(const Fixture& f, PassCounts* counts = nullptr,
                                              sync::Controller::ScopedResult result = sync::Controller::ScopedResult::Started) {
        static sync::Controller leases;
        return sync::events::Applier({
            .tryAcquirePass = [](const uint32_t v) { return leases.tryAcquirePass(v); },
            .releasePass = [](const uint32_t v) { leases.releasePass(v); },
            .runScoped = [f, counts, result](const uint32_t, std::shared_ptr<sync::model::PassScope> scope) {
                if (result != sync::Controller::ScopedResult::Started) return result;
                const auto before = f.engine->s3RequestMetrics();
                auto cloud = std::make_shared<sync::Cloud>(f.engine, scope);
                cloud->event = std::make_shared<sync::model::Event>();
                cloud->event->vault_id = f.vault->id;
                cloud->event->timestamp_begin = std::time(nullptr);
                db::query::sync::Event::create(cloud->event);
                cloud->loadRemovedKeys();
                cloud->initScopedBins();
                const auto plan = cloud->planPass();
                for (const auto& a : plan) {
                    if (a.type == ActionType::EnsureDirectories) cloud->ensureDirectoriesFromRemote();
                    else if (a.type == ActionType::Upload)
                        sync::tasks::Upload(f.engine, a.local, cloud->op(sync::model::Throughput::Metric::UPLOAD))();
                    else if (a.type == ActionType::Download)
                        sync::tasks::Download(f.engine, a.remote, cloud->op(sync::model::Throughput::Metric::DOWNLOAD), false)();
                    else if (a.type == ActionType::DeleteLocal)
                        f.engine->removeLocally(a.local->path);
                }
                f.engine->applyRemoteIndexMutation(plan);
                cloud->clearBins();
                scope->on_finish(true, "");
                if (counts) {
                    ++counts->passes;
                    const auto after = f.engine->s3RequestMetrics();
                    counts->last = {};
                    counts->last.list_requests = after.list_requests - before.list_requests;
                    counts->last.head_requests = after.head_requests - before.head_requests;
                    counts->last.get_requests = after.get_requests - before.get_requests;
                    counts->last.put_requests = after.put_requests - before.put_requests;
                }
                return sync::Controller::ScopedResult::Started;
            },
        });
    }

    static size_t countState(const uint32_t vaultId, const umodel::InboxState state) {
        return db::Transactions::exec("UpstreamEventOpsTest::countState", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM upstream_event_inbox WHERE vault_id = $1 AND state = $2",
                            pqxx::params{vaultId, umodel::to_string(state)}).one_field_ref().as<size_t>();
        });
    }

    static bool localExists(const Fixture& f, const std::string& path) {
        return db::query::fs::File::getFileByPath(f.vault->id, path) != nullptr;
    }

    static std::vector<up::AuditEntry> auditFor(const std::string& bucket, const std::string& action) {
        std::vector<up::AuditEntry> out;
        for (auto& e : up::audit(superUser, {.bucket = bucket, .limit = 100}))
            if (e.action == action) out.push_back(std::move(e));
        return out;
    }
};

// ---- ops: authority, support, audit, error mapping ------------------------------------------------------------------

TEST_F(UpstreamEventOpsTest, EventOpsFollowTheUpstreamBitsTheVaultAndTheKey) {
    using KeyPerm = rbac::permission::admin::keys::APIPermissions;
    using VaultPerm = rbac::permission::admin::VaultPermissions;
    const auto v = vaultOn(awsKey());
    ASSERT_EQ(up::enableEvents(superUser, v.f.vault->id, {}).state, "active");

    for (const auto* role : {"unprivileged", "auditor", "support", "identity_admin", "security_admin", "platform_operator",
                             "vault_admin", "admin", "key_custodian", "super_admin"}) {
        const auto user = std::string(role) == "super_admin" ? superUser : createUser(std::string("ev_rbac_") + role, role);
        const auto bits = user->upstreamPerms();
        const auto key = [&](const KeyPerm p) {
            return rbac::resolver::Admin::has<KeyPerm>({.user = user, .permission = p, .api_key_id = v.keyId});
        };
        const auto vault = [&](const VaultPerm p) {
            return rbac::resolver::Admin::has<VaultPerm>({.user = user, .permission = p, .vault_id = v.f.vault->id});
        };
        const auto allowed = [&](auto&& fn) {
            try {
                fn();
                return true;
            } catch (const ops::Denied&) {
                return false;
            } catch (const ops::Error&) {
                return true;   // authorized, refused for another reason
            }
        };
        const bool canConfigure = bits.canConfigure() && vault(VaultPerm::Edit) && key(KeyPerm::Consume);
        EXPECT_EQ(allowed([&] { (void)up::eventStatus(user, v.f.vault->id); }),
                  bits.canView() && vault(VaultPerm::View) && key(KeyPerm::View)) << role;
        EXPECT_EQ(allowed([&] { (void)up::enableEvents(user, v.f.vault->id, {}); }), canConfigure) << role;
        EXPECT_EQ(allowed([&] { (void)up::repairEvents(user, v.f.vault->id); }), canConfigure) << role;
        EXPECT_EQ(allowed([&] { (void)up::disableEvents(user, v.f.vault->id); }), canConfigure) << role;
        // Every vault list only shows what the actor may see; without view it is refused outright.
        EXPECT_EQ(allowed([&] { (void)up::eventStatus(user); }), bits.canView()) << role;
        if (canConfigure) (void)up::enableEvents(superUser, v.f.vault->id, {});   // back on for the next role
    }
}

TEST_F(UpstreamEventOpsTest, UnsupportedKeysAreExplainedAndRefused) {
    // A plain storage key: no provider administration.
    const auto plain = vaultOn(awsKey(false));
    auto status = up::eventStatus(superUser, plain.f.vault->id).at(0);
    EXPECT_FALSE(status.supported);
    EXPECT_NE(status.unsupported_reason.find("not enabled for provider administration"), std::string::npos)
        << status.unsupported_reason;
    EXPECT_EQ(status.state, "none");
    EXPECT_THROW((void)up::enableEvents(superUser, plain.f.vault->id, {}), ops::Invalid);

    // An R2 key without the Cloudflare API token: status says what is missing, enable names the token permissions.
    auto r2 = std::make_shared<vault::model::APIKey>(superUser->id, "ev_r2_" + tag(), vault::model::S3Provider::CloudflareR2,
                                                     "0123456789abcdef0123456789abcdef",
                                                     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "auto",
                                                     "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com");
    const auto r2Id = runtime::Deps::get().apiKeyManager->addAPIKey(r2);
    (void)up::enableAdmin(superUser, r2Id, {});
    const auto r2Vault = vaultOn(r2Id);
    status = up::eventStatus(superUser, r2Vault.f.vault->id).at(0);
    EXPECT_FALSE(status.supported);
    EXPECT_NE(status.unsupported_reason.find("Queues: Edit"), std::string::npos) << status.unsupported_reason;
    EXPECT_NE(status.unsupported_reason.find("Workers R2 Storage: Edit"), std::string::npos) << status.unsupported_reason;
    try {
        (void)up::enableEvents(superUser, r2Vault.f.vault->id, {});
        ADD_FAILURE() << "enable without a Cloudflare token must be refused";
    } catch (const ops::Invalid& e) {
        EXPECT_NE(std::string(e.what()).find("Cloudflare API token"), std::string::npos) << e.what();
    }

    (void)up::enableAdmin(superUser, r2Id, {.provider_token = std::string("cf-test-token-value")});
    EXPECT_TRUE(up::eventStatus(superUser, r2Vault.f.vault->id).at(0).supported) << "a stored token is all it needed";
}

TEST_F(UpstreamEventOpsTest, EventOpsAreAuditedAndProviderFailuresMapToOpsErrors) {
    const auto keyId = awsKey();
    const auto ok = vaultOn(keyId);
    EXPECT_EQ(up::enableEvents(superUser, ok.f.vault->id, {}).state, "active");
    ASSERT_EQ(auditFor(ok.bucket, "events.enable").size(), 1u);
    EXPECT_EQ(auditFor(ok.bucket, "events.enable").front().outcome, "ok");

    // A conflicting rule of another application: Invalid (not a fault), recorded, repairable once it's gone.
    const auto overlap = vaultOn(keyId);
    ue::providerState()->subscribeFailures = 1;
    EXPECT_THROW((void)up::enableEvents(superUser, overlap.f.vault->id, {}), ops::Invalid);
    const auto failed = auditFor(overlap.bucket, "events.enable");
    ASSERT_EQ(failed.size(), 1u);
    EXPECT_EQ(failed.front().outcome, "failed");
    auto status = up::eventStatus(superUser, overlap.f.vault->id).at(0);
    EXPECT_EQ(status.state, "failed");
    ASSERT_TRUE(status.last_error.has_value());
    EXPECT_NE(status.last_error->find("overlap"), std::string::npos) << *status.last_error;
    EXPECT_EQ(up::repairEvents(superUser, overlap.f.vault->id).state, "active");
    EXPECT_EQ(auditFor(overlap.bucket, "events.repair").size(), 1u);

    // The credential can't create queues: Invalid naming what to grant.
    const auto noQueues = vaultOn(keyId);
    ue::providerState()->capabilityMissing = "sqs:CreateQueue denied: grant sqs:CreateQueue on arn:aws:sqs:*:*:vaulthalla-*";
    try {
        (void)up::enableEvents(superUser, noQueues.f.vault->id, {});
        ADD_FAILURE() << "a missing capability must be refused";
    } catch (const ops::Invalid& e) {
        EXPECT_NE(std::string(e.what()).find("sqs:CreateQueue"), std::string::npos) << e.what();
    }
    ue::providerState()->capabilityMissing.reset();

    // A protected bucket: Denied, and the provider is never asked.
    const auto locked = vaultOn(keyId);
    (void)up::protect(superUser, keyId, locked.bucket, "not for events");
    const auto subscribes = ue::providerState()->subscribeCalls;
    EXPECT_THROW((void)up::enableEvents(superUser, locked.f.vault->id, {}), ops::Denied);
    EXPECT_EQ(ue::providerState()->subscribeCalls, subscribes);
}

// ---- vault creation with events ------------------------------------------------------------------------------------

TEST_F(UpstreamEventOpsTest, CreateWithEventsSubscribesAndAFailedSubscriptionOnlyWarns) {
    const auto keyId = awsKey();
    const auto make = [&] {
        return attach(ops::vaults::create(
            superUser, {.name = "ev_new_" + tag(), .type = vault::model::VaultType::S3, .owner_id = superUser->id,
                        .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = bucketName(),
                                                  .provision = up::Provision{.mode = up::BucketMode::Create,
                                                                             .region = std::string("us-east-2"),
                                                                             .events = true}}}));
    };
    const auto first = make();
    EXPECT_EQ(up::eventStatus(superUser, first.vault->id).at(0).state, "active");

    ue::providerState()->subscribeFailures = 1;
    const auto second = make();   // the vault is created: event setup failing is a warning, not a failure
    ASSERT_TRUE(second.vault);
    EXPECT_EQ(up::eventStatus(superUser, second.vault->id).at(0).state, "failed");
    write(second, "/works.txt", "the vault is usable");
    EXPECT_EQ(readLocal(second, "/works.txt"), "the vault is usable");
    EXPECT_EQ(up::repairEvents(superUser, second.vault->id).state, "active");
}

TEST_F(UpstreamEventOpsTest, AdoptionWithEventsHoldsEventsUntilTheBaselineListing) {
    const auto keyId = awsKey();
    const auto name = bucketName();
    seedBucket(name, {{"existing.txt", 4}});
    const auto f = attach(ops::vaults::create(
        superUser, {.name = "ev_adopt_" + tag(), .type = vault::model::VaultType::S3, .owner_id = superUser->id,
                    .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = name,
                                              .provision = up::Provision{.mode = up::BucketMode::Adopt, .events = true,
                                                                         .accept_adoption = true}}}));
    const auto status = up::eventStatus(superUser, f.vault->id).at(0);
    EXPECT_EQ(status.state, "active");
    EXPECT_EQ(status.baseline_state, "pending") << "the subscription exists before the first listing";

    ue::providerState()->push(ue::awsBody(name, "ObjectCreated:Put", "before-listing.txt", "01", 3, std::string("o"),
                                          "2020-01-01T00:00:00.000Z"));
    ue::providerState()->push(ue::awsBody(name, "ObjectCreated:Put", "during-listing.txt", "02", 3, std::string("n"),
                                          "2099-01-01T00:00:00.000Z"));
    f.bucket->put("during-listing.txt", bytes("new"), {});
    EXPECT_EQ(poll(f.vault->id).inserted, 2u);

    PassCounts counts;
    auto applier = inlineApplier(f, &counts);
    EXPECT_TRUE(applier.applyVault(f.vault->id).held) << "held until the baseline";
    EXPECT_EQ(countState(f.vault->id, umodel::InboxState::Pending), 2u);

    sync::events::Applier::onBaselineListed(f.vault->id, std::time(nullptr));
    const auto out = applier.applyVault(f.vault->id);
    EXPECT_EQ(out.applied, 1u) << "the event newer than the listing";
    EXPECT_EQ(out.skipped, 1u) << "the event the listing already covered";
    EXPECT_EQ(readLocal(f, "/during-listing.txt"), "new");
}

TEST_F(UpstreamEventOpsTest, KeysOperatingASubscriptionCannotBeRemovedOrDemoted) {
    const auto key1 = awsKey();
    const auto key2 = awsKey();   // same account and region: the channel is shared
    // A region of their own: channels are per account and region, and other tests' subscriptions would share it.
    const auto region = "us-test-" + tag();
    const auto a = vaultOn(key1, region);
    const auto b = vaultOn(key2, region);
    ASSERT_EQ(up::enableEvents(superUser, a.f.vault->id, {}).state, "active");
    ASSERT_EQ(up::enableEvents(superUser, b.f.vault->id, {}).state, "active");
    EXPECT_EQ(channelOf(a.f.vault->id).id, channelOf(b.f.vault->id).id) << "one queue per account and region";
    EXPECT_EQ(channelOf(a.f.vault->id).api_key_id.value_or(0), key2) << "the latest subscriber's key polls it";

    // key2 no longer stores any vault, but it still polls the channel both subscriptions use.
    (void)ops::vaults::update(superUser, {.id = b.f.vault->id, .api_key_id = key1});
    EXPECT_THROW((void)ops::api_keys::remove(superUser, key2), ops::Conflict);
    EXPECT_THROW((void)up::disableAdmin(superUser, key2), ops::Conflict);

    (void)up::disableEvents(superUser, a.f.vault->id);
    (void)up::disableEvents(superUser, b.f.vault->id);
    EXPECT_NO_THROW((void)up::disableAdmin(superUser, key2));
    EXPECT_NO_THROW((void)ops::api_keys::remove(superUser, key2));
}

// Found by the test above: changing a vault's key inserted a second s3 row for the vault (s3_pkey violation), and a
// vault created on a (key, bucket) another vault used silently took that vault's binding over.
TEST_F(UpstreamEventOpsTest, AVaultsBindingIsEditedInPlaceAndNeverTakenFromAnotherVault) {
    const auto key1 = awsKey(), key2 = awsKey();
    const auto a = vaultOn(key1);
    const auto moved = std::static_pointer_cast<vault::model::S3Vault>(
        ops::vaults::update(superUser, {.id = a.f.vault->id, .api_key_id = key2}));
    EXPECT_EQ(moved->api_key_id, key2);
    EXPECT_EQ(std::static_pointer_cast<vault::model::S3Vault>(db::query::vault::Vault::getVault(a.f.vault->id))->api_key_id,
              key2);

    EXPECT_THROW((void)ops::vaults::create(superUser, {.name = "ev_steal_" + tag(), .type = vault::model::VaultType::S3,
                                                       .owner_id = superUser->id,
                                                       .s3 = ops::vaults::S3Spec{.api_key_id = key2, .bucket = a.bucket}}),
                 ops::Conflict);
    const auto b = vaultOn(key2);
    EXPECT_THROW((void)ops::vaults::update(superUser, {.id = b.f.vault->id, .bucket = a.bucket}), ops::Conflict);
    const auto owner = db::query::vault::Vault::bucketOwner(key2, a.bucket);
    ASSERT_TRUE(owner);
    EXPECT_EQ(owner->vault_id, a.f.vault->id) << "the first vault keeps its bucket";
}

// ---- end to end ----------------------------------------------------------------------------------------------------

TEST_F(UpstreamEventOpsTest, ExternalChangesSyncThroughTheOpsLayerAndALockStopsThemUntilUnlocked) {
    const auto v = vaultOn(awsKey());
    ASSERT_EQ(up::enableEvents(superUser, v.f.vault->id, {}).state, "active");
    write(v.f, "/stays.txt", "keeps the index non-empty");
    (void)pass(v.f);
    PassCounts counts;
    auto applier = inlineApplier(v.f, &counts);

    // An external PUT of a new key: exactly that object is fetched.
    v.f.bucket->put("photos/new.jpg", bytes("jpeg bytes"), {});
    ue::providerState()->push(ue::awsBody(v.bucket, "ObjectCreated:Put", "photos/new.jpg", "0A", 10, std::string("e1")));
    sync::events::Service::PollerState state;
    EXPECT_EQ(sync::events::Service::pollStep(channelOf(v.f.vault->id), state), sync::events::Service::StepResult::Inserted);
    auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 1u);
    EXPECT_EQ(readLocal(v.f, "/photos/new.jpg"), "jpeg bytes");
    EXPECT_EQ(counts.last.list_requests, 0u) << "an event pass never lists the bucket";
    EXPECT_EQ(counts.last.get_requests, 1u);
    EXPECT_LE(counts.last.head_requests, 1u);

    // An overwrite downloads it again; a delete removes the (unchanged) local copy.
    v.f.bucket->put("photos/new.jpg", bytes("better jpeg"), {});
    ue::providerState()->push(ue::awsBody(v.bucket, "ObjectCreated:Put", "photos/new.jpg", "0B", 11, std::string("e2")));
    (void)poll(v.f.vault->id);
    (void)applier.applyVault(v.f.vault->id);
    EXPECT_EQ(readLocal(v.f, "/photos/new.jpg"), "better jpeg");

    ue::providerState()->push(ue::awsBody(v.bucket, "ObjectRemoved:Delete", "photos/new.jpg", "0C"));
    (void)poll(v.f.vault->id);
    (void)applier.applyVault(v.f.vault->id);
    EXPECT_FALSE(localExists(v.f, "/photos/new.jpg"));

    // A redelivery and a stale create (older than the delete): nothing changes, nothing is fetched.
    const auto passes = counts.passes;
    ue::providerState()->push(ue::awsBody(v.bucket, "ObjectRemoved:Delete", "photos/new.jpg", "0C"));
    ue::providerState()->push(ue::awsBody(v.bucket, "ObjectCreated:Put", "photos/new.jpg", "0B", 11, std::string("e2")));
    const auto dup = poll(v.f.vault->id);
    EXPECT_EQ(dup.inserted, 0u) << "both were seen before";
    out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 0u);
    EXPECT_EQ(counts.passes, passes);
    EXPECT_FALSE(localExists(v.f, "/photos/new.jpg"));

    // A restart with work applied but not reconciled: a fresh applier settles it.
    v.f.bucket->put("after-restart.txt", bytes("resumed"), {});
    ue::providerState()->push(ue::awsBody(v.bucket, "ObjectCreated:Put", "after-restart.txt", "0A", 7, std::string("r")));
    (void)poll(v.f.vault->id);
    auto busy = inlineApplier(v.f, nullptr, sync::Controller::ScopedResult::Busy);
    EXPECT_TRUE(busy.applyVault(v.f.vault->id).busy);
    EXPECT_EQ(countState(v.f.vault->id, umodel::InboxState::Applied), 1u);
    auto fresh = inlineApplier(v.f, &counts);
    EXPECT_TRUE(fresh.applyVault(v.f.vault->id).pass_started);
    EXPECT_EQ(readLocal(v.f, "/after-restart.txt"), "resumed");

    // A lock stops everything at once; its events wait, untouched.
    (void)up::protect(superUser, v.keyId, v.bucket, "maintenance");
    EXPECT_EQ(up::eventStatus(superUser, v.f.vault->id).at(0).state, "failed");
    EXPECT_FALSE(sync::events::subscriptions::activeFor(v.f.vault->id)) << "no write intents while locked";
    v.f.bucket->put("while-locked.txt", bytes("waits"), {});
    ue::providerState()->push(ue::awsBody(v.bucket, "ObjectCreated:Put", "while-locked.txt", "0A", 5, std::string("w")));
    (void)poll(v.f.vault->id);
    const auto before = v.f.engine->s3RequestMetrics();
    const auto passesLocked = counts.passes;
    out = fresh.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 0u);
    EXPECT_EQ(counts.passes, passesLocked);
    const auto after = v.f.engine->s3RequestMetrics();
    EXPECT_EQ(after.get_requests + after.head_requests + after.put_requests + after.list_requests,
              before.get_requests + before.head_requests + before.put_requests + before.list_requests);
    EXPECT_FALSE(localExists(v.f, "/while-locked.txt"));

    // The unlock re-arms the subscription and its held events are due at once (not after the lock's backoff).
    (void)up::unprotect(superUser, v.keyId, v.bucket, true);
    EXPECT_EQ(up::eventStatus(superUser, v.f.vault->id).at(0).state, "active");
    out = fresh.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 1u);
    EXPECT_EQ(readLocal(v.f, "/while-locked.txt"), "waits");
}

TEST_F(UpstreamEventOpsTest, VaulthallasOwnUploadTriggersNoTransfer) {
    const auto v = vaultOn(awsKey());
    ASSERT_EQ(up::enableEvents(superUser, v.f.vault->id, {}).state, "active");
    sync::events::subscriptions::invalidateCache();
    write(v.f, "/mine.txt", "written in Vaulthalla");
    (void)pass(v.f);
    const auto object = v.f.bucket->get("mine.txt");
    ASSERT_TRUE(object.has_value());
    auto etag = object->etag;
    std::erase(etag, '"');
    ue::providerState()->push(ue::awsBody(v.bucket, "ObjectCreated:Put", "mine.txt", "0A", object->body.size(), etag, ue::nowIso()));
    (void)poll(v.f.vault->id);

    PassCounts counts;
    auto applier = inlineApplier(v.f, &counts);
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.self, 1u);
    EXPECT_EQ(counts.passes, 0u);
    EXPECT_EQ(up::eventStatus(superUser, v.f.vault->id).at(0).inbox_self_24h, 1u);
}

// ---- vault deletion -------------------------------------------------------------------------------------------------

TEST_F(UpstreamEventOpsTest, VaultDeletionTearsDownOnlyOurRuleKeepsTheBucketAndARestoreRearms) {
    padmin::NotificationRule foreign;
    foreign.id = "someone-elses-lambda";
    foreign.destination = "arn:aws:lambda:us-east-2:123456789012:function:thumbs";
    foreign.foreign = true;
    ue::providerState()->foreignRules = {foreign};

    const auto v = vaultOn(awsKey());
    seedBucket(v.bucket, {{"upstream-data.bin", 100}});
    v.f.bucket->put("upstream-data.bin", bytes("keep me"), {});
    const auto enabled = up::enableEvents(superUser, v.f.vault->id, {});
    ASSERT_EQ(enabled.state, "active");
    EXPECT_EQ(enabled.foreign_rules, 1u);
    const auto ourRules = enabled.rule_ids;
    ASSERT_FALSE(ourRules.empty());
    const auto deletesBefore = cloud->deleteBucketCalls;

    (void)ops::vaults::remove(superUser, {.id = v.f.vault->id, .accept_key_loss = true});
    auto sub = db::query::upstream::Subscription::getLiveForVault(v.f.vault->id);
    ASSERT_TRUE(sub);
    EXPECT_EQ(sub->state, umodel::SubscriptionState::Removing) << "a delete never waits on the provider";
    EXPECT_FALSE(sync::events::subscriptions::activeFor(v.f.vault->id));

    sync::events::subscriptions::retryTeardowns();   // the event service's sweep
    EXPECT_FALSE(db::query::upstream::Subscription::getLiveForVault(v.f.vault->id));
    EXPECT_EQ(ue::providerState()->unsubscribed, ourRules) << "only Vaulthalla's rule was removed";
    for (const auto& id : ue::providerState()->unsubscribed) EXPECT_NE(id, foreign.id);
    EXPECT_EQ(cloud->deleteBucketCalls, deletesBefore) << "deleting a vault never deletes its bucket";
    {
        std::scoped_lock lock(cloud->mutex);
        ASSERT_TRUE(cloud->buckets.contains(v.bucket));
        EXPECT_EQ(cloud->buckets.at(v.bucket).objects.size(), 1u);
    }
    EXPECT_TRUE(v.f.bucket->get("upstream-data.bin").has_value()) << "upstream objects are untouched";

    (void)ops::vaults::restore(superUser, v.f.vault->id);
    sync::events::subscriptions::invalidateCache();
    EXPECT_EQ(up::eventStatus(superUser, v.f.vault->id).at(0).state, "active") << "a restore re-arms";
}

}
