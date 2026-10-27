// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Event-driven upstream sync pipeline (#96), against the test DB, an in-memory bucket (sync-conflict harness) and an
// in-memory provider (upstream_event_fakes.hpp):
//  - poll → durable inbox → ack: nothing is acknowledged unless stored; redelivery is deduplicated; undecodable
//    messages are left for the DLQ; test events are acknowledged and ignored;
//  - the applier orders per key, drops stale and superseded events (also across batches), recognises Vaulthalla's own
//    writes, and drives scoped passes that download overwrites and remove deleted objects;
//  - adoption baselines hold events until the first full listing; restart resumes applied rows; queue outages back
//    off and recover; protected buckets are never touched and lose nothing; foreign objects can be ignored;
//  - shutdown cancels an in-flight long poll at once.

#include "../helpers/sync_conflict_harness.hpp"
#include "../helpers/upstream_event_fakes.hpp"

#include "db/query/upstream/Channel.hpp"
#include "db/query/upstream/Inbox.hpp"
#include "db/query/upstream/Subscription.hpp"
#include "db/query/upstream/WriteIntent.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/Controller.hpp"
#include "sync/events/Applier.hpp"
#include "sync/events/Service.hpp"
#include "sync/events/Subscriptions.hpp"
#include "sync/model/Scope.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "ops/Error.hpp"
#include "ops/Roles.hpp"
#include "ops/Upstream.hpp"

#include <nlohmann/json.hpp>

namespace vh::test_upstream_events {

using namespace test_support::sync_conflicts;
using namespace test_support::upstream_events;
namespace umodel = storage::upstream::model;
using ActionType = sync::model::ActionType;

class UpstreamEventsTest : public Harness {
protected:
    void SetUp() override {
        Harness::SetUp();
        if (skipTests) return;
        installFakeProvider();
        storage::upstream::guard::clearForTesting();
        sync::events::subscriptions::invalidateCache();
    }

    void TearDown() override {
        removeFakeProvider();
        storage::upstream::guard::clearForTesting();
        sync::Cloud::setPendingRemovalsProvider({});
        sync::Cloud::setEventHooks({});
    }

    struct EventVault {
        Fixture f;
        std::string bucket;
        umodel::Channel channel;
        int64_t subscriptionId = 0;
    };

    // An S3 vault on an admin-enabled key, subscribed to events.
    static EventVault subscribed(const bool baseline = false, const std::string& foreign = "import") {
        EventVault v;
        v.f = remoteVault(superUser);
        const auto s3 = std::static_pointer_cast<vault::model::S3Vault>(v.f.vault);
        v.bucket = s3->bucket;
        runtime::Deps::get().apiKeyManager->setAdmin(s3->api_key_id, true, providerState()->account, "{}", std::time(nullptr));
        const auto status = sync::events::subscriptions::enable(
            {.vault_id = v.f.vault->id, .prefix = "", .foreign_objects = foreign, .baseline_required = baseline});
        EXPECT_EQ(status.state, "active");
        v.subscriptionId = status.subscription_id;
        v.channel = *db::query::upstream::Channel::get(status.channel->id);
        return v;
    }

    // The scoped pass, inline (as the harness runs regular passes): plan, transfer, settle the rows.
    static sync::events::Applier inlineApplier(const Fixture& f, unsigned* passes = nullptr,
                                              sync::Controller::ScopedResult result = sync::Controller::ScopedResult::Started) {
        static sync::Controller leases;
        return sync::events::Applier({
            .tryAcquirePass = [](const uint32_t v) { return leases.tryAcquirePass(v); },
            .releasePass = [](const uint32_t v) { leases.releasePass(v); },
            .runScoped = [f, passes, result](const uint32_t, std::shared_ptr<sync::model::PassScope> scope) {
                if (result != sync::Controller::ScopedResult::Started) return result;
                if (passes) ++*passes;
                auto cloud = std::make_shared<sync::Cloud>(f.engine, scope);
                cloud->event = std::make_shared<sync::model::Event>();
                cloud->event->vault_id = f.vault->id;
                cloud->event->timestamp_begin = std::time(nullptr);
                db::query::sync::Event::create(cloud->event);
                cloud->loadRemovedKeys();
                cloud->initScopedBins();
                const auto plan = cloud->planPass();
                for (const auto& a : plan) {
                    if (a.type == ActionType::EnsureDirectories)
                        cloud->ensureDirectoriesFromRemote();
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
                return sync::Controller::ScopedResult::Started;
            },
        });
    }

    static std::vector<umodel::InboxEvent> inbox(const uint32_t vaultId) {
        return db::Transactions::exec("UpstreamEventsTest::inbox", [&](pqxx::work& txn) {
            const auto res = txn.exec("SELECT * FROM upstream_event_inbox WHERE vault_id = $1 ORDER BY id", pqxx::params{vaultId});
            std::vector<umodel::InboxEvent> out;
            for (const auto& row : res) out.emplace_back(row);
            return out;
        });
    }

    static size_t countState(const uint32_t vaultId, const umodel::InboxState state) {
        size_t n = 0;
        for (const auto& r : inbox(vaultId))
            if (r.state == state) ++n;
        return n;
    }

    static sync::events::PollOutcome poll(const EventVault& v) {
        FakeEvents client(providerState());
        return sync::events::Service::pollOnce(*db::query::upstream::Channel::get(v.channel.id), client);
    }

    // A foreign writer puts plaintext bytes straight into the bucket.
    static void externalPut(const EventVault& v, const std::string& key, const std::string& content) {
        v.f.bucket->put(key, bytes(content), {});
    }
};

TEST_F(UpstreamEventsTest, MessagesAreAcknowledgedOnlyAfterTheyAreStored) {
    const auto v = subscribed();
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "a.txt", "0A", 5, std::string("e1")));

    // The insert fails (the channel id doesn't exist: a foreign-key violation): nothing may be acknowledged.
    auto broken = *db::query::upstream::Channel::get(v.channel.id);
    broken.id = 987654321;
    FakeEvents client(providerState());
    EXPECT_ANY_THROW((void)sync::events::Service::pollOnce(broken, client));
    EXPECT_TRUE(providerState()->acked.empty());
    EXPECT_EQ(providerState()->queue.size(), 1u) << "the message is redelivered";

    const auto ok = poll(v);
    EXPECT_EQ(ok.inserted, 1u);
    EXPECT_EQ(ok.acked, 1u);
    EXPECT_TRUE(providerState()->queue.empty());
}

TEST_F(UpstreamEventsTest, RedeliveryIsDeduplicatedAndUndecodableMessagesStayForTheDlq) {
    const auto v = subscribed();
    const auto body = awsBody(v.bucket, "ObjectCreated:Put", "dup.txt", "0A", 5, std::string("e1"));
    providerState()->push(body);
    providerState()->push(body);   // the same notification delivered twice
    providerState()->push("not json at all");
    providerState()->push(R"({"Service":"Amazon S3","Event":"s3:TestEvent","Bucket":"x"})");

    const auto out = poll(v);
    EXPECT_EQ(out.messages, 4u);
    EXPECT_EQ(out.inserted, 1u) << "one logical event";
    EXPECT_EQ(out.undecodable, 1u);
    EXPECT_EQ(out.ignored, 1u);
    EXPECT_EQ(out.acked, 3u);
    ASSERT_EQ(providerState()->queue.size(), 1u);
    EXPECT_EQ(providerState()->queue.front().body, "not json at all") << "only the undecodable message is left";
    EXPECT_EQ(inbox(v.f.vault->id).size(), 1u);
}

TEST_F(UpstreamEventsTest, ExternalUploadIsDownloadedByAScopedPass) {
    const auto v = subscribed();
    externalPut(v, "inbox/report.txt", "uploaded straight to the bucket");
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "inbox/report.txt", "0A", 31, std::string("etag-x")));
    (void)poll(v);

    unsigned passes = 0;
    auto applier = inlineApplier(v.f, &passes);
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 1u);
    EXPECT_TRUE(out.pass_started);
    EXPECT_EQ(passes, 1u);
    EXPECT_EQ(readLocal(v.f, "/inbox/report.txt"), "uploaded straight to the bucket");
    EXPECT_EQ(countState(v.f.vault->id, umodel::InboxState::Done), 1u);
    const auto metrics = v.f.engine->s3RequestMetrics();
    EXPECT_EQ(metrics.list_requests, 0u) << "an event pass never lists the bucket";
}

TEST_F(UpstreamEventsTest, ExternalOverwriteAndDeleteSynchronise) {
    const auto v = subscribed();
    write(v.f, "/doc.txt", "first");
    write(v.f, "/gone.txt", "will be deleted upstream");
    write(v.f, "/keep.txt", "unrelated");
    (void)pass(v.f);   // uploaded; baselines recorded

    externalPut(v, "doc.txt", "second, written by another tool");
    v.f.bucket->erase("gone.txt");   // really deleted upstream: the removal is confirmed by a HEAD
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "doc.txt", "0B", 31, std::string("etag-new")));
    providerState()->push(awsBody(v.bucket, "ObjectRemoved:Delete", "gone.txt", "0C"));
    (void)poll(v);

    auto applier = inlineApplier(v.f);
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 2u);
    EXPECT_EQ(readLocal(v.f, "/doc.txt"), "second, written by another tool");
    EXPECT_EQ(db::query::fs::File::getFileByPath(v.f.vault->id, "/gone.txt"), nullptr) << "the removal propagated";
    EXPECT_NE(db::query::fs::File::getFileByPath(v.f.vault->id, "/keep.txt"), nullptr);
}

TEST_F(UpstreamEventsTest, SameSizeOverwriteOfAnUploadedFileIsNotMissed) {
    const auto v = subscribed();
    write(v.f, "/same-size.txt", "first");
    (void)pass(v.f);   // uploaded by Vaulthalla: the baseline knows no ETag yet
    externalPut(v, "same-size.txt", "fifth");   // another tool, same length
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "same-size.txt", "0F", 5, std::string("etag-other")));
    (void)poll(v);

    auto applier = inlineApplier(v.f);
    (void)applier.applyVault(v.f.vault->id);
    EXPECT_EQ(readLocal(v.f, "/same-size.txt"), "fifth");
}

TEST_F(UpstreamEventsTest, OutOfOrderAndSupersededEventsAreDropped) {
    const auto v = subscribed();
    externalPut(v, "o.txt", "content");
    // Same batch: the delete is newer than the create.
    providerState()->push(awsBody(v.bucket, "ObjectRemoved:Delete", "o.txt", "0B"));
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "o.txt", "0A", 7, std::string("e1")));
    (void)poll(v);
    auto applier = inlineApplier(v.f);
    (void)applier.applyVault(v.f.vault->id);
    EXPECT_EQ(db::query::sync::RemoteObjectIndex::getFile(v.f.vault->id, "o.txt"), nullptr);

    // A later batch delivers an even older create (delayed past its delete): stale, never resurrected.
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "o.txt", "09", 7, std::string("e0")));
    (void)poll(v);
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 0u);
    EXPECT_EQ(db::query::sync::RemoteObjectIndex::getFile(v.f.vault->id, "o.txt"), nullptr);
    EXPECT_EQ(db::query::fs::File::getFileByPath(v.f.vault->id, "/o.txt"), nullptr);
}

TEST_F(UpstreamEventsTest, VaulthallasOwnWritesAreNotSyncedBack) {
    const auto v = subscribed();
    sync::events::subscriptions::invalidateCache();
    write(v.f, "/mine.txt", "written in Vaulthalla");
    (void)pass(v.f);   // the upload records a write intent (the vault has an active subscription)
    const auto intents = db::Transactions::exec("UpstreamEventsTest::intents", [&](pqxx::work& txn) {
        return txn.exec("SELECT COUNT(*) FROM upstream_write_intent WHERE vault_id = $1 AND object_key = 'mine.txt'",
                        pqxx::params{v.f.vault->id}).one_field_ref().as<unsigned>();
    });
    EXPECT_EQ(intents, 1u) << "the upload announced itself";
    const auto indexed = db::query::sync::RemoteObjectIndex::getFile(v.f.vault->id, "mine.txt");
    ASSERT_NE(indexed, nullptr);
    const auto object = v.f.bucket->get("mine.txt");
    ASSERT_TRUE(object.has_value());

    auto etag = object->etag;
    std::erase(etag, '"');
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "mine.txt", "0A", object->body.size(), etag, nowIso()));
    (void)poll(v);
    unsigned passes = 0;
    auto applier = inlineApplier(v.f, &passes);
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.self, 1u);
    EXPECT_EQ(passes, 0u) << "no pass for our own write";
    const auto after = db::query::sync::RemoteObjectIndex::getFile(v.f.vault->id, "mine.txt");
    ASSERT_NE(after, nullptr);
    EXPECT_EQ(after->encryption_iv, indexed->encryption_iv) << "the row keeps Vaulthalla's encryption metadata";
    EXPECT_EQ(after->content_hash, indexed->content_hash);
}

TEST_F(UpstreamEventsTest, BaselineHoldsEventsUntilTheFirstListing) {
    const auto v = subscribed(true);
    EXPECT_TRUE(sync::events::Applier::baselineNeeded(v.f.vault->id));
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "old.txt", "01", 3, std::string("o"),
                                  "2020-01-01T00:00:00.000Z"));
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "new.txt", "02", 3, std::string("n"),
                                  "2099-01-01T00:00:00.000Z"));
    externalPut(v, "new.txt", "new");
    (void)poll(v);

    auto applier = inlineApplier(v.f);
    EXPECT_TRUE(applier.applyVault(v.f.vault->id).held);
    EXPECT_EQ(countState(v.f.vault->id, umodel::InboxState::Pending), 2u);

    sync::events::Applier::onBaselineListed(v.f.vault->id, std::time(nullptr));
    EXPECT_FALSE(sync::events::Applier::baselineNeeded(v.f.vault->id));
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 1u) << "only the event newer than the listing";
    EXPECT_EQ(out.skipped, 1u);
}

TEST_F(UpstreamEventsTest, AppliedRowsSurviveARestartAndAreSettledLater) {
    const auto v = subscribed();
    externalPut(v, "r.txt", "resume me");
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "r.txt", "0A", 9, std::string("e")));
    (void)poll(v);

    // The pass couldn't start (another pass held the vault): the rows stay applied, the index already moved.
    auto busy = inlineApplier(v.f, nullptr, sync::Controller::ScopedResult::Busy);
    const auto first = busy.applyVault(v.f.vault->id);
    EXPECT_TRUE(first.busy);
    EXPECT_EQ(countState(v.f.vault->id, umodel::InboxState::Applied), 1u);
    EXPECT_FALSE(sync::events::Applier::pendingRemovals(v.f.vault->id).contains(u8"/r.txt"));

    // A new process: a fresh applier finds the applied rows and settles them.
    auto fresh = inlineApplier(v.f);
    const auto second = fresh.applyVault(v.f.vault->id);
    EXPECT_TRUE(second.pass_started);
    EXPECT_EQ(countState(v.f.vault->id, umodel::InboxState::Done), 1u);
    EXPECT_EQ(readLocal(v.f, "/r.txt"), "resume me");
}

TEST_F(UpstreamEventsTest, QueueOutageBacksOffDegradesAndRecovers) {
    const auto v = subscribed();
    providerState()->pollError = "queue unavailable";
    sync::events::Service::PollerState state;
    for (int i = 0; i < 3; ++i) {
        const auto ch = *db::query::upstream::Channel::get(v.channel.id);
        EXPECT_EQ(sync::events::Service::pollStep(ch, state), sync::events::Service::StepResult::Failed);
    }
    auto ch = *db::query::upstream::Channel::get(v.channel.id);
    EXPECT_EQ(ch.consecutive_failures, 3u);
    EXPECT_EQ(ch.state, umodel::ChannelState::Degraded);
    ASSERT_TRUE(ch.next_poll_at.has_value());
    EXPECT_GT(*ch.next_poll_at, std::time(nullptr)) << "backs off";
    ASSERT_TRUE(ch.last_error.has_value());

    providerState()->pollError.reset();
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "after.txt", "0A", 1, std::string("e")));
    EXPECT_EQ(sync::events::Service::pollStep(ch, state), sync::events::Service::StepResult::Inserted);
    ch = *db::query::upstream::Channel::get(v.channel.id);
    EXPECT_EQ(ch.consecutive_failures, 0u);
    EXPECT_EQ(ch.state, umodel::ChannelState::Active);
    EXPECT_TRUE(ch.last_success_at.has_value());
}

TEST_F(UpstreamEventsTest, ProtectedBucketIsNeverTouchedAndLosesNothing) {
    const auto v = subscribed();
    externalPut(v, "p.txt", "x");
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "p.txt", "0A", 1, std::string("e")));
    (void)poll(v);
    const auto before = v.f.engine->s3RequestMetrics();
    storage::upstream::guard::setForTesting({{.provider = "aws-s3", .account_ref = providerState()->account, .bucket = v.bucket}});

    unsigned passes = 0;
    auto applier = inlineApplier(v.f, &passes);
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 0u);
    EXPECT_EQ(passes, 0u);
    const auto after = v.f.engine->s3RequestMetrics();
    EXPECT_EQ(after.get_requests + after.head_requests + after.put_requests,
              before.get_requests + before.head_requests + before.put_requests);
    const auto rows = inbox(v.f.vault->id);
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].state, umodel::InboxState::Pending) << "kept for after an unprotect";
    EXPECT_EQ(db::query::upstream::Subscription::get(v.subscriptionId)->state, umodel::SubscriptionState::Failed);
}

TEST_F(UpstreamEventsTest, ForeignObjectsCanBeIgnoredAndTheHeadIsMetered) {
    const auto v = subscribed(false, "ignore");
    externalPut(v, "foreign.bin", "not written by Vaulthalla");
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "foreign.bin", "0A", 25, std::string("e")));
    (void)poll(v);
    const auto heads = v.f.engine->s3RequestMetrics().head_requests;

    auto applier = inlineApplier(v.f);
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 0u);
    EXPECT_EQ(out.skipped, 1u);
    EXPECT_EQ(v.f.engine->s3RequestMetrics().head_requests, heads + 1) << "one HEAD, counted like any request";
    EXPECT_EQ(db::query::fs::File::getFileByPath(v.f.vault->id, "/foreign.bin"), nullptr);
}

TEST_F(UpstreamEventsTest, EventsForUnsubscribedBucketsAreStoredAsUnrouted) {
    const auto v = subscribed();
    providerState()->push(awsBody("someone-elses-bucket", "ObjectCreated:Put", "k", "0A", 1, std::string("e")));
    const auto out = poll(v);
    EXPECT_EQ(out.unrouted, 1u);
    EXPECT_EQ(out.acked, 1u);
    EXPECT_TRUE(inbox(v.f.vault->id).empty());
}

TEST_F(UpstreamEventsTest, R2NotificationFromAnotherAccountIsRefused) {
    const auto v = subscribed();
    auto ch = *db::query::upstream::Channel::get(v.channel.id);
    ch.provider = "cloudflare-r2";
    ch.account_ref = "0123456789abcdef0123456789abcdef";
    providerState()->push(R"({"account":"ffffffffffffffffffffffffffffffff","action":"PutObject","bucket":")" + v.bucket +
                          R"(","object":{"key":"k","size":1,"eTag":"e"},"eventTime":"2026-10-15T12:00:00Z"})");
    FakeEvents client(providerState());
    const auto out = sync::events::Service::pollOnce(ch, client);
    EXPECT_EQ(out.undecodable, 1u);
    EXPECT_EQ(out.acked, 0u);
}

TEST_F(UpstreamEventsTest, ManualIngestGoesThroughTheSameDurableInbox) {
    const auto f = remoteVault(superUser);
    const auto bucket = std::static_pointer_cast<vault::model::S3Vault>(f.vault)->bucket;
    const auto file = std::filesystem::temp_directory_path() / ("vh_events_" + tag() + ".json");
    {
        std::ofstream out(file);
        out << awsBody(bucket, "ObjectCreated:Put", "manual/a.txt", "0A", 3, std::string("e1"));
    }
    const auto router = std::make_shared<protocols::shell::Router>();
    protocols::shell::commands::vault::registerCommands(router);
    const auto line = "vault sync events " + std::to_string(f.vault->id) + " --file " + file.string();

    const auto first = router->executeLine(line, superUser, nullptr);
    EXPECT_EQ(first.exit_code, 0) << first.stderr_text;
    EXPECT_NE(first.stdout_text.find("Events stored: 1 new"), std::string::npos) << first.stdout_text;
    EXPECT_NE(db::query::sync::RemoteObjectIndex::getFile(f.vault->id, "manual/a.txt"), nullptr);

    const auto again = router->executeLine(line, superUser, nullptr);
    EXPECT_EQ(again.exit_code, 0);
    EXPECT_NE(again.stdout_text.find("Events stored: 0 new, 1 already known"), std::string::npos) << again.stdout_text;
    std::filesystem::remove(file);
}

TEST_F(UpstreamEventsTest, ShutdownCancelsAnInFlightLongPoll) {
    const auto v = subscribed();
    providerState()->blockPolls = true;
    sync::events::Service service;
    service.start();
    for (int i = 0; i < 200 && !providerState()->pollEntered.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ASSERT_TRUE(providerState()->pollEntered.load()) << "the poller reached the long poll";

    const auto started = std::chrono::steady_clock::now();
    service.requestStop();
    service.join();
    const auto took = std::chrono::steady_clock::now() - started;
    EXPECT_LT(took, std::chrono::seconds(1));
    EXPECT_EQ(service.pollerCount(), 0u);
    providerState()->blockPolls = false;
}

}

// ---- FX-3 hardening (review findings) --------------------------------------------------------------------------

namespace vh::test_upstream_events {

class UpstreamEventsHardeningTest : public UpstreamEventsTest {
protected:
    static std::optional<std::string> manifestEtag(const EventVault& v) {
        if (const auto o = v.f.bucket->get(".vaulthalla/index-v1.json")) return o->etag;
        return std::nullopt;
    }
    static bool locallyPresent(const Fixture& f, const std::string& path) {
        return db::query::fs::File::getFileByPath(f.vault->id, path) != nullptr;
    }
    static size_t intents(const uint32_t vaultId) {
        return db::Transactions::exec("UpstreamEventsHardeningTest::intents", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM upstream_write_intent WHERE vault_id = $1", pqxx::params{vaultId})
                .one_field_ref()
                .as<size_t>();
        });
    }
};

TEST_F(UpstreamEventsHardeningTest, TheIndexManifestsOwnNotificationIsNeverWorkAndNeverRepublished) {
    const auto v = subscribed();
    const auto before = manifestEtag(v);
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", ".vaulthalla/index-v1.json", "0F", 120, std::string("m1")));
    (void)poll(v);

    unsigned passes = 0;
    auto applier = inlineApplier(v.f, &passes);
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_FALSE(out.index_changed);
    EXPECT_EQ(passes, 0u) << "no scoped pass for Vaulthalla's own manifest";
    EXPECT_EQ(manifestEtag(v), before) << "nothing republished: no feedback loop";
    const auto rows = inbox(v.f.vault->id);
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].state, umodel::InboxState::Skipped);
    EXPECT_EQ(rows[0].origin, umodel::InboxOrigin::Self);
}

TEST_F(UpstreamEventsHardeningTest, EventsOfOneSecondApplyInMillisecondOrderWhateverTheArrivalOrder) {
    const auto v = subscribed();
    externalPut(v, "ms.txt", "created last");
    // No sequencers (as on R2): a delete at .100 and a create at .900 of the same second, delivered create-last-first.
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "ms.txt", "", 12, std::string("e9"),
                                  "2026-10-15T12:00:00.900Z"));
    providerState()->push(awsBody(v.bucket, "ObjectRemoved:Delete", "ms.txt", "", std::nullopt, std::nullopt,
                                  "2026-10-15T12:00:00.100Z"));
    (void)poll(v);
    const auto rows = inbox(v.f.vault->id);
    ASSERT_EQ(rows.size(), 2u);
    for (const auto& r : rows) EXPECT_TRUE(r.event_time_ms.has_value()) << "milliseconds are stored";

    auto applier = inlineApplier(v.f);
    (void)applier.applyVault(v.f.vault->id);
    EXPECT_NE(db::query::sync::RemoteObjectIndex::getFile(v.f.vault->id, "ms.txt"), nullptr) << "the create (later) wins";
    EXPECT_EQ(readLocal(v.f, "/ms.txt"), "created last");
}

TEST_F(UpstreamEventsHardeningTest, ATrueTieBetweenCreateAndRemoveIsDecidedByTheProvider) {
    const auto v = subscribed();
    // Same millisecond, no sequencer: the object exists, so the create stands.
    externalPut(v, "tie-exists.txt", "still here");
    providerState()->push(awsBody(v.bucket, "ObjectRemoved:Delete", "tie-exists.txt", "", std::nullopt, std::nullopt,
                                  "2026-10-15T12:00:01.500Z"));
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "tie-exists.txt", "", 10, std::string("t1"),
                                  "2026-10-15T12:00:01.500Z"));
    // Same millisecond, the object is gone: the removal stands.
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "tie-gone.txt", "", 4, std::string("t2"),
                                  "2026-10-15T12:00:02.250Z"));
    providerState()->push(awsBody(v.bucket, "ObjectRemoved:Delete", "tie-gone.txt", "", std::nullopt, std::nullopt,
                                  "2026-10-15T12:00:02.250Z"));
    (void)poll(v);

    auto applier = inlineApplier(v.f);
    (void)applier.applyVault(v.f.vault->id);
    EXPECT_NE(db::query::sync::RemoteObjectIndex::getFile(v.f.vault->id, "tie-exists.txt"), nullptr);
    EXPECT_EQ(readLocal(v.f, "/tie-exists.txt"), "still here");
    EXPECT_EQ(db::query::sync::RemoteObjectIndex::getFile(v.f.vault->id, "tie-gone.txt"), nullptr);
    EXPECT_FALSE(locallyPresent(v.f, "/tie-gone.txt"));
}

TEST_F(UpstreamEventsHardeningTest, ARemovalTheProviderDoesNotConfirmDeletesNothing) {
    const auto v = subscribed();
    write(v.f, "/forged.txt", "real data");
    (void)pass(v.f);   // uploaded: the object exists upstream
    // A forged (or misordered) notification: the object is still there.
    providerState()->push(awsBody(v.bucket, "ObjectRemoved:Delete", "forged.txt", "FF"));
    (void)poll(v);

    unsigned passes = 0;
    auto applier = inlineApplier(v.f, &passes);
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.applied, 0u);
    EXPECT_TRUE(locallyPresent(v.f, "/forged.txt")) << "never deleted on an unconfirmed removal";
    EXPECT_NE(db::query::sync::RemoteObjectIndex::getFile(v.f.vault->id, "forged.txt"), nullptr);
    const auto rows = inbox(v.f.vault->id);
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].state, umodel::InboxState::Skipped);
    EXPECT_NE(rows[0].note.value_or("").find("not confirmed"), std::string::npos);
}

TEST_F(UpstreamEventsHardeningTest, AFailedHeadIsRetriedNeverTakenForADeletion) {
    const auto v = subscribed();
    write(v.f, "/outage.txt", "kept through an outage");
    (void)pass(v.f);
    v.f.bucket->erase("outage.txt");   // really deleted upstream, but the HEAD that would confirm it fails
    v.f.bucket->failHeads = true;
    providerState()->push(awsBody(v.bucket, "ObjectRemoved:Delete", "outage.txt", "FE"));
    (void)poll(v);

    auto applier = inlineApplier(v.f);
    const auto out = applier.applyVault(v.f.vault->id);
    EXPECT_EQ(out.failed, 1u);
    EXPECT_TRUE(locallyPresent(v.f, "/outage.txt"));
    const auto rows = inbox(v.f.vault->id);
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].state, umodel::InboxState::Pending) << "retried with backoff";
    EXPECT_TRUE(rows[0].next_attempt_at.has_value());

    v.f.bucket->failHeads = false;
    db::Transactions::exec("t", [&](pqxx::work& txn) {
        txn.exec("UPDATE upstream_event_inbox SET next_attempt_at = NULL WHERE vault_id = $1", pqxx::params{v.f.vault->id});
    });
    (void)applier.applyVault(v.f.vault->id);
    EXPECT_FALSE(locallyPresent(v.f, "/outage.txt")) << "once confirmed, the removal goes through";
}

TEST_F(UpstreamEventsHardeningTest, LostContinuityHoldsEventsUntilTheBucketIsListedAgain) {
    const auto v = subscribed();
    db::query::upstream::Channel::recordPoll(v.channel.id, true, 0, std::nullopt, std::nullopt, std::nullopt);
    sync::events::Applier::onBaselineListed(v.f.vault->id, std::time(nullptr) - 100);
    EXPECT_TRUE(sync::events::Applier::indexKeptFresh(v.f.vault->id, std::chrono::hours(24)));

    db::query::upstream::Channel::markContinuityBroken(v.channel.id, "test: lost messages");
    EXPECT_FALSE(sync::events::Applier::indexKeptFresh(v.f.vault->id, std::chrono::hours(24)));
    // Every subscription on the channel shares its stream (the fake account's subscriptions all do).
    EXPECT_GE(sync::events::Applier::checkContinuity(), 1u);
    EXPECT_TRUE(sync::events::Applier::baselineNeeded(v.f.vault->id)) << "the next regular pass lists the bucket";
    EXPECT_EQ(sync::events::Applier::checkContinuity(), 0u) << "reset once";

    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "held.txt", "0A", 1, std::string("h")));
    (void)poll(v);
    auto applier = inlineApplier(v.f);
    EXPECT_TRUE(applier.applyVault(v.f.vault->id).held);

    sync::events::Applier::onBaselineListed(v.f.vault->id, std::time(nullptr) + 1);
    EXPECT_FALSE(sync::events::Applier::baselineNeeded(v.f.vault->id));
    EXPECT_TRUE(sync::events::Applier::indexKeptFresh(v.f.vault->id, std::chrono::hours(24)));
}

TEST_F(UpstreamEventsHardeningTest, ADeliveryGapLongerThanTheRetentionBreaksContinuity) {
    const auto v = subscribed();
    db::Transactions::exec("t", [&](pqxx::work& txn) {   // the fake account's channel is shared by earlier tests
        txn.exec("UPDATE upstream_event_channel SET continuity_broken_at = NULL WHERE id = $1", pqxx::params{v.channel.id});
    });
    db::query::upstream::Channel::recordPoll(v.channel.id, true, 0, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_FALSE(db::query::upstream::Channel::get(v.channel.id)->continuity_broken_at.has_value());
    db::Transactions::exec("t", [&](pqxx::work& txn) {
        txn.exec("UPDATE upstream_event_channel SET last_success_at = CURRENT_TIMESTAMP - INTERVAL '5 days' WHERE id = $1",
                 pqxx::params{v.channel.id});
    });
    db::query::upstream::Channel::recordPoll(v.channel.id, true, 0, std::nullopt, std::nullopt, std::nullopt);
    const auto ch = db::query::upstream::Channel::get(v.channel.id);
    EXPECT_TRUE(ch->continuity_broken_at.has_value());
    EXPECT_FALSE(sync::events::Applier::indexKeptFresh(v.f.vault->id, std::chrono::hours(24 * 30)));
}

TEST_F(UpstreamEventsHardeningTest, DeadLettersAreReportedAndBreakContinuity) {
    const auto v = subscribed();
    db::Transactions::exec("t", [&](pqxx::work& txn) {   // the fake account's channel is shared by earlier tests
        txn.exec("UPDATE upstream_event_channel SET continuity_broken_at = NULL, dlq_depth = NULL WHERE id = $1",
                 pqxx::params{v.channel.id});
    });
    providerState()->dlqDepth = 3;
    {
        sync::events::Service service;
        service.cycle();   // the first cycle runs maintenance: dead-letter check + continuity sweep
    }
    const auto ch = db::query::upstream::Channel::get(v.channel.id);
    EXPECT_EQ(ch->dlq_depth.value_or(0), 3u);
    EXPECT_TRUE(ch->continuity_broken_at.has_value());
    EXPECT_TRUE(sync::events::Applier::baselineNeeded(v.f.vault->id));
}

TEST_F(UpstreamEventsHardeningTest, AnIngestFailureOnAMessagesLastDeliveryBreaksContinuity) {
    const auto v = subscribed();
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "last-try.txt", "0A", 1, std::string("l")));
    providerState()->queue.front().attempts = 7;   // the 8th delivery is the last before the DLQ
    db::Transactions::exec("t", [&](pqxx::work& txn) {
        txn.exec("CREATE OR REPLACE FUNCTION vh_test_refuse_inbox() RETURNS trigger LANGUAGE plpgsql AS "
                 "$f$ BEGIN RAISE EXCEPTION 'test: inbox unavailable'; END $f$");
        txn.exec("CREATE TRIGGER vh_test_refuse_inbox BEFORE INSERT ON upstream_event_inbox "
                 "FOR EACH ROW EXECUTE FUNCTION vh_test_refuse_inbox()");
    });
    EXPECT_ANY_THROW((void)poll(v));
    db::Transactions::exec("t", [&](pqxx::work& txn) {
        txn.exec("DROP TRIGGER vh_test_refuse_inbox ON upstream_event_inbox");
        txn.exec("DROP FUNCTION vh_test_refuse_inbox()");
    });
    EXPECT_TRUE(providerState()->acked.empty());
    EXPECT_TRUE(db::query::upstream::Channel::get(v.channel.id)->continuity_broken_at.has_value());
}

TEST_F(UpstreamEventsHardeningTest, AFailedUploadLeavesNoWriteIntentAndASuccessfulOneLivesFromCompletion) {
    const auto v = subscribed();
    sync::events::subscriptions::invalidateCache();
    const auto file = write(v.f, "/intent.txt", "payload");
    v.f.bucket->failPuts = true;
    EXPECT_ANY_THROW(v.f.engine->upload(file));
    EXPECT_EQ(intents(v.f.vault->id), 0u) << "a failed request can never claim someone else's notification";

    v.f.bucket->failPuts = false;
    v.f.engine->upload(file);
    ASSERT_EQ(intents(v.f.vault->id), 1u);
    const auto completed = db::Transactions::exec("t", [&](pqxx::work& txn) {
        return !txn.exec("SELECT completed_at FROM upstream_write_intent WHERE vault_id = $1", pqxx::params{v.f.vault->id})
                    .one_row_ref()["completed_at"].is_null();
    });
    EXPECT_TRUE(completed);
}

TEST_F(UpstreamEventsHardeningTest, TheApplierTakesTheLeaseBeforeItReadsAndYieldsToAWaitingRegularPass) {
    const auto v = subscribed();
    providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "lease.txt", "0A", 1, std::string("x")));
    (void)poll(v);

    sync::events::Applier busy({.tryAcquirePass = [](uint32_t) { return false; },
                                .releasePass = [](uint32_t) {},
                                .runScoped = {}, .regularWaiting = [](uint32_t) { return false; }, .shouldStop = {}});
    const auto a = busy.applyVault(v.f.vault->id);
    EXPECT_TRUE(a.busy);
    EXPECT_EQ(a.claimed, 0u) << "nothing read without the lease";

    sync::events::Applier yielding({.tryAcquirePass = [](uint32_t) { return true; },
                                    .releasePass = [](uint32_t) {},
                                    .runScoped = {}, .regularWaiting = [](uint32_t) { return true; }, .shouldStop = {}});
    const auto b = yielding.applyVault(v.f.vault->id);
    EXPECT_TRUE(b.busy);
    EXPECT_EQ(b.claimed, 0u);
    EXPECT_EQ(countState(v.f.vault->id, umodel::InboxState::Pending), 1u);
}

TEST_F(UpstreamEventsHardeningTest, AScopedPassDroppedBeforeItRunsReleasesItsLeaseAndReportsFailure) {
    const auto f = remoteVault(superUser);
    const auto previous = runtime::Deps::get().syncController;
    const auto controller = std::make_shared<sync::Controller>();
    runtime::Deps::setSyncController(controller);
    ASSERT_TRUE(controller->tryAcquirePass(f.vault->id));
    bool failed = false;
    {
        auto scope = std::make_shared<sync::model::PassScope>();
        scope->on_finish = [&](const bool ok, const std::string&) { failed = !ok; };
        auto cloud = std::make_shared<sync::Cloud>(f.engine, scope);
        cloud->adoptPassLease();
    }   // dropped unrun
    EXPECT_FALSE(controller->passRunning(f.vault->id));
    EXPECT_TRUE(failed);
    runtime::Deps::setSyncController(previous);
}

TEST_F(UpstreamEventsHardeningTest, ManualIngestNeedsTheEventConfigurationRights) {
    const auto owner = createUser("ingest_owner", "unprivileged");
    const auto f = remoteVault(owner);
    EXPECT_THROW((void)ops::upstream::ingestEventRecords(owner, f.vault->id, {"{}"}), ops::Denied)
        << "owning the vault is not enough: a removal could delete files";
    const auto bucket = std::static_pointer_cast<vault::model::S3Vault>(f.vault)->bucket;
    const auto body = nlohmann::json::parse(awsBody(bucket, "ObjectCreated:Put", "m.txt", "0A", 1, std::string("e")));
    const auto r = ops::upstream::ingestEventRecords(superUser, f.vault->id, {body["Records"][0].dump()});
    EXPECT_EQ(r.inserted, 1u);
}

TEST_F(UpstreamEventsHardeningTest, EncryptingVaultsIgnoreForeignObjectsByDefault) {
    auto f = remoteVault(superUser);
    const auto s3 = std::static_pointer_cast<vault::model::S3Vault>(f.vault);
    ASSERT_TRUE(s3->encrypt_upstream);
    runtime::Deps::get().apiKeyManager->setAdmin(s3->api_key_id, true, providerState()->account, "{}", std::time(nullptr));
    const auto status = ops::upstream::enableEvents(superUser, f.vault->id, {});
    EXPECT_EQ(status.foreign_objects, "ignore");
}

TEST_F(UpstreamEventsHardeningTest, ChannelAccountAndErrorsAreShownOnlyToWhoMayViewTheChannelsKey) {
    const auto v = subscribed();
    db::query::upstream::Channel::setState(v.channel.id, umodel::ChannelState::Active,
                                           "provider said: account 123456789012 queue vaulthalla-events-us-east-1");
    // A reader of upstream status and of vaults, but of no API key.
    const auto roleName = "ev_reader_" + tag();
    (void)ops::roles::createAdminRole(superUser, {.name = roleName, .from = std::string("unprivileged")}, "test");
    db::Transactions::exec("t", [&](pqxx::work& txn) {
        txn.exec("UPDATE admin_role SET upstream_permissions = B'00000001', "
                 "vaults_permissions = (SELECT vaults_permissions FROM admin_role WHERE name = 'auditor') WHERE name = $1",
                 pqxx::params{roleName});
    });
    (void)identities::manager().reconcile();
    const auto reader = createUser("ev_reader", roleName);

    const auto find = [&](const std::vector<ops::upstream::EventStatus>& all) -> std::optional<ops::upstream::EventStatus> {
        for (const auto& s : all)
            if (s.vault_id == v.f.vault->id) return s;
        return std::nullopt;
    };
    const auto mine = find(ops::upstream::eventStatus(superUser));
    ASSERT_TRUE(mine && mine->channel);
    EXPECT_FALSE(mine->channel->account_ref.empty());
    EXPECT_TRUE(mine->channel->last_error.has_value());

    const auto theirs = find(ops::upstream::eventStatus(reader));
    ASSERT_TRUE(theirs && theirs->channel) << "the vault and its subscription are still visible";
    EXPECT_TRUE(theirs->channel->account_ref.empty()) << "no keys.api View on the channel's key";
    EXPECT_FALSE(theirs->channel->last_error.has_value());
    EXPECT_EQ(theirs->state, mine->state);
}

TEST_F(UpstreamEventsHardeningTest, ShutdownIsBoundedDuringATeardownRetry) {
    const auto v = subscribed();
    db::query::upstream::Subscription::setState(v.subscriptionId, umodel::SubscriptionState::Removing, "test");
    providerState()->blockUnsubscribe = true;
    sync::events::Service service;
    service.start();
    for (int i = 0; i < 300 && !providerState()->unsubscribeEntered.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ASSERT_TRUE(providerState()->unsubscribeEntered.load()) << "the teardown retry reached the provider";
    const auto started = std::chrono::steady_clock::now();
    service.requestStop();
    service.join();
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(1));
    providerState()->blockUnsubscribe = false;
}

TEST_F(UpstreamEventsHardeningTest, ShutdownIsBoundedDuringAnApplyBatch) {
    const auto v = subscribed(false, "ignore");
    for (int i = 0; i < 3; ++i)
        providerState()->push(awsBody(v.bucket, "ObjectCreated:Put", "new-" + std::to_string(i) + ".txt",
                                      "0" + std::to_string(i + 1), 1, std::string("n") + std::to_string(i)));
    (void)poll(v);
    v.f.bucket->blockHeads = true;   // the ignore policy HEADs unknown keys; this one never answers
    sync::events::Service service;
    service.start();
    for (int i = 0; i < 300 && !v.f.bucket->headEntered.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ASSERT_TRUE(v.f.bucket->headEntered.load()) << "the applier reached a HEAD";
    const auto started = std::chrono::steady_clock::now();
    service.requestStop();
    service.join();
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(1));
    v.f.bucket->blockHeads = false;
    EXPECT_GE(countState(v.f.vault->id, umodel::InboxState::Pending), 1u) << "keys not reached stay pending";
}

}
