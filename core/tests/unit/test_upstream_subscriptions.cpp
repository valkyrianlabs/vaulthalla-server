// Event subscriptions of S3 vaults (#96), against the test DB and an in-memory provider:
//  - enable is idempotent, records other applications' rules, resolves and persists an AWS account once;
//  - disable removes only our rule ids; the shared channel goes only when nothing uses it and we created it;
//  - a failed provisioning is recorded and repaired; a missing capability names what to grant;
//  - deleting a vault marks its subscription for teardown (finished by the sweep), restoring re-arms it;
//  - keys that aren't administrative credentials are refused.

#include "../helpers/sync_conflict_harness.hpp"
#include "../helpers/upstream_event_fakes.hpp"

#include "db/query/upstream/Channel.hpp"
#include "db/query/upstream/Subscription.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/events/Subscriptions.hpp"

namespace vh::test_upstream_subscriptions {

using namespace test_support::sync_conflicts;
using namespace test_support::upstream_events;
namespace subs = sync::events::subscriptions;
namespace umodel = storage::upstream::model;

class UpstreamSubscriptionsTest : public Harness {
protected:
    void SetUp() override {
        Harness::SetUp();
        if (skipTests) return;
        installFakeProvider();
        storage::upstream::guard::clearForTesting();
        subs::invalidateCache();
    }

    void TearDown() override {
        removeFakeProvider();
        storage::upstream::guard::clearForTesting();
    }

    static Fixture adminVault(const std::optional<std::string>& account) {
        auto f = remoteVault(superUser);
        const auto keyId = std::static_pointer_cast<vault::model::S3Vault>(f.vault)->api_key_id;
        runtime::Deps::get().apiKeyManager->setAdmin(keyId, true, account, "{}", std::time(nullptr));
        if (!account) runtime::Deps::get().apiKeyManager->setAccountRef(keyId, std::nullopt);
        return f;
    }
};

TEST_F(UpstreamSubscriptionsTest, EnableIsIdempotentAndCountsForeignRules) {
    storage::s3::provider::admin::NotificationRule other;
    other.id = "other-app";
    other.destination = "arn:aws:sqs:us-east-1:123456789012:someone-else";
    other.foreign = true;
    providerState()->foreignRules = {other};
    const auto f = adminVault(providerState()->account);
    const auto first = subs::enable({.vault_id = f.vault->id});
    EXPECT_EQ(first.state, "active");
    EXPECT_EQ(first.foreign_rules, 1u);
    ASSERT_EQ(first.rule_ids.size(), 1u);
    EXPECT_EQ(first.rule_ids[0], "vaulthalla-" + std::to_string(first.subscription_id));
    ASSERT_TRUE(first.channel.has_value());
    EXPECT_EQ(first.channel->queue_name, "vaulthalla-events-us-east-1");
    EXPECT_TRUE(subs::activeFor(f.vault->id));

    const auto again = subs::enable({.vault_id = f.vault->id});
    EXPECT_EQ(again.subscription_id, first.subscription_id);
    EXPECT_EQ(providerState()->subscribeCalls, 1u) << "an active subscription with the same settings is left alone";
}

TEST_F(UpstreamSubscriptionsTest, AwsAccountIsResolvedOnceAndPersisted) {
    const auto f = adminVault(std::nullopt);
    (void)subs::enable({.vault_id = f.vault->id});
    EXPECT_EQ(providerState()->identityCalls, 1u);
    const auto keyId = std::static_pointer_cast<vault::model::S3Vault>(f.vault)->api_key_id;
    EXPECT_EQ(runtime::Deps::get().apiKeyManager->getAPIKey(keyId)->provider_account_id.value_or(""), providerState()->account);
    (void)subs::repair(f.vault->id);
    EXPECT_EQ(providerState()->identityCalls, 1u) << "cached on the key";
}

TEST_F(UpstreamSubscriptionsTest, DisableRemovesOnlyOurRulesAndTheChannelWhenUnused) {
    providerState()->region = "eu-west-3";   // a channel no other test in this database uses
    const auto a = adminVault(providerState()->account);
    const auto b = adminVault(providerState()->account);
    const auto sa = subs::enable({.vault_id = a.vault->id});
    const auto sb = subs::enable({.vault_id = b.vault->id});
    ASSERT_TRUE(sa.channel && sb.channel);
    EXPECT_EQ(sa.channel->id, sb.channel->id) << "one shared queue per account and region";

    const auto da = subs::disable(a.vault->id);
    EXPECT_EQ(da.state, "removed");
    EXPECT_EQ(providerState()->unsubscribed, std::vector<std::string>{"vaulthalla-" + std::to_string(sa.subscription_id)});
    EXPECT_EQ(providerState()->removeChannelCalls, 0u) << "still used by the other vault";
    EXPECT_FALSE(subs::activeFor(a.vault->id));

    (void)subs::disable(b.vault->id);
    EXPECT_EQ(providerState()->removeChannelCalls, 1u);
    EXPECT_EQ(db::query::upstream::Channel::get(sa.channel->id)->state, umodel::ChannelState::Removed);
}

TEST_F(UpstreamSubscriptionsTest, FailedProvisioningIsRecordedAndRepaired) {
    const auto f = adminVault(providerState()->account);
    providerState()->subscribeFailures = 1;
    EXPECT_ANY_THROW((void)subs::enable({.vault_id = f.vault->id}));
    const auto failed = subs::status(f.vault->id);
    EXPECT_EQ(failed.state, "failed");
    ASSERT_TRUE(failed.last_error.has_value());
    EXPECT_NE(failed.last_error->find("overlap"), std::string::npos);

    const auto repaired = subs::repair(f.vault->id);
    EXPECT_EQ(repaired.state, "active");
    EXPECT_FALSE(repaired.last_error.has_value() && !repaired.last_error->empty());
}

TEST_F(UpstreamSubscriptionsTest, MissingCapabilityFailsWithWhatToGrant) {
    const auto f = adminVault(providerState()->account);
    providerState()->capabilityMissing = "grant sqs:CreateQueue on arn:aws:sqs:*:123456789012:vaulthalla-*";
    EXPECT_THROW((void)subs::enable({.vault_id = f.vault->id}), storage::s3::provider::admin::CapabilityMissing);
    const auto s = subs::status(f.vault->id);
    EXPECT_EQ(s.state, "failed");
    EXPECT_NE(s.last_error.value_or("").find("sqs:CreateQueue"), std::string::npos);
}

TEST_F(UpstreamSubscriptionsTest, RetiredVaultIsTornDownBySweepAndRestoreRearms) {
    const auto f = adminVault(providerState()->account);
    const auto enabled = subs::enable({.vault_id = f.vault->id, .prefix = "data/"});

    subs::onVaultRetired(f.vault->id);
    EXPECT_EQ(subs::status(f.vault->id).state, "removing");
    EXPECT_TRUE(providerState()->unsubscribed.empty()) << "deleting a vault never waits on the provider";
    EXPECT_FALSE(subs::activeFor(f.vault->id));

    subs::retryTeardowns();
    const auto removed = subs::status(f.vault->id);
    EXPECT_EQ(removed.state, "removed");
    EXPECT_EQ(providerState()->unsubscribed.size(), 1u);

    subs::onVaultReinstated(f.vault->id);
    const auto back = subs::status(f.vault->id);
    EXPECT_EQ(back.state, "active");
    EXPECT_EQ(back.prefix, "data/");
    EXPECT_NE(back.subscription_id, enabled.subscription_id);
}

TEST_F(UpstreamSubscriptionsTest, DisabledManuallyIsNotRearmedByARestore) {
    const auto f = adminVault(providerState()->account);
    (void)subs::enable({.vault_id = f.vault->id});
    (void)subs::disable(f.vault->id);
    subs::onVaultReinstated(f.vault->id);
    EXPECT_EQ(subs::status(f.vault->id).state, "removed");
}

TEST_F(UpstreamSubscriptionsTest, OnlyAdministrativeKeysAndUnprotectedBucketsQualify) {
    const auto plain = remoteVault(superUser);
    EXPECT_THROW((void)subs::enable({.vault_id = plain.vault->id}), std::invalid_argument);

    const auto f = adminVault(providerState()->account);
    const auto bucket = std::static_pointer_cast<vault::model::S3Vault>(f.vault)->bucket;
    storage::upstream::guard::setForTesting({{.provider = "aws-s3", .account_ref = providerState()->account, .bucket = bucket}});
    EXPECT_THROW((void)subs::enable({.vault_id = f.vault->id}), storage::upstream::BucketProtected);
    EXPECT_EQ(providerState()->subscribeCalls, 0u);
}

}
