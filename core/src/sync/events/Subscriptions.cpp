#include "sync/events/Subscriptions.hpp"

#include "db/Transactions.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "db/query/upstream/Channel.hpp"
#include "db/query/upstream/Inbox.hpp"
#include "db/query/upstream/Subscription.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/Controller.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <chrono>
#include <mutex>
#include <stdexcept>
#include <unordered_set>

namespace vh::sync::events::subscriptions {

namespace {

namespace smodel = storage::upstream::model;
namespace sadmin = storage::s3::provider::admin;
using SubQ = db::query::upstream::Subscription;
using ChanQ = db::query::upstream::Channel;

// The note a retirement teardown leaves, so a restore knows to re-arm.
constexpr const char* kRetiredNote = "vault deleted";
// The note a bucket lock leaves (the applier's too), so an unlock knows what to re-arm.
constexpr const char* kProtectedNote = "bucket is protected";

// activeFor cache.
struct ActiveCache {
    std::mutex mutex;
    std::unordered_set<uint32_t> vaults;
    std::chrono::steady_clock::time_point loadedAt{};
    bool loaded = false;
};

ActiveCache& activeCache() {
    static ActiveCache c;
    return c;
}

void cacheSet(const uint32_t vaultId, const bool active) {
    auto& c = activeCache();
    std::scoped_lock lock(c.mutex);
    if (active) c.vaults.insert(vaultId);
    else c.vaults.erase(vaultId);
}

struct Context {
    std::shared_ptr<vault::model::S3Vault> vault;
    std::shared_ptr<vault::model::APIKey> key;
    storage::upstream::BucketIdentity identity;
};

// The vault, its (decrypted) administrative key and the resolved bucket identity. Throws std::invalid_argument for
// anything the operator must fix first.
Context contextFor(const uint32_t vaultId) {
    const auto& deps = runtime::Deps::get();
    if (!deps.storageManager || !deps.apiKeyManager) throw std::runtime_error("storage is not initialised");
    const auto vault = std::dynamic_pointer_cast<vault::model::S3Vault>(deps.storageManager->getVault(vaultId));
    if (!vault) throw std::invalid_argument("vault " + std::to_string(vaultId) + " is not an S3 vault");

    Context ctx;
    ctx.vault = vault;
    ctx.key = deps.apiKeyManager->getAPIKey(vault->api_key_id);
    if (!sadmin::supportsAdmin(*ctx.key))
        throw std::invalid_argument("event-driven sync supports AWS S3 and Cloudflare R2 vaults only");
    if (!ctx.key->admin_enabled)
        throw std::invalid_argument("API key '" + ctx.key->name + "' is not an administrative credential: enable "
                                    "provider administration on it first (vh upstream admin enable " +
                                    std::to_string(ctx.key->id) + ")");

    auto account = sadmin::staticAccountRef(*ctx.key);
    if (!account) {
        // AWS: one STS call, then cached on the key.
        const auto admin = sadmin::adminFor(ctx.key);
        if (!admin) throw std::invalid_argument("no administration adapter for this provider");
        account = admin->identity().account_ref;
        deps.apiKeyManager->setAccountRef(ctx.key->id, account);
        ctx.key->provider_account_id = account;
    }
    ctx.identity = {.provider = sadmin::providerIdentity(ctx.key->provider), .account_ref = account, .bucket = vault->bucket};
    return ctx;
}

sadmin::ChannelRef refOf(const smodel::Channel& ch) {
    return {.queue_name = ch.queue_name,
            .queue_ref = ch.queue_ref.value_or(""),
            .queue_arn = ch.queue_arn.value_or(""),
            .dlq_ref = ch.dlq_ref.value_or(""),
            .dlq_arn = ch.dlq_arn.value_or(""),
            .created = ch.created_by_vaulthalla};
}

std::string ruleIdFor(const int64_t subscriptionId) { return std::string(sadmin::kOwnedPrefix) + std::to_string(subscriptionId); }

smodel::ForeignObjects foreignFrom(const std::string& value) {
    try {
        return smodel::foreignObjectsFromString(value.empty() ? "import" : value);
    } catch (const std::invalid_argument&) {
        throw std::invalid_argument("foreign_objects must be 'import' or 'ignore'");
    }
}

// Removes our rules and, when nothing references the channel any more and Vaulthalla created it, the queue.
void teardown(const smodel::Subscription& sub, const std::optional<std::string>& endNote) {
    SubQ::setState(sub.id, smodel::SubscriptionState::Removing);
    if (sub.vault_id) cacheSet(*sub.vault_id, false);

    const auto channel = sub.channel_id ? ChanQ::get(*sub.channel_id) : std::nullopt;
    const auto bucket = db::query::upstream::Bucket::get(sub.upstream_bucket_id);
    if (channel && channel->api_key_id && bucket && (!sub.rule_ids.empty() || channel->queue_ref)) {
        const auto key = runtime::Deps::get().apiKeyManager->getAPIKey(*channel->api_key_id);
        const auto events = sadmin::eventsFor(key);
        if (!events) throw std::invalid_argument("no event adapter for this provider");
        if (!sub.rule_ids.empty())
            events->unsubscribe(refOf(*channel), {.bucket = bucket->bucket, .rule_id = ruleIdFor(sub.id), .prefix = sub.prefix},
                                sub.rule_ids);
        SubQ::setRuleIds(sub.id, {});
        SubQ::setState(sub.id, smodel::SubscriptionState::Removed, endNote ? *endNote : std::string{});

        const auto live = ChanQ::countSubscriptions(channel->id, {smodel::SubscriptionState::Pending,
                                                                  smodel::SubscriptionState::Active,
                                                                  smodel::SubscriptionState::Failed,
                                                                  smodel::SubscriptionState::Removing});
        if (live == 0 && channel->created_by_vaulthalla && channel->queue_ref) {
            events->removeChannel(refOf(*channel));
            ChanQ::setState(channel->id, smodel::ChannelState::Removed, "");
        }
        return;
    }
    // Never provisioned at the provider (or its credential is gone): nothing to remove there.
    SubQ::setState(sub.id, smodel::SubscriptionState::Removed, endNote ? *endNote : std::string{});
}

// Provider side of an enable/repair, on an existing subscription row. Persists each step before the call it guards.
void provision(const Context& ctx, smodel::Subscription sub) {
    const auto admin = sadmin::adminFor(ctx.key);
    if (!admin) throw std::invalid_argument("no administration adapter for this provider");

    std::string region;
    if (ctx.key->provider == vault::model::S3Provider::AWS) {
        const auto located = admin->headBucket(ctx.vault->bucket);
        if (!located) throw std::invalid_argument("bucket '" + ctx.vault->bucket + "' does not exist");
        region = *located;
    }

    auto channel = ChanQ::getOrCreate(ctx.identity.provider, *ctx.identity.account_ref, region,
                                      sadmin::defaultQueueName(ctx.identity.provider, region), ctx.key->id);
    SubQ::setChannel(sub.id, channel.id);

    const auto events = sadmin::eventsFor(ctx.key);   // CapabilityMissing for R2 without a token
    if (!events) throw std::invalid_argument("no event adapter for this provider");

    if (channel.state != smodel::ChannelState::Active || !channel.queue_ref) {
        const auto ref = events->ensureChannel({.account_ref = *ctx.identity.account_ref,
                                                .region = region,
                                                .queue_name = channel.queue_name});
        ChanQ::updateRefs(channel.id, ref.queue_ref, ref.queue_arn.empty() ? std::nullopt : std::make_optional(ref.queue_arn),
                          ref.dlq_ref.empty() ? std::nullopt : std::make_optional(ref.dlq_ref),
                          ref.dlq_arn.empty() ? std::nullopt : std::make_optional(ref.dlq_arn),
                          channel.created_by_vaulthalla || ref.created, smodel::ChannelState::Active);
        ChanQ::setState(channel.id, smodel::ChannelState::Active, "");
        channel = *ChanQ::get(channel.id);
    }

    unsigned int foreign = 0;
    for (const auto& rule : events->rules(ctx.vault->bucket))
        if (rule.foreign) ++foreign;
    SubQ::setForeignRules(sub.id, foreign);

    const auto ruleIds = events->subscribe(refOf(channel), {.bucket = ctx.vault->bucket, .rule_id = ruleIdFor(sub.id),
                                                            .prefix = sub.prefix});
    SubQ::setRuleIds(sub.id, ruleIds);
    SubQ::setState(sub.id, smodel::SubscriptionState::Active, "");
    if (sub.vault_id) {
        cacheSet(*sub.vault_id, true);
        (void)db::query::upstream::Inbox::routeUnassigned(ctx.identity.provider, *ctx.identity.account_ref,
                                                          ctx.vault->bucket, *sub.vault_id, sub.id);
    }
}

Status statusOf(const uint32_t vaultId, const std::optional<smodel::Subscription>& sub, const std::string& bucket) {
    Status s;
    s.vault_id = vaultId;
    s.bucket = bucket;
    const auto counts = db::query::upstream::Inbox::counts(vaultId);
    s.inbox_pending = counts.pending;
    s.inbox_applied = counts.applied;
    s.inbox_failed = counts.failed;
    s.inbox_done_24h = counts.done_24h;
    s.inbox_self_24h = counts.self_24h;
    s.last_event_at = counts.last_event_at;
    if (!sub) return s;

    s.subscription_id = sub->id;
    s.state = smodel::to_string(sub->state);
    s.baseline_state = smodel::to_string(sub->baseline_state);
    s.foreign_objects = smodel::to_string(sub->foreign_objects);
    s.prefix = sub->prefix;
    s.last_error = sub->last_error;
    s.rule_ids = sub->rule_ids;
    s.foreign_rules = sub->foreign_rules;
    if (sub->channel_id)
        if (const auto ch = ChanQ::get(*sub->channel_id)) {
            ChannelInfo info;
            info.id = ch->id;
            info.provider = ch->provider;
            info.account_ref = ch->account_ref;
            info.region = ch->region;
            info.queue_name = ch->queue_name;
            info.state = smodel::to_string(ch->state);
            info.last_poll_at = ch->last_poll_at;
            info.last_success_at = ch->last_success_at;
            info.last_message_at = ch->last_message_at;
            info.last_error_at = ch->last_error_at;
            info.last_error = ch->last_error;
            info.backlog = ch->backlog_estimate;
            info.consecutive_failures = ch->consecutive_failures;
            s.channel = info;
        }
    return s;
}

std::string bucketOf(const uint32_t vaultId) {
    const auto& storage = runtime::Deps::get().storageManager;
    if (!storage) return {};
    if (const auto v = std::dynamic_pointer_cast<vault::model::S3Vault>(storage->getVault(vaultId))) return v->bucket;
    return {};
}

std::optional<smodel::Subscription> latestForVault(const uint32_t vaultId) {
    std::optional<int64_t> id;
    db::Transactions::exec("upstream::subscriptions::latestForVault", [&](pqxx::work& txn) {
        const auto res = txn.exec("SELECT id FROM upstream_event_subscription WHERE vault_id = $1 ORDER BY id DESC LIMIT 1",
                                  pqxx::params{vaultId});
        if (!res.empty()) id = res.one_row_ref()["id"].as<int64_t>();
    });
    return id ? SubQ::get(*id) : std::nullopt;
}

Status enableImpl(const EnableRequest& request, const bool forceProvision) {
    const auto ctx = contextFor(request.vault_id);
    storage::upstream::guard::require(ctx.identity);
    const auto foreign = foreignFrom(request.foreign_objects);

    // The bucket row (identity-keyed) the subscription hangs off.
    auto bucket = db::query::upstream::Bucket::getByIdentity(ctx.identity.provider, *ctx.identity.account_ref,
                                                            ctx.vault->bucket);
    if (!bucket) {
        db::query::upstream::Bucket::recordSeen(ctx.identity.provider, *ctx.identity.account_ref, ctx.key->id,
                                                {{.bucket = ctx.vault->bucket}});
        bucket = db::query::upstream::Bucket::getByIdentity(ctx.identity.provider, *ctx.identity.account_ref,
                                                           ctx.vault->bucket);
        if (!bucket) throw std::runtime_error("could not record bucket '" + ctx.vault->bucket + "'");
    }
    if (!bucket->vault_id) db::query::upstream::Bucket::bindVault(bucket->id, request.vault_id, bucket->ownership);

    auto sub = SubQ::getLiveForVault(request.vault_id);
    if (sub && sub->state == smodel::SubscriptionState::Removing)
        throw std::invalid_argument("event subscription of vault " + std::to_string(request.vault_id) +
                                    " is being removed; repair it or wait for the teardown to finish");
    const bool sameSettings = sub && sub->prefix == request.prefix && sub->foreign_objects == foreign;
    if (sub && sub->state == smodel::SubscriptionState::Active && sameSettings && !forceProvision)
        return statusOf(request.vault_id, sub, ctx.vault->bucket);

    if (sub && !sameSettings) {
        if (sub->prefix != request.prefix && !sub->rule_ids.empty())
            throw std::invalid_argument("disable event-driven sync first to change its prefix");
        SubQ::setSettings(sub->id, request.prefix, foreign);
    }
    if (!sub) {
        sub = SubQ::create(std::nullopt, bucket->id, request.vault_id, request.prefix, foreign,
                           request.baseline_required ? smodel::BaselineState::Pending : smodel::BaselineState::None);
        if (!sub) throw std::runtime_error("another event subscription for vault " + std::to_string(request.vault_id) +
                                           " was created concurrently");
    } else {
        SubQ::setState(sub->id, smodel::SubscriptionState::Pending);
    }
    sub = SubQ::get(sub->id);

    try {
        provision(ctx, *sub);
    } catch (const std::exception& e) {
        SubQ::setState(sub->id, smodel::SubscriptionState::Failed, e.what());
        throw;
    }

    sub = SubQ::get(sub->id);
    if (sub && sub->baseline_state == smodel::BaselineState::Pending)
        if (const auto& controller = runtime::Deps::get().syncController)
            (void)controller->runNow(request.vault_id, 3);   // the baseline listing
    return statusOf(request.vault_id, sub, ctx.vault->bucket);
}

}

Status enable(const EnableRequest& request) { return enableImpl(request, false); }

Status disable(const uint32_t vaultId) {
    const auto sub = SubQ::getLiveForVault(vaultId);
    if (!sub) return statusOf(vaultId, latestForVault(vaultId), bucketOf(vaultId));
    try {
        teardown(*sub, std::nullopt);
    } catch (const std::exception& e) {
        SubQ::setState(sub->id, smodel::SubscriptionState::Removing, e.what());
        throw;
    }
    return statusOf(vaultId, SubQ::get(sub->id), bucketOf(vaultId));
}

Status repair(const uint32_t vaultId) {
    const auto sub = SubQ::getLiveForVault(vaultId);
    if (!sub) throw std::invalid_argument("vault " + std::to_string(vaultId) + " has no event subscription to repair");
    if (sub->state == smodel::SubscriptionState::Removing) return disable(vaultId);
    return enableImpl({.vault_id = vaultId,
                       .prefix = sub->prefix,
                       .foreign_objects = smodel::to_string(sub->foreign_objects),
                       .baseline_required = sub->baseline_state == smodel::BaselineState::Pending},
                      true);
}

Status status(const uint32_t vaultId) {
    auto sub = SubQ::getLiveForVault(vaultId);
    if (!sub) sub = latestForVault(vaultId);
    return statusOf(vaultId, sub, bucketOf(vaultId));
}

void onVaultRetired(const uint32_t vaultId) noexcept {
    try {
        // Only marked here (a delete never waits on the provider); the event service's sweep removes the rules.
        const auto sub = SubQ::getLiveForVault(vaultId);
        if (!sub) return;
        SubQ::setState(sub->id, smodel::SubscriptionState::Removing, std::string(kRetiredNote));
        cacheSet(vaultId, false);
    } catch (const std::exception& e) {
        log::Registry::sync()->error("[UpstreamEvents] Vault {}: retirement hook failed: {}", vaultId, e.what());
    }
}

void onVaultReinstated(const uint32_t vaultId) noexcept {
    try {
        if (const auto live = SubQ::getLiveForVault(vaultId)) {
            // Restored before the teardown ran: re-arm the same subscription.
            if (live->state != smodel::SubscriptionState::Removing || !live->last_error ||
                !live->last_error->starts_with(kRetiredNote))
                return;
            SubQ::setState(live->id, smodel::SubscriptionState::Failed, "");
            (void)enableImpl({.vault_id = vaultId, .prefix = live->prefix,
                              .foreign_objects = smodel::to_string(live->foreign_objects)}, true);
            log::Registry::sync()->info("[UpstreamEvents] Vault {} restored; event-driven sync re-armed", vaultId);
            return;
        }
        const auto last = latestForVault(vaultId);
        if (!last || last->state != smodel::SubscriptionState::Removed || !last->last_error ||
            !last->last_error->starts_with(kRetiredNote))
            return;
        (void)enable({.vault_id = vaultId, .prefix = last->prefix, .foreign_objects = smodel::to_string(last->foreign_objects)});
        log::Registry::sync()->info("[UpstreamEvents] Vault {} restored; event-driven sync re-armed", vaultId);
    } catch (const std::exception& e) {
        log::Registry::sync()->warn("[UpstreamEvents] Vault {} restored, but event-driven sync was not re-armed: {}", vaultId, e.what());
    }
}

void onBucketProtected(const storage::upstream::BucketIdentity& bucket) noexcept {
    try {
        if (!bucket.account_ref) return;
        for (const auto& sub : SubQ::listLiveForBucket(bucket.provider, *bucket.account_ref, bucket.bucket)) {
            if (sub.state != smodel::SubscriptionState::Active && sub.state != smodel::SubscriptionState::Pending) continue;
            SubQ::setState(sub.id, smodel::SubscriptionState::Failed, std::string(kProtectedNote));
            if (sub.vault_id) cacheSet(*sub.vault_id, false);
        }
    } catch (const std::exception& e) {
        log::Registry::sync()->error("[UpstreamEvents] protecting '{}': stopping its subscriptions failed: {}", bucket.bucket,
                                     e.what());
    }
}

void onBucketUnprotected(const storage::upstream::BucketIdentity& bucket) noexcept {
    try {
        if (!bucket.account_ref) return;
        for (const auto& sub : SubQ::listLiveForBucket(bucket.provider, *bucket.account_ref, bucket.bucket)) {
            if (sub.state != smodel::SubscriptionState::Failed || !sub.last_error ||
                !sub.last_error->starts_with(kProtectedNote))
                continue;
            const auto channel = sub.channel_id ? ChanQ::get(*sub.channel_id) : std::nullopt;
            if (!sub.rule_ids.empty() && channel && channel->queue_ref &&
                channel->state != smodel::ChannelState::Removed && channel->state != smodel::ChannelState::Failed) {
                // The lock never touched the provider: rules and queue are as they were.
                SubQ::setState(sub.id, smodel::SubscriptionState::Active, "");
                if (sub.vault_id) cacheSet(*sub.vault_id, true);
            } else {
                SubQ::setState(sub.id, smodel::SubscriptionState::Failed,
                               "the bucket was unprotected; run `vh upstream events repair` to finish setting events up");
            }
            // Events held while the bucket was locked are due again now, not after their protection backoff.
            if (sub.vault_id)
                db::Transactions::exec("upstream::subscriptions::onBucketUnprotected", [&](pqxx::work& txn) {
                    txn.exec("UPDATE upstream_event_inbox SET next_attempt_at = NULL "
                             "WHERE vault_id = $1 AND state = 'pending' AND last_error LIKE 'bucket is protected%'",
                             pqxx::params{*sub.vault_id});
                });
        }
    } catch (const std::exception& e) {
        log::Registry::sync()->error("[UpstreamEvents] unprotecting '{}': re-arming its subscriptions failed: {}",
                                     bucket.bucket, e.what());
    }
}

bool activeFor(const uint32_t vaultId) {
    auto& c = activeCache();
    {
        std::scoped_lock lock(c.mutex);
        if (c.loaded && std::chrono::steady_clock::now() - c.loadedAt < std::chrono::seconds(15))
            return c.vaults.contains(vaultId);
    }
    try {
        const auto ids = SubQ::listActiveVaultIds();
        std::scoped_lock lock(c.mutex);
        c.vaults = std::unordered_set<uint32_t>(ids.begin(), ids.end());
        c.loaded = true;
        c.loadedAt = std::chrono::steady_clock::now();
        return c.vaults.contains(vaultId);
    } catch (const std::exception&) {
        std::scoped_lock lock(c.mutex);
        return c.vaults.contains(vaultId);
    }
}

void retryTeardowns() noexcept {
    try {
        for (const auto& sub : SubQ::listByState(smodel::SubscriptionState::Removing)) {
            try {
                teardown(sub, sub.last_error && sub.last_error->starts_with(kRetiredNote)
                                  ? std::make_optional<std::string>(kRetiredNote)
                                  : std::nullopt);
            } catch (const std::exception& e) {
                SubQ::setState(sub.id, smodel::SubscriptionState::Removing,
                               (sub.last_error && sub.last_error->starts_with(kRetiredNote) ? std::string(kRetiredNote) + ": "
                                                                                            : std::string{}) + e.what());
            }
        }
    } catch (const std::exception& e) {
        log::Registry::sync()->warn("[UpstreamEvents] teardown retry sweep failed: {}", e.what());
    }
}

bool importsForeignObjects(const uint32_t vaultId) {
    try {
        const auto sub = SubQ::getLiveForVault(vaultId);
        return sub && sub->state == smodel::SubscriptionState::Active &&
               sub->foreign_objects == smodel::ForeignObjects::Import;
    } catch (const std::exception&) {
        return false;   // unknown: keep the strict (authenticated) behaviour
    }
}

void invalidateCache() noexcept {
    auto& c = activeCache();
    std::scoped_lock lock(c.mutex);
    c.loaded = false;
}

}
