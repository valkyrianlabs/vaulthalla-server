#include "sync/events/Service.hpp"

#include "db/query/upstream/Channel.hpp"
#include "db/query/upstream/Inbox.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/s3/curl/Http.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/Cloud.hpp"
#include "sync/events/Event.hpp"
#include "sync/events/Ingest.hpp"
#include "sync/events/Subscriptions.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"

#include <algorithm>
#include <set>

namespace vh::sync::events {

namespace {

namespace svcmodel = storage::upstream::model;
namespace svcadmin = storage::s3::provider::admin;

constexpr auto kMaintenanceInterval = std::chrono::seconds(30);
constexpr auto kVisibility = std::chrono::seconds(120);
constexpr auto kCycleWait = std::chrono::seconds(1);

svcadmin::ChannelRef channelRef(const svcmodel::Channel& ch) {
    return {.queue_name = ch.queue_name,
            .queue_ref = ch.queue_ref.value_or(""),
            .queue_arn = ch.queue_arn.value_or(""),
            .dlq_ref = ch.dlq_ref.value_or(""),
            .dlq_arn = ch.dlq_arn.value_or(""),
            .created = ch.created_by_vaulthalla};
}

// Sleeps up to `d`, returning early once `stop` is set.
void sleepUnlessStopped(const std::atomic<bool>& stop, const std::chrono::milliseconds d) {
    const auto until = std::chrono::steady_clock::now() + d;
    while (!stop.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < until)
        std::this_thread::sleep_for(std::min<std::chrono::milliseconds>(
            std::chrono::milliseconds(50),
            std::chrono::duration_cast<std::chrono::milliseconds>(until - std::chrono::steady_clock::now())));
}

void installCloudHooks() {
    Cloud::setPendingRemovalsProvider([](const uint32_t vaultId) {
        try {
            return Applier::pendingRemovals(vaultId);
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[UpstreamEvents] Vault {}: pending removals unavailable: {}", vaultId, e.what());
            return std::unordered_set<std::u8string>{};
        }
    });
    Cloud::setEventHooks({
        .baselineNeeded = [](const uint32_t v) {
            try { return Applier::baselineNeeded(v); } catch (const std::exception&) { return false; }
        },
        .baselineListed = [](const uint32_t v, const std::time_t at) {
            try { Applier::onBaselineListed(v, at); } catch (const std::exception& e) {
                log::Registry::sync()->warn("[UpstreamEvents] Vault {}: could not record the baseline listing: {}", v, e.what());
            }
        },
        .indexFresh = [](const uint32_t v, const std::chrono::seconds maxAge) {
            try { return Applier::indexKeptFresh(v, maxAge); } catch (const std::exception&) { return false; }
        },
    });
}

}

std::chrono::seconds channelBackoff(const unsigned int failures) {
    const auto exp = std::min(failures > 0 ? failures - 1 : 0u, 6u);
    return std::min(std::chrono::seconds(300), std::chrono::seconds(5) * (1 << exp));
}

Service::Service() : AsyncService("UpstreamEventService") {}

Service::~Service() { stopPollers(); }

PollOutcome Service::pollOnce(const svcmodel::Channel& channel, svcadmin::EventsClient& client,
                              const std::chrono::seconds wait) {
    PollOutcome out;
    const auto ref = channelRef(channel);
    const bool aws = channel.provider == "aws-s3";
    const auto received = client.poll(ref, aws ? 10 : 100, aws ? wait : std::chrono::seconds(0), kVisibility);
    out.messages = received.messages.size();
    out.backlog = received.backlog;

    std::vector<UpstreamEvent> events;
    std::vector<std::string> ackable;
    for (const auto& m : received.messages) {
        auto decoded = aws ? decodeAwsMessage(m.body, m.message_id) : decodeR2Message(m.body, m.message_id, m.sent_at);
        if (decoded.error.empty() && !aws)
            for (const auto& e : decoded.events)
                if (e.account_ref != channel.account_ref) {
                    decoded.error = "notification names another Cloudflare account";
                    break;
                }
        if (!decoded.error.empty()) {
            // Not acknowledged: redelivered until the queue's retry limit moves it to the dead-letter queue.
            ++out.undecodable;
            log::Registry::sync()->warn("[UpstreamEvents] {} queue '{}': message {} not understood ({}); left for the DLQ",
                                        channel.provider, channel.queue_name, m.message_id, decoded.error);
            continue;
        }
        if (decoded.events.empty()) {
            ++out.ignored;
            ackable.push_back(m.receipt);
            continue;
        }
        for (auto& e : decoded.events) {
            if (aws) e.account_ref = channel.account_ref;
            events.push_back(std::move(e));
        }
        ackable.push_back(m.receipt);
    }
    out.events = events.size();

    // The durability point: nothing is acknowledged unless it is stored.
    if (!events.empty()) {
        const auto ingested = ingest(events, channel.id);
        out.inserted = ingested.inserted;
        out.unrouted = ingested.unrouted;
    }
    if (!ackable.empty()) {
        client.ack(ref, ackable);
        out.acked = ackable.size();
    }
    return out;
}

void Service::notifyWork() {
    {
        std::scoped_lock lock(workMutex_);
        workPending_ = true;
    }
    workCv_.notify_one();
}

size_t Service::pollerCount() const {
    std::scoped_lock lock(pollersMutex_);
    return pollers_.size();
}

void Service::pollerLoop(const std::shared_ptr<Poller>& poller) {
    // Every request this thread makes aborts once the poller is told to stop (bounded shutdown).
    const storage::s3::curl::http::ScopedCancellation cancellation(&poller->stop);
    PollerState state;

    while (!poller->stop.load(std::memory_order_acquire)) {
        std::optional<svcmodel::Channel> channel;
        try {
            channel = db::query::upstream::Channel::get(poller->channelId);
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[UpstreamEvents] channel {}: database unavailable: {}", poller->channelId, e.what());
            sleepUnlessStopped(poller->stop, std::chrono::seconds(5));
            continue;
        }
        if (!channel || !channel->api_key_id || channel->state == svcmodel::ChannelState::Removed ||
            channel->state == svcmodel::ChannelState::Failed)
            break;
        if (channel->next_poll_at && *channel->next_poll_at > std::time(nullptr)) {
            sleepUnlessStopped(poller->stop, std::chrono::milliseconds(250));
            continue;
        }

        const auto step = pollStep(*channel, state, &poller->stop);
        if (step == StepResult::Stopped) break;
        if (step == StepResult::Inserted) notifyWork();
    }
}

Service::StepResult Service::pollStep(const svcmodel::Channel& channel, PollerState& state, const std::atomic<bool>* stop) {
    const auto stopped = [&] { return stop && stop->load(std::memory_order_acquire); };
    try {
        if (!state.client || state.clientKey != channel.api_key_id) {
            if (!channel.api_key_id) throw std::runtime_error("the channel has no operating API key");
            const auto key = runtime::Deps::get().apiKeyManager->getAPIKey(*channel.api_key_id);
            state.client = svcadmin::eventsFor(key);
            if (!state.client) throw std::runtime_error("no event adapter for this provider");
            state.clientKey = channel.api_key_id;
        }
        const auto outcome = pollOnce(channel, *state.client);
        if (stopped()) return StepResult::Stopped;

        std::optional<std::time_t> next;
        if (outcome.messages > 0) {
            state.idlePolls = 0;
        } else if (channel.provider != "aws-s3") {
            // HTTP pull returns at once: back off while the queue is empty (1 s → 5 s).
            state.idlePolls = std::min(state.idlePolls + 1, 5u);
            next = std::time(nullptr) + state.idlePolls;
        }
        db::query::upstream::Channel::recordPoll(channel.id, true, static_cast<unsigned int>(outcome.messages),
                                                 outcome.backlog, std::nullopt, next);
        state.last = outcome;
        return outcome.inserted > 0 ? StepResult::Inserted : StepResult::Polled;
    } catch (const std::exception& e) {
        if (stopped()) return StepResult::Stopped;   // cancelled by shutdown, not a failure
        state.client.reset();
        const auto failures = channel.consecutive_failures + 1;
        try {
            db::query::upstream::Channel::recordPoll(channel.id, false, 0, std::nullopt, std::string(e.what()),
                                                     std::time(nullptr) + channelBackoff(failures).count());
        } catch (const std::exception&) {}
        log::Registry::sync()->warn("[UpstreamEvents] {} queue '{}' poll failed ({} in a row): {}", channel.provider,
                                    channel.queue_name, failures, e.what());
        return StepResult::Failed;
    }
}

void Service::superviseChannels() {
    std::set<int64_t> wanted;
    for (const auto& ch : db::query::upstream::Channel::listPollable()) wanted.insert(ch.id);

    std::vector<std::shared_ptr<Poller>> finished;
    {
        std::scoped_lock lock(pollersMutex_);
        for (auto it = pollers_.begin(); it != pollers_.end();) {
            if (!wanted.contains(it->first) || it->second->finished.load(std::memory_order_acquire)) {
                it->second->stop.store(true, std::memory_order_release);
                finished.push_back(it->second);
                it = pollers_.erase(it);
            } else {
                ++it;
            }
        }
        for (const auto id : wanted) {
            if (pollers_.contains(id) || shouldStop()) continue;
            auto poller = std::make_shared<Poller>();
            poller->channelId = id;
            poller->thread = std::thread([this, poller] {
                pollerLoop(poller);
                poller->finished.store(true, std::memory_order_release);
            });
            pollers_.emplace(id, std::move(poller));
        }
    }
    for (const auto& p : finished)
        if (p->thread.joinable()) p->thread.join();
}

void Service::stopPollers() {
    std::map<int64_t, std::shared_ptr<Poller>> pollers;
    {
        std::scoped_lock lock(pollersMutex_);
        for (auto& [_, p] : pollers_) p->stop.store(true, std::memory_order_release);
        pollers.swap(pollers_);
    }
    for (auto& [_, p] : pollers)
        if (p->thread.joinable()) p->thread.join();
}

void Service::maintenance() {
    storage::upstream::guard::reload();
    subscriptions::invalidateCache();
    subscriptions::retryTeardowns();
}

void Service::cycle() {
    const auto now = std::chrono::steady_clock::now();
    if (now - lastMaintenance_ >= kMaintenanceInterval) {
        lastMaintenance_ = now;
        try {
            maintenance();
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[UpstreamEvents] maintenance failed: {}", e.what());
        }
    }

    try {
        superviseChannels();
    } catch (const std::exception& e) {
        log::Registry::sync()->warn("[UpstreamEvents] channel supervision failed: {}", e.what());
    }

    std::vector<uint32_t> vaults;
    try {
        vaults = db::query::upstream::Inbox::listVaultsWithWork();
    } catch (const std::exception& e) {
        log::Registry::sync()->warn("[UpstreamEvents] inbox unavailable: {}", e.what());
        return;
    }
    for (const auto vaultId : vaults) {
        if (shouldStop()) return;
        try {
            (void)applier_.applyVault(vaultId);
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[UpstreamEvents] Vault {}: applying events failed: {}", vaultId, e.what());
        }
    }
}

void Service::runLoop() {
    installCloudHooks();
    log::Registry::sync()->info("[UpstreamEvents] Upstream event service started");
    while (!shouldStop()) {
        cycle();
        std::unique_lock lock(workMutex_);
        workCv_.wait_for(lock, kCycleWait, [this] { return workPending_ || shouldStop(); });
        workPending_ = false;
    }
    stopPollers();
}

void Service::onStop() {
    {
        std::scoped_lock lock(pollersMutex_);
        for (auto& [_, p] : pollers_) p->stop.store(true, std::memory_order_release);
    }
    {
        std::scoped_lock lock(workMutex_);
        workPending_ = true;
    }
    workCv_.notify_all();
}

}
