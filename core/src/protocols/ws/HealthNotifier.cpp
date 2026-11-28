#include "protocols/ws/HealthNotifier.hpp"

#include "health/Findings.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "ops/Stats.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

#include <exception>
#include <utility>

namespace vh::protocols::ws {

HealthNotifier::HealthNotifier() : AsyncService("HealthNotifier") {}

const std::shared_ptr<HealthNotifier>& HealthNotifier::instance() {
    static const auto notifier = [] {
        auto created = std::make_shared<HealthNotifier>();
        listenForStateChanges(created);
        return created;
    }();
    return notifier;
}

void HealthNotifier::listenForStateChanges(const std::shared_ptr<HealthNotifier>& notifier) {
    health::setStateListener([weak = std::weak_ptr<HealthNotifier>(notifier)] {
        if (const auto self = weak.lock()) self->stateChanged();
    });
}

std::uint64_t HealthNotifier::subscribe(const std::shared_ptr<Session>& session) {
    if (!session) throw ops::Denied("not authenticated");
    ops::stats::requireSystem(session->user, "health findings");

    bool idle = false;
    {
        std::scoped_lock lock(mutex_);
        idle = subscriptions_.empty();
    }
    // Nobody was following: what was last evaluated may be old. Look now, so the answer's revision is current and
    // the first pass doesn't tell this session about a change it is about to list anyway.
    if (idle) {
        try {
            evaluate(Clock::now());
        } catch (const std::exception& e) {
            log::Registry::ws()->warn("[HealthNotifier] Health findings not evaluated on subscribe: {}", e.what());
        }
    }

    std::scoped_lock lock(mutex_);
    auto& sub = subscriptions_[session->uuid];
    sub.session = session;
    sub.dropped = false;
    return revision_;
}

void HealthNotifier::unsubscribe(const std::shared_ptr<Session>& session) {
    if (!session) return;
    std::scoped_lock lock(mutex_);
    subscriptions_.erase(session->uuid);
}

bool HealthNotifier::subscribed(const Session& session) const {
    std::scoped_lock lock(mutex_);
    const auto it = subscriptions_.find(session.uuid);
    return it != subscriptions_.end() && !it->second.dropped;
}

std::size_t HealthNotifier::sessionCount() const {
    std::scoped_lock lock(mutex_);
    return subscriptions_.size();
}

std::uint64_t HealthNotifier::revision() const {
    std::scoped_lock lock(mutex_);
    return revision_;
}

void HealthNotifier::tick(const Clock::time_point now) {
    bool evaluateNow = false;
    bool revalidateNow = false;
    {
        std::scoped_lock lock(mutex_);
        if (subscriptions_.empty()) {
            dirty_.store(false, std::memory_order_release);  // nobody to tell: the next subscriber looks itself
            return;
        }
        revalidateNow = now >= nextRevalidate_;
        if (revalidateNow) nextRevalidate_ = now + kRevalidateInterval;
        evaluateNow = now >= nextEvaluate_;
    }
    if (revalidateNow) revalidate();
    if (dirty_.exchange(false, std::memory_order_acq_rel)) evaluateNow = true;
    if (evaluateNow && sessionCount() == 0) evaluateNow = false;  // the last one closed: nobody to tell
    if (evaluateNow) {
        try {
            evaluate(now);
        } catch (const std::exception& e) {
            {
                std::scoped_lock lock(mutex_);
                nextEvaluate_ = now + kEvaluateInterval;
            }
            log::Registry::ws()->warn("[HealthNotifier] Health findings not evaluated: {}", e.what());
        }
    }
    flush();
}

void HealthNotifier::evaluate(const Clock::time_point now) {
    // The findings are read with no subscription lock held: subscribe, unsubscribe and delivery never wait on them.
    std::scoped_lock evaluating(evaluateMutex_);
    const auto snapshot = health::snapshot();
    evaluations_.fetch_add(1, std::memory_order_acq_rel);
    auto digest = health::digest(snapshot);

    std::scoped_lock lock(mutex_);
    nextEvaluate_ = now + kEvaluateInterval;
    if (digest_ == digest) return;
    digest_ = std::move(digest);
    ++revision_;
    summary_ = {.overallStatus = snapshot.overallStatus,
                .errorCount = snapshot.errorCount,
                .warningCount = snapshot.warningCount,
                .unattendedErrorCount = snapshot.unattendedErrorCount,
                .unattendedWarningCount = snapshot.unattendedWarningCount};
    for (auto& [_, sub] : subscriptions_)
        if (!sub.dropped) sub.pending = true;
}

void HealthNotifier::revalidate() {
    std::scoped_lock lock(mutex_);
    for (auto it = subscriptions_.begin(); it != subscriptions_.end();) {
        auto& sub = it->second;
        const auto session = sub.session.lock();
        if (!session || session->closing()) {
            it = subscriptions_.erase(it);
            continue;
        }
        if (!sub.dropped && !ops::stats::canViewSystem(session->user)) {
            sub.pending = false;
            sub.dropped = true;
        }
        ++it;
    }
}

void HealthNotifier::flush() {
    std::scoped_lock lock(mutex_);
    for (auto it = subscriptions_.begin(); it != subscriptions_.end();) {
        auto& sub = it->second;
        const auto session = sub.session.lock();
        if (!session || session->closing()) {
            it = subscriptions_.erase(it);
            continue;
        }
        if (sub.dropped) {
            if (deliver(session, healthEvent(false))) it = subscriptions_.erase(it);
            else ++it;
            continue;
        }
        if (sub.pending && deliver(session, healthEvent(true))) sub.pending = false;
        ++it;
    }
}

nlohmann::json HealthNotifier::healthEvent(const bool subscribedEvent) const {
    nlohmann::json data = {{"revision", revision_}};
    if (!subscribedEvent) data["subscribed"] = false;  // and nothing about the findings: it may no longer see them
    else {
        data["overall_status"] = summary_.overallStatus;
        data["error_count"] = summary_.errorCount;
        data["warning_count"] = summary_.warningCount;
        data["unattended_error_count"] = summary_.unattendedErrorCount;
        data["unattended_warning_count"] = summary_.unattendedWarningCount;
    }
    return {{"command", "health.changed"}, {"data", std::move(data)}};
}

bool HealthNotifier::deliver(const std::shared_ptr<Session>& session, const nlohmann::json& event) const {
    if (delivery_) return delivery_(session, event);
    if (session->closing()) return true;
    if (session->queuedFrames() >= kMaxQueuedFrames) return false;
    session->pushEvent(event);
    return true;
}

void HealthNotifier::setDeliveryForTesting(Delivery delivery) {
    std::scoped_lock lock(mutex_);
    delivery_ = std::move(delivery);
}

void HealthNotifier::reset() {
    std::scoped_lock evaluating(evaluateMutex_);
    std::scoped_lock lock(mutex_);
    subscriptions_.clear();
    digest_.reset();
    summary_ = {};
    nextEvaluate_ = {};
    nextRevalidate_ = {};
    dirty_.store(false, std::memory_order_release);
}

void HealthNotifier::runLoop() {
    while (!shouldStop()) {
        try {
            tick();
        } catch (const std::exception& e) {
            log::Registry::ws()->warn("[HealthNotifier] Health push pass failed: {}", e.what());
        }
        lazySleep(kWakeInterval);
    }
}

}
