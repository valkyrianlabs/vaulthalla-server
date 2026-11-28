#pragma once

#include "concurrency/AsyncService.hpp"
#include "protocols/ws/Fwd.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <string>

// ws push for health findings (design/health/findings.md §6): health.subscribe / unsubscribe and the unsolicited
//   {"command": "health.changed", "data": {"revision": R, "overall_status": …, "error_count": …, "warning_count": …,
//                                          "unattended_error_count": …, "unattended_warning_count": …}}
// a subscribed session gets whenever the findings or their state change. The event carries no findings: the client
// calls health.findings.list.
//  - Who: a signed-in web or paired device session whose user has admin.stats.view, re-checked every
//    kRevalidateInterval; a session that lost it gets one last {"revision": R, "subscribed": false}.
//  - When: while any session is subscribed, the service evaluates health::snapshot() every kEvaluateInterval on its
//    own thread and compares health::digest; no subscriber, no evaluation. An acknowledge, silence or unsilence
//    (health::stateChanged) makes the next pass, within kWakeInterval, evaluate at once.
//  - Backpressure: one pending event per session, the newest wins (it is built when it goes out), held while the
//    session has kMaxQueuedFrames or more frames waiting to be written. Nothing here waits on a socket.
namespace vh::protocols::ws {

class HealthNotifier : public concurrency::AsyncService {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr std::chrono::seconds kEvaluateInterval{15};
    static constexpr std::chrono::seconds kRevalidateInterval{30};
    static constexpr std::chrono::milliseconds kWakeInterval{250};
    static constexpr std::size_t kMaxQueuedFrames = 64;

    // Delivers one event to a session; false when the session can't take it now (it stays pending). The default
    // checks queuedFrames() against kMaxQueuedFrames and calls pushEvent.
    using Delivery = std::function<bool(const std::shared_ptr<Session>&, const nlohmann::json&)>;

    HealthNotifier();

    // The process's notifier (registered with runtime::Manager as "HealthNotifier"); it listens for state changes.
    static const std::shared_ptr<HealthNotifier>& instance();

    // Refused (ops::Denied) without admin.stats.view. Returns the current revision. The first subscriber after none
    // evaluates the findings on the caller's thread, so the revision it is answered matches what it lists next.
    std::uint64_t subscribe(const std::shared_ptr<Session>& session);
    void unsubscribe(const std::shared_ptr<Session>& session);
    [[nodiscard]] bool subscribed(const Session& session) const;
    [[nodiscard]] std::size_t sessionCount() const;
    [[nodiscard]] std::uint64_t revision() const;
    // How many times the findings were evaluated (tests: no subscriber, no evaluation).
    [[nodiscard]] std::uint64_t evaluations() const noexcept { return evaluations_.load(std::memory_order_acquire); }

    // An operator changed a finding's state: the next pass evaluates whatever the time.
    void stateChanged() noexcept { dirty_.store(true, std::memory_order_release); }
    // Makes `notifier` the one health::stateChanged() reaches, by a weak reference (instance() does it for itself;
    // tests re-point it).
    static void listenForStateChanges(const std::shared_ptr<HealthNotifier>& notifier);

    // One pass at `now`: revalidate when due, evaluate when due or dirty, flush. The loop calls it; tests call it.
    void tick(Clock::time_point now);
    void tick() { tick(Clock::now()); }

    void setDeliveryForTesting(Delivery delivery);
    // Drops every subscription and the last digest (test resets).
    void reset();

protected:
    void runLoop() override;

private:
    struct Subscription {
        std::weak_ptr<Session> session;
        bool pending = false;  // an event is owed (built from the newest evaluation when it goes out)
        bool dropped = false;  // the last "subscribed": false event is owed
    };

    struct Summary {
        std::string overallStatus{};
        std::uint32_t errorCount = 0;
        std::uint32_t warningCount = 0;
        std::uint32_t unattendedErrorCount = 0;
        std::uint32_t unattendedWarningCount = 0;
    };

    void evaluate(Clock::time_point now);
    void revalidate();
    void flush();
    [[nodiscard]] nlohmann::json healthEvent(bool subscribedEvent) const;  // mutex_ held
    [[nodiscard]] bool deliver(const std::shared_ptr<Session>& session, const nlohmann::json& event) const;

    mutable std::mutex mutex_;
    std::mutex evaluateMutex_;  // one evaluation at a time; never held with mutex_ while the findings are read
    std::map<std::string, Subscription> subscriptions_;  // by Session::uuid
    std::uint64_t revision_ = 0;
    std::optional<std::string> digest_{};
    Summary summary_{};
    Delivery delivery_{};
    Clock::time_point nextEvaluate_{};
    Clock::time_point nextRevalidate_{};
    std::atomic<bool> dirty_{false};
    std::atomic<std::uint64_t> evaluations_{0};
};

}
