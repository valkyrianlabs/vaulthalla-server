#pragma once

#include "concurrency/AsyncService.hpp"
#include "db/query/fs/ChangeLog.hpp"
#include "protocols/ws/Fwd.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <string>
#include <vector>

// ws push for the filesystem change journal (#260): fs.changes.subscribe / unsubscribe and the unsolicited
//   {"command": "fs.changed", "data": {"vault_id": N, "revision": R}}
// a subscribed session gets after changes to a vault commit. The client then calls fs.changes.list from its cursor;
// the event carries no changes and promises nothing but "ask again".
//  - Who: a signed-in web or paired device session, for vaults its user can follow (ops::fs_changes::canFollow: List
//    on the vault root). A vault the user can no longer follow (a role or override removed, the vault deleted) is
//    dropped with one last event carrying "subscribed": false.
//  - When: while any session is subscribed, the service sequences the journal every kPollInterval (a cheap read when
//    nothing is pending) and turns what was numbered into events, so out-of-band writes are pushed too.
//  - Backpressure: events are coalesced per session and vault (the newest revision wins) and held while the session
//    has kMaxQueuedFrames or more frames waiting to be written, so a slow consumer costs at most one pending entry
//    per subscribed vault (at most kMaxVaults) and never grows its write queue past the bound by events.
namespace vh::protocols::ws {

class ChangeNotifier : public concurrency::AsyncService {
public:
    static constexpr std::chrono::milliseconds kPollInterval{250};
    static constexpr std::chrono::seconds kRevalidateInterval{30};
    static constexpr std::size_t kMaxVaults = 256;
    static constexpr std::size_t kMaxQueuedFrames = 64;

    // Delivers one event to a session; false when the session can't take it now (it stays pending). The default
    // checks queuedFrames() against kMaxQueuedFrames and calls pushEvent.
    using Delivery = std::function<bool(const std::shared_ptr<Session>&, const nlohmann::json&)>;

    struct Refusal {
        uint32_t vault_id{};
        std::string code{};  // denied | not_found | limit
    };

    struct SubscribeResult {
        std::vector<uint32_t> vault_ids{};  // everything the session follows now, ascending
        std::vector<Refusal> refused{};
    };

    ChangeNotifier();

    // The process's notifier (registered with runtime::Manager as "FsChangeNotifier").
    static const std::shared_ptr<ChangeNotifier>& instance();

    SubscribeResult subscribe(const std::shared_ptr<Session>& session, const std::vector<uint32_t>& vaultIds);
    // `vaultIds` absent: every vault. Returns what the session still follows.
    std::vector<uint32_t> unsubscribe(const std::shared_ptr<Session>& session,
                                      const std::optional<std::vector<uint32_t>>& vaultIds);
    [[nodiscard]] std::vector<uint32_t> subscriptions(const Session& session) const;
    [[nodiscard]] std::size_t sessionCount() const;

    // One pass: sequence, coalesce, revalidate, flush. The loop calls it; tests call it directly.
    void tick();
    // Applies what a sequencing pass numbered (tick() does; tests feed passes directly).
    void apply(const db::query::fs::Sequenced& sequenced);
    // Re-checks every subscription now, not only the vaults with news.
    void revalidateAll();
    void flush();

    void setDeliveryForTesting(Delivery delivery);
    // Drops every subscription (test schema resets).
    void reset();

protected:
    void runLoop() override;

private:
    struct Subscription {
        std::weak_ptr<Session> session;
        std::map<uint32_t, bool> vaults;          // vault -> needs a visibility re-check
        std::map<uint32_t, uint64_t> pending;     // vault -> newest revision not yet delivered
        std::map<uint32_t, uint64_t> dropped;     // vault -> revision of the "subscribed: false" event owed
    };

    void revalidate(bool all);
    [[nodiscard]] bool deliver(const std::shared_ptr<Session>& session, const nlohmann::json& event) const;

    mutable std::mutex mutex_;
    std::map<std::string, Subscription> subscriptions_;  // by Session::uuid
    uint64_t revision_{0};                               // the newest watermark seen
    Delivery delivery_;
    std::chrono::steady_clock::time_point nextRevalidate_{};
};

}
