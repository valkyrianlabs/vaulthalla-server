#include "protocols/ws/ChangeNotifier.hpp"

#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/FsChanges.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <exception>
#include <set>
#include <utility>

namespace vh::protocols::ws {

namespace {

nlohmann::json changedEvent(const uint32_t vaultId, const uint64_t revision, const bool subscribed) {
    nlohmann::json data = {{"vault_id", vaultId}, {"revision", revision}};
    if (!subscribed) data["subscribed"] = false;
    return {{"command", "fs.changed"}, {"data", std::move(data)}};
}

std::vector<uint32_t> keysOf(const std::map<uint32_t, bool>& vaults) {
    std::vector<uint32_t> out;
    out.reserve(vaults.size());
    for (const auto& [vaultId, _] : vaults) out.push_back(vaultId);
    return out;
}

}

ChangeNotifier::ChangeNotifier() : AsyncService("FsChangeNotifier") {}

const std::shared_ptr<ChangeNotifier>& ChangeNotifier::instance() {
    static const auto notifier = std::make_shared<ChangeNotifier>();
    return notifier;
}

ChangeNotifier::SubscribeResult ChangeNotifier::subscribe(const std::shared_ptr<Session>& session,
                                                          const std::vector<uint32_t>& vaultIds) {
    if (!session || !session->user) throw ops::Denied("not authenticated");
    const auto& user = session->user;
    SubscribeResult out;
    std::vector<uint32_t> accepted;
    for (const auto vaultId : std::set(vaultIds.begin(), vaultIds.end())) {
        const auto& storage = runtime::Deps::get().storageManager;
        if (!storage || !storage->getEngine(vaultId)) out.refused.push_back({.vault_id = vaultId, .code = "not_found"});
        else if (!ops::fs_changes::canFollow(user, vaultId)) out.refused.push_back({.vault_id = vaultId, .code = "denied"});
        else accepted.push_back(vaultId);
    }

    std::scoped_lock lock(mutex_);
    auto& sub = subscriptions_[session->uuid];
    sub.session = session;
    for (const auto vaultId : accepted) {
        if (!sub.vaults.contains(vaultId) && sub.vaults.size() >= kMaxVaults) {
            out.refused.push_back({.vault_id = vaultId, .code = "limit"});
            continue;
        }
        sub.vaults.emplace(vaultId, false);
        sub.dropped.erase(vaultId);
    }
    out.vault_ids = keysOf(sub.vaults);
    if (sub.vaults.empty() && sub.dropped.empty()) subscriptions_.erase(session->uuid);
    return out;
}

std::vector<uint32_t> ChangeNotifier::unsubscribe(const std::shared_ptr<Session>& session,
                                                  const std::optional<std::vector<uint32_t>>& vaultIds) {
    if (!session) return {};
    std::scoped_lock lock(mutex_);
    const auto it = subscriptions_.find(session->uuid);
    if (it == subscriptions_.end()) return {};
    auto& sub = it->second;
    if (!vaultIds) {
        subscriptions_.erase(it);
        return {};
    }
    for (const auto vaultId : *vaultIds) {
        sub.vaults.erase(vaultId);
        sub.pending.erase(vaultId);
        sub.dropped.erase(vaultId);
    }
    auto remaining = keysOf(sub.vaults);
    if (sub.vaults.empty() && sub.dropped.empty()) subscriptions_.erase(it);
    return remaining;
}

std::vector<uint32_t> ChangeNotifier::subscriptions(const Session& session) const {
    std::scoped_lock lock(mutex_);
    const auto it = subscriptions_.find(session.uuid);
    return it == subscriptions_.end() ? std::vector<uint32_t>{} : keysOf(it->second.vaults);
}

std::size_t ChangeNotifier::sessionCount() const {
    std::scoped_lock lock(mutex_);
    return subscriptions_.size();
}

void ChangeNotifier::tick() {
    {
        std::scoped_lock lock(mutex_);
        if (subscriptions_.empty()) return;
    }
    apply(db::query::fs::ChangeLog::sequence());
    const auto now = std::chrono::steady_clock::now();
    const bool all = now >= nextRevalidate_;
    if (all) nextRevalidate_ = now + kRevalidateInterval;
    revalidate(all);
    flush();
}

void ChangeNotifier::apply(const db::query::fs::Sequenced& sequenced) {
    std::scoped_lock lock(mutex_);
    revision_ = std::max(revision_, sequenced.revision);
    const auto note = [](Subscription& sub, const uint32_t vaultId, const uint64_t revision) {
        const auto it = sub.vaults.find(vaultId);
        if (it == sub.vaults.end()) return;
        it->second = true;  // re-check visibility before telling anyone
        auto& pending = sub.pending[vaultId];
        pending = std::max(pending, revision);
    };

    for (auto& [_, sub] : subscriptions_) {
        for (const auto& [vaultId, revision] : sequenced.vaults) note(sub, vaultId, revision);
        if (sequenced.resets.empty()) continue;
        const auto session = sub.session.lock();
        const auto userId = session && session->user ? std::optional(session->user->id) : std::nullopt;
        for (const auto& reset : sequenced.resets) {
            if (reset.user_id && reset.user_id != userId) continue;
            if (reset.vault_id) note(sub, *reset.vault_id, reset.revision);
            else
                for (const auto vaultId : keysOf(sub.vaults)) note(sub, vaultId, reset.revision);
        }
    }
}

void ChangeNotifier::revalidateAll() { revalidate(true); }

void ChangeNotifier::revalidate(const bool all) {
    std::scoped_lock lock(mutex_);
    for (auto it = subscriptions_.begin(); it != subscriptions_.end();) {
        auto& sub = it->second;
        const auto session = sub.session.lock();
        if (!session || session->closing()) {
            it = subscriptions_.erase(it);
            continue;
        }
        for (auto v = sub.vaults.begin(); v != sub.vaults.end();) {
            if (!all && !v->second) {
                ++v;
                continue;
            }
            v->second = false;
            if (ops::fs_changes::canFollow(session->user, v->first)) {
                ++v;
                continue;
            }
            sub.pending.erase(v->first);
            sub.dropped[v->first] = revision_;
            v = sub.vaults.erase(v);
        }
        ++it;
    }
}

void ChangeNotifier::flush() {
    std::scoped_lock lock(mutex_);
    for (auto it = subscriptions_.begin(); it != subscriptions_.end();) {
        auto& sub = it->second;
        const auto session = sub.session.lock();
        if (!session || session->closing()) {
            it = subscriptions_.erase(it);
            continue;
        }
        bool full = false;
        for (auto d = sub.dropped.begin(); !full && d != sub.dropped.end();) {
            if (!deliver(session, changedEvent(d->first, d->second, false))) full = true;
            else d = sub.dropped.erase(d);
        }
        for (auto p = sub.pending.begin(); !full && p != sub.pending.end();) {
            if (!deliver(session, changedEvent(p->first, p->second, true))) full = true;
            else p = sub.pending.erase(p);
        }
        if (sub.vaults.empty() && sub.dropped.empty()) it = subscriptions_.erase(it);
        else ++it;
    }
}

bool ChangeNotifier::deliver(const std::shared_ptr<Session>& session, const nlohmann::json& event) const {
    if (delivery_) return delivery_(session, event);
    if (session->closing()) return true;
    if (session->queuedFrames() >= kMaxQueuedFrames) return false;
    session->pushEvent(event);
    return true;
}

void ChangeNotifier::setDeliveryForTesting(Delivery delivery) {
    std::scoped_lock lock(mutex_);
    delivery_ = std::move(delivery);
}

void ChangeNotifier::reset() {
    std::scoped_lock lock(mutex_);
    subscriptions_.clear();
    revision_ = 0;
}

void ChangeNotifier::runLoop() {
    while (!shouldStop()) {
        try {
            tick();
        } catch (const std::exception& e) {
            log::Registry::ws()->warn("[FsChangeNotifier] Change push pass failed: {}", e.what());
        }
        lazySleep(kPollInterval);
    }
}

}
