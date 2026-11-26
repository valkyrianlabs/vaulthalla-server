#include "mirror/follow/Follower.hpp"

#include "config/Registry.hpp"
#include "db/query/mirror/Contents.hpp"
#include "log/Registry.hpp"
#include "mirror/Contents.hpp"
#include "mirror/follow/Protocol.hpp"
#include "peer/Links.hpp"

#include <algorithm>
#include <exception>
#include <vector>

namespace vh::mirror::follow {

namespace mq = vh::db::query::mirror;
namespace ap = vh::mirror::apply;
using json = nlohmann::json;
using SteadyClock = std::chrono::steady_clock;

const char* toString(const Step s) {
    switch (s) {
    case Step::Idle: return "idle";
    case Step::Progress: return "progress";
    case Step::CopyFinished: return "copy_finished";
    case Step::Waiting: return "waiting";
    case Step::Stopped: return "stopped";
    case Step::Gone: return "gone";
    case Step::Error: return "error";
    }
    return "unknown";
}

namespace {

bool followExperimental() { return config::Registry::get().peers.experimental; }

class FollowLinkTransport final : public Transport {
public:
    bool connected(const uint32_t peerId) override {
        const auto links = vh::peer::linkService();
        return links && links->connected(peerId);
    }
    std::optional<Answer> request(const uint32_t peerId, const std::string& command, const json& payload) override {
        const auto links = vh::peer::linkService();
        if (!links) return std::nullopt;
        const auto a = links->request(peerId, command, payload);
        if (!a) return std::nullopt;
        return Answer{.ok = a->ok, .data = a->data, .code = a->code, .error = a->error};
    }
    bool notify(const uint32_t peerId, const std::string& command, const json& payload) override {
        const auto links = vh::peer::linkService();
        return links && links->notify(peerId, command, payload);
    }
};

json followPositionPayload(const std::string& vaultUid, const mq::Position at) {
    return {{"vault_uid", vaultUid}, {"term", at.term}, {"seq", at.seq}};
}

// An answer that says the vault is no longer the core's to serve this server: the lane's "not found" (no such vault,
// or not mirrored with this server any more) or an expired position. Stops the vault with that reason.
StepResult followStopExpired(const uint32_t vaultId, const std::string& reason, const std::string& why) {
    (void)mq::MirrorVaults::stop(vaultId, "expired", reason, {{"why", why}});
    log::Registry::sync()->warn("[MirrorFollower] Vault {} stopped as expired ({}): {}", vaultId, reason, why);
    return {.step = Step::Stopped, .detail = reason};
}

StepResult followCoreDiverged(const uint32_t vaultId) {
    (void)mq::MirrorVaults::stop(vaultId, "diverged", "mirror_core_diverged",
                                 {{"why", "the core stopped this vault as diverged"}});
    log::Registry::sync()->warn("[MirrorFollower] Vault {} stopped: the core holds it as diverged", vaultId);
    return {.step = Step::Stopped, .detail = "mirror_core_diverged"};
}

}

std::shared_ptr<Transport> linkTransport() {
    static const auto transport = std::make_shared<FollowLinkTransport>();
    return transport;
}

Follower::Follower() : AsyncService("MirrorFollower") {}

Follower::~Follower() {
    fetchStop_.store(true);
    if (fetcher_.joinable()) fetcher_.join();
}

const std::shared_ptr<Follower>& Follower::instance() {
    static const auto follower = std::make_shared<Follower>();
    return follower;
}

void Follower::wake(const uint32_t vaultId) {
    {
        std::scoped_lock lock(mutex_);
        woken_.insert(vaultId);
    }
    cv_.notify_all();
}

void Follower::numbered(const uint32_t vaultId, const mq::Position last) {
    {
        std::scoped_lock lock(mutex_);
        auto& at = notices_[vaultId];
        at = std::max(at, last);
    }
    cv_.notify_all();
}

void Follower::setTransportForTesting(std::shared_ptr<Transport> transport) {
    std::scoped_lock lock(mutex_);
    testTransport_ = std::move(transport);
}

std::shared_ptr<Transport> Follower::transport() {
    std::scoped_lock lock(mutex_);
    return testTransport_ ? testTransport_ : linkTransport();
}

std::size_t Follower::sendNoticesForTesting(Transport& transport) { return sendNotices(transport); }

std::size_t Follower::sendNotices(Transport& transport) {
    std::map<uint32_t, mq::Position> due;
    {
        std::scoped_lock lock(mutex_);
        due.swap(notices_);
    }
    std::size_t sent = 0;
    for (const auto& [vaultId, at] : due) {
        try {
            const auto mv = mq::MirrorVaults::get(vaultId);
            if (!mv || mv->role != "core" || mv->state == "starting") continue;
            const auto uid = mq::MirrorVaults::vaultUidOf(vaultId);
            if (!uid) continue;
            if (transport.notify(mv->peer_id, "peer.mirror.notify", followPositionPayload(*uid, at))) ++sent;
        } catch (const std::exception& e) {
            log::Registry::sync()->debug("[MirrorFollower] Notice for vault {} not sent: {}", vaultId, e.what());
        }
    }
    return sent;
}

bool Follower::acknowledge(Transport& transport, const mq::MirrorVault& mv, const std::string& vaultUid,
                           const mq::Position at, const vh::mirror::Digest& digest) {
    auto payload = followPositionPayload(vaultUid, at);
    payload["digest"] = digest.hex();
    payload["entries"] = digest.entries;
    const auto a = transport.request(mv.peer_id, "peer.mirror.ack", payload);
    if (!a || !a->ok) return false;   // acknowledged again on the next visit
    if (a->data.value("known", false) && !a->data.value("match", true)) {
        (void)mq::MirrorVaults::stop(mv.vault_id, "diverged", "mirror_digest_mismatch",
                                     {{"term", at.term}, {"seq", at.seq}, {"mirror_digest", digest.hex()},
                                      {"mirror_entries", digest.entries},
                                      {"core_digest", a->data.value("core_digest", json(nullptr))},
                                      {"core_entries", a->data.value("core_entries", json(nullptr))},
                                      {"why", "the core's digest at this position is not this server's"}});
        log::Registry::sync()->warn("[MirrorFollower] Vault {} stopped as diverged: its digest at ({}, {}) is not the "
                                    "core's",
                                    mv.vault_id, at.term, at.seq);
        return false;
    }
    if (a->data.value("match", false)) (void)mq::MirrorVaults::recordAcknowledged(mv.vault_id, at);
    return true;
}

StepResult Follower::step(const uint32_t vaultId, Transport& transport, const ap::Options& options) {
    StepResult out;
    auto mv = mq::MirrorVaults::get(vaultId);
    if (!mv || mv->role != "mirror") {
        std::scoped_lock lock(mutex_);
        partials_.erase(vaultId);
        return {.step = Step::Gone};
    }
    if (mv->state != "live") return {.step = Step::Stopped, .detail = mv->state};
    if (!transport.connected(mv->peer_id)) return {.step = Step::Waiting, .detail = "link_down"};
    const auto uid = mq::MirrorVaults::vaultUidOf(vaultId);
    if (!uid) return {.step = Step::Gone};
    const auto deadline = SteadyClock::now() + kStepBudget;

    // ---- the first copy
    if (!mv->copy_finished) {
        while (SteadyClock::now() < deadline) {
            const auto a = transport.request(mv->peer_id, "peer.mirror.tree",
                                             {{"vault_uid", *uid}, {"after", mv->copy_cursor}});
            if (!a) return {.step = Step::Waiting, .detail = "no_answer", .applied = out.applied};
            if (!a->ok) {
                if (a->code == "not_found")
                    return followStopExpired(vaultId, "mirror_core_gone",
                                             "the core no longer holds this vault as mirrored with this server");
                return {.step = Step::Error, .detail = a->code.empty() ? a->error : a->code, .applied = out.applied};
            }
            if (a->data.value("core_state", std::string("live")) == "diverged") return followCoreDiverged(vaultId);
            if (a->data.value("expired", false))
                return followStopExpired(vaultId, "mirror_baseline_gone",
                                         "the core no longer holds the baseline this copy needs");
            const auto page = treePageFromJson(a->data);
            const auto r = ap::applyTreePage(vaultId, page, options);
            switch (r.status) {
            case ap::Status::Applied: ++out.applied; break;
            case ap::Status::AlreadyApplied:
            case ap::Status::NotNext: break;
            case ap::Status::Deferred: return {.step = Step::Waiting, .detail = r.reason, .applied = out.applied};
            case ap::Status::Gone: return {.step = Step::Gone, .applied = out.applied};
            case ap::Status::Diverged:
            case ap::Status::Stopped: return {.step = Step::Stopped, .detail = r.reason, .applied = out.applied};
            }
            mv = mq::MirrorVaults::get(vaultId);
            if (!mv || mv->role != "mirror") return {.step = Step::Gone, .applied = out.applied};
            if (mv->copy_finished) {
                log::Registry::sync()->info("[MirrorFollower] Vault {}: first copy finished at ({}, {}), digest {}, {} "
                                            "entries",
                                            vaultId, mv->term, mv->last_seq, mv->digest.hex(), mv->digest.entries);
                (void)acknowledge(transport, *mv, *uid, mv->position(), mv->digest);
                return {.step = Step::CopyFinished, .applied = out.applied};
            }
            if (r.status != ap::Status::Applied) break;
        }
        return {.step = Step::Progress, .applied = out.applied};
    }

    // ---- the log
    bool appliedAny = false;
    bool more = true;
    while (more && SteadyClock::now() < deadline) {
        const auto at = mv->position();
        auto payload = followPositionPayload(*uid, at);
        std::optional<Partial> partial;
        {
            std::scoped_lock lock(mutex_);
            if (const auto it = partials_.find(vaultId); it != partials_.end()) {
                if (it->second.after == at) partial = it->second;
                else partials_.erase(it);
            }
        }
        if (partial && !partial->group.rows.empty())
            payload["part"] = {{"txid", partial->group.txid}, {"after_seq", partial->group.rows.back().seq}};
        const auto a = transport.request(mv->peer_id, "peer.mirror.log", payload);
        if (!a) return {.step = Step::Waiting, .detail = "no_answer", .applied = out.applied};
        if (!a->ok) {
            if (a->code == "not_found")
                return followStopExpired(vaultId, "mirror_core_gone",
                                         "the core no longer holds this vault as mirrored with this server");
            return {.step = Step::Error, .detail = a->code.empty() ? a->error : a->code, .applied = out.applied};
        }
        if (a->data.value("core_state", std::string("live")) == "diverged") return followCoreDiverged(vaultId);
        if (a->data.value("expired", false))
            return followStopExpired(vaultId, "mirror_log_expired",
                                     "the core's log no longer reaches back to this server's position");

        std::vector<ap::LogGroup> groups;
        if (const auto part = a->data.find("part"); part != a->data.end() && part->is_object()) {
            auto piece = groupFromJson(*part);
            std::scoped_lock lock(mutex_);
            auto& p = partials_[vaultId];
            if (p.after != at || p.group.txid != piece.txid) p = Partial{.after = at, .group = piece};
            else for (auto& r : piece.rows) p.group.rows.push_back(std::move(r));
            if (!part->value("complete", false)) continue;
            groups.push_back(std::move(p.group));
            partials_.erase(vaultId);
            more = true;
        } else {
            for (const auto& g : a->data.value("groups", json::array())) groups.push_back(groupFromJson(g));
            more = a->data.value("more", false);
        }

        for (const auto& g : groups) {
            const auto r = ap::applyGroup(vaultId, g, options);
            switch (r.status) {
            case ap::Status::Applied:
                ++out.applied;
                appliedAny = true;
                break;
            case ap::Status::AlreadyApplied: break;
            case ap::Status::NotNext: more = false; break;
            case ap::Status::Deferred:
                return {.step = Step::Waiting, .detail = r.reason, .applied = out.applied};
            case ap::Status::Gone: return {.step = Step::Gone, .applied = out.applied};
            case ap::Status::Diverged:
            case ap::Status::Stopped: return {.step = Step::Stopped, .detail = r.reason, .applied = out.applied};
            }
            if (r.status == ap::Status::NotNext) break;
        }
        mv = mq::MirrorVaults::get(vaultId);
        if (!mv || mv->role != "mirror") return {.step = Step::Gone, .applied = out.applied};
        if (groups.empty()) break;
    }
    // Acknowledged after each visit that applied something (and again until the core has it).
    if (appliedAny || !mv->acked || *mv->acked < mv->position()) {
        if (appliedAny)
            log::Registry::sync()->info("[MirrorFollower] Vault {}: applied through ({}, {}), digest {}, {} entries",
                                        vaultId, mv->term, mv->last_seq, mv->digest.hex(), mv->digest.entries);
        (void)acknowledge(transport, *mv, *uid, mv->position(), mv->digest);
    }
    out.step = appliedAny ? Step::Progress : Step::Idle;
    return out;
}

void Follower::fetchLoop() {
    while (!fetchStop_.load() && !shouldStop()) {
        std::size_t fetched = 0;
        try {
            if (followExperimental())
                for (const auto& mv : mq::MirrorVaults::list()) {
                    if (fetchStop_.load() || shouldStop()) break;
                    if (mv.role != "mirror" || mv.state != "live") continue;
                    if (mq::PendingContents::countOutstanding(mv.vault_id) == 0) continue;
                    fetched += vh::mirror::contents::fetchOutstanding(mv.vault_id, kFetchPerPass);
                }
        } catch (const std::exception& e) {
            log::Registry::sync()->debug("[MirrorFollower] Contents pass failed: {}", e.what());
        }
        if (fetched == 0) lazySleep(std::chrono::seconds(2));
    }
}

void Follower::onStop() {
    fetchStop_.store(true);
    cv_.notify_all();
}

void Follower::runLoop() {
    fetchStop_.store(false);
    fetcher_ = std::thread([this] { fetchLoop(); });
    auto lastRows = SteadyClock::time_point{};
    std::vector<mq::MirrorVault> rows;
    while (!shouldStop()) {
        auto wait = std::chrono::milliseconds(250);
        try {
            if (!followExperimental()) {
                lazySleep(std::chrono::seconds(1));
                continue;
            }
            const auto t = transport();
            (void)sendNotices(*t);

            std::set<uint32_t> woken;
            {
                std::scoped_lock lock(mutex_);
                woken.swap(woken_);
            }
            const auto now = SteadyClock::now();
            if (!woken.empty() || now - lastRows >= kRowReload) {
                rows = mq::MirrorVaults::list();
                lastRows = now;
            }
            for (const auto& row : rows) {
                if (shouldStop()) break;
                if (row.role != "mirror") continue;
                Schedule s;
                {
                    std::scoped_lock lock(mutex_);
                    s = schedule_[row.vault_id];
                }
                const bool up = t->connected(row.peer_id);
                const bool due = woken.contains(row.vault_id) || (up && !s.linkWasUp) || SteadyClock::now() >= s.next;
                s.linkWasUp = up;
                if (!due) {
                    std::scoped_lock lock(mutex_);
                    schedule_[row.vault_id].linkWasUp = up;
                    continue;
                }
                StepResult r;
                try {
                    r = step(row.vault_id, *t);
                } catch (const std::exception& e) {
                    r = {.step = Step::Error, .detail = e.what()};
                }
                const auto after = SteadyClock::now();
                switch (r.step) {
                case Step::Progress:
                case Step::CopyFinished:
                    s.backoff = std::chrono::milliseconds(0);
                    s.next = after;   // more may be waiting: at once
                    break;
                case Step::Idle:
                    s.backoff = std::chrono::milliseconds(0);
                    s.next = after + kSlowInterval;
                    break;
                case Step::Waiting:
                    s.next = after + std::chrono::seconds(5);
                    break;
                case Step::Stopped:
                case Step::Gone:
                    s.next = after + kSlowInterval;
                    break;
                case Step::Error:
                    s.backoff = std::min<std::chrono::milliseconds>(
                        kBackoffCap, std::max<std::chrono::milliseconds>(std::chrono::seconds(1), s.backoff * 2));
                    s.next = after + s.backoff;
                    log::Registry::sync()->warn("[MirrorFollower] Vault {}: {} (next try in {} s)", row.vault_id,
                                                r.detail, s.backoff.count() / 1000);
                    break;
                }
                if (!row.copy_finished && r.step != Step::Error && r.step != Step::Stopped && r.step != Step::Gone)
                    s.next = std::min(s.next, after + kCopyInterval);
                std::scoped_lock lock(mutex_);
                schedule_[row.vault_id] = s;
            }
            {
                std::scoped_lock lock(mutex_);
                auto soonest = SteadyClock::now() + std::chrono::seconds(1);
                for (const auto& [_, s] : schedule_) soonest = std::min(soonest, s.next);
                wait = std::clamp(std::chrono::duration_cast<std::chrono::milliseconds>(soonest - SteadyClock::now()),
                                  std::chrono::milliseconds(0), std::chrono::milliseconds(1000));
            }
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[MirrorFollower] Pass failed: {}", e.what());
            wait = std::chrono::milliseconds(1000);
        }
        std::unique_lock lock(mutex_);
        cv_.wait_for(lock, wait, [this] { return shouldStop() || !woken_.empty() || !notices_.empty(); });
    }
    fetchStop_.store(true);
    if (fetcher_.joinable()) fetcher_.join();
}

}
