#include "mirror/start/Start.hpp"

#include "audit/Trail.hpp"
#include "config/Registry.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "peer/Links.hpp"

#include <vl/keykit/uid.hpp>

#include <fmt/format.h>

#include <set>

namespace vh::mirror::start {

namespace start_service_detail {

using Q = vh::db::query::mirror::MirrorStart;
using vh::db::query::mirror::MirrorVaults;
using SteadyClock = std::chrono::steady_clock;

std::mutex& transportMutex() {
    static std::mutex m;
    return m;
}

Transport& testTransport() {
    static Transport t;
    return t;
}

Transport linkTransport() {
    Transport t;
    t.request = [](const uint32_t peerId, const std::string& command, const json& payload,
                   const std::chrono::milliseconds timeout) -> std::optional<json> {
        const auto links = vh::peer::linkService();
        if (!links) return std::nullopt;
        return links->request(peerId, command, payload, timeout);
    };
    t.upSince = [](const uint32_t peerId) -> std::optional<std::time_t> {
        const auto links = vh::peer::linkService();
        if (!links) return std::nullopt;
        const auto h = links->health(peerId);
        if (!h.connected) return std::nullopt;
        return h.since.value_or(1);
    };
    return t;
}

bool ok(const std::optional<json>& answer) { return answer && answer->value("status", "") == "OK"; }

json dataOf(const json& answer) {
    if (const auto d = answer.find("data"); d != answer.end() && d->is_object()) return *d;
    return json::object();
}

std::string codeOf(const json& answer) {
    const auto d = dataOf(answer);
    return d.value("code", std::string());
}

std::string errorOf(const std::optional<json>& answer) {
    if (!answer) return "no answer from the linked server";
    if (const auto e = answer->find("error"); e != answer->end() && e->is_string()) return e->get<std::string>();
    const auto code = codeOf(*answer);
    return code.empty() ? std::string("refused") : code;
}

// A refusal of the keys that no retry will change: the mirror said why, and the start ends here.
bool finalKeysRefusal(const std::string& code) {
    return code == "mirror_keys_refused" || code == "mirror_vault_exists" || code == "mirror_name_taken" ||
           code == "mirror_no_space" || code == "mirror_offer_not_accepted" || code == "history_not_supported" ||
           code == "not_found" || code == "invalid";
}

}

void setTransportForTesting(Transport t) {
    std::scoped_lock lock(start_service_detail::transportMutex());
    start_service_detail::testTransport() = std::move(t);
}

Transport transport() {
    {
        std::scoped_lock lock(start_service_detail::transportMutex());
        if (start_service_detail::testTransport().request) return start_service_detail::testTransport();
    }
    return start_service_detail::linkTransport();
}

std::mutex& stepMutex() {
    static std::mutex m;
    return m;
}

Service::Service() : AsyncService("MirrorStarter") {}

const std::shared_ptr<Service>& Service::instance() {
    static const auto service = std::make_shared<Service>();
    return service;
}

void Service::wake() {
    std::scoped_lock lock(mutex_);
    woken_ = true;
}

void Service::resetForTesting() {
    std::scoped_lock lock(mutex_);
    sentGrants_.clear();
    retryAt_.clear();
    woken_ = false;
}

void Service::runLoop() {
    while (!shouldStop()) {
        try {
            tick();
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[MirrorStarter] {}", e.what());
        }
        for (int i = 0; i < 10 && !shouldStop(); ++i) {
            {
                std::scoped_lock lock(mutex_);
                if (woken_) {
                    woken_ = false;
                    break;
                }
            }
            lazySleep(kInterval / 10);
        }
    }
}

void Service::tick() {
    using namespace start_service_detail;
    if (!config::Registry::get().peers.experimental) return;
    // Unlinking ends the trust: the copies of an unlinked core are kept orphaned, its queued notices dropped.
    (void)reconcileUnlinked();
    for (const auto& o : Q::expireOffers())
        log::Registry::sync()->info("[MirrorStarter] The offer of vault {} ({} side) expired unanswered", o.core_vault_id,
                                    o.side);
    (void)Q::sweepFinished(std::chrono::duration_cast<std::chrono::seconds>(kFinishedKept));
    for (const auto& o : Q::offersWithWork()) {
        {
            std::scoped_lock lock(mutex_);
            if (const auto it = retryAt_.find(o.id); it != retryAt_.end() && SteadyClock::now() < it->second) continue;
        }
        try {
            step(o);
        } catch (const std::exception& e) {
            Q::noteAttempt(o.id, e.what());
            log::Registry::sync()->warn("[MirrorStarter] Offer {} of vault {} ({}): {}", o.id, o.core_vault_id, o.state,
                                        e.what());
            std::scoped_lock lock(mutex_);
            retryAt_[o.id] = SteadyClock::now() + kRetryAfter;
        }
    }
    syncGrants();
}

void Service::step(const Offer& o) {
    using namespace start_service_detail;
    const auto t = transport();
    if (!t.request || !t.upSince || !t.upSince(o.peer_id)) return;  // the link is down: nothing is sent, nothing counted
    const auto peer = db::query::peer::Peers::byId(o.peer_id);
    if (!peer || peer->revoked()) return;

    const auto ask = [&](const std::string& command, const json& payload,
                         const std::chrono::milliseconds timeout) -> std::optional<json> {
        auto answer = t.request(o.peer_id, command, payload, timeout);
        if (!ok(answer)) {
            Q::noteAttempt(o.id, command + ": " + errorOf(answer));
            std::scoped_lock lock(mutex_);
            retryAt_[o.id] = SteadyClock::now() + kRetryAfter;
        }
        return answer;
    };
    const auto cancelPayload = [&] {
        return json{{"offer_uid", o.offer_uid}, {"vault_uid", vl::keykit::toBase32(o.vault_uid)},
                    {"reason", o.reason.value_or("cancelled")}, {"remove_copy", o.side == "core" && o.remove_copy}};
    };

    if (o.side == "core") {
        if (o.state == "offered" && o.notify) {
            const auto a = ask("peer.mirror.offer", offerPayload(o), std::chrono::seconds(15));
            if (ok(a)) {
                (void)Q::told(o.id, "offered");
                // The answer can come with the offer (a link set to accept, or a refusal at once): it is sent again as
                // peer.mirror.answer anyway, so this only saves a round.
            }
            return;
        }
        if (o.state == "accepted") {
            const auto a = ask("peer.mirror.keys", keysPayload(o, *peer), kKeysTimeout);
            if (ok(a)) {
                if (Q::transition(o.id, {"accepted"}, {.to = "keys_acked", .notify = false})) {
                    audit::record({.action = "mirror.keys", .vault_id = o.vault_id,
                                   .details = {{"peer", o.peer_id}, {"node_id", peer->node_id}, {"side", "core"}}},
                                  fmt::format("[mirror] linked server {} proved and installed the keys of vault {}",
                                              peer->node_id, o.vault_id.value_or(0)));
                    if (auto next = Q::offer(o.id)) step(*next);
                }
            } else if (a && finalKeysRefusal(codeOf(*a))) {
                (void)Q::transition(o.id, {"accepted"},
                                    {.to = "failed", .notify = false, .reason = codeOf(*a), .detail = errorOf(a)});
                audit::record({.action = "mirror.keys", .outcome = audit::Outcome::Failure, .vault_id = o.vault_id,
                               .details = {{"peer", o.peer_id}, {"side", "core"}, {"reason", codeOf(*a)}}},
                              fmt::format("[mirror] linked server {} refused the keys of vault {}: {}", peer->node_id,
                                          o.vault_id.value_or(0), errorOf(a)),
                              spdlog::level::warn);
            }
            return;
        }
        if (o.state == "keys_acked") {
            if (!o.vault_id) return;
            {
                // The core row only once the mirror holds its keys and its own row; never after a cancel.
                std::scoped_lock lock(stepMutex());
                const auto now = Q::offer(o.id);
                if (!now || now->state != "keys_acked") return;
                // No row yet, or a `starting` one a start that crashed left behind (startCore replaces it; while it stays,
                // the vault's writers wait). A busy vault throws ops::Conflict and this step runs again next pass.
                if (const auto mv = MirrorVaults::get(*o.vault_id); !mv || mv->state == "starting")
                    (void)MirrorVaults::startCore(*o.vault_id, o.peer_id, o.term);
            }
            const auto a = ask("peer.mirror.begin", beginPayload(o), std::chrono::seconds(15));
            if (ok(a) && Q::transition(o.id, {"keys_acked"}, {.to = "started", .notify = false})) {
                const auto grant = grantFor(o.peer_id, *o.vault_id);
                {
                    std::scoped_lock lock(mutex_);
                    sentGrants_[*o.vault_id] = {grant.dump(), t.upSince(o.peer_id).value_or(0)};
                }
                audit::record({.action = "mirror.start", .vault_id = o.vault_id,
                               .details = {{"peer", o.peer_id}, {"node_id", peer->node_id}, {"side", "core"},
                                           {"term", o.term}}},
                              fmt::format("[mirror] vault {} is mirrored with linked server {} (term {})", *o.vault_id,
                                          peer->node_id, o.term));
            }
            return;
        }
        if ((o.state == "cancelled" || o.state == "expired") && o.notify) {
            const auto a = ask("peer.mirror.cancel", cancelPayload(), std::chrono::seconds(15));
            if (ok(a) || (a && codeOf(*a) == "not_found")) {
                (void)Q::told(o.id, o.state);
                // What the mirror did with its copy: recorded and shown (mirror info), audited.
                const auto copy = ok(a) ? dataOf(*a).value("copy", std::string("none")) : std::string("none");
                const auto outcome = copy == "removed" || copy == "kept" ? copy : std::string("none");
                (void)Q::recordCopyOutcome(o.id, outcome);
                audit::record({.action = "mirror.cancel.copy", .outcome = audit::Outcome::Info, .vault_id = o.vault_id,
                               .details = {{"peer", o.peer_id}, {"node_id", peer->node_id},
                                           {"remove_copy", o.remove_copy}, {"copy", outcome}}},
                              fmt::format("[mirror] linked server {} {} its copy of vault {}{}", peer->node_id,
                                          outcome == "removed" ? "removed" : outcome == "kept" ? "kept" : "held no",
                                          o.vault_id.value_or(0),
                                          o.remove_copy && outcome == "kept" ? " (removal was asked; it keeps copies)" : ""));
            }
            return;
        }
        return;
    }

    // The mirror's side.
    if (o.state == "accepted" && o.notify) {
        const auto a = ask("peer.mirror.answer", json{{"offer_uid", o.offer_uid}, {"decision", "accepted"}},
                           std::chrono::seconds(15));
        if (ok(a)) (void)Q::told(o.id, "accepted");
        else if (a && codeOf(*a) == "not_found") (void)Q::told(o.id, "accepted");
        return;
    }
    if (o.state == "declined" && o.notify) {
        json payload{{"offer_uid", o.offer_uid}, {"decision", "declined"}, {"reason", o.reason.value_or("declined")}};
        if (o.detail) payload["detail"] = o.detail->substr(0, 500);
        const auto a = ask("peer.mirror.answer", payload, std::chrono::seconds(15));
        if (ok(a) || (a && codeOf(*a) == "not_found")) (void)Q::told(o.id, "declined");
        return;
    }
    if ((o.state == "cancelled" || o.state == "expired") && o.notify) {
        const auto a = ask("peer.mirror.cancel", cancelPayload(), std::chrono::seconds(15));
        if (ok(a) || (a && codeOf(*a) == "not_found")) (void)Q::told(o.id, o.state);
    }
}

void Service::syncGrants() {
    using namespace start_service_detail;
    const auto t = transport();
    if (!t.request || !t.upSince) return;
    std::set<uint32_t> cores;
    for (const auto& row : MirrorVaults::list()) {
        if (row.role != "core") continue;
        cores.insert(row.vault_id);
        const auto up = t.upSince(row.peer_id);
        if (!up) continue;
        const auto facts = Q::facts(row.vault_id);
        if (!facts) continue;
        const auto grant = grantFor(row.peer_id, row.vault_id);
        const auto fingerprint = grant.dump();
        {
            std::scoped_lock lock(mutex_);
            const auto it = sentGrants_.find(row.vault_id);
            // Sent already over this connection: nothing changed.
            if (it != sentGrants_.end() && it->second.first == fingerprint && it->second.second == *up) continue;
        }
        const auto a = t.request(row.peer_id, "peer.mirror.grant",
                                 json{{"vault_uid", vl::keykit::toBase32(facts->vault_uid)}, {"grant", grant}},
                                 std::chrono::seconds(15));
        // A refusal (the mirror holds no such vault any more) is not asked again until the grant or the link changes;
        // no answer is.
        if (a) {
            std::scoped_lock lock(mutex_);
            sentGrants_[row.vault_id] = {fingerprint, *up};
        }
    }
    std::scoped_lock lock(mutex_);
    std::erase_if(sentGrants_, [&](const auto& kv) { return !cores.contains(kv.first); });
}

}
