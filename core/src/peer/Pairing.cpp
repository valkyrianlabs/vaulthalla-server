#include "peer/Pairing.hpp"

#include "device/Peer.hpp"
#include "ops/Error.hpp"

#include <algorithm>

namespace vh::peer {

namespace {

using vh::device::RequestState;
using vh::device::WindowKind;
namespace dc = vh::device::crypto;

constexpr std::chrono::minutes kLinkOutcomeLifetime{10};

std::time_t asTime(const PairingClock::time_point tp) { return PairingClock::to_time_t(tp); }

bool liveState(const RequestState s) {
    return s == RequestState::AwaitingConfirm || s == RequestState::Pending || s == RequestState::Approving;
}

// Uniform 0, 1 or 2 from the CSPRNG.
std::size_t randomChoiceSlot() {
    for (;;) {
        const auto byte = dc::randomNonce()[0];
        if (byte < 255) return byte % 3;
    }
}

std::optional<vh::device::PairingWindow> peerWindow(const PairingClock::time_point now) {
    auto w = vh::device::Pairing::instance().window(now);
    if (w && w->kind != WindowKind::Peer) w.reset();
    return w;
}

}

Pairing& Pairing::instance() {
    static Pairing pairing;
    return pairing;
}

void Pairing::finishLocked(const std::map<std::string, Request>::iterator it, const RequestState state,
                           const std::optional<uint32_t> row, const time_point now) {
    outcomes_[it->first] = Outcome{.spki = it->second.spki, .state = state, .row = row, .until = now + kLinkOutcomeLifetime};
    requests_.erase(it);
}

void Pairing::expireLocked(const std::optional<vh::device::PairingWindow>& window, const time_point now) {
    for (auto it = requests_.begin(); it != requests_.end();) {
        const auto next = std::next(it);
        const bool windowGone = !window || window->owner_id != it->second.owner_id;
        if (it->second.state != RequestState::Approving && (windowGone || it->second.expires_at <= now))
            finishLocked(it, RequestState::Expired, std::nullopt, now);
        it = next;
    }
    std::erase_if(outcomes_, [&](const auto& kv) { return kv.second.until <= now; });
    for (auto it = recentByAddress_.begin(); it != recentByAddress_.end();) {
        auto& times = it->second;
        while (!times.empty() && times.front() + std::chrono::minutes(1) <= now) times.pop_front();
        it = times.empty() ? recentByAddress_.erase(it) : std::next(it);
    }
}

std::vector<PendingLink> Pairing::pending(const uint32_t ownerId, const time_point now) {
    const auto window = peerWindow(now);
    std::scoped_lock lock(mutex_);
    expireLocked(window, now);
    std::vector<PendingLink> out;
    for (const auto& [id, r] : requests_) {
        if (r.owner_id != ownerId || r.state != RequestState::Pending) continue;
        out.push_back(PendingLink{.request_id = id, .node_id = r.card.node_id, .name = r.card.name,
                                  .product_version = r.card.product_version, .peer_protocol = r.card.peer_protocol,
                                  .spki_sha256 = dc::toHex(r.spki), .source_ip = r.source_ip, .code_choices = r.choices,
                                  .created_at = asTime(r.created_at), .expires_at = asTime(r.expires_at)});
    }
    std::ranges::sort(out, {}, &PendingLink::created_at);
    return out;
}

LinkClaim Pairing::checkLocked(const uint32_t ownerId, const std::string& requestId, const std::string& code,
                               const std::optional<std::string>& expectSpki, const time_point now) {
    const auto it = requests_.find(requestId);
    if (it == requests_.end() || it->second.owner_id != ownerId || it->second.state != RequestState::Pending)
        throw ops::NotFound("no pending link request '" + requestId + "' (it may have expired)");
    auto& r = it->second;
    // The brokered path: the key the broker pinned for the dialling server, or nothing (and the code is not looked at).
    if (expectSpki && !dc::constantTimeEqual(*expectSpki, dc::toHex(r.spki))) {
        finishLocked(it, RequestState::Denied, std::nullopt, now);
        throw ops::Invalid("the link request comes from another server key than expected: it was denied");
    }
    const auto chosen = dc::normalizeCode(code).value_or("");
    if (chosen.empty() || !dc::constantTimeEqual(chosen, r.code)) {
        finishLocked(it, RequestState::Denied, std::nullopt, now);
        throw ops::Invalid("that is not the code the other server shows: the request was denied (link again and "
                           "compare the codes)");
    }
    return LinkClaim{.request_id = requestId, .owner_id = r.owner_id, .spki_sha256 = dc::toHex(r.spki),
                     .card = r.card, .source_ip = r.source_ip};
}

LinkClaim Pairing::check(const uint32_t ownerId, const std::string& requestId, const std::string& code,
                         const std::optional<std::string>& expectSpki, const time_point now) {
    const auto window = peerWindow(now);
    std::scoped_lock lock(mutex_);
    expireLocked(window, now);
    return checkLocked(ownerId, requestId, code, expectSpki, now);
}

LinkClaim Pairing::begin(const uint32_t ownerId, const std::string& requestId, const std::string& code,
                         const std::optional<std::string>& expectSpki, const time_point now) {
    const auto window = peerWindow(now);
    std::scoped_lock lock(mutex_);
    expireLocked(window, now);
    auto claim = checkLocked(ownerId, requestId, code, expectSpki, now);
    requests_.at(requestId).state = RequestState::Approving;
    return claim;
}

void Pairing::finish(const std::string& requestId, const uint32_t peerRowId, const time_point now) {
    std::scoped_lock lock(mutex_);
    if (const auto it = requests_.find(requestId); it != requests_.end())
        finishLocked(it, RequestState::Approved, peerRowId, now);
}

void Pairing::abort(const std::string& requestId, const time_point now) {
    std::scoped_lock lock(mutex_);
    if (const auto it = requests_.find(requestId); it != requests_.end())
        finishLocked(it, RequestState::Denied, std::nullopt, now);
}

void Pairing::deny(const uint32_t ownerId, const std::string& requestId, const time_point now) {
    const auto window = peerWindow(now);
    std::scoped_lock lock(mutex_);
    expireLocked(window, now);
    const auto it = requests_.find(requestId);
    if (it == requests_.end() || it->second.owner_id != ownerId || it->second.state != RequestState::Pending)
        throw ops::NotFound("no pending link request '" + requestId + "' (it may have expired)");
    finishLocked(it, RequestState::Denied, std::nullopt, now);
}

LinkRequestReceipt Pairing::request(const vh::device::Peer& connection, const LinkRequestInput& input, const Card& own,
                                    const time_point now) {
    const auto window = peerWindow(now);
    std::scoped_lock lock(mutex_);
    expireLocked(window, now);
    if (!window)
        throw ops::Refused("no_pairing_window", "no window for linking a server is open on this server: open one "
                                                "(`vh peer pair` there), then try again");

    auto& recent = recentByAddress_[connection.address];
    if (recent.size() >= vh::device::kMaxRequestsPerAddressPerMinute)
        throw ops::Refused("rate_limited", "too many link requests from this address; wait a minute");
    recent.push_back(now);

    // One live request per key: a new one replaces it.
    for (auto it = requests_.begin(); it != requests_.end(); ++it)
        if (it->second.spki == connection.spki && it->second.state != RequestState::Approving) {
            finishLocked(it, RequestState::Expired, std::nullopt, now);
            break;
        }
    const auto live = std::ranges::count_if(requests_, [](const auto& kv) { return liveState(kv.second.state); });
    if (static_cast<std::size_t>(live) >= vh::device::kMaxRequestsPerWindow)
        throw ops::Refused("rate_limited", "this window already has the most link requests it takes; deny some or "
                                           "wait for them to expire");

    Request r;
    do r.id = dc::randomHex(8);
    while (requests_.contains(r.id) || outcomes_.contains(r.id));
    r.owner_id = window->owner_id;
    r.spki = connection.spki;
    r.card = input.card;
    r.own = own;
    r.commitment = input.commitment;
    r.nonce_b = dc::randomNonce();
    r.source_ip = connection.address;
    r.created_at = now;
    r.expires_at = std::min(now + vh::device::kPairingRequestLifetime, PairingClock::from_time_t(window->expires_at));
    LinkRequestReceipt receipt{.request_id = r.id, .nonce_b = r.nonce_b, .card = own, .expires_at = asTime(r.expires_at)};
    requests_.emplace(r.id, std::move(r));
    return receipt;
}

std::time_t Pairing::confirm(const vh::device::Peer& connection, const std::string& requestId,
                             const crypto::Hash& nonceA, const crypto::Hash& serverSpki, const time_point now) {
    const auto window = peerWindow(now);
    std::scoped_lock lock(mutex_);
    expireLocked(window, now);
    const auto it = requests_.find(requestId);
    if (it == requests_.end() || it->second.spki != connection.spki)
        throw ops::NotFound("no such link request (it may have expired)");
    auto& r = it->second;
    if (r.state != RequestState::AwaitingConfirm) throw ops::Conflict("this link request is already confirmed");
    if (!dc::constantTimeEqual(crypto::commitment(connection.spki, nonceA), r.commitment)) {
        requests_.erase(it);  // deleted outright, as device pairing does: no outcome to report
        throw ops::Invalid("nonce_a does not match the request's commitment");
    }

    r.code = crypto::sasCode(
        crypto::sasDigest(serverSpki, connection.spki, nonceA, r.nonce_b, crypto::cardHash(r.card), crypto::cardHash(r.own)));
    std::array<std::string, 3> choices;
    const auto slot = randomChoiceSlot();
    choices[slot] = r.code;
    for (std::size_t i = 0; i < choices.size(); ++i) {
        if (i == slot) continue;
        std::string decoy;
        do decoy = dc::randomCode();
        while (std::ranges::find(choices, decoy) != choices.end());
        choices[i] = decoy;
    }
    r.choices = choices;
    r.state = RequestState::Pending;
    r.expires_at = std::min(now + vh::device::kPairingRequestLifetime, PairingClock::from_time_t(window->expires_at));
    return asTime(r.expires_at);
}

LinkRequestStatus Pairing::status(const vh::device::Peer& connection, const std::string& requestId,
                                  const time_point now) {
    const auto window = peerWindow(now);
    std::scoped_lock lock(mutex_);
    expireLocked(window, now);
    if (const auto it = requests_.find(requestId); it != requests_.end() && it->second.spki == connection.spki)
        return LinkRequestStatus{.state = it->second.state};
    if (const auto it = outcomes_.find(requestId); it != outcomes_.end() && it->second.spki == connection.spki)
        return LinkRequestStatus{.state = it->second.state, .peer_row_id = it->second.row};
    throw ops::NotFound("no such link request (it may have expired)");
}

std::size_t Pairing::abandonAll() {
    std::scoped_lock lock(mutex_);
    const auto dropped = requests_.size();
    requests_.clear();
    return dropped;
}

std::optional<std::string> Pairing::codeForTesting(const std::string& requestId) {
    std::scoped_lock lock(mutex_);
    const auto it = requests_.find(requestId);
    if (it == requests_.end() || it->second.code.empty()) return std::nullopt;
    return it->second.code;
}

void Pairing::resetForTesting() {
    std::scoped_lock lock(mutex_);
    requests_.clear();
    outcomes_.clear();
    recentByAddress_.clear();
}

}
