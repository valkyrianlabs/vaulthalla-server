#include "device/Pairing.hpp"

#include "device/Peer.hpp"
#include "ops/Error.hpp"

#include <algorithm>

namespace vh::device {

namespace {

// How long device.pair.status still answers for a finished request.
constexpr std::chrono::minutes kOutcomeLifetime{10};

std::time_t toTime(const PairingClock::time_point tp) { return PairingClock::to_time_t(tp); }

std::string clockText(const PairingClock::time_point tp) {
    const auto t = toTime(tp);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%H:%M:%S UTC", &tm);
    return buf;
}

bool live(const RequestState s) {
    return s == RequestState::AwaitingConfirm || s == RequestState::Pending || s == RequestState::Approving;
}

// Uniform 0, 1 or 2 from the CSPRNG.
std::size_t randomSlot() {
    for (;;) {
        const auto byte = crypto::randomNonce()[0];
        if (byte < 255) return byte % 3;
    }
}

}

std::string to_string(const RequestState state) {
    switch (state) {
        case RequestState::AwaitingConfirm:
        case RequestState::Pending:
        case RequestState::Approving: return "pending";
        case RequestState::Approved: return "approved";
        case RequestState::Denied: return "denied";
        case RequestState::Expired: return "expired";
    }
    return "expired";
}

Pairing& Pairing::instance() {
    static Pairing pairing;
    return pairing;
}

void Pairing::finishLocked(const std::map<std::string, Request>::iterator it, const RequestState state,
                           const std::optional<uint32_t> rowId, const time_point now) {
    outcomes_[it->first] = Outcome{.device_spki = it->second.device_spki, .state = state, .device_row_id = rowId,
                                   .until = now + kOutcomeLifetime};
    requests_.erase(it);
}

void Pairing::expireLocked(const time_point now) {
    if (window_ && PairingClock::from_time_t(window_->expires_at) <= now) window_.reset();
    for (auto it = requests_.begin(); it != requests_.end();) {
        const auto next = std::next(it);
        // An approval in progress finishes on its own (the devices row is being written).
        const bool windowGone = !window_ || window_->owner_id != it->second.owner_id;
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

PairingWindow Pairing::open(const uint32_t ownerId, const time_point now) {
    std::scoped_lock lock(mutex_);
    expireLocked(now);
    if (window_ && window_->owner_id != ownerId)
        throw ops::Conflict("another user is pairing a device on this node until " +
                            clockText(PairingClock::from_time_t(window_->expires_at)) + "; try again then");
    const auto opened = window_ ? window_->opened_at : toTime(now);
    window_ = PairingWindow{.owner_id = ownerId, .opened_at = opened, .expires_at = toTime(now + kPairingWindowLifetime)};
    return *window_;
}

std::optional<PairingWindow> Pairing::window(const time_point now) {
    std::scoped_lock lock(mutex_);
    expireLocked(now);
    return window_;
}

bool Pairing::close(const uint32_t ownerId, const bool any, const time_point now) {
    std::scoped_lock lock(mutex_);
    expireLocked(now);
    if (!window_ || (!any && window_->owner_id != ownerId)) return false;
    window_.reset();
    expireLocked(now);  // every request of the window expires with it
    return true;
}

std::vector<PendingRequest> Pairing::pending(const uint32_t ownerId, const time_point now) {
    std::scoped_lock lock(mutex_);
    expireLocked(now);
    std::vector<PendingRequest> out;
    for (const auto& [id, r] : requests_) {
        if (r.owner_id != ownerId || r.state != RequestState::Pending) continue;
        out.push_back(PendingRequest{.request_id = id, .name = r.name, .platform = r.platform,
                                     .app_version = r.app_version, .source_ip = r.source_ip,
                                     .device_id = crypto::toHex(r.device_spki), .code_choices = r.choices,
                                     .created_at = toTime(r.created_at), .expires_at = toTime(r.expires_at)});
    }
    std::ranges::sort(out, {}, &PendingRequest::created_at);
    return out;
}

std::map<std::string, Pairing::Request>::iterator Pairing::ownedLocked(const uint32_t ownerId,
                                                                       const std::string& requestId) {
    const auto it = requests_.find(requestId);
    if (it == requests_.end() || it->second.owner_id != ownerId || it->second.state != RequestState::Pending)
        throw ops::NotFound("no pending pairing request '" + requestId + "' (it may have expired)");
    return it;
}

ApprovalClaim Pairing::beginApproval(const uint32_t ownerId, const std::string& requestId, const std::string& code,
                                     const time_point now) {
    std::scoped_lock lock(mutex_);
    expireLocked(now);
    const auto it = ownedLocked(ownerId, requestId);
    auto& r = it->second;
    // Whatever was typed is compared as six digits; anything else is a wrong code, and a wrong code denies.
    const auto chosen = crypto::normalizeCode(code).value_or("");
    if (chosen.empty() || !crypto::constantTimeEqual(chosen, r.code)) {
        finishLocked(it, RequestState::Denied, std::nullopt, now);
        throw ops::Invalid("that is not the code the device shows: the request was denied (pair again from the "
                           "device and compare the codes)");
    }
    r.state = RequestState::Approving;
    return ApprovalClaim{.request_id = requestId, .owner_id = r.owner_id, .device_id = crypto::toHex(r.device_spki),
                         .name = r.name, .platform = r.platform, .app_version = r.app_version,
                         .source_ip = r.source_ip};
}

void Pairing::finishApproval(const std::string& requestId, const uint32_t deviceRowId, const time_point now) {
    std::scoped_lock lock(mutex_);
    if (const auto it = requests_.find(requestId); it != requests_.end())
        finishLocked(it, RequestState::Approved, deviceRowId, now);
}

void Pairing::abortApproval(const std::string& requestId, const time_point now) {
    std::scoped_lock lock(mutex_);
    if (const auto it = requests_.find(requestId); it != requests_.end())
        finishLocked(it, RequestState::Denied, std::nullopt, now);
}

void Pairing::deny(const uint32_t ownerId, const std::string& requestId, const time_point now) {
    std::scoped_lock lock(mutex_);
    expireLocked(now);
    finishLocked(ownedLocked(ownerId, requestId), RequestState::Denied, std::nullopt, now);
}

PairRequestReceipt Pairing::request(const Peer& peer, const PairRequestInput& input, const time_point now) {
    std::scoped_lock lock(mutex_);
    expireLocked(now);
    if (!window_)
        throw ops::Refused("no_pairing_window", "no pairing window is open on this node: open one (`vh device pair` on "
                                                "the node), then try again");

    auto& recent = recentByAddress_[peer.address];
    if (recent.size() >= kMaxRequestsPerAddressPerMinute)
        throw ops::Refused("rate_limited", "too many pairing requests from this address; wait a minute");
    recent.push_back(now);

    // One live request per device key: a new one replaces it.
    for (auto it = requests_.begin(); it != requests_.end(); ++it)
        if (it->second.device_spki == peer.spki && it->second.state != RequestState::Approving) {
            finishLocked(it, RequestState::Expired, std::nullopt, now);
            break;
        }
    const auto liveInWindow = std::ranges::count_if(requests_, [](const auto& kv) { return live(kv.second.state); });
    if (static_cast<std::size_t>(liveInWindow) >= kMaxRequestsPerWindow)
        throw ops::Refused("rate_limited", "this pairing window already has the most requests it takes; deny some or "
                                           "wait for them to expire");

    Request r;
    do r.id = crypto::randomHex(8);
    while (requests_.contains(r.id) || outcomes_.contains(r.id));
    r.owner_id = window_->owner_id;
    r.device_spki = peer.spki;
    r.name = input.name;
    r.platform = input.platform;
    r.app_version = input.app_version;
    r.source_ip = peer.address;
    r.commitment = input.commitment;
    r.nonce_server = crypto::randomNonce();
    r.created_at = now;
    r.expires_at = std::min(now + kPairingRequestLifetime, PairingClock::from_time_t(window_->expires_at));
    const PairRequestReceipt receipt{.request_id = r.id, .nonce_server = r.nonce_server, .expires_at = toTime(r.expires_at)};
    requests_.emplace(r.id, std::move(r));
    return receipt;
}

std::time_t Pairing::confirm(const Peer& peer, const std::string& requestId, const crypto::Hash& nonceDevice,
                             const crypto::Hash& serverSpki, const time_point now) {
    std::scoped_lock lock(mutex_);
    expireLocked(now);
    const auto it = requests_.find(requestId);
    if (it == requests_.end() || it->second.device_spki != peer.spki)
        throw ops::NotFound("no such pairing request (it may have expired)");
    auto& r = it->second;
    if (r.state != RequestState::AwaitingConfirm) throw ops::Conflict("this pairing request is already confirmed");

    const auto expected = crypto::commitment(peer.spki, nonceDevice);
    if (!crypto::constantTimeEqual(expected, r.commitment)) {
        requests_.erase(it);  // the spec deletes it outright: no outcome to report
        throw ops::Invalid("nonce_device does not match the request's commitment");
    }

    r.code = crypto::sasCode(crypto::sasDigest(serverSpki, peer.spki, nonceDevice, r.nonce_server));
    std::array<std::string, 3> choices;
    const auto slot = randomSlot();
    choices[slot] = r.code;
    for (std::size_t i = 0; i < choices.size(); ++i) {
        if (i == slot) continue;
        std::string decoy;
        do decoy = crypto::randomCode();
        while (std::ranges::find(choices, decoy) != choices.end());
        choices[i] = decoy;
    }
    r.choices = choices;
    r.state = RequestState::Pending;
    r.expires_at = std::min(now + kPairingRequestLifetime, PairingClock::from_time_t(window_->expires_at));
    return toTime(r.expires_at);
}

RequestStatus Pairing::status(const Peer& peer, const std::string& requestId, const time_point now) {
    std::scoped_lock lock(mutex_);
    expireLocked(now);
    if (const auto it = requests_.find(requestId); it != requests_.end() && it->second.device_spki == peer.spki)
        return RequestStatus{.state = it->second.state};
    if (const auto it = outcomes_.find(requestId); it != outcomes_.end() && it->second.device_spki == peer.spki)
        return RequestStatus{.state = it->second.state, .device_row_id = it->second.device_row_id,
                             .device_id = it->second.state == RequestState::Approved ? crypto::toHex(peer.spki)
                                                                                     : std::string{}};
    throw ops::NotFound("no such pairing request (it may have expired)");
}

std::optional<std::string> Pairing::codeForTesting(const std::string& requestId) {
    std::scoped_lock lock(mutex_);
    const auto it = requests_.find(requestId);
    if (it == requests_.end() || it->second.code.empty()) return std::nullopt;
    return it->second.code;
}

void Pairing::resetForTesting() {
    std::scoped_lock lock(mutex_);
    window_.reset();
    requests_.clear();
    outcomes_.clear();
    recentByAddress_.clear();
}

}
