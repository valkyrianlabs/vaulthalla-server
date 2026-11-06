// Device approvals (#361): the approval key's challenges and console-mediated approvals (auth/approval/Approvals.hpp).

#include "auth/approval/Approvals.hpp"

#include "audit/Trail.hpp"
#include "auth/mfa/Passkeys.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Manager.hpp"
#include "db/query/device/ApprovalKey.hpp"
#include "db/query/device/Device.hpp"
#include "device/Device.hpp"
#include "device/Peer.hpp"
#include "device/ServerIdentity.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "ops/Sessions.hpp"
#include "protocols/device/Endpoints.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"

#include <algorithm>
#include <deque>
#include <map>
#include <mutex>
#include <unordered_map>

namespace vh::auth::approval {

namespace {

using ApprovalClock = std::chrono::system_clock;

// How long a finished or expired request still answers device.approval.status.
constexpr std::chrono::minutes kApprovalOutcomeLifetime{10};

int64_t approvalUnix(const ApprovalClock::time_point t) {
    return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

nlohmann::json approvalTargetJson(const std::optional<std::string>& target) {
    return target ? nlohmann::json(*target) : nlohmann::json(nullptr);
}

bool approvalPrintable(const std::string& s) {
    return std::ranges::all_of(s, [](const char c) { return c >= 0x20 && c < 0x7f; });
}

// The target a family takes: the refusal's, required and bounded for the target-bound families; none otherwise.
std::optional<std::string> approvalTarget(const stepup::Family family, const std::optional<std::string>& target) {
    if (!stepup::targetBound(family)) return std::nullopt;
    if (!target || target->empty() || target->size() > stepup::kMaxTargetLength || !approvalPrintable(*target))
        throw ops::Invalid("target is required for " + std::string(stepup::to_string(family)) +
                           ": pass the one the step_up_required refusal named");
    return target;
}

struct ApprovalDevice {
    std::shared_ptr<identities::User> user;
    const device::Peer* peer;
    uint32_t row_id;
};

// A paired device's own session: the only place a device asks for an approval.
ApprovalDevice approvalDeviceCaller(const std::shared_ptr<protocols::ws::Session>& session) {
    if (!session || !session->isDeviceSession() || !session->user || !session->devicePeer() ||
        !session->devicePeer()->paired())
        throw ops::Refused("device_unknown", "this command is only answered on a paired device's own session");
    return {.user = session->user, .peer = session->devicePeer().get(), .row_id = *session->devicePeer()->deviceRowId};
}

struct ApprovalWeb {
    std::shared_ptr<identities::User> user;
    std::string jti;
};

// A signed-in console session: the only place a person approves a device's request (never a device, its own or
// another).
ApprovalWeb approvalWebCaller(const std::shared_ptr<protocols::ws::Session>& session) {
    if (!session) throw std::runtime_error("No session");
    if (session->onDeviceListener())
        throw ops::Denied("A paired device can't approve requests: approve it in the web console");
    if (session->isShareSession() || !session->user || !session->tokens || !session->tokens->refreshToken)
        throw ops::Denied("Sign in first");
    return {.user = session->user, .jti = session->tokens->refreshToken->jti};
}

std::optional<db::query::device::ApprovalKey> liveApprovalKey(const uint32_t deviceRowId) {
    auto key = db::query::device::ApprovalKeys::forDevice(deviceRowId);
    if (!key || key->revoked()) return std::nullopt;
    return key;
}

// ---- challenges

struct OpenChallenge {
    std::string id;
    std::string session_uuid;
    uint32_t user_id{};
    uint32_t device_row_id{};
    device::crypto::Hash challenge{};
    stepup::Family family{};
    std::string target;
    int64_t expires_at{};
    ApprovalClock::time_point issued{};
};

struct ChallengeStore {
    std::mutex mutex;
    std::unordered_map<std::string, OpenChallenge> open;

    void expireLocked(const int64_t now) {
        std::erase_if(open, [&](const auto& kv) { return kv.second.expires_at <= now; });
    }
};

ChallengeStore& challengeStore() {
    static ChallengeStore store;
    return store;
}

std::vector<uint8_t> approvalPayload(const OpenChallenge& c, const device::Peer& peer) {
    const auto identity = device::currentServerIdentity();
    if (!identity) throw std::runtime_error("the device listener has no server identity yet");
    auto payload = device::crypto::approvalMessage(protocols::device::endpoints::nodeId(), identity->spkiSha256(),
                                                    peer.spki, c.challenge, stepup::to_string(c.family), c.target,
                                                    static_cast<uint64_t>(c.expires_at));
    if (!payload) throw ops::Invalid("the target can't be signed");
    return std::move(*payload);
}

// ---- console approvals

struct ApprovalStore {
    std::mutex mutex;
    std::map<std::string, Approval> approvals;
    std::unordered_map<uint32_t, std::deque<ApprovalClock::time_point>> recentByDevice;

    void expireLocked(const ApprovalClock::time_point now) {
        for (auto& [_, a] : approvals)
            if (a.state == State::Pending && now >= a.expires_at) {
                a.state = State::Expired;
                a.decided_at = a.expires_at;
            }
        std::erase_if(approvals, [&](const auto& kv) {
            const auto& a = kv.second;
            return a.state != State::Pending && a.decided_at && now >= *a.decided_at + kApprovalOutcomeLifetime;
        });
        for (auto it = recentByDevice.begin(); it != recentByDevice.end();) {
            auto& times = it->second;
            while (!times.empty() && now - times.front() >= std::chrono::hours(1)) times.pop_front();
            it = times.empty() ? recentByDevice.erase(it) : std::next(it);
        }
    }
};

ApprovalStore& approvalStore() {
    static ApprovalStore store;
    return store;
}

std::string approvalScope(const Approval& a) {
    return "approval\x1f" + a.id + "\x1f" + std::string(stepup::to_string(a.family)) + "\x1f" + a.target.value_or("");
}

nlohmann::json approvalAuditDetails(const Approval& a) {
    return {{"family", std::string(stepup::to_string(a.family))}, {"target", approvalTargetJson(a.target)},
            {"approval_id", a.id}, {"device", a.device_row_id}};
}

std::mutex& approvalPushMutex() {
    static std::mutex m;
    return m;
}

PushDelivery& approvalPushDelivery() {
    static PushDelivery delivery;
    return delivery;
}

// The push auth.approval.pending to the account's signed-in console sessions (never a device's).
void approvalPush(const Approval& a) {
    const auto& manager = runtime::Deps::get().sessionManager;
    if (!manager) return;
    const nlohmann::json event{{"command", "auth.approval.pending"},
                               {"data", {{"approval_id", a.id},
                                         {"device", {{"id", a.device_row_id}, {"name", a.device_name}}},
                                         {"family", std::string(stepup::to_string(a.family))},
                                         {"target", approvalTargetJson(a.target)},
                                         {"summary", a.summary},
                                         {"expires_at", approvalUnix(a.expires_at)}}}};
    for (const auto& s : manager->getSessionsByUserId(a.user_id)) {
        if (!s || s->closing() || s->onDeviceListener() || s->isShareSession() || !s->user || s->user->id != a.user_id)
            continue;
        try {
            PushDelivery delivery;
            {
                std::scoped_lock lock(approvalPushMutex());
                delivery = approvalPushDelivery();
            }
            if (delivery) delivery(s, event);
            else s->pushEvent(event);
        } catch (const std::exception& e) {
            log::Registry::auth()->debug("[auth::approval] push to a console session failed: {}", e.what());
        }
    }
}

}

std::string to_string(const State state) {
    switch (state) {
        case State::Pending: return "pending";
        case State::Approved: return "approved";
        case State::Denied: return "denied";
        case State::Expired: return "expired";
    }
    return "expired";
}

nlohmann::json toJson(const Approval& a) {
    return {{"approval_id", a.id},
            {"state", to_string(a.state)},
            {"family", std::string(stepup::to_string(a.family))},
            {"target", approvalTargetJson(a.target)},
            {"summary", a.summary},
            {"device", {{"id", a.device_row_id}, {"device_id", a.device_id}, {"name", a.device_name}}},
            {"created_at", approvalUnix(a.created_at)},
            {"expires_at", approvalUnix(a.expires_at)}};
}

bool hasLiveApprovalKey(const std::shared_ptr<protocols::ws::Session>& session) {
    if (!session || !session->devicePeer() || !session->devicePeer()->paired()) return false;
    try {
        return liveApprovalKey(*session->devicePeer()->deviceRowId).has_value();
    } catch (const std::exception&) {
        return false;  // only a hint in a refusal: the challenge itself checks again
    }
}

// ---- the approval key ---------------------------------------------------------------------------------------------------

Challenge challenge(const std::shared_ptr<protocols::ws::Session>& session, const stepup::Family family,
                    const std::string& target) {
    const auto caller = approvalDeviceCaller(session);
    if (!stepup::deviceApprovalMaySatisfy(family))
        throw ops::Refused("console_approval_required",
                           "A device's approval key can approve only keys and device.trust; ask for a console "
                           "approval (device.approval.request) instead");
    const auto bound = approvalTarget(family, target).value_or(std::string{});
    if (!liveApprovalKey(caller.row_id))
        throw ops::Refused("approval_key_unavailable", "This device has no approval key registered here");

    OpenChallenge c{.id = device::crypto::randomHex(16),
                    .session_uuid = session->uuid,
                    .user_id = caller.user->id,
                    .device_row_id = caller.row_id,
                    .challenge = device::crypto::randomNonce(),
                    .family = family,
                    .target = bound,
                    .expires_at = approvalUnix(ApprovalClock::now() + kChallengeTtl),
                    .issued = ApprovalClock::now()};
    auto payload = approvalPayload(c, *caller.peer);
    {
        auto& store = challengeStore();
        std::scoped_lock lock(store.mutex);
        store.expireLocked(approvalUnix(ApprovalClock::now()));
        // At most kMaxChallengesPerSession open per session: a new one replaces the oldest.
        std::vector<std::unordered_map<std::string, OpenChallenge>::iterator> mine;
        for (auto it = store.open.begin(); it != store.open.end(); ++it)
            if (it->second.session_uuid == c.session_uuid) mine.push_back(it);
        if (mine.size() >= kMaxChallengesPerSession) {
            const auto oldest = std::ranges::min_element(mine, {}, [](const auto& it) { return it->second.issued; });
            store.open.erase(*oldest);
        }
        if (store.open.size() >= kMaxChallenges)
            throw ops::Refused("rate_limited", "Too many approvals are open on this node; try again in a minute");
        store.open.emplace(c.id, c);
    }
    return {.challenge_id = c.id, .challenge = c.challenge, .payload = std::move(payload), .family = family,
            .target = bound, .expires_at = c.expires_at};
}

Submitted submit(const std::shared_ptr<protocols::ws::Session>& session, const std::string& challengeId,
                 const std::vector<uint8_t>& signature) {
    const auto caller = approvalDeviceCaller(session);
    std::optional<OpenChallenge> taken;
    {
        auto& store = challengeStore();
        std::scoped_lock lock(store.mutex);
        store.expireLocked(approvalUnix(ApprovalClock::now()));
        // Single use: spent by this answer whatever it is. Another session's id is not this session's to spend.
        if (const auto it = store.open.find(challengeId);
            it != store.open.end() && it->second.session_uuid == session->uuid) {
            taken = it->second;
            store.open.erase(it);
        }
    }
    if (!taken) throw ops::NotFound("That approval expired or was used. Ask for a new challenge.");
    const auto familyName = std::string(stepup::to_string(taken->family));
    const auto failed = [&](const std::string& reason, const audit::Outcome outcome) {
        audit::record({.action = "device.approval.submit", .outcome = outcome, .actor_id = caller.user->id,
                       .actor = caller.user->name(),
                       .details = {{"family", familyName}, {"target", taken->target}, {"device", caller.row_id},
                                   {"method", std::string(stepup::kDeviceApprovalMethod)}, {"reason", reason}}},
                      "[auth::approval] a device approval (" + familyName + ") was refused: " + reason,
                      spdlog::level::warn);
    };

    const auto key = liveApprovalKey(caller.row_id);
    if (!key || taken->device_row_id != caller.row_id || taken->user_id != caller.user->id) {
        failed("approval_key_unavailable", audit::Outcome::Denied);
        throw ops::Refused("approval_key_unavailable", "This device's approval key is no longer registered here");
    }
    // The payload as it is now: a node or server key that changed since the challenge never verifies.
    const auto payload = approvalPayload(*taken, *caller.peer);
    if (signature.empty() || signature.size() > 80 ||
        !device::crypto::verifyEcdsaP256Sha256(key->public_key_spki, payload, signature)) {
        failed("bad_signature", audit::Outcome::Failure);
        throw ops::Invalid("The approval signature does not verify under this device's approval key");
    }

    const auto expires = ApprovalClock::now() + stepup::ttl();
    std::optional<std::string> target;
    if (stepup::targetBound(taken->family)) target = taken->target;
    session->stepUp().addGrant({.user_id = caller.user->id, .refresh_jti = {}, .family = taken->family,
                                .target = target, .method = std::string(stepup::kDeviceApprovalMethod),
                                .expires_at = expires});
    audit::record({.action = "device.approval.submit", .actor_id = caller.user->id, .actor = caller.user->name(),
                   .details = {{"family", familyName}, {"target", taken->target}, {"device", caller.row_id},
                               {"method", std::string(stepup::kDeviceApprovalMethod)}}},
                  "[auth::approval] " + caller.user->name() + " approved a " + familyName +
                      " operation with the device's approval key");
    return {.family = taken->family, .target = taken->target, .expires_at = expires};
}

// ---- console approvals --------------------------------------------------------------------------------------------------

Approval request(const std::shared_ptr<protocols::ws::Session>& session, const stepup::Family family,
                 const std::optional<std::string>& target, const std::string& summary) {
    const auto caller = approvalDeviceCaller(session);
    const auto bound = approvalTarget(family, target);
    const auto text = device::normalizeDisplayText(summary, kMaxSummaryCodePoints);
    if (!text)
        throw ops::Invalid("summary is what the person approves, 1-" + std::to_string(kMaxSummaryCodePoints) +
                           " characters without control characters");
    const auto row = db::query::device::Devices::byId(caller.row_id);
    if (!row || row->revoked() || row->user_id != caller.user->id)
        throw ops::Refused("device_unknown", "this device is not paired with this node");

    const auto now = ApprovalClock::now();
    Approval a{.id = device::crypto::randomHex(16),
               .user_id = caller.user->id,
               .device_row_id = caller.row_id,
               .device_name = row->name,
               .device_id = row->spki_sha256,
               .session_uuid = session->uuid,
               .family = family,
               .target = bound,
               .summary = *text,
               .state = State::Pending,
               .created_at = now,
               .expires_at = now + kRequestTtl};
    {
        auto& store = approvalStore();
        std::scoped_lock lock(store.mutex);
        store.expireLocked(now);
        const auto open = std::ranges::count_if(store.approvals, [&](const auto& kv) {
            return kv.second.device_row_id == caller.row_id && kv.second.state == State::Pending;
        });
        auto& recent = store.recentByDevice[caller.row_id];
        if (static_cast<std::size_t>(open) >= kMaxOpenPerDevice)
            throw ops::Refused("rate_limited", "This device already has " + std::to_string(kMaxOpenPerDevice) +
                                                   " approvals waiting; wait for them or let them expire");
        if (recent.size() >= kMaxPerHourPerDevice)
            throw ops::Refused("rate_limited", "This device asked for too many approvals this hour");
        recent.push_back(now);
        store.approvals.emplace(a.id, a);
    }
    audit::record({.action = "auth.approval.request", .outcome = audit::Outcome::Info, .actor_id = caller.user->id,
                   .actor = caller.user->name(), .details = approvalAuditDetails(a)},
                  "[auth::approval] device " + row->spki_sha256.substr(0, 16) + " asked for a console approval of a " +
                      std::string(stepup::to_string(family)) + " operation");
    approvalPush(a);
    return a;
}

Approval status(const std::shared_ptr<protocols::ws::Session>& session, const std::string& approvalId) {
    const auto caller = approvalDeviceCaller(session);
    auto& store = approvalStore();
    std::scoped_lock lock(store.mutex);
    const auto now = ApprovalClock::now();
    store.expireLocked(now);
    const auto it = store.approvals.find(approvalId);
    if (it == store.approvals.end() || it->second.session_uuid != session->uuid ||
        it->second.user_id != caller.user->id)
        throw ops::NotFound("no such approval request on this session (it may have expired)");
    auto& a = it->second;
    if (a.state == State::Approved && !a.granted) {
        // The grant goes to the session that asked, once, with the same binding rules as a web session's.
        session->stepUp().addGrant({.user_id = a.user_id, .refresh_jti = {}, .family = a.family, .target = a.target,
                                    .method = std::string(stepup::kConsoleApprovalMethod),
                                    .expires_at = now + stepup::ttl()});
        a.granted = true;
    }
    return a;
}

std::vector<Approval> list(const std::shared_ptr<protocols::ws::Session>& session) {
    const auto caller = approvalWebCaller(session);
    auto& store = approvalStore();
    std::scoped_lock lock(store.mutex);
    store.expireLocked(ApprovalClock::now());
    std::vector<Approval> out;
    for (const auto& [_, a] : store.approvals)
        if (a.user_id == caller.user->id && a.state == State::Pending) out.push_back(a);
    std::ranges::sort(out, {}, &Approval::created_at);
    return out;
}

namespace {

// The open request `approvalId` of the console caller's account.
Approval approvalPendingFor(const uint32_t userId, const std::string& approvalId) {
    auto& store = approvalStore();
    std::scoped_lock lock(store.mutex);
    store.expireLocked(ApprovalClock::now());
    const auto it = store.approvals.find(approvalId);
    if (it == store.approvals.end() || it->second.user_id != userId || it->second.state != State::Pending)
        throw ops::NotFound("That request expired or was already answered");
    return it->second;
}

// Moves a pending request to `to` (approve, deny); NotFound when it changed meanwhile.
Approval approvalDecide(const uint32_t userId, const std::string& approvalId, const State to) {
    auto& store = approvalStore();
    std::scoped_lock lock(store.mutex);
    const auto now = ApprovalClock::now();
    store.expireLocked(now);
    const auto it = store.approvals.find(approvalId);
    if (it == store.approvals.end() || it->second.user_id != userId || it->second.state != State::Pending)
        throw ops::NotFound("That request expired or was already answered");
    it->second.state = to;
    it->second.decided_at = now;
    return it->second;
}

std::string approvalIdOf(const nlohmann::json& payload) {
    if (!payload.is_object() || !payload.contains("approval_id") || !payload.at("approval_id").is_string())
        throw ops::Invalid("approval_id is required");
    return payload.at("approval_id").get<std::string>();
}

}

ApproveAnswer approve(const std::shared_ptr<protocols::ws::Session>& session, const nlohmann::json& payload) {
    const auto caller = approvalWebCaller(session);
    const auto id = approvalIdOf(payload);
    // A passkey with user verification, nothing else (design 6.3): a TOTP code or a password never approves a
    // device's request; a TOTP-only account does the action in the console instead.
    const bool otherMethod = (payload.contains("method") && payload.at("method") != "webauthn") ||
                             payload.contains("code") || payload.contains("password");
    if (otherMethod) {
        audit::record({.action = "auth.approval.approve", .outcome = audit::Outcome::Denied,
                       .actor_id = caller.user->id, .actor = caller.user->name(),
                       .details = {{"approval_id", id}, {"reason", "passkey_only"}}},
                      "[auth::approval] " + caller.user->name() + " tried to approve a device's request without a "
                      "passkey", spdlog::level::warn);
        throw ops::Invalid("Only a passkey can approve a device's request. Without one, do the action in the console.");
    }
    auto a = approvalPendingFor(caller.user->id, id);
    const auto credentials = mfa::passkeys::available() ? mfa::passkeys::usableCredentials(caller.user->id)
                                                        : std::vector<mfa::WebAuthnCredential>{};
    if (credentials.empty())
        throw ops::Refused("passkey_required", "Approving a device's request takes a passkey. Add one (Account > "
                                               "Security), or do the action in the console instead.");
    if (const auto& manager = runtime::Deps::get().sessionManager) manager->noteUserActivity(session);

    const auto scope = approvalScope(a);
    if (!payload.contains("credential") || payload.at("credential").is_null())
        return {.approval = a, .publicKey = mfa::passkeys::approvalOptions(session->uuid, caller.user->id, credentials,
                                                                          scope)};
    if (!payload.at("credential").is_object()) throw ops::Invalid("credential is a PublicKeyCredential's JSON form");

    const auto verified = mfa::passkeys::verifyApproval(session->uuid, caller.user->id, payload.at("credential").dump(),
                                                        scope);
    if (!verified) {
        const int failures = session->stepUp().recordFailure();
        const int remaining = std::max(0, stepup::kMaxFailures - failures);
        audit::record({.action = "auth.approval.approve", .outcome = audit::Outcome::Failure,
                       .actor_id = caller.user->id, .actor = caller.user->name(),
                       .details = [&] {
                           auto d = approvalAuditDetails(a);
                           d["failures"] = failures;
                           return d;
                       }()},
                      "[auth::approval] a passkey approval failed for " + caller.user->name(), spdlog::level::warn);
        if (remaining == 0) {
            // Like step-up: five failed ceremonies within 15 minutes sign this console session out.
            try {
                (void)ops::sessions::revoke(caller.user, caller.jti, {.id = ops::sessions::handle(caller.jti)}, session);
            } catch (const std::exception& e) {
                log::Registry::auth()->error("[auth::approval] revoking the session of {} failed: {}",
                                             caller.user->name(), e.what());
                if (const auto& manager = runtime::Deps::get().sessionManager) manager->invalidate(session);
                session->closeAfterReply();
            }
        }
        return {.approval = a, .failed_attempts_remaining = remaining};
    }
    a = approvalDecide(caller.user->id, id, State::Approved);
    auto details = approvalAuditDetails(a);
    details["factor_id"] = verified->factor_id;
    audit::record({.action = "auth.approval.approve", .actor_id = caller.user->id, .actor = caller.user->name(),
                   .details = std::move(details)},
                  "[auth::approval] " + caller.user->name() + " approved a device's " +
                      std::string(stepup::to_string(a.family)) + " request with a passkey");
    return {.approval = a};
}

Approval deny(const std::shared_ptr<protocols::ws::Session>& session, const std::string& approvalId) {
    const auto caller = approvalWebCaller(session);
    auto a = approvalDecide(caller.user->id, approvalId, State::Denied);
    audit::record({.action = "auth.approval.deny", .actor_id = caller.user->id, .actor = caller.user->name(),
                   .details = approvalAuditDetails(a)},
                  "[auth::approval] " + caller.user->name() + " declined a device's " +
                      std::string(stepup::to_string(a.family)) + " request");
    return a;
}

void resetForTesting() {
    {
        auto& store = challengeStore();
        std::scoped_lock lock(store.mutex);
        store.open.clear();
    }
    auto& store = approvalStore();
    std::scoped_lock lock(store.mutex);
    store.approvals.clear();
    store.recentByDevice.clear();
}

void setPushForTesting(PushDelivery delivery) {
    std::scoped_lock lock(approvalPushMutex());
    approvalPushDelivery() = std::move(delivery);
}

}
