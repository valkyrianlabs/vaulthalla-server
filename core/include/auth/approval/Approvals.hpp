#pragma once

#include "auth/stepup/StepUp.hpp"
#include "device/Crypto.hpp"
#include "protocols/ws/Fwd.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Device approvals (#361; MFA design note docs/dev/mfa-design.md sections 6.1-6.3 and 6.5, decision D6;
// docs/reference/device-approvals.md): how a person approves a step-up family for a paired device's session.
//
// A paired device's mTLS key proves which device is connecting, never that a person is there: a routine connection,
// a device saying the OS checked a biometric, or any client flag never counts as presence. What counts is one of two
// cryptographic artifacts, each leaving a grant (auth/stepup/StepUp.hpp Grant) on the device session that asked, never
// on another:
//
// 1. The approval key (device.approval.challenge / .submit). A second P-256 key per device, kept by Vaulthalla Desktop
//    in the Secure Enclave behind user presence, registered with the pairing request (device.pair.request
//    approval_key) or later through a console approval (device.approval.key.register). The server issues a challenge
//    (32 random bytes, single use, 120 s, bound to this device session, the family and the target) and verifies an
//    ECDSA P-256/SHA-256 signature by the device's live approval key over device::crypto::approvalMessage (node id,
//    server key, the device's own key, the challenge, family, target, expiry). The server can't verify that the
//    key's access control really asks for Touch ID, so it is accepted only for keys and device.trust (the key-backup
//    grant commands are device.trust): D6, stepup::deviceApprovalMaySatisfy.
//
// 2. A console approval (device.approval.request / .status, auth.approval.list / .approve / .deny). The device asks
//    for {family, target, summary}; at most kMaxOpenPerDevice open and kMaxPerHourPerDevice per hour per device; it
//    lives kRequestTtl. The user's signed-in console sessions get the push auth.approval.pending. A person approves it
//    with a passkey assertion with user verification over a challenge bound to their console session and to this
//    approval (purpose approval), nothing else: a TOTP code or a password never approves a device's request. The
//    device's next device.approval.status on the same session makes the grant (any family, design 6.3).
//
// Grants made here last stepup::ttl() and, for target-bound families, are spent by one use, like a web session's.
// Everything here is in memory: a restart drops challenges, requests and grants, and the device asks again. Audit:
// device.approval.submit, auth.approval.request|approve|deny.
namespace vh::auth::approval {

// ---- the approval key -------------------------------------------------------------------------------------------------

inline constexpr std::chrono::seconds kChallengeTtl{120};
inline constexpr std::size_t kMaxChallengesPerSession = 4;
inline constexpr std::size_t kMaxChallenges = 4096;

// Whether the device of this (device) session has a live approval key.
[[nodiscard]] bool hasLiveApprovalKey(const std::shared_ptr<protocols::ws::Session>& session);

struct Challenge {
    std::string challenge_id{};
    device::crypto::Hash challenge{};
    std::vector<uint8_t> payload{};  // the exact bytes to sign
    stepup::Family family{};
    std::string target{};
    int64_t expires_at{};            // Unix seconds, also inside the payload
};

// device.approval.challenge: a paired device's own session, a family the approval key may approve (else
// ops::Refused("console_approval_required")), a target (the one the step_up_required refusal named), and a live
// approval key (else ops::Refused("approval_key_unavailable")). An older open challenge past kMaxChallengesPerSession
// is dropped.
[[nodiscard]] Challenge challenge(const std::shared_ptr<protocols::ws::Session>& session, stepup::Family family,
                                  const std::string& target);

struct Submitted {
    stepup::Family family{};
    std::string target{};
    std::chrono::system_clock::time_point expires_at{};  // the grant's
};

// device.approval.submit: spends the challenge (single use) and, when the DER signature by the device's live approval
// key verifies over the payload as it is now (the node's id and the server key it presents included), leaves a grant
// on this session. ops::NotFound: no such open challenge on this session (expired, used, another session's);
// ops::Invalid: the signature doesn't verify; ops::Refused("approval_key_unavailable"): the key was revoked.
[[nodiscard]] Submitted submit(const std::shared_ptr<protocols::ws::Session>& session, const std::string& challengeId,
                               const std::vector<uint8_t>& signature);

// ---- console approvals --------------------------------------------------------------------------------------------------

inline constexpr std::chrono::minutes kRequestTtl{5};
inline constexpr std::size_t kMaxOpenPerDevice = 3;
inline constexpr std::size_t kMaxPerHourPerDevice = 10;
inline constexpr std::size_t kMaxSummaryCodePoints = 160;
// A WebAuthn ceremony that fails this many times on one console session within stepup::kFailureWindow signs it out
// (the same count as step-up failures: they are the same session guessing).

enum class State { Pending, Approved, Denied, Expired };
[[nodiscard]] std::string to_string(State state);

struct Approval {
    std::string id{};
    uint32_t user_id{};
    uint32_t device_row_id{};
    std::string device_name{};
    std::string device_id{};  // the device key's SPKI SHA-256 (hex)
    std::string session_uuid{};
    stepup::Family family{};
    std::optional<std::string> target{};  // target-bound families only
    std::string summary{};
    State state{State::Pending};
    std::chrono::system_clock::time_point created_at{}, expires_at{};
    std::optional<std::chrono::system_clock::time_point> decided_at{};
    bool granted{false};  // the device's status made its grant
};

// {approval_id, state, family, target, summary, device: {id, device_id, name}, created_at, expires_at}.
[[nodiscard]] nlohmann::json toJson(const Approval& approval);

// device.approval.request on a paired device's own session. ops::Refused("rate_limited") past the limits.
[[nodiscard]] Approval request(const std::shared_ptr<protocols::ws::Session>& session, stepup::Family family,
                               const std::optional<std::string>& target, const std::string& summary);
// device.approval.status on the session that asked (another session: ops::NotFound). Once approved, the first call
// makes the grant on this session.
[[nodiscard]] Approval status(const std::shared_ptr<protocols::ws::Session>& session, const std::string& approvalId);

// auth.approval.list: the signed-in console user's open requests (web sessions only).
[[nodiscard]] std::vector<Approval> list(const std::shared_ptr<protocols::ws::Session>& session);

struct ApproveAnswer {
    Approval approval{};
    std::optional<nlohmann::json> publicKey{};  // without a credential: the request options to sign with
    // Set when the assertion didn't hold: how many more may fail before this console session is signed out (0: it was).
    std::optional<int> failed_attempts_remaining{};
};
// auth.approval.approve {approval_id, credential?}: without credential, the WebAuthn request options (a challenge bound
// to this console session and this approval); with one, verifies the UV assertion and approves. Only a passkey:
// any other method is ops::Invalid, and an account without a usable passkey gets ops::Refused("passkey_required").
[[nodiscard]] ApproveAnswer approve(const std::shared_ptr<protocols::ws::Session>& session, const nlohmann::json& payload);
// auth.approval.deny {approval_id}.
[[nodiscard]] Approval deny(const std::shared_ptr<protocols::ws::Session>& session, const std::string& approvalId);

// Tests: drops every challenge and request.
void resetForTesting();
// Tests: where auth.approval.pending goes instead of the console sessions' sockets (empty: back to them).
using PushDelivery = std::function<void(const std::shared_ptr<protocols::ws::Session>&, const nlohmann::json&)>;
void setPushForTesting(PushDelivery delivery);

}
