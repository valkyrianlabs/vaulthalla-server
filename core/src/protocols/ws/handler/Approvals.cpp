#include "protocols/ws/handler/Approvals.hpp"

#include "auth/approval/Approvals.hpp"
#include "device/Crypto.hpp"
#include "ops/Devices.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/Refusal.hpp"

#include <chrono>

namespace vh::protocols::ws::handler {

namespace {

namespace approval = ::vh::auth::approval;
namespace stepup = ::vh::auth::stepup;

std::string approvalsString(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || !payload.at(key).is_string())
        throw ops::Invalid(std::string(key) + " is required (a string)");
    return payload.at(key).get<std::string>();
}

std::optional<std::string> approvalsOptionalString(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    if (!payload.at(key).is_string()) throw ops::Invalid(std::string(key) + " is a string");
    return payload.at(key).get<std::string>();
}

stepup::Family approvalsFamily(const json& payload) {
    const auto family = stepup::parseFamily(approvalsString(payload, "family"));
    if (!family) throw ops::Invalid("unknown step-up family");
    return *family;
}

std::vector<uint8_t> approvalsBase64(const json& payload, const char* key) {
    const auto decoded = vh::device::crypto::fromBase64(approvalsString(payload, key));
    if (!decoded || decoded->empty()) throw ops::Invalid(std::string(key) + " must be standard base64 (with padding)");
    return *decoded;
}

int64_t approvalsUnix(const std::chrono::system_clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

}

json Approvals::challenge(const json& payload, const std::shared_ptr<Session>& session) {
    const auto family = approvalsFamily(payload);
    const auto c = approval::challenge(session, family, approvalsOptionalString(payload, "target").value_or(""));
    return {{"challenge_id", c.challenge_id},
            {"challenge", vh::device::crypto::toHex(c.challenge)},
            {"payload_b64", vh::device::crypto::toBase64(c.payload)},
            {"family", std::string(stepup::to_string(c.family))},
            {"target", c.target},
            {"expires_at", c.expires_at}};
}

json Approvals::submit(const json& payload, const std::shared_ptr<Session>& session) {
    const auto done = approval::submit(session, approvalsString(payload, "challenge_id"),
                                       approvalsBase64(payload, "signature_b64"));
    return {{"family", std::string(stepup::to_string(done.family))},
            {"target", done.target},
            {"expires_at", approvalsUnix(done.expires_at)}};
}

json Approvals::request(const json& payload, const std::shared_ptr<Session>& session) {
    return approval::toJson(approval::request(session, approvalsFamily(payload),
                                              approvalsOptionalString(payload, "target"),
                                              approvalsString(payload, "summary")));
}

json Approvals::status(const json& payload, const std::shared_ptr<Session>& session) {
    return approval::toJson(approval::status(session, approvalsString(payload, "approval_id")));
}

json Approvals::keyRegister(const json& payload, const std::shared_ptr<Session>& session) {
    if (!session || !session->user || !session->isDeviceSession() || !session->devicePeer())
        throw ops::Refused("device_unknown", "this command is only answered on a paired device's own session");
    ops::devices::registerApprovalKey(session->user, *session->devicePeer(),
                                      approvalsBase64(payload, "public_key_spki_b64"));
    return {{"registered", true}};
}

json Approvals::list(const std::shared_ptr<Session>& session) {
    json out = json::array();
    for (const auto& a : approval::list(session)) out.push_back(approval::toJson(a));
    return {{"approvals", std::move(out)}};
}

json Approvals::approve(const json& payload, const std::shared_ptr<Session>& session) {
    const auto answer = approval::approve(session, payload);
    if (answer.failed_attempts_remaining) {
        throw core::DetailedRefusal(
            "approval_failed",
            *answer.failed_attempts_remaining == 0
                ? "Too many failed attempts: this session was signed out. Sign in again."
                : "That passkey didn't confirm it. Try again.",
            {{"attempts_remaining", *answer.failed_attempts_remaining}});
    }
    json out{{"approval", approval::toJson(answer.approval)}};
    if (answer.publicKey) out["webauthn"] = {{"publicKey", *answer.publicKey}};
    return out;
}

json Approvals::deny(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"approval", approval::toJson(approval::deny(session, approvalsString(payload, "approval_id")))}};
}

}
