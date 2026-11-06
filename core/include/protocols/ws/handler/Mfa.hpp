#pragma once

#include "protocols/ws/Fwd.hpp"

#include <nlohmann/json.hpp>

#include <memory>

// auth.mfa.* (#357; MFA design note sections 5.2, 7.2, 8.1, 8.2 and 10): the second sign-in step on a pending-MFA
// socket, the guided first-factor enrollment, and the account's own factor management (Account → Security).
//
// Pending sockets reach only kPendingCommands (+ kPendingEnrollmentCommands while enrolling; auth/mfa/Pending.hpp):
// the router enforces it, and every handler here checks the state it acts on again. Factor management is for web
// sessions only: a paired device's session (Vaulthalla Desktop) is refused, and never prompted.
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Mfa {
    // The pending sign-in as auth.login and auth.mfa.verify describe it: {kind, expires_at, methods,
    // attempts_remaining, webauthn?: {publicKey}}. Each call issues a fresh passkey challenge.
    static json pending(const std::shared_ptr<Session>& session);
    // auth.login's answer for a socket left pending: ERROR mfa_required / mfa_enrollment_required with data.pending.
    [[noreturn]] static void throwPending(const std::shared_ptr<Session>& session);

    static json verify(const json& payload, const std::shared_ptr<Session>& session);
    static json cancel(const std::shared_ptr<Session>& session);
    static json status(const std::shared_ptr<Session>& session);

    static json registerOptions(const json& payload, const std::shared_ptr<Session>& session);
    static json registerFinish(const json& payload, const std::shared_ptr<Session>& session);
    static json totpStart(const json& payload, const std::shared_ptr<Session>& session);
    static json totpConfirm(const json& payload, const std::shared_ptr<Session>& session);
    static json renameFactor(const json& payload, const std::shared_ptr<Session>& session);
    static json generateRecovery(const std::shared_ptr<Session>& session);
    static json acknowledgeRecovery(const json& payload, const std::shared_ptr<Session>& session);
};

}
