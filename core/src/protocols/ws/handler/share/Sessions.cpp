#include "protocols/ws/handler/share/Sessions.hpp"
#include "protocols/ws/handler/RequestErrors.hpp"
#include "ops/Error.hpp"

#include "protocols/ws/Session.hpp"
#include "rbac/fs/policy/Share.hpp"
#include "share/EmailChallenge.hpp"
#include "share/Link.hpp"
#include "share/Manager.hpp"
#include "share/Principal.hpp"
#include "runtime/Deps.hpp"
#include "auth/session/Manager.hpp"

#include <array>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler::share {
namespace sessions_handler_detail {
[[nodiscard]] std::shared_ptr<vh::share::Manager> defaultManager() {
    return std::make_shared<vh::share::Manager>();
}

[[nodiscard]] Sessions::ManagerFactory& managerFactory() {
    static Sessions::ManagerFactory factory = defaultManager;
    return factory;
}

[[nodiscard]] std::shared_ptr<vh::share::Manager> manager() {
    auto instance = managerFactory()();
    if (!instance) throw std::runtime_error("Share manager is unavailable");
    return instance;
}

[[nodiscard]] const json& objectPayload(const json& payload) {
    if (!payload.is_object()) throw std::invalid_argument("Share session payload must be an object");
    return payload;
}

[[nodiscard]] std::string requiredString(const json& payload, const char* field) {
    if (!payload.contains(field) || payload.at(field).is_null())
        throw std::invalid_argument(std::string("Missing required share field: ") + field);
    return payload.at(field).get<std::string>();
}

[[nodiscard]] std::optional<std::string> optionalString(const json& payload, const char* field) {
    if (!payload.contains(field) || payload.at(field).is_null()) return std::nullopt;
    auto value = payload.at(field).get<std::string>();
    if (value.empty()) return std::nullopt;
    return value;
}

[[nodiscard]] std::optional<std::string> optionalSessionText(const std::string& value) {
    if (value.empty()) return std::nullopt;
    return value;
}

[[nodiscard]] std::optional<std::string> optionalClientText(const std::string& value) {
    if (value.empty()) return std::nullopt;
    return value;
}

void requireNonHumanShareBootstrap(const std::shared_ptr<Session>& session) {
    if (!session) throw std::runtime_error("Share session requires websocket session");
    if (session->user) throw vh::ops::Denied("Share session commands require a public websocket session");
}

[[nodiscard]] vh::share::TargetType capabilityTargetType(
    const vh::share::Principal& principal,
    const vh::share::Operation operation
) {
    switch (operation) {
        case vh::share::Operation::List:
        case vh::share::Operation::Mkdir:
            return vh::share::TargetType::Directory;
        case vh::share::Operation::Preview:
        case vh::share::Operation::Download:
        case vh::share::Operation::Upload:
        case vh::share::Operation::Overwrite:
            return vh::share::TargetType::File;
        case vh::share::Operation::Metadata:
            return principal.grant.target_type;
    }
    return principal.grant.target_type;
}

[[nodiscard]] bool capabilityTargetExists(const vh::share::Operation operation) {
    return operation != vh::share::Operation::Upload && operation != vh::share::Operation::Mkdir;
}

[[nodiscard]] uint32_t effectiveAllowedOps(const vh::share::Principal& principal) {
    constexpr std::array operations{
        vh::share::Operation::Metadata,
        vh::share::Operation::List,
        vh::share::Operation::Preview,
        vh::share::Operation::Download,
        vh::share::Operation::Upload,
        vh::share::Operation::Mkdir,
        vh::share::Operation::Overwrite
    };

    uint32_t out = 0;
    for (const auto operation : operations) {
        if (!principal.allows(operation)) continue;

        const auto decision = vh::rbac::fs::policy::Share::evaluate(principal, {
            .vault_id = principal.vault_id,
            .vault_path = principal.root_path,
            .operation = operation,
            .target_type = capabilityTargetType(principal, operation),
            .target_exists = capabilityTargetExists(operation)
        });
        if (decision.allowed) out |= vh::share::bit(operation);
    }
    return out;
}

[[nodiscard]] json publicLinkJson(
    const std::shared_ptr<vh::share::Link>& link,
    const vh::share::Principal* principal = nullptr
) {
    if (!link) return nullptr;
    return Sessions::publicLinkJson(*link, principal ? std::optional<uint32_t>(effectiveAllowedOps(*principal))
                                                     : std::nullopt);
}

void attachReadyPrincipal(
    const std::shared_ptr<Session>& session,
    vh::share::Manager& manager,
    const std::string& sessionToken
) {
    auto principal = manager.resolvePrincipal(
        sessionToken,
        optionalClientText(session->ipAddress),
        optionalClientText(session->userAgent)
    );
    session->setSharePrincipal(std::move(principal), sessionToken);
}
}
namespace detail = sessions_handler_detail;

json Sessions::publicLinkJson(const vh::share::Link& link, const std::optional<uint32_t> effectiveAllowedOps) {
    auto out = link.toPublicJson();
    out.erase("token_lookup_id");
    out.erase("token_hash");
    if (effectiveAllowedOps) out["effective_allowed_ops"] = *effectiveAllowedOps;
    return out;
}

json Sessions::open(const json& payload, const std::shared_ptr<Session>& session) try {
    detail::requireNonHumanShareBootstrap(session);
    const auto& body = detail::objectPayload(payload);
    const auto publicToken = detail::requiredString(body, "public_token");
    auto mgr = detail::manager();
    auto requestedLink = mgr->resolvePublicLink(publicToken);

    if (session->isShareMode() && session->sharePrincipal() &&
        session->sharePrincipal()->share_id == requestedLink->id) {
        return {
            {"status", "ready"},
            {"share", detail::publicLinkJson(requestedLink, session->sharePrincipal().get())},
            {"session_id", session->shareSessionId()},
            {"session_token", session->shareSessionToken()}
        };
    }

    if (session->isShareSession()) session->clearShareSession();

    auto result = mgr->openPublicSession(
        publicToken,
        detail::optionalClientText(session->ipAddress),
        detail::optionalClientText(session->userAgent)
    );

    const auto ready = result.ready();
    if (ready) detail::attachReadyPrincipal(session, *mgr, result.session_token);
    else session->setPendingShareSession(result.session->id, result.session_token);
    vh::runtime::Deps::get().sessionManager->cache(session);
    const auto principal = ready ? session->sharePrincipal().get() : nullptr;

    return {
        {"status", ready ? "ready" : "email_required"},
        {"share", detail::publicLinkJson(result.link, principal)},
        {"session_id", result.session ? result.session->id : ""},
        {"session_token", result.session_token}
    };
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Sessions::startEmailChallenge(const json& payload, const std::shared_ptr<Session>& session) try {
    detail::requireNonHumanShareBootstrap(session);
    if (session->isShareMode())
        throw vh::ops::Conflict("Share session is already verified");

    const auto& body = detail::objectPayload(payload);
    auto publicToken = detail::optionalString(body, "public_token");
    auto sessionToken = detail::optionalString(body, "session_token");
    if (!publicToken && !sessionToken)
        sessionToken = detail::optionalSessionText(session->shareSessionToken());

    auto mgr = detail::manager();
    auto result = mgr->startEmailChallenge(vh::share::StartEmailChallengeRequest{
        .public_token = publicToken,
        .session_token = sessionToken,
        .email = detail::requiredString(body, "email"),
        .ip_address = detail::optionalClientText(session->ipAddress),
        .user_agent = detail::optionalClientText(session->userAgent)
    });

    const auto effectiveSessionToken = result.session_token.empty()
                                           ? sessionToken.value_or("")
                                           : result.session_token;
    if (!effectiveSessionToken.empty() && result.session)
        session->setPendingShareSession(result.session->id, effectiveSessionToken);

    json response = {
        {"status", "challenge_created"},
        {"share", detail::publicLinkJson(result.link)},
        {"challenge_id", result.challenge ? result.challenge->id : ""},
        {"session_id", result.session ? result.session->id : ""}
    };
    if (!result.session_token.empty()) response["session_token"] = result.session_token;
    return response;
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Sessions::confirmEmailChallenge(const json& payload, const std::shared_ptr<Session>& session) try {
    detail::requireNonHumanShareBootstrap(session);
    if (session->isShareMode())
        throw vh::ops::Conflict("Share session is already verified");

    const auto& body = detail::objectPayload(payload);
    const auto sessionId = detail::optionalString(body, "session_id").value_or(session->shareSessionId());
    const auto sessionToken = detail::optionalString(body, "session_token").value_or(session->shareSessionToken());
    if (sessionId.empty()) throw std::invalid_argument("Share session id is required");
    if (sessionToken.empty()) throw std::invalid_argument("Share session token is required");

    auto mgr = detail::manager();
    auto result = mgr->confirmEmailChallenge(vh::share::ConfirmEmailChallengeRequest{
        .challenge_id = detail::requiredString(body, "challenge_id"),
        .session_id = sessionId,
        .session_token = sessionToken,
        .code = detail::requiredString(body, "code")
    });

    if (result.verified) {
        detail::attachReadyPrincipal(session, *mgr, sessionToken);
        vh::runtime::Deps::get().sessionManager->cache(session);
    }

    return {
        {"status", result.verified ? "ready" : "email_required"},
        {"verified", result.verified},
        {"session_id", result.session ? result.session->id : sessionId}
    };
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

void Sessions::setManagerFactoryForTesting(ManagerFactory factory) {
    if (!factory) throw std::invalid_argument("Share manager factory is required");
    detail::managerFactory() = std::move(factory);
}

void Sessions::resetManagerFactoryForTesting() {
    detail::managerFactory() = detail::defaultManager;
}

}
