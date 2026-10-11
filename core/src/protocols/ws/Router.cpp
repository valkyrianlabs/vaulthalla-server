#include "protocols/ws/Router.hpp"

#include "auth/session/Manager.hpp"
#include "log/Registry.hpp"
#include "config/Config.hpp"
#include "protocols/ws/LogRedaction.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/ShareRateLimit.hpp"
#include "protocols/ws/core/handler_templates.hpp"
#include "runtime/Deps.hpp"
#include "identities/User.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <array>

namespace {
template<size_t N>
bool containsCommand(const std::array<std::string_view, N>& commands, const std::string_view command) {
    return std::ranges::find(commands, command) != commands.end();
}

// Commands that establish, refresh, inspect or end a session. They must work before (or without a valid) access
// token. Everything else under `auth.` (user register/update/delete/get/list, password change) is account
// management and goes through RequireHumanAuth like any other command; a `starts_with("auth")` rule used to
// let unauthenticated sockets reach handlers that dereference session->user.
bool isSessionLifecycleCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"auth.login"},
        std::string_view{"auth.logout"},
        std::string_view{"auth.refresh"},
        std::string_view{"auth.isAuthenticated"}
    };
    return containsCommand(commands, command);
}

vh::protocols::ws::ShareRateLimit& shareRateLimit() {
    return vh::protocols::ws::ShareRateLimit::instance();
}

std::string refusalClient(const vh::protocols::ws::Session& session) {
    if (!session.clientAddress.empty()) return session.clientAddress;
    return session.ipAddress.empty() ? "unknown" : session.ipAddress;
}

// The command string is client-supplied: keep it short and printable before it reaches a log line.
std::string printableCommand(const std::string_view command) {
    constexpr std::size_t kMaxLoggedCommand = 64;
    std::string out;
    out.reserve(std::min(command.size(), kMaxLoggedCommand) + 3);
    for (const char c : command.substr(0, kMaxLoggedCommand))
        out.push_back(c >= 0x20 && c < 0x7f ? c : '?');
    if (command.size() > kMaxLoggedCommand) out += "...";
    return out;
}
}

namespace vh::protocols::ws {

using namespace core;
using namespace model;

void Router::registerWs(const std::string& cmd, RawWsHandler fn) {
    handlers_[cmd] = makeWsHandler(cmd, std::move(fn));
}

void Router::registerPayload(const std::string& cmd, RawPayloadHandler fn) {
    handlers_[cmd] = makePayloadHandler(cmd, std::move(fn));
}

void Router::registerPayloadOnly(const std::string &cmd, RawPayloadHandlerOnly fn) {
    handlers_[cmd] = makePayloadOnlyHandler(cmd, std::move(fn));
}

void Router::registerHandlerWithToken(const std::string& cmd, RawHandlerWithToken fn) {
    handlers_[cmd] = makeHandlerWithToken(cmd, std::move(fn));
}

void Router::registerSessionOnlyHandler(const std::string& cmd, RawSessionOnly fn) {
    handlers_[cmd] = makeSessionOnlyHandler(cmd, std::move(fn));
}

void Router::registerEmptyHandler(const std::string& cmd, RawEmpty fn) {
    handlers_[cmd] = makeEmptyHandler(cmd, std::move(fn));
}

void Router::registerHandler(const std::string& cmd, Handler h) {
    handlers_[cmd] = std::move(h);
}

void Router::logRefusal(const std::string& label, const std::string_view suffix, const std::string_view detail) {
    const auto logger = log::Registry::ws();
    const auto decision = refusalLog_.record(label);
    for (const auto& summary : decision.summaries)
        logger->warn("[Router] {}: suppressed {} more in {}s", summary.label, summary.suppressed, summary.span.count());
    if (decision.warn) logger->warn("[Router] {}{}", label, suffix);
    logger->debug("[Router] {}{}{}", label, suffix, detail);
}

std::string Router::commandForLog(const std::string_view command) const {
    // Throttle labels key on the command, so an unregistered (client-invented) name must not mint a fresh label
    // per request: they all share one.
    if (handlers_.contains(std::string(command)) || ShareRateLimit::isLimitedCommand(command))
        return fmt::format("'{}'", command);
    return "an unregistered command";
}

bool Router::isPublicShareCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"share.session.open"},
        std::string_view{"share.email.challenge.start"},
        std::string_view{"share.email.challenge.confirm"}
    };
    return containsCommand(commands, command);
}

bool Router::isShareFilesystemCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"share.fs.metadata"},
        std::string_view{"share.fs.list"}
    };
    return containsCommand(commands, command);
}

namespace {
bool isShareNativeFilesystemCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"fs.metadata"},
        std::string_view{"fs.list"}
    };
    return containsCommand(commands, command);
}

bool isShareNativeDownloadCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"fs.download.start"},
        std::string_view{"fs.download.chunk"},
        std::string_view{"fs.download.cancel"}
    };
    return containsCommand(commands, command);
}

bool isShareNativeUploadCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"fs.upload.start"},
        std::string_view{"fs.upload.finish"},
        std::string_view{"fs.upload.cancel"}
    };
    return containsCommand(commands, command);
}
}

bool Router::isShareDownloadCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"share.download.start"},
        std::string_view{"share.download.chunk"},
        std::string_view{"share.download.cancel"}
    };
    return containsCommand(commands, command);
}

bool Router::isSharePreviewCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"share.preview.get"}
    };
    return containsCommand(commands, command);
}

bool Router::isShareUploadCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"share.upload.start"},
        std::string_view{"share.upload.finish"},
        std::string_view{"share.upload.cancel"}
    };
    return containsCommand(commands, command);
}

bool Router::isShareModeCommand(const std::string_view command) {
    return isPublicShareCommand(command) ||
           isShareFilesystemCommand(command) ||
           isShareNativeFilesystemCommand(command) ||
           isShareNativeDownloadCommand(command) ||
           isShareNativeUploadCommand(command) ||
           isShareDownloadCommand(command) ||
           isSharePreviewCommand(command) ||
           isShareUploadCommand(command);
}

bool Router::isAuthenticatedShareManagementCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"share.link.create"},
        std::string_view{"share.link.get"},
        std::string_view{"share.link.list"},
        std::string_view{"share.link.update"},
        std::string_view{"share.link.revoke"},
        std::string_view{"share.link.rotate_token"}
    };
    return containsCommand(commands, command);
}

Router::CommandAuthDecision Router::classifyCommand(const std::string_view command, const Session& session) {
    if (session.isSharePending()) {
        return isPublicShareCommand(command) ? CommandAuthDecision::Allow : CommandAuthDecision::Deny;
    }

    if (session.isShareMode()) {
        return isShareModeCommand(command) ? CommandAuthDecision::Allow : CommandAuthDecision::Deny;
    }

    if (session.user) {
        // The session holds the canonical user: a deactivation or deletion is seen here on the very next command.
        if (session.user->systemOnly() || !session.user->authorizing()) return CommandAuthDecision::Deny;

        if (isPublicShareCommand(command) ||
            isShareFilesystemCommand(command) ||
            isShareDownloadCommand(command) ||
            isSharePreviewCommand(command) ||
            isShareUploadCommand(command))
            return CommandAuthDecision::Deny;
        if (isSessionLifecycleCommand(command)) return CommandAuthDecision::Allow;
        return CommandAuthDecision::RequireHumanAuth;
    }

    if (isSessionLifecycleCommand(command) || isPublicShareCommand(command)) return CommandAuthDecision::Allow;
    return CommandAuthDecision::Deny;
}

void Router::routeMessage(json&& msg, const SessionPtr& session) {
    try {
        if (!session) {
            log::Registry::ws()->error("[Router] Cannot route message: session is null");
            return;
        }

        log::Registry::ws()->debug("[Router] Routing message: {}", redactForLog(msg).dump());

        auto command = msg.at("command").get<std::string>();
        const std::string accessToken = msg.value("token", "");

        const auto decision = classifyCommand(command, *session);

        if (decision == CommandAuthDecision::Deny ||
            (decision == CommandAuthDecision::RequireHumanAuth &&
             !runtime::Deps::get().sessionManager->validate(session, accessToken))) {
            logRefusal(fmt::format("Unauthorized access attempt for {} from client {}",
                                   commandForLog(command), refusalClient(*session)),
                       "", fmt::format(" (command: {})", printableCommand(command)));
            Response::UNAUTHORIZED(std::move(command), std::move(msg))(session);
            return;
        }

        const auto rateLimit = shareRateLimit().check(command, msg, *session);
        if (!rateLimit.allowed) {
            // The limiter covers auth.login as well as share traffic: say "share" only for share traffic.
            const bool shareTraffic = command.starts_with("share.") || session->isShareMode();
            logRefusal(fmt::format("{} '{}' for client {}",
                                   shareTraffic ? "Share rate limited" : "Rate limited",
                                   command, refusalClient(*session)),
                       fmt::format(" (retry in {}s)", rateLimit.retry_after.count()), "");
            Response::ERROR(std::move(command), std::move(msg),
                            "Rate limit exceeded. Try again in " + std::to_string(rateLimit.retry_after.count()) +
                            "s.")(session);
            return;
        }

        if (handlers_.contains(command)) handlers_[command](std::move(msg), session);
        else {
            log::Registry::ws()->warn("[Router] Unknown command: {}", command);
            Response::ERROR(std::move(command), std::move(msg), "Unknown command")(session);
        }
    } catch (const std::exception& e) {
        log::Registry::ws()->error("[Router] Error routing message: {}", e.what());
        if (session) Response::INTERNAL_ERROR(std::move(msg), e.what())(session);
    }
}

}
