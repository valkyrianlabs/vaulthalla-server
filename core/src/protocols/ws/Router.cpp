#include "protocols/ws/Router.hpp"

#include "auth/session/Manager.hpp"
#include "log/Registry.hpp"
#include "config/Config.hpp"
#include "protocols/ws/Envelope.hpp"
#include "protocols/ws/LogRedaction.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/ShareRateLimit.hpp"
#include "protocols/ws/core/handler_templates.hpp"
#include "runtime/Deps.hpp"
#include "identities/User.hpp"
#include "device/Peer.hpp"
#include "log/AuditOrigin.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace {
template<size_t N>
bool containsCommand(const std::array<std::string_view, N>& commands, const std::string_view command) {
    return std::ranges::find(commands, command) != commands.end();
}

// The protocol handshake (WsProtocol.hpp). Allowed where meta.contract.get is: pairing-only and paired device sessions,
// and signed-in web sessions (RequireHumanAuth); never an unauthenticated socket (no pre-login build fingerprinting,
// bc342115) or a share session.
constexpr std::string_view kHelloCommand{"meta.hello"};

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
    auto out = !session.clientAddress.empty() ? session.clientAddress
                                              : (session.ipAddress.empty() ? "unknown" : session.ipAddress);
    if (const auto& peer = session.devicePeer()) out += " (device " + peer->shortId() + ")";
    // What the client said it is in meta.hello (validated printable ASCII).
    if (const auto client = session.clientInfo(); !client.name.empty())
        out += " [" + client.name + (client.version.empty() ? "" : " " + client.version) + "]";
    return out;
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

std::vector<std::string> Router::commands() const {
    std::vector<std::string> out;
    out.reserve(handlers_.size());
    for (const auto& [command, _] : handlers_) out.push_back(command);
    std::ranges::sort(out);
    return out;
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

bool Router::isDevicePairCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"device.pair.request"},
        std::string_view{"device.pair.confirm"},
        std::string_view{"device.pair.status"}
    };
    return containsCommand(commands, command);
}

bool Router::isDeviceOnlyCommand(const std::string_view command) {
    constexpr std::array commands{
        std::string_view{"device.identity.rotate"},
        std::string_view{"device.server.identity"},
        std::string_view{"device.endpoints"}
    };
    return containsCommand(commands, command);
}

model::Response Router::unknownCommand(std::string&& command, json&& msg) {
    // The text stays what clients before the code matched on.
    return {std::move(command), std::move(msg), Status::ERROR, json{{"code", "unknown_command"}}, "Unknown command"};
}

Router::CommandAuthDecision Router::classifyCommand(const std::string_view command, const Session& session) {
    // The device listener: who this is was decided at the TLS handshake, never by a token.
    if (session.isDevicePairing()) {
        if (isDevicePairCommand(command) || command == "meta.contract.get" || command == kHelloCommand)
            return CommandAuthDecision::Allow;
        return CommandAuthDecision::DenyDeviceUnknown;
    }
    if (session.isDeviceSession()) {
        // The canonical user: deactivation, deletion and permission changes apply on the very next command.
        if (session.closing() || !session.user || session.user->systemOnly() || !session.user->authorizing())
            return CommandAuthDecision::Deny;
        // No password sign-in, refresh tokens or account creation through a device; a device signs out by being
        // unpaired (device.revoke).
        if (isSessionLifecycleCommand(command) && command != "auth.isAuthenticated") return CommandAuthDecision::Deny;
        if (command == "auth.register") return CommandAuthDecision::Deny;
        if (isPublicShareCommand(command) || isShareFilesystemCommand(command) || isShareDownloadCommand(command) ||
            isSharePreviewCommand(command) || isShareUploadCommand(command))
            return CommandAuthDecision::Deny;
        return CommandAuthDecision::Allow;
    }
    if (isDevicePairCommand(command) || isDeviceOnlyCommand(command)) return CommandAuthDecision::Deny;

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
    // Taken before anything can move `msg`: a fault answers the request's own command with its requestId.
    std::string faultCommand = msg.is_object() && msg.contains("command") && msg.at("command").is_string()
                                   ? msg.at("command").get<std::string>()
                                   : std::string("error");
    json faultRequest{{"requestId", envelope::requestId(msg)}};
    try {
        if (!session) {
            log::Registry::ws()->error("[Router] Cannot route message: session is null");
            return;
        }

        log::Registry::ws()->debug("[Router] Routing message: {}", redactForLog(msg).dump());

        if (const auto problem = envelope::problem(msg)) throw std::invalid_argument(*problem);
        auto command = msg.at("command").get<std::string>();
        const auto token = msg.find("token");
        const std::string accessToken = token != msg.end() && token->is_string() ? token->get<std::string>() : "";

        const auto decision = classifyCommand(command, *session);

        if (decision == CommandAuthDecision::DenyDeviceUnknown) {
            logRefusal(fmt::format("Unpaired device asked for {} from client {}", commandForLog(command),
                                   refusalClient(*session)),
                       "", fmt::format(" (command: {})", printableCommand(command)));
            Response(std::move(command), std::move(msg), Status::ERROR, json{{"code", "device_unknown"}},
                     "This device is not paired with this node.")(session);
            return;
        }

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

        // Everything a paired device does is attributed to it: audit lines written while its command runs carry the
        // device id (the actor stays its user, for RBAC as for the log).
        std::optional<log::AuditOrigin> origin;
        if (const auto& peer = session->devicePeer(); peer && peer->paired()) {
            ::vh::device::touch(*peer);
            origin.emplace("device " + peer->shortId());
            log::Registry::ws()->debug("[Router] device {} ({}) runs {}", peer->shortId(),
                                       session->user ? session->user->name() : std::string{"-"},
                                       commandForLog(command));
        }

        if (handlers_.contains(command)) handlers_[command](std::move(msg), session);
        else {
            log::Registry::ws()->warn("[Router] Unknown command: {}", printableCommand(command));
            unknownCommand(std::move(command), std::move(msg))(session);
        }
    } catch (const std::exception& e) {
        log::Registry::ws()->error("[Router] Error routing message: {}", e.what());
        if (session) Response::INTERNAL_ERROR(std::move(faultCommand), std::move(faultRequest), e.what())(session);
    }
}

}
