#include "protocols/device/Mcp.hpp"

#include "Mcp.hpp"
#include "device/Peer.hpp"
#include "identities/User.hpp"
#include "log/AuditOrigin.hpp"
#include "log/Registry.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Session.hpp"
#include "version.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace vh::protocols::device::mcp {

namespace {

namespace bhttp = boost::beast::http;
using Json = nlohmann::json;

std::atomic<int64_t> callDeadlineMs{std::chrono::duration_cast<std::chrono::milliseconds>(kCallDeadline).count()};

const vh::mcp::Catalog& catalog() {
    static const vh::mcp::Catalog value;
    return value;
}

const std::shared_ptr<shell::Router>& shellRouter() {
    static const auto router = [] {
        auto r = std::make_shared<shell::Router>();
        shell::commands::registerAllCommands(r);
        return r;
    }();
    return router;
}

protocols::http::model::preview::Response reply(const protocols::http::request& req, const bhttp::status status, std::string body,
                                     const std::string_view contentType = "application/json") {
    bhttp::response<bhttp::string_body> res{status, req.version()};
    res.set(bhttp::field::server, "Vaulthalla");
    if (!body.empty()) res.set(bhttp::field::content_type, contentType);
    res.set(bhttp::field::cache_control, "no-store");
    res.keep_alive(req.keep_alive());
    res.body() = std::move(body);
    res.prepare_payload();
    return res;
}

protocols::http::model::preview::Response jsonRpcError(const protocols::http::request& req, const bhttp::status status, const int code,
                                            const std::string& message) {
    return reply(req, status,
                 Json{{"jsonrpc", "2.0"}, {"id", nullptr}, {"error", {{"code", code}, {"message", message}}}}.dump());
}

std::string_view header(const protocols::http::request& req, const bhttp::field f) {
    const auto it = req.find(f);
    return it == req.end() ? std::string_view{} : std::string_view(it->value().data(), it->value().size());
}

std::string_view header(const protocols::http::request& req, const std::string_view name) {
    const auto it = req.find(boost::beast::string_view(name.data(), name.size()));
    return it == req.end() ? std::string_view{} : std::string_view(it->value().data(), it->value().size());
}

bool mentions(const std::string_view value, const std::string_view what) {
    return value.find(what) != std::string_view::npos;
}

// One tool call: the CLI line for the device's user, non-interactive. Abandoned (not interrupted) past the deadline.
vh::mcp::CommandOutput execute(const vh::mcp::Invocation& call, const std::shared_ptr<ws::Session>& principal) {
    if (!principal || principal->closing() || !principal->user || !principal->user->authorizing())
        return {.exit_code = 1, .out = {}, .err = "this device session has ended", .confirmation = std::nullopt};

    struct State {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        vh::mcp::CommandOutput output{};
    };
    auto state = std::make_shared<State>();
    const auto user = principal->user;
    const auto origin = "device " + (principal->devicePeer() ? principal->devicePeer()->shortId() : std::string{"?"}) +
                        " mcp";
    std::thread([state, user, origin, line = call.line] {
        vh::mcp::CommandOutput out;
        try {
            const log::AuditOrigin scope(origin);
            const auto result = shellRouter()->executeLine(line, user, nullptr);
            out.exit_code = result.exit_code;
            out.out = result.stdout_text;
            out.err = result.stderr_text;
            if (result.confirmation)
                out.confirmation = vh::mcp::Confirmation{.code = result.confirmation->code,
                                                         .flags = result.confirmation->flags};
        } catch (const std::exception& e) {
            out = {.exit_code = 1, .out = {}, .err = e.what(), .confirmation = std::nullopt};
        }
        std::scoped_lock lock(state->mutex);
        state->output = std::move(out);
        state->done = true;
        state->cv.notify_all();
    }).detach();

    std::unique_lock lock(state->mutex);
    const auto deadline = std::chrono::milliseconds(callDeadlineMs.load(std::memory_order_relaxed));
    if (!state->cv.wait_for(lock, deadline, [&] { return state->done; })) {
        log::Registry::http()->warn("[mcp] abandoned `{}` after {} ms (it keeps running)", call.command, deadline.count());
        return {.exit_code = 1, .out = {},
                .err = "the command did not finish within " + std::to_string(deadline.count() / 1000) +
                       " s; it may still complete on the node. Check its effect before retrying.",
                .confirmation = std::nullopt};
    }
    return std::move(state->output);
}

}

void setCallDeadlineForTesting(const std::chrono::milliseconds deadline) {
    callDeadlineMs.store(deadline.count(), std::memory_order_relaxed);
}

protocols::http::model::preview::Response handle(protocols::http::request&& req, const std::shared_ptr<ws::Session>& principal) {
    if (!principal || !principal->isDeviceSession() || principal->closing())
        return reply(req, bhttp::status::forbidden, Json{{"error", "device_unknown"}}.dump());

    // Browsers can't present a device certificate, but DNS rebinding is refused regardless (MCP: validate Origin).
    if (!header(req, bhttp::field::origin).empty())
        return reply(req, bhttp::status::forbidden, Json{{"error", "Origin not allowed"}}.dump());

    if (req.method() != bhttp::verb::post) {
        // No server-initiated stream (GET) and no MCP session to end (DELETE).
        auto res = reply(req, bhttp::status::method_not_allowed, {});
        std::visit([](auto& r) { r.set(bhttp::field::allow, "POST"); }, res);
        return res;
    }

    if (const auto version = header(req, "MCP-Protocol-Version"); !version.empty()) {
        const auto& supported = vh::mcp::kProtocolVersions;
        if (std::ranges::find(supported, version) == supported.end())
            return jsonRpcError(req, bhttp::status::bad_request, -32600,
                                "Unsupported MCP-Protocol-Version: " + std::string(version));
    }
    if (!mentions(header(req, bhttp::field::content_type), "application/json"))
        return jsonRpcError(req, bhttp::status::unsupported_media_type, -32600, "Content-Type must be application/json");
    if (const auto accept = header(req, bhttp::field::accept);
        !accept.empty() && !mentions(accept, "application/json") && !mentions(accept, "*/*"))
        return jsonRpcError(req, bhttp::status::not_acceptable, -32600, "Accept must allow application/json");

    const auto message = Json::parse(req.body(), nullptr, /*allow_exceptions=*/false);
    if (message.is_discarded())
        return reply(req, bhttp::status::bad_request, vh::mcp::Server::parseError().dump());
    if (message.is_array())
        return jsonRpcError(req, bhttp::status::bad_request, -32600, "Batches are not supported: send one message");

    vh::mcp::Server server(catalog(), [&principal](const vh::mcp::Invocation& call) { return execute(call, principal); },
                           VH_VERSION);
    const auto answer = server.handle(message);
    if (!answer) return reply(req, bhttp::status::accepted, {});  // a notification or a response: nothing to say
    return reply(req, bhttp::status::ok, answer->dump(-1, ' ', false, Json::error_handler_t::replace));
}

}
