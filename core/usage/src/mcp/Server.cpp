// MCP over JSON-RPC 2.0: lifecycle (initialize, notifications/initialized, ping) and tools (tools/list, tools/call).
// The transport (stdio in `vh mcp`, Streamable HTTP in the daemon later) frames the messages; this decides answers.

#include "Mcp.hpp"

#include <algorithm>
#include <exception>
#include <utility>

namespace vh::mcp {

namespace {

Json response(const Json& id, Json result) { return {{"jsonrpc", "2.0"}, {"id", id}, {"result", std::move(result)}}; }

Json errorResponse(const Json& id, const int code, std::string message) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", std::move(message)}}}};
}

constexpr int kParseError = -32700;
constexpr int kInvalidRequest = -32600;
constexpr int kMethodNotFound = -32601;
constexpr int kInvalidParams = -32602;
constexpr int kInternalError = -32603;

}

std::string instructions() {
    return "Vaulthalla is a self-hosted encrypted cloud (vaults, users, groups, roles, S3/R2 sync, an S3 gateway, file "
           "recovery). Every tool runs an ordinary vh command as the human's own Vaulthalla user, so their permissions "
           "apply. Read before you write: inspect with vh_read or a read-only typed tool first, and change only what "
           "was asked. Discover commands with vh_help; prefer typed tools, then vh_read (read-only), then vh_run. "
           "When a result says needs_confirmation, nothing happened: show the message to the human and set confirm "
           "only after they explicitly approve that exact action in this conversation. Destructive commands are "
           "refused until confirm carries \"destructive\": true: first state what will be affected and why, and "
           "set it only with the human's approval. Keys and secrets are never handled by agents: for a key backup, ask "
           "the human to run `vh vault keys export <vault>` in their own terminal. Afterwards, report what changed.";
}

Server::Server(const Catalog& catalog, Executor executor, std::string version)
    : catalog_(catalog), executor_(std::move(executor)), version_(std::move(version)) {}

Json Server::parseError() { return errorResponse(nullptr, kParseError, "Parse error"); }

std::optional<Json> Server::handle(const Json& message) {
    if (!message.is_object() || !message.contains("jsonrpc") || message["jsonrpc"] != "2.0")
        return errorResponse(nullptr, kInvalidRequest, "Invalid Request: expected one JSON-RPC 2.0 object");
    if (!message.contains("method")) return std::nullopt;  // a response to something we never send
    if (!message["method"].is_string()) return errorResponse(message.value("id", Json()), kInvalidRequest, "Invalid Request");

    const auto method = message["method"].get<std::string>();
    if (!message.contains("id")) return std::nullopt;  // notifications: initialized, cancelled, ... need no answer
    const auto& id = message["id"];
    if (!id.is_string() && !id.is_number_integer())
        return errorResponse(nullptr, kInvalidRequest, "Invalid Request: id must be a string or an integer");
    const Json params = message.value("params", Json::object());

    try {
        if (method == "initialize") {
            const auto requested = params.is_object() && params.contains("protocolVersion") &&
                                           params["protocolVersion"].is_string()
                                       ? params["protocolVersion"].get<std::string>()
                                       : std::string{};
            protocolVersion_ = std::ranges::find(kProtocolVersions, requested) != kProtocolVersions.end()
                                   ? requested
                                   : std::string(kProtocolVersions.front());
            return response(id, {{"protocolVersion", protocolVersion_},
                                 {"capabilities", {{"tools", {{"listChanged", false}}}}},
                                 {"serverInfo", {{"name", kServerName}, {"title", "Vaulthalla"}, {"version", version_}}},
                                 {"instructions", instructions()}});
        }
        if (method == "ping") return response(id, Json::object());
        if (method == "tools/list") return response(id, {{"tools", catalog_.tools()}});
        if (method == "tools/call") {
            if (!params.is_object() || !params.contains("name") || !params["name"].is_string())
                return errorResponse(id, kInvalidParams, "tools/call needs params.name");
            const auto name = params["name"].get<std::string>();
            if (!catalog_.hasTool(name)) return errorResponse(id, kInvalidParams, "Unknown tool: " + name);
            const Json args = params.value("arguments", Json::object());
            if (!args.is_object()) return errorResponse(id, kInvalidParams, "tools/call arguments must be an object");

            auto prepared = catalog_.prepare(name, args);
            if (auto* immediate = std::get_if<Json>(&prepared)) return response(id, std::move(*immediate));
            const auto& call = std::get<Invocation>(prepared);
            CommandOutput output;
            try {
                output = executor_(call);
            } catch (const std::exception& e) {
                output = {.exit_code = 1, .out = {}, .err = e.what()};
            }
            return response(id, catalog_.finish(call, output));
        }
        return errorResponse(id, kMethodNotFound, "Method not found: " + method);
    } catch (const std::exception& e) {
        return errorResponse(id, kInternalError, std::string("Internal error: ") + e.what());
    }
}

}
