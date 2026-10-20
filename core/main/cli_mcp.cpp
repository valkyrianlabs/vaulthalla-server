// `vh mcp`: the Model Context Protocol server over stdio (newline-delimited JSON-RPC 2.0). The catalog and the
// JSON-RPC handling are the usage module's (Mcp.hpp), shared with the daemon's remote /mcp; this file is only the
// transport. Each tool call opens its own non-interactive control-socket connection, so the daemon authorizes it by
// peer UID like any `vh` run, and a daemon that is down only fails the calls (initialize and tools/list still work).
// stdout carries protocol messages only; diagnostics go to stderr.

#include "cli_client.hpp"

#include "CommandUsage.hpp"
#include "Mcp.hpp"
#include "UsageManager.hpp"
#include "version.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <string>
#include <vector>

namespace vh::cli {

std::string localHelp(const std::vector<std::string>& path) {
    return protocols::shell::UsageManager{}.renderHelp(path);
}

namespace {

bool wantsHelp(const std::vector<std::string>& argv) {
    for (size_t i = 1; i < argv.size(); ++i)
        if (argv[i] == "--help" || argv[i] == "-h" || argv[i] == "help" || argv[i] == "?") return true;
    return false;
}

bool blank(const std::string& s) {
    return s.find_first_not_of(" \t\r\n") == std::string::npos;
}

// How long one tool call may take before it is abandoned (VAULTHALLA_MCP_TIMEOUT seconds; 0 = no limit).
int callDeadlineSeconds() {
    if (const char* env = std::getenv("VAULTHALLA_MCP_TIMEOUT"); env && *env) {
        char* end = nullptr;
        const long v = std::strtol(env, &end, 10);
        if (end && *end == '\0' && v >= 0 && v <= 86400) return static_cast<int>(v);
    }
    return 600;
}

// Tool calls run on their own threads so ping, cancellation and other requests are answered while one is running.
constexpr std::size_t kMaxCallsInFlight = 8;

thread_local CallControl* tlsCall = nullptr;

class Stdio {
public:
    // One response per line; invalid UTF-8 in command output is replaced rather than failing the response.
    bool write(const nlohmann::json& message) {
        const auto text = message.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        std::scoped_lock lock(mutex_);
        return std::fwrite(text.data(), 1, text.size(), stdout) == text.size() && std::fputc('\n', stdout) != EOF &&
               std::fflush(stdout) == 0;
    }

private:
    std::mutex mutex_;
};

nlohmann::json rpcError(const nlohmann::json& id, const int code, std::string message) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", std::move(message)}}}};
}

}

int runMcp(const std::vector<std::string>& argv) {
    if (wantsHelp(argv)) {
        fmt::print("{}", localHelp({"mcp"}));
        return 0;
    }
    if (argv.size() > 1) {
        fmt::print(stderr, "vh mcp takes no arguments (see 'vh mcp --help')\n");
        return 2;
    }

    const int deadline = callDeadlineSeconds();
    const mcp::Catalog catalog;
    mcp::Server server(catalog, [deadline](const mcp::Invocation& call) {
        const auto reply = runCaptured(call.argv, call.line, tlsCall, deadline);
        mcp::CommandOutput out{.exit_code = reply.exit_code, .out = reply.out, .err = reply.err, .confirmation = {}};
        if (reply.confirmation)
            out.confirmation = mcp::Confirmation{.code = reply.confirmation->code, .flags = reply.confirmation->flags};
        return out;
    }, VH_VERSION);

    Stdio io;
    struct Call {
        std::shared_ptr<CallControl> control;
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::mutex callsMutex;
    std::map<std::string, Call> calls;  // by the request id's JSON text

    const auto reap = [&] {
        std::vector<std::thread> finished;
        {
            std::scoped_lock lock(callsMutex);
            for (auto it = calls.begin(); it != calls.end();)
                if (it->second.done->load()) {
                    finished.push_back(std::move(it->second.thread));
                    it = calls.erase(it);
                } else {
                    ++it;
                }
        }
        for (auto& t : finished) t.join();
    };

    const auto answer = [&](const nlohmann::json& message) -> std::optional<nlohmann::json> {
        try {
            return server.handle(message);
        } catch (const std::exception& e) {
            fmt::print(stderr, "vh mcp: {}\n", e.what());
            return rpcError(message.is_object() ? message.value("id", nlohmann::json()) : nlohmann::json(), -32603,
                            "Internal error");
        }
    };

    std::string line;
    bool ok = true;
    while (ok && std::getline(std::cin, line)) {
        reap();
        if (blank(line)) continue;
        const auto message = nlohmann::json::parse(line, nullptr, /*allow_exceptions=*/false);
        if (message.is_discarded()) {
            ok = io.write(mcp::Server::parseError());
            continue;
        }
        const bool isObject = message.is_object();
        const auto method = isObject && message.contains("method") && message["method"].is_string()
                                ? message["method"].get<std::string>() : std::string{};

        if (method == "notifications/cancelled") {
            const auto params = message.value("params", nlohmann::json::object());
            if (params.is_object() && params.contains("requestId")) {
                std::scoped_lock lock(callsMutex);
                if (const auto it = calls.find(params["requestId"].dump()); it != calls.end())
                    it->second.control->cancel();
            }
            continue;
        }

        if (method == "tools/call" && message.contains("id")) {
            const auto key = message["id"].dump();
            std::scoped_lock lock(callsMutex);
            if (calls.contains(key)) {
                ok = io.write(rpcError(message["id"], -32600, "Invalid Request: that id is already in flight"));
                continue;
            }
            if (calls.size() >= kMaxCallsInFlight) {
                ok = io.write(rpcError(message["id"], -32000, "Too many tool calls in flight; retry when one finishes"));
                continue;
            }
            auto control = std::make_shared<CallControl>();
            auto done = std::make_shared<std::atomic<bool>>(false);
            std::thread worker([&, message, control, done] {
                tlsCall = control.get();
                const auto response = answer(message);
                bool wasCancelled = false;
                {
                    std::scoped_lock l(control->mutex);
                    wasCancelled = control->cancelled;
                }
                // A cancelled request gets no response (MCP cancellation).
                if (response && !wasCancelled) (void)io.write(*response);
                done->store(true);
            });
            calls.emplace(key, Call{.control = std::move(control), .thread = std::move(worker), .done = std::move(done)});
            continue;
        }

        if (const auto response = answer(message)) ok = io.write(*response);
    }

    // The agent closed stdin (or stdout): nobody is left to answer, so stop what is still running.
    {
        std::scoped_lock lock(callsMutex);
        for (auto& [key, call] : calls) call.control->cancel();
    }
    std::vector<std::thread> rest;
    {
        std::scoped_lock lock(callsMutex);
        for (auto& [key, call] : calls) rest.push_back(std::move(call.thread));
        calls.clear();
    }
    for (auto& t : rest) t.join();
    return 0;
}

}
