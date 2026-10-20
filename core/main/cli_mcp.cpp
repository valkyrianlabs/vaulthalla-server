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

#include <cstdio>
#include <exception>
#include <optional>
#include <iostream>
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

    const mcp::Catalog catalog;
    mcp::Server server(catalog, [](const mcp::Invocation& call) {
        const auto reply = runCaptured(call.argv, call.line);
        return mcp::CommandOutput{.exit_code = reply.exit_code, .out = reply.out, .err = reply.err};
    }, VH_VERSION);

    std::string line;
    while (std::getline(std::cin, line)) {
        if (blank(line)) continue;
        const auto message = nlohmann::json::parse(line, nullptr, /*allow_exceptions=*/false);
        std::optional<nlohmann::json> answer;
        try {
            answer = message.is_discarded() ? std::optional(mcp::Server::parseError()) : server.handle(message);
        } catch (const std::exception& e) {
            fmt::print(stderr, "vh mcp: {}\n", e.what());
            answer = nlohmann::json{{"jsonrpc", "2.0"}, {"id", nullptr},
                                    {"error", {{"code", -32603}, {"message", "Internal error"}}}};
        }
        if (!answer) continue;
        // Command output is arbitrary bytes; invalid UTF-8 is replaced rather than failing the response.
        const auto text = answer->dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        if (std::fwrite(text.data(), 1, text.size(), stdout) != text.size() || std::fputc('\n', stdout) == EOF ||
            std::fflush(stdout) != 0)
            return 0;  // the agent went away
    }
    return 0;
}

}
