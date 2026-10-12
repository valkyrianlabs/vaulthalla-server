#pragma once

#include "protocols/shell/SocketIO.hpp"
#include "identities/Fwd.hpp"
#include "protocols/shell/Fwd.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <sstream>

namespace vh::protocols::shell {

struct FlagKV {
    std::string key;
    std::optional<std::string> value;

    [[nodiscard]] std::string toString() const {
        if (value) return key + "=" + *value;
        return key;
    }
};

// The connection a `vh fs get|put` moves bytes over (protocols/shell/Transfer.hpp), present only when the client
// asked for a transfer in its request. Handlers that don't transfer ignore it.
struct TransferPeer {
    int fd = -1;
    std::optional<uint64_t> putSize;  // put: the byte count the client declared
};

struct CommandCall {
    std::string name;
    std::vector<FlagKV> options;
    std::vector<std::string> positionals, original_positionals;
    bool rewrote = false;
    std::shared_ptr<identities::User> user;
    SocketIO* io = nullptr; // if set, command was run interactively
    std::optional<TransferPeer> transfer;

    // owns any strings you create at runtime (JSON, rewrites, etc.)
    std::vector<std::string> arena;

    [[nodiscard]] inline std::vector<std::string> constructFullArgs() const {
        if (name == "vh" && original_positionals.empty()) return {};
        std::vector<std::string> args;
        args.reserve(1 + original_positionals.size());
        args.push_back(name);
        for (const auto& pos : original_positionals) args.push_back(pos);
        return args;
    }

    [[nodiscard]] std::string toString() const {
        std::ostringstream oss;
        oss << "CommandCall:\n";
        const std::string in(2, ' ');
        oss << in << "Name: " << name << "\n";
        oss << in << "Options:\n";
        for (const auto& option : options) oss << std::string(4, ' ') << "  " << option.toString() << "\n";
        oss << in << "Positionals:\n";
        for (const auto& pos : positionals) oss << std::string(4, ' ') << "  " << pos << std::endl;
        oss << in << "Original Positionals:\n";
        for (const auto& pos : original_positionals) oss << std::string(4, ' ') << "  " << pos << std::endl;
        return oss.str();
    }
};

struct CommandResult {
    int exit_code = 0;                 // 0 = success
    std::string stdout_text;           // CLI stdout
    std::string stderr_text;           // CLI stderr
};

using CommandHandler = std::function<CommandResult(const CommandCall&)>;

struct CommandInfo {
    std::string description;                 // own
    CommandHandler handler;
    std::shared_ptr<CommandUsage> usage;     // definition the options are validated against
    std::unordered_set<std::string> aliases; // own normalized aliases (no dashes)
    void print(std::string canonical) const;
};

}
