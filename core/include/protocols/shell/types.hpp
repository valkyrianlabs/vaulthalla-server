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

// A refusal for want of a confirmation a person must give (the terminal prompt, or the flag that gives it): the
// ops::NeedsConfirmation code when there is one, and the flags that would confirm it ("--yes", "--accept-key-loss").
// Sent as the result frame's optional `confirmation` member, so a client such as `vh mcp` needn't parse the text.
struct ConfirmationNeeded {
    std::string code{};
    std::vector<std::string> flags{};
};

struct CommandResult {
    int exit_code = 0;                 // 0 = success
    std::string stdout_text{};         // CLI stdout
    std::string stderr_text{};         // CLI stderr
    std::optional<ConfirmationNeeded> confirmation{};  // set by Router::executeLine (noteConfirmationNeeded)
};

// Called where a command refuses because nobody confirmed (no terminal, no flag), right before it returns or throws
// that refusal. Router::executeLine attaches it to the failed result; one per running command (thread-local).
void noteConfirmationNeeded(std::string code, std::vector<std::string> flags);
[[nodiscard]] std::optional<ConfirmationNeeded> takeConfirmationNeeded();

// Set on the thread while a command runs for an MCP client: the device listener's /mcp, or a `vh mcp` client that says
// so in its request. Commands that hand out or take in key material refuse under it (D4), so a gap in the MCP layer's
// exclusions (mcp::exclusions()) still can't reach them. A local agent that runs `vh` itself is the terminal's user.
class AgentCallScope {
public:
    AgentCallScope();
    ~AgentCallScope();
    AgentCallScope(const AgentCallScope&) = delete;
    AgentCallScope& operator=(const AgentCallScope&) = delete;

    [[nodiscard]] static bool active() noexcept;

private:
    bool previous_;
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
