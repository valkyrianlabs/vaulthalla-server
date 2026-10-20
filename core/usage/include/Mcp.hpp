#pragma once

#include "types.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

// The MCP (Model Context Protocol) catalog and JSON-RPC server, shared by both transports: `vh mcp` (stdio, in the vh
// client, which runs each tool call as an ordinary non-interactive CLI request over the control socket) and the
// daemon's remote `/mcp` (which runs it through shell::Router::executeLine for the device's user). It lives in the
// usage module because everything it needs is here: the CLI usage book (commands, options, effects, examples) and the
// operation catalog (typed tools). It has no daemon types, so the client links it without the daemon.
namespace vh::mcp {

using Json = nlohmann::json;

// Newest first; initialize answers the client's version when it is one of these, else the newest.
inline constexpr std::array<std::string_view, 3> kProtocolVersions{"2025-11-25", "2025-06-18", "2025-03-26"};
inline constexpr std::string_view kServerName = "vaulthalla";

// Commands agents can never reach (not listed by any tool, refused before anything runs), by canonical usage path
// prefix. D4: key and secret export only through the local CLI or a paired device, never MCP.
struct Exclusion {
    std::vector<std::string> path{};  // primary aliases: {"vault", "key", "export"}
    std::string_view reason{};
};
const std::vector<Exclusion>& exclusions();

// One command line the transport runs for the agent: never interactive, never with a confirmation flag the agent did
// not pass in `confirm`.
struct Invocation {
    std::string tool{};
    std::vector<std::string> argv{};  // tokens as the daemon's parser will see them (argv[0] is the command)
    std::string line{};               // argv rendered for the shell tokenizer (no leading "vh")
    std::string command{};            // canonical path, "vault delete"
    protocols::shell::CommandEffect effect = protocols::shell::CommandEffect::Unset;
    std::vector<std::string> gates{};      // the leaf's confirmation flags (primary spellings)
    std::vector<std::string> confirmed{};  // the ones this call passes
};

// The result frame's `confirmation` member: the refusal was for want of a confirmation (ops::NeedsConfirmation code
// when there is one, and the flags that give it).
struct Confirmation {
    std::string code{};
    std::vector<std::string> flags{};
};

struct CommandOutput {
    int exit_code = 0;
    std::string out{}, err{};
    std::optional<Confirmation> confirmation{};
};

class Catalog {
public:
    Catalog();
    ~Catalog();
    Catalog(const Catalog&) = delete;
    Catalog& operator=(const Catalog&) = delete;

    // The tools/list `tools` array.
    [[nodiscard]] const Json& tools() const;
    [[nodiscard]] bool hasTool(const std::string& name) const;

    // A tools/call: either the command to run, or the finished CallToolResult (vh_help, bad arguments, an unknown or
    // excluded command).
    [[nodiscard]] std::variant<Invocation, Json> prepare(const std::string& tool, const Json& arguments) const;

    // The CallToolResult for a command that ran: stdout as text, isError with stderr on a non-zero exit, and a
    // structured needs_confirmation result when the refusal names one of the command's confirmation flags.
    [[nodiscard]] Json finish(const Invocation& call, const CommandOutput& output) const;

    // Markdown reference of every command agents can run (the skill's references/commands.md).
    [[nodiscard]] std::string commandReference(std::string_view version) const;

    // Every CLI leaf with its canonical path, for tests and the reference.
    struct LeafInfo {
        std::string command{};  // "vault delete"
        protocols::shell::CommandEffect effect = protocols::shell::CommandEffect::Unset;
        bool excluded = false;
        std::vector<std::string> gates{};
        bool json = false;
    };
    [[nodiscard]] std::vector<LeafInfo> leaves() const;

    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

// Runs one Invocation (the transport's half): the stdio server sends it over the control socket, the daemon through
// its Router.
using Executor = std::function<CommandOutput(const Invocation&)>;

// The JSON-RPC 2.0 side: initialize, notifications/initialized, ping, tools/list, tools/call. One message in, at most
// one response out (none for notifications and for responses the client sends).
class Server {
public:
    Server(const Catalog& catalog, Executor executor, std::string version);

    [[nodiscard]] std::optional<Json> handle(const Json& message);
    // A line that did not parse as JSON: the JSON-RPC parse error to answer with.
    [[nodiscard]] static Json parseError();

    [[nodiscard]] const std::string& protocolVersion() const { return protocolVersion_; }

private:
    const Catalog& catalog_;
    Executor executor_;
    std::string version_;
    std::string protocolVersion_{kProtocolVersions.front()};
};

// What initialize tells the agent before it sees any tool.
std::string instructions();

// ---------------------------------------------------------------------------------------------------------------
// Agent skill (vh skill install): the hand-written SKILL.md and where each agent looks for it.
// ---------------------------------------------------------------------------------------------------------------

namespace skill {

inline constexpr std::string_view kName = "vaulthalla";

std::string skillMarkdown();

enum class Agent { Claude, Codex };
enum class Scope { User, Project };

std::optional<Agent> parseAgent(std::string_view s);
std::optional<Scope> parseScope(std::string_view s);
std::string_view agentName(Agent a);

// The skill directory: Claude Code ~/.claude/skills/vaulthalla (project: <dir>/.claude/skills/vaulthalla); Codex
// ~/.agents/skills/vaulthalla (project: <dir>/.agents/skills/vaulthalla).
std::string skillDir(Agent agent, Scope scope, const std::string& home, const std::string& projectDir);

// The agent CLI command that registers `vh mcp` (argv; empty for a Codex project, which `codex mcp add` can't
// target), and the Codex config.toml stanza for when its CLI can't be used.
std::vector<std::string> registerCommand(Agent agent, Scope scope, const std::string& vhCommand);
std::string codexTomlStanza(const std::string& vhCommand);

}

}
