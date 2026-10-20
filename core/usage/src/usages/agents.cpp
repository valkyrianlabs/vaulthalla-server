// `vh mcp` and `vh skill`: the AI-agent integration. Both run inside the vh client (core/main/cli_mcp.cpp,
// core/main/cli_skill.cpp); the daemon only knows their names so its help and option checks stay complete.

#include "usages.hpp"

namespace vh::protocols::shell::agents {

static std::shared_ptr<CommandUsage> mcpBase(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    cmd->aliases = {"mcp"};
    cmd->effect = CommandEffect::Read;
    cmd->description =
        "Run a Model Context Protocol server on standard input/output for an AI agent (Claude Code, Codex, ...). "
        "Every tool call is an ordinary non-interactive vh command run as you, so your Vaulthalla permissions apply "
        "unchanged. Key and secret export, secrets update, setup, teardown and file transfer are never available "
        "to agents, and commands that need confirmation are only run when the agent passes the human's explicit "
        "approval. Register it once with 'vh skill install'.";
    cmd->examples = {
        {"vh mcp", "Serve MCP on stdin/stdout (started by the agent, not by hand). Register it yourself with "
                   "'claude mcp add --scope user vaulthalla -- vh mcp' or 'codex mcp add vaulthalla -- vh mcp'."},
        {"vh skill install --agent claude", "Install the skill and register 'vh mcp' with Claude Code in one step."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> skillInstall(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    cmd->aliases = {"install"};
    cmd->effect = CommandEffect::Write;
    cmd->description =
        "Write the 'vaulthalla' agent skill (SKILL.md plus a command reference) and register 'vh mcp' with the "
        "agent's CLI when it is installed (otherwise the registration command is printed). Claude Code: "
        "~/.claude/skills/vaulthalla (project: .claude/skills/vaulthalla). Codex: ~/.agents/skills/vaulthalla "
        "(project: .agents/skills/vaulthalla). Needs no daemon. An existing skill is only replaced with --force.";
    cmd->required = {Option::Single("agent", "The agent to install for", "agent", "claude|codex")
                         .withGen("claude|codex", contract::gen::oneOf({"claude", "codex"}))};
    cmd->optional = {Optional::Single("scope", "Install for your user (default) or for the current project directory",
                                      "scope", "user|project", "user")
                         .withGen("user|project", contract::gen::oneOf({"user", "project"}))};
    cmd->optional_flags = {
        Flag::Alias("no_register", "Only write the skill; don't register the MCP server", "no-register"),
        Flag::Alias("force", "Replace an existing skill (and, for Codex without its CLI, write the MCP config)",
                    "force")};
    cmd->examples = {
        {"vh skill install --agent claude", "Install the skill for Claude Code and register 'vh mcp' (user scope)."},
        {"vh skill install --agent codex --scope project", "Install into ./.agents/skills for Codex in this project."},
        {"vh skill install --agent claude --no-register --force", "Refresh the skill files only."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> skillBase(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    cmd->aliases = {"skill", "skills"};
    cmd->description = "Install the Vaulthalla skill for an AI agent (runs in the vh client; no daemon needed).";
    cmd->subcommands = {skillInstall(cmd->weak_from_this())};
    cmd->examples = {{"vh skill install --agent claude", "Install the skill for Claude Code."}};
    return cmd;
}

}

namespace vh::protocols::shell {

std::shared_ptr<CommandBook> mcp_book::get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "MCP Server";
    book->root = agents::mcpBase(parent);
    return book;
}

std::shared_ptr<CommandBook> skill_book::get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Agent Skills";
    book->root = agents::skillBase(parent);
    return book;
}

}
