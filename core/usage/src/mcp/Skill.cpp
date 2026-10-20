// The Vaulthalla agent skill that `vh skill install` writes. The text below is hand-written and ships inside the vh
// binary (nothing extra is packaged); references/commands.md is generated next to it from the usage book
// (Catalog::commandReference). Locations: Claude Code https://code.claude.com/docs/en/skills (~/.claude/skills,
// .claude/skills); Codex https://learn.chatgpt.com/docs/build-skills (~/.agents/skills, .agents/skills) and
// https://learn.chatgpt.com/docs/extend/mcp (codex mcp add, [mcp_servers.<name>] in config.toml).

#include "Mcp.hpp"

namespace vh::mcp::skill {

std::string skillMarkdown() {
    return R"md(---
name: vaulthalla
description: Operate a Vaulthalla server (self-hosted encrypted cloud with vaults, users, groups, roles, S3/R2 sync, an S3 gateway and file recovery) through the vaulthalla MCP tools. Use when the user asks to inspect or change anything in Vaulthalla, or mentions vh, vaults or their Vaulthalla server.
---

# Vaulthalla

Vaulthalla is a self-hosted cloud: encrypted vaults on local disk or S3/R2, users, groups and roles (RBAC), sync,
an S3-compatible gateway and file recovery. The `vaulthalla` MCP server (`vh mcp`) runs every tool as an ordinary
`vh` command under the human's own Vaulthalla account, so their permissions decide what works. A permission
refusal is final: report it, don't look for a way around it.

## Tools

- `vh_help {path}`: the command reference. Use it before any command you have not run before; never guess
  options.
- Typed tools (`users_create`, `vaults_delete`, `recovery_list`, ...): use one whenever it fits.
- `vh_read {command}`: any read-only command (`vault list`, `user info alice`, `status`).
- `vh_run {command}`: any other command available to agents. Output is JSON when the command supports it.

## Rules

1. **Read before you write.** Look at the current state first (`vh_read`, a read-only typed tool), then change
   only what the human asked for.
2. **Confirmations belong to the human.** A result with `needs_confirmation` means nothing happened. Show its
   message to the human and ask. Set `confirm` only after they explicitly approve that exact action in this
   conversation. Never set it pre-emptively, never carry an approval over to a different action, and never put
   `--yes`, `--accept-*` or `--confirm-token` in a command.
3. **Destructive tools need a stated reason.** Before anything that deletes, revokes, purges, rotates keys,
   restores over files or unprotects a bucket, tell the human the exact target and why. Prefer the reversible
   option: a deleted vault stays restorable (`vault restore`) until its retention window ends.
4. **Keys and secrets are never handled by agents.** Vault key export, secret export, `secrets update`, `setup`,
   `teardown` and file transfer (`fs get`, `fs put`) are not available. When a key backup is needed, ask the human
   to run `vh vault keys export <vault>` in their own terminal and keep the output safe. Never ask them to paste
   key material, passwords or secrets into the conversation.
5. **Report what changed.** After writing, list each command you ran, its target and its result, and verify with a
   read.
6. **Errors.** Exit 69 or 75: the Vaulthalla daemon is not running or not responding; tell the human. Exit 77:
   their account may not use the vh control socket (`vaulthalla` group).

## Reference

- [references/commands.md](references/commands.md): every command available to agents, with its effect (read,
  write, destructive), its confirmations and its typed tool.
)md";
}

std::optional<Agent> parseAgent(const std::string_view s) {
    if (s == "claude" || s == "claude-code") return Agent::Claude;
    if (s == "codex") return Agent::Codex;
    return std::nullopt;
}

std::optional<Scope> parseScope(const std::string_view s) {
    if (s == "user") return Scope::User;
    if (s == "project") return Scope::Project;
    return std::nullopt;
}

std::string_view agentName(const Agent a) { return a == Agent::Claude ? "Claude Code" : "Codex"; }

std::string skillDir(const Agent agent, const Scope scope, const std::string& home, const std::string& projectDir) {
    const std::string base = scope == Scope::User ? home : projectDir;
    const std::string dir = agent == Agent::Claude ? "/.claude/skills/" : "/.agents/skills/";
    return base + dir + std::string(kName);
}

std::vector<std::string> registerCommand(const Agent agent, const Scope scope, const std::string& vhCommand) {
    if (agent == Agent::Claude)
        return {"claude", "mcp", "add", "--scope", scope == Scope::User ? "user" : "project", std::string(kName), "--",
                vhCommand, "mcp"};
    // `codex mcp add` writes ~/.codex/config.toml only; a project's .codex/config.toml gets the stanza instead.
    if (scope == Scope::Project) return {};
    return {"codex", "mcp", "add", std::string(kName), "--", vhCommand, "mcp"};
}

std::string codexTomlStanza(const std::string& vhCommand) {
    return "[mcp_servers." + std::string(kName) + "]\ncommand = \"" + vhCommand + "\"\nargs = [\"mcp\"]\n";
}

}
