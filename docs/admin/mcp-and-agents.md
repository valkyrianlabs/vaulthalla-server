---
title: AI Agents And MCP
navTitle: AI Agents (MCP)
description: Let Claude Code, Codex or another MCP client operate Vaulthalla through vh mcp, with your permissions, confirmations kept for you, and keys out of reach.
order: 40
status: published
tags:
  - admin
  - cli
  - mcp
  - agents
---

# AI Agents And MCP

`vh mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server built into the `vh` CLI. An AI agent
such as Claude Code or Codex starts it and can then list, inspect and change Vaulthalla the way you would with `vh`,
inside the limits below. `vh skill install` sets an agent up in one step.

:::toc[On this page]{depth="3" theme="compact"}
:::

## What an agent can and can't do

- **It acts as you.** Every tool call is an ordinary, non-interactive `vh` command over the local control socket, so
  the daemon maps it to your Vaulthalla account exactly as it maps your own `vh` commands. Your roles and permissions
  decide what works. An agent can't do anything your `vh` can't.
- **Destructive commands always need your OK.** Anything marked destructive (deleting a vault or a user, rotating
  keys, revoking a credential, restoring over files) is refused by the MCP server itself until the agent passes
  `confirm: {"destructive": true}`, even where the command wouldn't ask at a terminal. The agent is told to show you
  what will be affected and to pass it only after you approve.
- **It asks before confirmations.** Commands that would ask you to confirm in a terminal (deleting a user or a vault,
  accepting an encryption waiver, restoring over files, a bucket cleanup) refuse the first time. The agent gets the
  refusal's message and is told to show it to you; it can only go ahead by passing a `confirm` value, and its skill
  tells it to do so only after you explicitly approve that action. The server never passes `--yes`, `--accept-*` or
  `--confirm-token` on its own, and it rejects them inside a command.
- **Keys and secrets stay with you.** These commands are never available to agents: `vh vault keys export`,
  `vh secrets export`, `vh secrets update`, every `vh setup` and `vh teardown` command (including
  `vh setup set-super-admin-password`), and `vh fs get` / `vh fs put`. Neither are pairing decisions
  (`vh device pair`, `approve`, `deny`) or `vh device remote enable|disable`. To back up a vault key, run
  `vh vault keys export <vault>` yourself in a terminal.

:::callout[Your account, your blast radius]{variant="warning"}
An agent with your account can still make every change your account can: delete vaults, revoke credentials, change
roles. Use an account whose roles match what you want the agent to do, and read what it proposes before approving
a confirmation.
:::

## Set up an agent

Install the skill and register the server with the agent's own CLI:

:::tabs{default="claude"}

:::tab[Claude Code]{value="claude"}
```bash
vh skill install --agent claude
```

Writes `~/.claude/skills/vaulthalla/` and runs `claude mcp add --scope user vaulthalla -- vh mcp`.
:::

:::tab[Codex]{value="codex"}
```bash
vh skill install --agent codex
```

Writes `~/.agents/skills/vaulthalla/` and runs `codex mcp add vaulthalla -- vh mcp`.
:::

:::

Options:

| Option | Effect |
| --- | --- |
| `--scope project` | Install into the current directory instead: `.claude/skills/vaulthalla` (Claude Code registers the server in the project's `.mcp.json`) or `.agents/skills/vaulthalla` (Codex: add the printed stanza to `.codex/config.toml`). |
| `--no-register` | Only write the skill files. |
| `--force` | Replace a skill that differs from this version's; for Codex without its CLI (or for a project), also write the `[mcp_servers.vaulthalla]` stanza into `config.toml`. |

The command needs no running daemon. When the agent's CLI isn't installed it prints the exact registration command
instead. Running it again is safe: an identical skill is left alone, and a skill you edited is only replaced with
`--force`. After upgrading Vaulthalla, run it again with `--force` to refresh the command reference.

To register the server by hand with any MCP client, run `vh mcp` as a stdio server:

```bash
claude mcp add --scope user vaulthalla -- vh mcp
codex mcp add vaulthalla -- vh mcp
```

The user who runs the agent needs the same access as for `vh`: membership in the `vaulthalla` group and a mapped
Vaulthalla account (see [Users, Groups And Roles](/admin/users-groups-roles)).

## Tools

| Tool | What it does |
| --- | --- |
| `vh_help` | Browses the command reference: descriptions, arguments, options, examples, the command's effect and its confirmations. |
| `vh_read` | Runs any read-only command (`vault list`, `user info alice`, `status`). |
| `vh_run` | Runs any other command available to agents. |
| Typed tools | One per catalogued operation, with typed arguments: `users_create`, `users_delete`, `groups_add_user`, `roles_vault_assign`, `vaults_create`, `vaults_delete`, `recovery_list`, `recovery_restore`, and more. |

Each command is marked **read** (changes nothing), **write** (changes something that can be changed back) or
**destructive** (deletes, revokes, rotates keys, or can't be undone). The tools carry the matching MCP hints, so a
client can run read-only tools without asking and ask you before destructive ones. Output is JSON where the command
supports `--json`.

The skill (`SKILL.md`) tells the agent to read before it writes, to prefer typed tools, never to set `confirm`
without your explicit approval, to state the reason before a destructive action, never to handle keys or secrets,
and to report what it changed. `references/commands.md` next to it lists every command available to agents.

A tool call that gets no result within 10 minutes is abandoned (set `VAULTHALLA_MCP_TIMEOUT` in the server's
environment to change it, in seconds; `0` turns the limit off), and an agent can cancel a call it no longer needs.
The daemon may still finish a command whose call was abandoned, so check the state before retrying. Calls run side
by side, so one slow command doesn't hold up the others.

## Remote MCP for a paired Mac

A Mac paired with the node (see [Paired Devices](/admin/devices)) reaches the same MCP server remotely, at `/mcp` on
the device listener (port `36972`), for clients that connect with the device's key over mutual TLS. It is the same catalog: the same tools, the same commands out of reach, the same `confirm` rules, acting as
the account the Mac is paired with. Each call is abandoned after 10 minutes; the node may still finish it.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Tools fail with exit 69 or 75 | The daemon isn't running or isn't responding. The server itself still starts; check the service. |
| A tool fails with exit 124 | The command gave no result before the deadline (`VAULTHALLA_MCP_TIMEOUT`). |
| Tools fail with exit 77 | The agent's user isn't in the `vaulthalla` group, or its login session predates joining it. |
| "user not found: no Vaulthalla user is mapped to Linux UID …" | Map the account first (`vh setup assign-admin` for the first operator, or `--linux-uid` on `vh user update`). |
| `vh skill install` says the skill already exists | You or an older version changed it. Re-run with `--force` to replace it. |
| A command is "not available to agents" | It is on the exclusion list above. Run it yourself in a terminal. |
