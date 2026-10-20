<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
## CLI
- Add `vh mcp`: an MCP server (JSON-RPC 2.0 over stdio, protocol 2025-11-25, also 2025-06-18 and 2025-03-26).
  - Tools: `vh_help` (usage book), `vh_read` (read-only commands), `vh_run` (any agent-available command) and one
    typed tool per catalogued operation with a CLI binding, annotated readOnly/destructive from the command's effect.
  - Each tool call is a non-interactive control-socket request authorized by peer UID like any `vh` run; `--json`
    is added where supported; confirmation flags are only passed from the agent's explicit `confirm` argument.
  - A command with effect `destructive` is refused before it runs unless `confirm` carries `"destructive": true`,
    independent of the command's own prompt (closes the non-interactive `vault delete` path for agents).
  - A refusal for want of a confirmation becomes a `needs_confirmation` result, from the result frame's new
    `confirmation` member (text matching only for older daemons).
  - Calls run concurrently (ping and cancellation are never queued behind one); `notifications/cancelled` closes
    the call's connection; a call is abandoned after `VAULTHALLA_MCP_TIMEOUT` seconds (default 600).
  - Never exposed: `vault keys export`, `secrets export|update`, `setup …`, `teardown …`, `fs get|put`.
- Add `vh skill install --agent claude|codex [--scope user|project] [--no-register] [--force]`: writes the
  `vaulthalla` skill (`SKILL.md`, `references/commands.md`) to `~/.claude/skills` / `~/.agents/skills` (or the
  project's `.claude/skills` / `.agents/skills`) and registers `vh mcp` via `claude mcp add` / `codex mcp add`;
  idempotent, replaces a changed skill only with `--force`, needs no daemon.
- The control socket's `result` frame gains an optional `confirmation` member (`code`, `flag`, `flags`) when a
  command refused because nobody confirmed it; the CLI ignores it.
- Every CLI leaf declares its effect (`read`, `write`, `destructive`), exported as `effect` by `vh_usage --json`.
