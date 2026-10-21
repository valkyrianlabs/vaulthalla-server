<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- ws contract: the usage book (`core/usage/src/contract/ws`) declares every registered ws command (202, was 76).
  `UsageContract.EveryRegisteredWsCommandHasABookEntry` and `test_ws_contract.py` fail on a command without one.
- web: client timeouts come only from the contract; WebSocketCommandMap payload types follow the server (no `null`
  payloads, no members the handlers never read).
- ws contract version 2: `models[]` and `models_hash` (163 named model shapes, `core/usage/src/contract/models`),
  field `one_of` / `values` / `element` / `partial`, command `response_model`; `meta.contract.get` answers
  `models_hash`. `ContractModels.*` checks every model against its serializer with seeded instances;
  `UsageContract.UnionsObjectsAndArraysAreSpelledOut` keeps unions and objects typed (free-form JSON is an explicit
  allowlist).
- Handler JSON builders the contract tests need are public and database-free (S3 gateway, vault details and removal
  plan, share entries and links, email history, vault stats); their output is unchanged.
- ws contract: commands list `refusal_kinds` and `confirmations` (`{code, accept_field, description}`, 19 codes);
  `refusal_codes` stays their union. Generated TS exports `WS_CONTRACT_CONFIRMATIONS`.
- ws: fs, share, pricing, email, settings, S3 gateway, vault/API key, permission and dashboard-preference refusals
  carry `data.code` (untyped refusals: 61 commands, now 2); messages unchanged. Share Manager, TargetResolver and
  PrincipalResolver throw ops refusal types; HTTP share lanes are unaffected.
- ws: unroutable frames are answered `parse_error` with `error` (and `message`, kept for old clients) and the
  frame's requestId; router faults answer `<command>.response` with status ERROR instead of `UNKNOWN` /
  `Unknown.response`; a non-string requestId no longer breaks an answer; a missing `payload` reads as `{}`.
- ws contract: `envelope` documents the request, answer and error frames.

