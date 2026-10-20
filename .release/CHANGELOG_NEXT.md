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
