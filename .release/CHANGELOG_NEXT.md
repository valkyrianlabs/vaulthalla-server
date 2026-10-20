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
