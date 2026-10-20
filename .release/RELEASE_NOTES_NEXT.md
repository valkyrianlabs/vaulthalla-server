# A complete ws contract

## Every ws command is in the published contract

The ws contract the daemon publishes (`vh_usage --json`, identified by `meta.contract.get`) now describes every
command it answers on `/ws`: 202 commands, up from 76. File management, vaults and API keys, roles and permissions,
shares and share sessions, stats and dashboards, sync conflicts, pricing budgets, the S3 gateway, settings and
operator email are covered, each with its payload, response, session requirement, refusals and client timeout.
Native clients can be generated from it, and the web console now takes every command's timeout from the server.
