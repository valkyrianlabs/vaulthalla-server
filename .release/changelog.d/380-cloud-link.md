- Groundwork for Vaulthalla Cloud, which isn't open yet: `vh cloud link|status|unlink` (super admins, CLI only,
  excluded from `vh mcp`) link a server to a vaulthalla.cloud account. Adds migration 134 (`cloud_link`), a sealed
  `cloud_identity` key, VHC1-Ed25519 request signing (`core/{include,src}/cloud/`) and a read-only `cloud.endpoint` in
  config.yaml (default `https://api.vaulthalla.cloud`; https, or http to localhost). Nothing contacts the cloud unless
  asked. Operator docs are held in `design/cloud/server-link.md` until the service opens.
