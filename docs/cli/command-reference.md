---
title: Command Reference
description: Operator-oriented reference for Vaulthalla CLI command families and common examples.
order: 110
status: published
tags:
  - cli
  - reference
---

# Command Reference

This is an operator reference for the command families exposed through `vh`. Use `vh help <namespace>` on the host for the exact help text shipped by the installed version.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Global

| Command | Purpose |
| --- | --- |
| `vh help` | Show root help. |
| `vh help <namespace>` | Show help for a namespace or subcommand. |
| `vh version` | Print the installed CLI version. |
| `vh status` | Print runtime/service status. |

## Setup And Teardown

```bash
vh setup assign-admin
vh setup set-super-admin-password
sudo vh setup db
sudo vh setup remote-db --host <host> --port 5432 --user <user> --database <name> --password-file <path>
sudo vh setup nginx --domain vault.example.com
sudo vh setup nginx --domain vault.example.com --certbot
sudo vh setup nginx --domain vaulthalla.dev --s3-domain s3.vaulthalla.dev --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini
sudo vh teardown nginx
sudo vh teardown db
sudo vh setup caddy --domain <name> [--s3-domain <name>|none] [--internal] [--ca-scope <domain>]
sudo vh setup caddy --domain <name> --email <address> [--acme-staging]
sudo vh setup caddy --domain <name> --dns-cloudflare <credentials>
sudo vh setup caddy --domain <name> --cert <file> --key <file>
sudo vh setup caddy [--listen <address>] [--trust] [--hosts-entry] [--dry-run] [--status]
sudo vh teardown caddy [--purge]
```

`setup db`, `setup remote-db`, `setup nginx` and their teardowns are Linux commands; `setup caddy` and `teardown caddy` (alias `https`) are macOS commands, and each platform says so instead of running the other's. Every `setup caddy` option is described in [Serve Vaulthalla With Caddy](/https/caddy#options).

The `--s3-domain` form needs a Cloudflare API token in a root-only credentials file (`dns_cloudflare_api_token = <token>`). See [S3 Gateway Setup](/s3-gateway/setup#create-the-credentials-file).

`setup assign-admin` and `setup set-super-admin-password` are normal CLI commands. `setup set-super-admin-password` changes the web console password of the built-in `admin` account; only the local user bound as the super admin may run it, without `sudo`, and it removes the generated initial password file. The database, remote database, nginx, Caddy, and teardown commands are privileged lifecycle commands and must be run with `sudo`.

`setup nginx` checks for the generated initial `admin` password first. If it is still in use and its plaintext copy (`/var/lib/vaulthalla/super_admin_initial_password`) still exists, it offers to change the password, delete the file and keep the password, continue, or cancel. Run without a terminal, it warns and continues.

## Users

Aliases include `vh users`, `vh user`, and `vh u`.

```bash
vh user create <username> --role <role-or-id> [--email <email>] [--linux-uid <uid>]
vh user info <username-or-id>
vh user update <username-or-id> --name <new-name> --email <email> --role <role-or-id> --linux-uid <uid>
vh user delete <username-or-id>
```

The built-in `super_admin` role and user are protected from normal create, update, and delete operations.

## Groups

```bash
vh group create <name> [--desc <description>] [--linux-gid <gid>]
vh group info <name-or-id>
vh group update <name-or-id> --name <new-name> --desc <description> --linux-gid <gid>
vh group delete <name-or-id>
vh group user add <group> <user>
vh group user remove <group> <user>
vh group users <group>
```

Use groups when permissions should follow a team rather than an individual user.

## Roles And Permissions

List supported permissions:

```bash
vh permissions
vh permissions --type user
vh permissions --type vault
```

Admin roles:

```bash
vh role admin list
vh role admin info <role>
vh role admin create <name> --manage-users --manage-vaults
vh role admin update <role> --audit-log-access
vh role admin delete <role>
```

Vault roles:

```bash
vh role vault list
vh role vault info <role>
vh role vault create <name> --list --download --sync
vh role vault update <role> --share
vh role vault delete <role>
```

Admin permissions include user, group, role, vault, API key, encryption key, audit, and admin management capabilities. Vault permissions include list, create, download, delete, rename, move, share, sync, version, tag, metadata, file lock, access, and vault management capabilities.

## API Keys

Aliases include `vh api-key`, `vh aku`, and `vh ak`.

```bash
vh api-key list
vh api-key create <name> \
  --access <access-key> \
  --secret <secret-key> \
  --provider <provider> \
  --endpoint <url> \
  [--region <region>]
vh api-key info <name-or-id>
vh api-key delete <name-or-id>
```

Supported provider values include `aws`, `cloudflare-r2`, `wasabi`, `backblaze-b2`, `digitalocean`, `minio`, `ceph`, `storj`, and `other`.

Cloudflare R2 example:

```bash
vh api-key create r2-main \
  --access <access-key> \
  --secret <secret-key> \
  --provider cloudflare-r2 \
  --endpoint https://<account-id>.r2.cloudflarestorage.com
```

The endpoint is required. The default region is `auto`.

## Vaults

```bash
vh vaults
vh vaults --local
vh vaults --s3 --limit 5
vh vaults --json
vh vault info <id-or-name> [--owner <user-or-id>]
vh vault delete <id-or-name> [--owner <user-or-id>] [--now] [--delete-upstream | --keep-upstream] [--accept-key-loss] [--yes]
vh vault deleted [--json]
vh vault restore <id-or-name> [--owner <user-or-id>]
```

`vault delete` schedules the deletion: the vault disappears at once and `vault restore` brings it back until `vaults.retention_window` ends (default `5m`); then its data is purged. `--now` purges right away and needs `--yes` (or a typed confirmation in a terminal). For S3 vaults, `--delete-upstream` also deletes the bucket's objects at purge time; the default keeps them, and keeping encrypted objects whose key was never exported needs `--accept-key-loss`. In a terminal, without `--yes`, the command asks instead. `vault deleted` lists pending, purging and purged vaults whose key is still kept. See [Deleting And Restoring Vaults](/vaults/deleting-vaults).

Create a local vault:

```bash
vh vault create docs --local --desc "Team documents" --quota 50G --on-sync-conflict keep_both
```

Create an S3/R2 vault:

```bash
vh vault create archive \
  --s3 \
  --api-key r2-main \
  --bucket vaulthalla-archive \
  --sync-strategy cache \
  --on-sync-conflict keep_local \
  --encrypt
```

Update a vault:

```bash
vh vault update archive --sync-strategy sync --interval 15m
```

## Vault Access

Assign a vault role to a user or group:

```bash
vh vault role assign <vault> <role-id> --user alice
vh vault role assign <vault> <role-id> --group operators
```

Remove a vault role:

```bash
vh vault role unassign <vault> <role-id> --user alice
vh vault role list <vault>
```

Add permission overrides for a path pattern:

```bash
vh vault role override add <vault> --user alice --pattern "/finance/*" --download --disable
vh vault role override list <vault>
vh vault role override remove <vault> <override-id>
```

## Sync

```bash
vh vault sync <vault>
vh vault sync info <vault>
vh vault sync set <vault> --interval 15m
vh vault sync dry-run <vault>
vh vault sync inventory <vault> --file inventory.csv
vh vault sync events <vault> --file s3-events.json
vh vault sync reconcile <vault> --allow-list-scan
```

S3/R2 sync policy fields include strategy, conflict policy, interval, request budgets, and maximum remote-index age. See [Sync](/vaults/sync) and [Request Budgets](/cost-control/request-budgets).

### Sync Conflicts

Conflicts recorded under the `ask` policy (S3/R2 vaults) wait for a decision:

```bash
vh sync resolve                                         # interactive session (needs a terminal)
vh sync resolve --list [--vault <vault>] [--json]
vh sync resolve <id>... --keep-local | --keep-remote [--json]
vh sync resolve --vault <vault> --all --keep-local | --keep-remote [--yes]
```

`vh resolve` takes the same arguments. Keep local uploads the local copy over the remote object; keep remote downloads the remote object over the local copy. A decision needs `vault.sync.action.resolve_conflicts` and Overwrite on the file, and is refused when either side changed since the conflict was recorded. Exit status is 2 when any conflict was not resolved; each one is reported with its reason. Without a terminal, `--all` needs `--yes`. See [Resolving Conflicts](/vaults/sync#resolving-conflicts).

## Vault Files

```bash
vh fs ls <vault> <path> [--owner <user>]
vh fs get <vault> <path> [-o <file>|-] [--owner <user>]
vh fs put <vault> <local-file|-> <path> [--overwrite] [--owner <user>]
```

:::callout{theme="warning" title="Interim"}
`vh fs` is a stopgap for hosts without a usable mount (macOS today). It will be retired once the macOS FUSE identity
adapter maps each local user to their own Vaulthalla identity on the mount; scripts should not treat it as permanent.
:::

Reads and writes vault files without a mount, through the control socket. `vh` itself reads the local file (or standard input) for `put` and writes the local file for `get`; the daemon only ever sees the vault path. Permissions are the web console's: `ls` needs List, `get` needs Read, `put` needs Write on the new path (missing folders are created) and `--overwrite` needs Overwrite on the existing file. A path you can't read reports "permission denied" whether or not it exists.

`get -o <file>` writes to a temporary file next to `<file>` and replaces `<file>` only when every byte arrived and the stored file passed its integrity check; anything else leaves `<file>` as it was. Without `-o`, the bytes go to standard output, and `vh` refuses to write them to a terminal unless you pass `-o -`. A `put` stores nothing unless the whole file arrives, and a replacement fails if the file changed while uploading. Removing someone's access stops their running transfer.

Exit status: `0` done; `64` invalid arguments; `65` a damaged or incomplete transfer; `66` no such file (local or, where you can read, in the vault); `73` the vault path exists (no `--overwrite`) or the local output can't be written; `74` reading or writing a local file failed; `75` too many transfers in progress; `77` permission denied.

## Vault Keys

```bash
vh vault keys export <vault-or-all> --recipient <gpg-fingerprint> --output vaulthalla-vault-keys.json.gpg
vh vault keys export <vault-or-all> --output vaulthalla-vault-keys.json
vh vault keys rotate <vault-or-all> [--sync-now]
```

Unencrypted key exports are dangerous. Prefer `--recipient` and `--output`.

## File Recovery

Earlier versions of files come from three places: local snapshots you take, local versions kept automatically when
local versioning is on, and the provider's own object versions when an AWS S3 bucket has versioning enabled. Their
ids are `snap-<id>`, `lv-<id>` and `pv-<id>`. Undeleting a whole vault is `vh vault restore`, not this.

Vault settings:

```bash
vh vault recovery status <vault> [--refresh] [--json]
vh vault recovery set <vault> [--mode off|local-snapshots|provider-versioning] [--retention 30d|90d|365d|indefinite]
                              [--snapshot-quota <size>] [--cost-alert <amount>|none]
                              [--local-versioning on|off] [--keep-last <n>] [--max-age-days <n>] [--version-quota <size>]
                              [--accept-unpriced] [--accept-retention-shortening] [--adopt-bucket] [--yes]
vh vault recovery disclosure <vault> [--retention <r>] [--json]
vh vault recovery suspend <vault> [--yes]
```

`--mode provider-versioning` always fetches and prints the cost disclosure first (provider, bucket, region, storage
class, current data, observed or illustrative write traffic, the estimated monthly additional storage, growth over
12 months, retention, confidence and catalog freshness, what is not included, and the consequences, including that
AWS can't return a bucket to unversioned, only suspend it). In a terminal you then type `ENABLE VERSIONING`, and when
the cost can't be estimated you accept that separately (`ACCEPT UNPRICED`). Without a terminal it needs `--yes`, plus
`--accept-unpriced` when unpriced. A shorter retention deletes history sooner and is asked separately (`SHORTEN`, or
`--accept-retention-shortening`), and so is adopting the vault's unmanaged bucket (`ADOPT`, or `--adopt-bucket`).
`--retention` takes `30d`, `90d`, `365d`, `indefinite` or any number of days from 1 to 36500; there is no default.
Changing the mode never suspends a versioned bucket; `suspend` does (type `SUSPEND`, or `--yes`), and it deletes
nothing. Local versioning flags you leave out keep their stored values; `--keep-last 0`, `--max-age-days 0` and
`--version-quota 0` remove the limit, and `--cost-alert none` clears the alert.

Snapshots and recovery points:

```bash
vh snapshot create <vault> <path> [--name <name>] [--json]
vh snapshot list <vault> [path] [--json]
vh snapshot delete <snap-id> [--yes]
vh recovery list <vault> [path] [--refresh] [--snapshots-only|--versions-only|--provider-only] [--limit <n>] [--json]
vh recovery inspect <recovery-id> [--json]
vh recovery delete <recovery-id> [--yes]
```

Snapshots need the mode `local-snapshots`. `recovery list` with a file path shows that file's history; `--refresh`
lists the provider's versions of the path first (metadata only). You only see points you can read. `recovery delete`
removes snapshots and local versions (type `DELETE`, or `--yes`); provider versions are removed by the bucket's
retention, and a local version still waiting to be uploaded can't be deleted.

Restoring:

```bash
vh recovery plan <recovery-id> [--to <path>] [--json]
vh recovery plan <vault> <path> --at <ISO-8601 time> [--prune] [--to <path>] [--json]
vh recovery restore <recovery-id> [--to <path>] [--yes] [--accept-unverified] [--json]
vh recovery restore <plan-id> --token <token> [--accept-unverified] [--json]
```

`plan` changes nothing: it shows what each item would do (create, overwrite, skip, conflict, remove, unavailable),
the size and method, a provider request and cost estimate, warnings and blockers, and the plan id and token (valid 30
minutes). A plan with `--at` is a timestamp-based reconstruction from each file's version history, not an atomic
snapshot; only a local snapshot is taken in one pass. It needs an S3 vault with provider versions. `--prune` also
removes files that did not exist at that time.

`restore <recovery-id>` plans, shows the plan and asks before it runs; type `RESTORE` when anything is overwritten or
removed (a plain yes/no otherwise). `--yes` skips the question for scripts. A plan made with `vh recovery plan` runs
with its id and the `--token` it printed, which is the confirmation. Every item is authorized again, and a destination
that changed after the plan was made is reported as a conflict and left alone. Provider versions Vaulthalla did not
write need `--accept-unverified` (or type `UNVERIFIED`). The exit status is `1` when anything was not restored and `2`
when the restore was refused; run the plan again (`<plan-id> --token`) to resume an interrupted or partial restore.
See [File Recovery](/vaults/recovery) for how each kind of history works and what it costs.

Costs:

```bash
vh recovery costs <vault> [--json]
```

Shows the versioning surcharge separately from the current object storage, the cost of recovery operations and what
is not modelled, with ranges, the basis of each figure (observed, scenario or illustrative) and the price catalog's
freshness. A figure that can't be estimated says so and why; it is never shown as zero. The figures are computed on
the host and are estimates, not provider invoices.

## Devices

```bash
vh device pair                                   # open a 10-minute pairing window and approve by number matching
vh device pending
vh device approve 7f3a9c1d2e4b6a80 --code 482913
vh device deny 7f3a9c1d2e4b6a80
vh device list [--all] [--json]
vh device rename 3 "Studio Mac"
vh device revoke 3
vh device remote status
vh device remote enable
vh device remote disable
```

A paired device acts as your account. `--all` and `remote` are for super admins. See [Paired Devices](/admin/devices).

## Internal Secrets

```bash
vh secret set db-password /root/db-password
vh secret set jwt-secret /root/jwt-secret
vh secret export db-password --recipient <gpg-fingerprint> --output db-password.json.gpg
vh secret export jwt-secret --recipient <gpg-fingerprint> --output jwt-secret.json.gpg
vh secret export all --recipient <gpg-fingerprint> --output vaulthalla-secrets.json.gpg
```

`secret set` reads the secret value from the file path you pass.

## S3 Gateway

```bash
vh s3-gateway status
vh s3-gateway enable
vh s3-gateway disable
vh s3-gateway creds create laptop --scope user-access --json
vh s3-gateway creds list
vh s3-gateway creds create backup --scope vault-allowlist --default-role reader --selected-vault archive --json
vh s3-gateway creds scope backup set --scope vault-allowlist --default-role reader --selected-vault archive
vh s3-gateway creds role assign backup --vault archive --role contributor
vh s3-gateway creds role override add backup --vault archive --pattern "/private/*" --permission download --effect deny
vh s3-gateway creds role override list backup --vault archive
vh s3-gateway creds role override remove backup --vault archive 42
vh s3-gateway creds role revoke backup --vault archive
vh s3-gateway bucket create-local archive
vh s3-gateway bucket bind archive --vault 12 --mode local
vh s3-gateway budget set-key backup --monthly 5 --mode enforce --currency USD
```

Gateway authorization is RBAC-native. `user_access` inherits the principal user's Vaulthalla RBAC. `vault_allowlist` uses selected vaults plus a key-level default vault role and optional per-vault exceptions. `global` requires an admin principal and a key-level default vault role. Boolean credential scope flags and `creds scope allow-vault` remain compatibility shorthand only.

## Pricing Budgets

```bash
vh pricing budget list
vh pricing budget set-global --mode warn --max-daily 5 --currency USD
vh pricing budget set-provider aws-s3 --mode enforce --max-run 1 --max-daily 10
vh pricing budget set-vault <vault> --mode report --max-run 0.25
vh pricing budget status
vh pricing budget ledger --limit 100
vh pricing budget disable-vault <vault>
```

See [Price Budgets](/cost-control/price-budgets).

## Email

```bash
vh email provider resend set
vh email provider ses set
vh email doctor
vh email test --dry-run
vh email test --send --to ops@example.com
vh email history --limit 100
```

See [Operator Emails](/admin/operator-emails).
