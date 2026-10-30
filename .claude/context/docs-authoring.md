# Consumer docs (`docs/`)

`docs/` is operator and end-user documentation: install, configure, operate, back up, recover,
troubleshoot, and use. Keep implementation internals out unless they change an operator decision.
`docs/contributors/` (8 pages) is contributor-facing, and `docs/dev/` holds implementation notes.

Authoring rules come from the `payload-markdown` and `payload-markdown-docs` skills in `.claude/skills/`.
Those are vendored by `pmdocs install skill --claude --docs-root ./docs --package-manager pnpm --force`, so
don't hand-edit them. `pmdocs skill check` reports drift (validate/plan also warn on stderr); `pmdocs skill update
--agent claude` upgrades them in place.

## Project conventions

- Every page has YAML frontmatter with supported fields only: `title navTitle description order status tags`.
  Use `status: published` for complete pages and `draft` only when a page is intentionally incomplete.
- Use root-relative route links (`/vaults/sync`), never `./sync.md`.
- Long pages get a compact TOC after the intro: `:::toc[On this page]{depth="3" theme="compact"}` / `:::`.
- `docs/stack.toml` is docs-set metadata (title, description, technology stack by category), synced as the manifest
  `project`, never a page. Update it in the same change whenever a language, library, database, platform, service or
  major tool is added, dropped or replaced (`core/meson.build`, `core/tools/*/meson.build`, `web/package.json`,
  `debian/control`). Rules: `.claude/skills/payload-markdown-docs/reference/stack-toml.md`.
- Never commit generated AI exports (`llms.txt`, `llms-full.txt`, `index.ai.yml|yaml`).
- Validate with `python3 .claude/skills/payload-markdown/scripts/check_payload_markdown_doc.py <files>`,
  then `pmdocs validate --source docs`. CI's `docs-validate` job runs the latter, and `docs-publish` pushes it.

## Sections

Cross-platform IA (Linux + macOS): shared behavior is documented once; platform differences live in the platform
sections and `reference/platforms.md`. Use `:::tabs` (`value="linux"` / `value="macos"`) only for genuinely parallel
commands.

`getting-started/` (installation = platform chooser, first-run, web-console) · `linux/` (index, installation,
administration, troubleshooting) · `macos/` (index, installation, administration, troubleshooting) · `https/` (index,
caddy, client-trust, nginx) · `web-console/` · `cli/` (incl. `command-reference.md`) · `vaults/` (local, S3/R2, sync,
filesystem access, encryption, secrets/key export, backup & recovery, S3 gateway) · `cost-control/` · `admin/` ·
`sharing/` · `s3-gateway/` (8 pages) · `reference/` (runtime paths, configuration, platforms) · `troubleshooting/`
(general only; install/service problems are per platform). Moved pages keep their old route in `redirectFrom`
(`/troubleshooting/install-troubleshooting` → `/linux/troubleshooting`).

## Product facts docs must stay consistent with

- Install (Linux, amd64, Ubuntu 24.04 tested): `curl -fsSL https://apt.vaulthalla.sh/install.sh | bash`, manual APT, or
  `./bin/vh/install.sh`. Source installs (`make install` / `make dev`) are development-only.
- Install (macOS, Apple Silicon): casks `valkyrianlabs/tap/vaulthalla` (server + Desktop, macOS 27+),
  `…/vaulthalla-server` (server only, macOS 14+), `…/vaulthalla-desktop` (app only); or
  `sudo installer -pkg vaulthalla-<version>-arm64.pkg -target /` (server only; Desktop is an Installer choice, off by
  default). Signed and notarized from 1.18.0.
  Postinstall = `vaulthalla-provision --apply --enroll <console user>` (hidden `_vaulthalla`, bundled PostgreSQL on
  127.0.0.1:36971, LaunchDaemons `sh.vaulthalla.{postgres,server,web}` + `caddy` after `vh setup caddy`, installing
  user enrolled and bound to `admin`). Uninstall: `sudo "/Library/Application Support/Vaulthalla/uninstall.sh"
  [--purge]`. Paths under `/Library/Application Support/Vaulthalla/{state,run,postgres,caddy,config.yaml}`, logs in
  `/Library/Logs/Vaulthalla`.
- macOS limits (never promise otherwise until shipped and accepted): no FUSE/Finder mount, ever, from the server (#262;
  Finder access belongs to Vaulthalla Desktop's File Provider, in development; `vh fs`, console, S3 gateway
  instead), secrets backend `file` (0600 files + FileVault, not Secure Enclave), unsigned package, no
  `vh setup db|remote-db|nginx`. HTTPS on macOS is `vh setup caddy` (internal CA with X.509 name constraints, Let's
  Encrypt, `--dns-cloudflare`, `--cert/--key`); on Linux `vh setup nginx`.
- CLI names: `vh`, `vaulthalla`. Socket: `/run/vaulthalla/cli.sock` (macOS: `…/Vaulthalla/run/cli.sock`). Non-root
  operators need the `vaulthalla` group (macOS `_vaulthalla`, `dseditgroup`) plus a UID mapping (`vh setup
  assign-admin` on Linux; the installer binds the installing user on macOS). Lifecycle commands need `sudo`:
  `setup db|remote-db|nginx` and `teardown db|nginx` (Linux), `setup|teardown caddy` (macOS).
- Services: `vaulthalla` (owns `/run/vaulthalla/cli.sock`), `vaulthalla-web`, `vaulthalla-swtpm`. `vaulthalla-cli.socket`/`.service` were retired in #110; mention them only as legacy units that upgrades remove.
- S3/R2 sync strategies: `cache | sync | mirror`. Request budgets and price budgets are separate systems.
  Price budget scopes are global, provider, and vault; modes are `off | report | warn | enforce`.
- Vault keys and internal secrets have separate export commands.
- **Never imply a one-command full backup/restore exists.** Dashboard backup indicators are policy or status
  signals, not proof that a backup ran.
