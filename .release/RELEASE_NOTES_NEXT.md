<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Vaulthalla on macOS

Vaulthalla now installs on Apple Silicon Macs (macOS 14 or later) as a system service, from an installer package or
Homebrew (`brew install --cask vaulthalla/tap/vaulthalla`). Both run the same package: it creates a hidden
`_vaulthalla` service account, keeps vault data, sealed secrets and a private PostgreSQL database in
`/Library/Application Support/Vaulthalla` where only that account can read them, and starts the server, the web
console and the database at boot through launchd, before anyone logs in. The person installing it is enrolled for
`vh` and becomes the CLI `admin` (change it later with `vh`). Upgrading reinstalls over the top and keeps every vault;
`/Library/Application Support/Vaulthalla/uninstall.sh` removes it and keeps the data unless given `--purge`.
On macOS the vault isn't mounted in Finder yet: use the web console, the S3 gateway or `vh fs`.

HTTPS on macOS is one command: `sudo vh setup caddy --domain vault.home.arpa` serves the console, WebSockets,
uploads and downloads (and, with `--s3-domain`, the S3 gateway) through Caddy, running as the service account.
Internal names (`.home.arpa`, `.internal`, `.lan`, `.local`, `.test`) get certificates from Vaulthalla's own CA, which is
name-constrained to your hostnames so trusting it on a device can't let it vouch for any other site; `--trust` trusts
it on the Mac, and the command prints how to trust it on phones and other computers. Public names get Let's Encrypt
certificates, through Cloudflare DNS with `--dns-cloudflare` (the same credentials file `vh setup nginx` uses on
Linux) when the Mac isn't reachable from the internet, or use your own certificate with `--cert`/`--key`. Caddy renews
certificates by itself; `vh setup caddy --status` shows what is served, and `vh teardown caddy` removes it.

The package isn't signed by Apple yet. Opened from Finder, macOS blocks it the first time: choose **Open Anyway** in
System Settings → Privacy & Security, then run it again. `sudo installer -pkg vaulthalla-<version>-arm64.pkg -target /`
and the Homebrew cask install it without that prompt.

Existing behavior on Ubuntu installs is unchanged. Internals that touched Linux-only system calls now sit behind small
platform interfaces, so one code base builds and passes its tests on both systems.

New: `vh fs ls`, `vh fs get` and `vh fs put` read and write vault files over the control socket, without a mount, with
the same permissions as the web console. Downloads to a file are written atomically and only when complete; uploads
are stored only when every byte arrives, and `--overwrite` refuses to replace a file that changed meanwhile. This is
an interim path for macOS until its FUSE mount can map local users to their own Vaulthalla identities.

Fixes found along the way:

- `vh … --help` no longer reads an uninitialized color theme while rendering help text.
- The `vh` client and daemon compute the control-socket address length portably and refuse socket paths that are
  too long instead of truncating them.
- On the FUSE mount, an exchange-rename (`renameat2(RENAME_EXCHANGE)`) is now refused instead of silently
  overwriting the second file.
- Binding the first CLI user to the `admin` account no longer attempts a group change the unprivileged daemon could
  never make (membership is already checked when `vh` connects).
