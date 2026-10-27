<!-- vl-release:generated-local -- regenerate with `vlr install-local-skill` after changing release.toml; local edits are overwritten -->
# Vaulthalla: release specifics

Generated from this repository's `release.toml`. The general workflow is in `SKILL.md`;
this file says how it applies here.

## Files

| Purpose | Path |
|---|---|
| Release contract | `release.toml` |
| Staged changelog (keep current) | `.release/CHANGELOG_NEXT.md` |
| Staged release notes (keep current) | `.release/RELEASE_NOTES_NEXT.md` |
| Published release notes (do not edit) | `RELEASE_NOTES.md` |
| Published Debian changelog (do not edit) | `debian/changelog` |

## Versions

- Canonical: `VERSION`
- Kept in sync by `vlr version …`: `meson.build` (meson), `web/package.json` (package_json)
- Tags: `vX.Y.Z` on branch `main`; GitHub release title: `vX.Y.Z — <title>`

## Release channels

- **Debian packages** (built by `vlr build-deb` from `debian/`, revision 1):
  - `vaulthalla`: architecture `amd64`; must ship `usr/bin/vaulthalla-server`, `usr/bin/vaulthalla-cli`, `usr/bin/vaulthalla`, `usr/bin/vh`, `usr/lib/vaulthalla/lifecycle`, `usr/share/vaulthalla/config/config.yaml`, `usr/share/vaulthalla/config/config_template.yaml.in`, `lib/systemd/system/vaulthalla.service`, `lib/systemd/system/vaulthalla-web.service`, `lib/systemd/system/vaulthalla-swtpm.service`, `usr/share/doc/vaulthalla/copyright`, `usr/share/vaulthalla/nginx/vaulthalla`, `usr/share/vaulthalla/psql/000_schema.sql`, `usr/share/vaulthalla-web/server.js`; must never ship `lib/systemd/system/vaulthalla-cli.service`, `lib/systemd/system/vaulthalla-cli.socket`, `usr/lib/systemd/system/vaulthalla-cli.service`, `usr/lib/systemd/system/vaulthalla-cli.socket`, `etc/vaulthalla/config.yaml`, `usr/lib/vaulthalla/helpers/*`; ships byte-identical copies of `deploy/config/config.yaml`
  - `vaulthalla-preview-cad`: architecture `amd64`; must ship `usr/lib/vaulthalla/helpers/vaulthalla-preview-cad`, `usr/share/doc/vaulthalla-preview-cad/copyright`; must never ship `usr/bin/*`, `etc/*`, `lib/systemd/*`, `usr/lib/systemd/*`, `usr/share/vaulthalla/*`, `usr/lib/vaulthalla/helpers/vaulthalla-preview-media`
  - `vaulthalla-preview-media`: architecture `amd64`; must ship `usr/lib/vaulthalla/helpers/vaulthalla-preview-media`, `usr/share/doc/vaulthalla-preview-media/copyright`; must never ship `usr/bin/*`, `etc/*`, `lib/systemd/*`, `usr/lib/systemd/*`, `usr/share/vaulthalla/*`, `usr/lib/vaulthalla/helpers/vaulthalla-preview-cad`
  - pre-build: `bash web/bin/build_release_payload.sh build/web-payload`
- **APT**: https://apt.valkyrianlabs.com (suite `stable`, components main), published by release CI with `vlr publish-deb`

## Before considering substantial work complete

```sh
vlr check
bash tools/dev/verify.sh release packaging lifecycle shell
```
