# Contributing to Vaulthalla

Vaulthalla welcomes contributors.

This is Linux-native infrastructure software, not a simple web app. Changes here can affect filesystem behavior, local services, PostgreSQL-backed state, authentication and session behavior, encryption, package lifecycle scripts, and systemd units.

Start here:

- [Contributor Guide](docs/contributors/README.md)
- [Contribution Boundaries](docs/contributors/contribution-boundaries.md)
- [Development Setup](docs/contributors/development-setup.md)
- [Validation Guide](docs/contributors/validation-guide.md)
- [Security-Sensitive Work](docs/contributors/security-sensitive-work.md)
- [AI-Assisted Contributions](docs/contributors/ai-assisted-contributions.md)

For early contributors, use the GitHub Projects roadmap linked from the repository or organization page as the canonical task source. If your idea is not represented there, open an issue or discussion before implementing it.

Small, scoped PRs are much easier to review than giant mystery rewrites.

If your change touches user data, filesystem semantics, auth or session behavior, RBAC, crypto, secret handling, package lifecycle behavior, service startup or shutdown, or release publication, coordinate with the maintainer before writing the patch.

Before opening a PR, run the checks that actually prove your change and say clearly what you did and did not validate.

AI assistance is allowed. AI abdication is not. You own the patch.

## Licensing of contributions

Vaulthalla is owned and published by Valkyrian Labs LLC under the GNU Affero General Public License, version 3 or
later. By submitting a contribution you confirm you have the right to submit it, and you license it under those same
terms. You keep the copyright in your contribution. Code from elsewhere keeps its original copyright and license:
say where it came from in the PR, and add it to `debian/copyright` if it ships.
