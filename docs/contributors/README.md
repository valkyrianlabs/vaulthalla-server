---
title: Contributor Guide
navTitle: Contributors
description: Contributor-facing entry point for Vaulthalla development.
order: 900
status: published
tags:
  - contributors
---

# Contributor Guide

Vaulthalla is self-hosted infrastructure software for Linux and macOS. It includes a C++ core daemon with OS-specific seams, a FUSE filesystem surface on Linux, a local CLI control socket owned by the daemon, a packaged Next.js admin client, PostgreSQL-backed state, systemd units and Debian lifecycle scripts on Linux, launchd LaunchDaemons and an installer package on macOS, and release tooling.

Contributions are welcome. Correctness matters more than patch velocity.

Small, scoped PRs are much easier to review and merge than giant mystery rewrites.

## Start Here

1. Read [Contribution Boundaries](/contributors/contribution-boundaries) before choosing work.
2. Skim the [Architecture Map](/contributors/architecture-map) so you know which subsystem you are touching.
3. Use the GitHub Projects roadmap linked from the repository or organization page as the default task source for early contributions.
4. Follow [Development Setup](/contributors/development-setup) for your environment.
5. Run the checks in the [Validation Guide](/contributors/validation-guide) before you open a PR.

When in doubt, open an issue first.

## What Kind Of Project This Is

Vaulthalla is not a simple web app. Changes here can affect:

- mounted filesystem behavior
- local privilege and socket boundaries
- PostgreSQL-backed metadata and auth/session state
- encryption and secret handling
- install, upgrade, remove, and purge behavior
- systemd service lifecycle
- storage provider and sync correctness

That does not mean contributors should stay away. It means contributors should choose scope carefully.

## Where To Find Work

For early contributors, the roadmap is the canonical source of tasks:

- GitHub Projects roadmap linked from the repository or organization page
- the repository issue tracker for scoped follow-up or proposed new work

If you want to work on something that is not already represented there, open an issue first before you start implementing it.

Contributors with a proven track record, or with a strong specialized skill set in an area Vaulthalla clearly needs, may work more independently over time. Major features and sharp subsystem changes still require maintainer alignment first.

## Quick Links

- [Contribution Boundaries](/contributors/contribution-boundaries)
- [Architecture Map](/contributors/architecture-map)
- [Development Setup](/contributors/development-setup)
- [Validation Guide](/contributors/validation-guide)
- [Packaging and Release](/contributors/packaging-and-release)
- [Security-Sensitive Work](/contributors/security-sensitive-work)
- [AI-Assisted Contributions](/contributors/ai-assisted-contributions)

## Boundary Summary

Vaulthalla work generally falls into four buckets:

| Category | What it means |
| --- | --- |
| Open contribution areas | Good entry points for scoped PRs that preserve behavior. |
| Coordinate before implementing | Reasonable contribution areas, but get maintainer alignment before significant work. |
| Maintainer-guided areas | Core correctness, data safety, lifecycle, or architecture-sensitive work. Design discussion comes first. |
| Security-sensitive or restricted work | Auth, permissions, crypto, secret handling, trust boundaries, or vulnerability work. Some of this should not start as a public PR. |

The full breakdown lives in [Contribution Boundaries](/contributors/contribution-boundaries).

## PR Expectations

- Keep changes narrow.
- Explain what changed, why, and which subsystem is affected.
- Run the relevant validation and say what you actually tested.
- Do not bundle unrelated fixes into one PR.
- Do not submit broad refactors in sharp subsystems without prior discussion.

If a change affects user data, filesystem semantics, authentication, encryption, packaging lifecycle behavior, or service shutdown/startup behavior, coordinate before implementing.

## AI Assistance

AI assistance is allowed.

AI abdication is not.

If you use AI, you still own the patch. Read [AI-Assisted Contributions](/contributors/ai-assisted-contributions) before sending generated changes into the repo.

## Validation

Vaulthalla contributors are expected to validate changes honestly. Some work can be checked quickly. Some work needs a real Linux environment with FUSE, PostgreSQL, systemd, and package lifecycle behavior in play.

Use the [Validation Guide](/contributors/validation-guide). If you could not run the meaningful checks for your change, say so clearly in the PR.

## Ownership, Trust, And Maintainer Path

Vaulthalla wants real contributors, not just drive-by patches.

Contributors who consistently ship good, scoped, well-validated work may earn broader ownership. Trusted contributors may eventually become maintainers with the ability to review, approve, and merge changes alongside the project owner.

That path is earned by judgment, follow-through, and technical correctness, not by volume.

## Beginners And Mentorship

Less experienced contributors are still welcome.

The best entry point is a small, scoped task from the roadmap. Mentorship may be available, but capacity is finite. Initiative matters. Follow-through matters. If you want help, show your work, ask specific questions, and start with something reviewable.

Future community channels such as Teams, Discord, or similar may exist later. Do not assume they exist yet.

## Repository Access

A contributors page is planned for `vaulthalla.io/contributors`, including a way to request repository access.

Treat that as planned infrastructure, not a current workflow. Until it exists, use the public GitHub roadmap, issues, and PR flow.
