---
title: AI-Assisted Contributions
description: Standards for contributors using AI tools on Vaulthalla changes.
order: 970
status: published
tags:
  - contributors
  - ai
---

# AI-Assisted Contributions

AI-assisted development is allowed in Vaulthalla.

Use Codex, Claude Code, ChatGPT, or whatever tools help you move faster. The maintainer uses these tools too. But Vaulthalla is system-level software, and AI-generated patches are held to the same standard as handwritten patches.

The rule is simple:

**The contributor owns the patch. The model does not.**

If you submit AI-assisted code, you are responsible for understanding it, validating it, and making sure it fits Vaulthalla’s existing architecture.

### What is acceptable

AI tools are useful for:

* tracing code paths
* explaining unfamiliar modules
* drafting focused patches
* writing tests
* generating documentation
* comparing behavior before and after a change
* producing narrow refactors that preserve existing abstractions

### What is not acceptable

AI tools are not an excuse to submit broad, unreviewed changes.

Do not submit patches that:

* rewrite core abstractions without discussion
* bypass existing architecture instead of fitting into it
* mix unrelated changes into one PR
* weaken RBAC, auth, crypto, database, or FUSE boundaries
* change package lifecycle behavior without clear operator impact notes
* add clever helper layers where the existing codebase already has a pattern
* “fix” things by working around the design instead of understanding it

### Special warning for the C++ core

The C++ core is not a playground for generated slop.

If a patch touches storage, FUSE, permissions, RBAC, crypto, TPM/swtpm, database state, protocol handling, or runtime lifecycle code, it needs to respect the existing abstractions or substantially improve on them. If it does not fit the architecture, it does not merge.

Small, boring, well-scoped patches are welcome.

Large agent-generated rewrites are not.

### Validation expectations

Vaulthalla runs on Linux and macOS, and some work can be validated on only one of them. FUSE, Debian packaging, systemd and TPM behavior need Linux; launchd, provisioning and the macOS package need a Mac; nothing runtime-related can be validated from Windows, browser sandboxes, or remote-only agent workflows. Every pushed change must also build without warnings on both platforms (see [Builds Must Be Silent](/contributors/development-setup#builds-must-be-silent)).

Contributors should be honest about what they actually tested.

For core/runtime changes, meaningful validation usually requires a Linux environment with the relevant dependencies installed. For FUSE, packaging, systemd, TPM/swtpm, Nginx, Certbot, or Debian lifecycle work, local compilation alone is not enough.

If you cannot run the full validation path, say so in the PR and provide the checks you did run.

A good PR includes:

* what changed
* why it changed
* affected domain/subsystem
* tests run
* manual validation commands
* known gaps in validation

### Agent usage guidance

Do not let an agent burn time compiling repeatedly unless that is actually worth it.

A better workflow is:

1. Use the agent to inspect and propose.
2. Review the patch yourself.
3. Run focused validation locally.
4. Feed the results back into the agent only when needed.
5. Keep the PR narrow.

The agent can help. It cannot be the maintainer.

See also:

- [Contributor Guide](/contributors/README)
- [Contribution Boundaries](/contributors/contribution-boundaries)
- [Validation Guide](/contributors/validation-guide)
