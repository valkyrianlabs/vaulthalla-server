---
title: Security-First Compatibility Policy
navTitle: Compatibility Policy
description: When Vaulthalla breaks backward compatibility, and what it never breaks - customer data, keys and recoverability.
order: 945
status: published
tags:
  - contributors
  - security
  - policy
---

# Security-First Compatibility Policy

Security, data integrity and architectural correctness take precedence over backward compatibility when preserving compatibility would perpetuate a material security risk, or when no established customer dependency justifies the extra complexity.

Vaulthalla's responsibility as a steward of customer data is to preserve its confidentiality, integrity, availability and recoverability, not to preserve historical implementation decisions indefinitely.

This policy applies to everyone who changes Vaulthalla, people and AI agents alike.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Governing Rules

### 1. No hypothetical compatibility obligations

When no verified external customer dependency exists, favor the cleanest secure implementation over compatibility scaffolding, transitional releases, deprecated interfaces or legacy fallbacks.

Don't manufacture migration complexity to accommodate hypothetical deployments or users.

### 2. Security takes precedence over compatibility

When keeping backward compatibility would preserve a confirmed material vulnerability, an insecure default or an unsafe trust boundary, a breaking change is explicitly permitted, and may be required.

A compatibility guarantee must never become the justification for knowingly keeping an exploitable weakness.

### 3. Breaking compatibility does not authorize data loss

Existing customer data, encryption keys, recovery material and other durable state must stay recoverable wherever technically possible.

Breaking interfaces, formats or operational behavior is acceptable. Silently destroying data, regenerating irreplaceable secrets, or leaving encrypted storage permanently inaccessible is not.

Migration-sensitive changes need validation and a recovery procedure proportionate to what they touch.

### 4. Real customer dependencies deserve deliberate handling

When actual customer dependencies exist, preserve compatibility where doing so doesn't compromise security or impose disproportionate architectural complexity.

If a breaking change is necessary, provide a migration path, regression coverage and clear release documentation. Security-critical fixes must not be delayed indefinitely just to keep compatibility.

### 5. Engineering agents exercise delegated judgment

Don't block implementation to ask the maintainer about purely hypothetical compatibility scenarios.

Proceed with the simplest secure, forward-compatible design when all of these hold:

- No verified customer dependency requires the legacy behavior.
- The implementation preserves durable data and the ability to recover it.
- The security and correctness implications are understood.
- Regression tests can establish the intended behavior.

Escalate to the maintainer when any of these hold:

- A change risks irreversible data loss or loss of decryptability.
- A verified customer dependency would be materially disrupted without a safe migration.
- Competing security properties need an explicit product-level decision.
- The change materially alters customer key custody or trust boundaries.

An escalation names the concrete risk and proposes a recommended resolution. It doesn't just list theoretical alternatives.

### 6. Document decisions, not hypothetical obstacles

For a breaking change, record:

- the security or architectural rationale;
- the affected interfaces or data formats;
- the migration actions operators must take.

Put them in the pull request and in the change's release-note fragment (`.release/notes.d/`).

Don't introduce multi-release compatibility machinery, redundant secret representations or downgrade paths unless a concrete operational requirement justifies them.

## Decision Principle

Backward compatibility is an engineering consideration, not an inviolable contract. Customer security and data recoverability are obligations.

When those priorities conflict, resolve the conflict in favor of protecting the customer, not preserving the past.

## Applying It

| Situation | What to do |
| --- | --- |
| A stored secret or format is insecure and no customer depends on the old form | Convert it in one release, verify the conversion before removing the old form, and document that downgrading isn't supported. |
| An insecure default ships today | Change the default. Document the new behavior and how an operator opts out where an opt-out is safe. |
| A protocol or API change would break a client Valkyrian Labs controls (web console, Vaulthalla Desktop) | Ship both sides together; don't keep the old surface for hypothetical third-party clients. |
| A change could make existing encrypted data or keys unrecoverable | Stop and escalate with a recommended recovery or rollback procedure. Rule 3 still applies to a breaking change. |
| A verified customer would lose a capability they rely on | Provide a migration path and release documentation, or escalate if that can't be done safely. |

Other rules still apply: shipped database migrations are append-only and must be safe on upgraded installs, and maintainer scripts never destructively reset data (see [Packaging And Release](/contributors/packaging-and-release) and [Security-Sensitive Work](/contributors/security-sensitive-work)).
