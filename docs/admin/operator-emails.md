---
title: Operator Emails
description: Configure and troubleshoot Resend or AWS SES operator notifications.
order: 10
status: published
tags:
  - admin
  - email
  - operations
---

# Operator Emails

Vaulthalla can send operator email through Resend or AWS SES. The runtime uses this channel for watchdog alerts, weekly digests, and security notifications.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Configuration

Enable the email provider in `config.yaml` and store provider credentials with `vh email provider ... set`. Do not put API keys, SES access keys, or secret keys in `.env` files or provider credential files.

Minimal recipient shape:

```yaml
email:
  enabled: true
  provider: resend
  from: "Vaulthalla <ops@example.com>"
  base_url: "https://vault.example.com"

operator_emails:
  enabled: true
  recipients:
    alerts:
      - ops@example.com
    weekly:
      - ops@example.com
    security:
      - security@example.com
```

Set `email.provider` to `resend`, `ses`, or `none` in `config.yaml`. Provider credentials are stored through:

```text
vh email provider resend set
vh email provider ses set
```

Validation and smoke checks:

```text
vh email doctor
vh email test --dry-run
vh email test --send --to ops@example.com
vh email history --limit 100
```

## Notification Types

Watchdog alerts use `operator_emails.recipients.alerts` and are deduped/rate-limited by runtime health fingerprint.

Weekly digests use `operator_emails.recipients.weekly` and are deduped by week start.

Security alerts use `operator_emails.recipients.security`. Admin role create, update, and delete events are emitted from both the shell command path and websocket handler path after the database mutation succeeds.

Account security notices (multi-factor sign-in) also go to `operator_emails.recipients.security`, and a copy to the
account's own email address when it has one: a recovery-code sign-in, an MFA reset, ten failed second factors in a
row, a passkey suspended as a possible clone, and the MFA policy weakened (security recipients only). The account
alone is told when one of its factors is added, renamed or removed, or new recovery codes are saved. They need
`security_alerts.enabled`; the [audit trail](/admin/audit-trail) records every one of these events either way.

Security alert controls:

```yaml
operator_emails:
  security_alerts:
    enabled: true
    admin_role_changes: true
```

## Privacy

Operator emails should never include raw secrets, provider credentials, auth tokens, session tokens, share tokens, raw IP addresses, or user agents.

Admin role security alerts include only the action, role id/name/description, a capped permission flag summary, actor username/user id, source path, timestamp, instance name, and optional base URL.

## Troubleshooting

If no email is sent, check `vh email doctor`, then inspect `vh email history --limit 100`. Disabled email, provider `none`, missing recipients, missing secrets manager, and provider failures are recorded as suppressed or failed delivery attempts.

If security alerts are missing, confirm `operator_emails.enabled`, `operator_emails.security_alerts.enabled`, `operator_emails.security_alerts.admin_role_changes`, and at least one `operator_emails.recipients.security` recipient.
