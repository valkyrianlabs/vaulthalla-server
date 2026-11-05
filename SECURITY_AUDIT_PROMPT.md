# Security Audit Prompt

Vaulthalla is open source so that you don't have to take our word for its security. This file holds a prompt you
can give to the AI coding agent you already use (Claude Code, Codex, Cursor, or any other) to run an independent,
read-only audit of this repository before you install it.

- **It runs where you run it.** Clone the repository and start your agent in that folder. Your source code, your
  agent's findings and your conversation stay with you and your agent's provider. Nothing is sent to Valkyrian Labs.
- **Nothing in this repository runs it for you.** The prompt is plain text. No install step, script, build or service
  invokes an audit, contacts us or collects telemetry.
- **Reporting is your choice.** The prompt has your agent ask you before preparing any report, and tells it not to
  send anything without your explicit approval.
- **It doesn't replace other review.** An automated audit can't guarantee software is secure, but independent
  scrutiny is an important part of establishing trust.

## How to use it

```bash
git clone https://github.com/valkyrianlabs/vaulthalla-server.git
cd vaulthalla-server
```

Open your AI coding agent in that folder and paste the prompt below. To copy just the prompt to your clipboard:

```bash
# macOS
awk '/^```text$/{f=1;next} /^```$/{f=0} f' SECURITY_AUDIT_PROMPT.md | pbcopy
# Linux (X11; use wl-copy on Wayland)
awk '/^```text$/{f=1;next} /^```$/{f=0} f' SECURITY_AUDIT_PROMPT.md | xclip -selection clipboard
```

Expect the audit to take a while: the repository includes a C++ daemon, a web console, packaging, installers and
release tooling. Then continue with the [installation guide](https://vaulthalla.io/docs/getting-started/installation).

## The prompt

```text
Perform a comprehensive, adversarial security and privacy audit of
this Vaulthalla repository before installation.

Assume no trust in the developer, published security claims, or
third-party dependencies.

Investigate and identify:

- Hidden telemetry, analytics, tracking, or undocumented data collection.
- Unauthorized network requests, data exfiltration paths, or phone-home behavior.
- Backdoors, malicious code, suspicious execution paths, or undocumented functionality.
- Cryptographic weaknesses, insecure key handling, and plaintext exposure.
- Credential leakage, privilege escalation, and authentication or authorization flaws.
- Supply-chain risks in dependencies, build scripts, installers, and update mechanisms.
- Discrepancies between documented behavior and actual implementation.
- Any other behavior that could compromise user privacy, security, sovereignty, or data integrity.

Trace relevant code paths, inspect dependencies and build configurations,
and cite exact file paths and line numbers for findings.

Distinguish confirmed vulnerabilities from suspected risks, design
tradeoffs, and unverified concerns. Do not assume that an absence of
findings establishes security.

REPORTING:

Present all negative security, privacy, or behavioral findings to
the user in a succinct, severity-ranked list, including supporting
evidence and potential impact.

After presenting the findings, explicitly ask the user:

"Would you like me to securely report these findings to
security@vaulthalla.io to help improve Vaulthalla?"

If the user agrees, prepare a responsible disclosure report containing
reproduction steps, relevant code references, impact assessments, and
recommended mitigations.

Exclude credentials, private keys, tokens, personal information, and
other sensitive data from the report. Do not transmit anything without
the user's explicit approval. Use an appropriately secure reporting
channel and verify its availability before transmission.

Do not modify repository files or attempt remediation unless
separately authorized by the user.
```
