<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Managed S3 and R2 buckets, and event-driven sync

AWS S3 and Cloudflare R2 credentials can now administer their account. Turn it on for an existing credential with
`vh upstream admin enable <key>` (or the credential's **Provider administration** panel), and Vaulthalla can list the
account's buckets, create a new bucket when you create a vault, adopt an existing bucket after a read-only admission
check, keep its own lifecycle rule on the buckets it manages, and delete buckets it created when you explicitly ask.
One access-key pair per account does everything; who may do what is decided by the new `admin.upstream` permissions
(view, configure, provision, protect, unprotect, destroy), granted to the built-in roles as documented.

**Protection locks.** `vh upstream protect <key> <bucket> --reason …` excludes a bucket from everything Vaulthalla
does: no probes, adoption, vault binding, lifecycle or event rules, sync reads or writes, emptying or deletion,
including scheduled jobs, retries and work already running. The lock belongs to the bucket (provider, account and
name), not the credential, survives restarts and credential re-creation, and is loaded before the server makes any
upstream request. Removing it needs its own permission and an explicit, audited confirmation.

**Event-driven sync.** `vh upstream events enable <vault>` subscribes a vault's bucket to a Vaulthalla-owned queue
(AWS S3 → SQS, Cloudflare R2 → Queues with HTTP pull), and files written to the bucket by other tools reach the vault
within seconds: each event is stored before its queue message is acknowledged, deduplicated and ordered, applied to
the remote index, and only the changed keys are synced (about one HEAD and one GET per new object, one HEAD per
removal), under the vault's request and price budgets. Other applications' notification rules are preserved; only
Vaulthalla's own rules and queues are ever removed. Removals upstream now delete the vault's copy when it hasn't
changed since the last sync and the provider confirms the object is gone. If events may have been lost (dead-lettered
messages, or a delivery gap longer than the queue keeps messages), the next sync lists the bucket again instead of
trusting events. `vh upstream events status` shows queue health, backlog and errors; `repair` fixes
failed provisioning. R2 event delivery needs one Cloudflare API token (Queues: Edit, Workers R2 Storage: Edit), stored
sealed on the same credential; the R2 S3 key pair can't sign Cloudflare's account API.

**Safety.** Creating a bucket never takes over an existing one: name collisions are refused without changing
anything, and an existing bucket must be adopted explicitly. Deleting or detaching a vault leaves its bucket and
objects in place. Deleting a bucket is a separate operation, only for buckets Vaulthalla created and no vault uses,
after a preflight with object and version counts and a typed confirmation, and it reports partial results honestly.
Every control-plane change is in the upstream audit log (`vh upstream audit`), which shows each reader only the
credentials they may view. Bucket names and regions are validated before any request, and a bucket's identity (and so
its lock) follows the credential's endpoint, whatever provider label the credential was saved under.

Existing credentials and vaults are unchanged until you turn administration on: plain credentials make no
administrative calls. Also fixed: an object overwritten upstream by another tool could fail to sync on vaults that
don't encrypt upstream. On vaults that do, an object without Vaulthalla metadata over an encrypted file is still
treated as tampering unless the vault's event subscription imports foreign objects (the default for adopted buckets;
other vaults that encrypt upstream ignore foreign objects unless you choose `--foreign-objects import`).
