---
title: Event-Driven Sync
description: Sync S3 and R2 vaults from provider event notifications - AWS S3 to Amazon SQS and Cloudflare R2 to Cloudflare Queues - instead of scanning buckets.
order: 232
status: published
tags:
  - vaults
  - sync
  - s3
  - r2
  - events
---

# Event-Driven Sync

With event-driven sync, files written to a vault's bucket by other applications (the AWS CLI, rclone, a camera upload,
a backup job) reach the vault within seconds, and only the objects that changed are fetched. The provider notifies a
Vaulthalla-owned queue; Vaulthalla records each event durably, updates the vault's remote index, and syncs just those
keys. No bucket listing is repeated.

| Provider | Path | Needs |
| --- | --- | --- |
| AWS S3 | bucket notification → Amazon SQS Standard queue → Vaulthalla | an administrative credential with the SQS permissions in [Managed Upstream Buckets](/vaults/upstream-buckets#aws-s3) |
| Cloudflare R2 | event notification rule → Cloudflare Queue (HTTP pull) → Vaulthalla | an administrative credential with a Cloudflare API token ([R2](/vaults/upstream-buckets#cloudflare-r2)) |

No Worker, Lambda or public webhook endpoint is deployed; Vaulthalla pulls from the queue.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Turn It On

For an existing S3 vault whose credential has provider administration enabled:

```bash
vh upstream events enable <vault>
vh upstream events enable <vault> --prefix photos/ --foreign-objects ignore
vh upstream events status <vault>
```

Or when creating a vault: `vh vault create ... --bucket-mode create --events`, or the event-sync option under the
advanced settings of **New vault**. For an existing vault: the vault's **Settings** → **Event-driven sync**.

Vaulthalla then:

1. Creates or reuses one queue per account (AWS: per account and region, `vaulthalla-events-<region>`; R2:
   `vaulthalla-events-r2`), with a dead-letter queue, message retention and a visibility timeout. On AWS it adds a
   queue policy statement (`vaulthalla-s3-publish`) that allows Amazon S3 to publish from the subscribed buckets only.
   On R2 it adds an HTTP pull consumer.
2. Adds one notification rule to the bucket for object creation, overwrite and removal (including lifecycle
   expirations), named `vaulthalla-<id>`.
3. Starts consuming the queue.

### Other Applications' Rules

Bucket notification rules belong to everyone who uses the bucket. Vaulthalla reads the existing configuration, keeps
every rule that isn't `vaulthalla-*` exactly as it is, and on teardown removes only its own. On AWS the notification
document is replaced as a whole on every write, so Vaulthalla re-reads and merges it each time and checks the result.
If another application's rule already covers the same events and prefix, the provider rejects the overlap; Vaulthalla
reports the conflict and changes nothing. A queue that already has a Worker consumer on R2 is left alone and reported.

## What Happens To An Event

- **Durable first.** Each event is written to the inbox in the database before its queue message is acknowledged. A
  crash or a database outage at any point means the message is delivered again, not lost.
- **Duplicates** (providers deliver at least once) are recognised and recorded once.
- **Order.** Events for one key are applied newest-wins: AWS sequencers when present, otherwise event time. A late,
  older event never overwrites newer state.
- **Targeted sync.** Changed keys are applied to the vault's remote index and a sync pass runs for just those keys,
  under the vault's request and price budgets. A new or overwritten object costs about one HEAD and one GET; a removal
  costs nothing upstream.
- **Removals.** A deletion upstream removes the vault's file only if it is unchanged since the two sides last agreed;
  a file changed in the vault meanwhile is kept and uploaded again. Under `mirror` with `keep_local`, the vault stays
  authoritative and deleted objects are uploaded again.
- **Vaulthalla's own writes.** Notifications about objects Vaulthalla itself uploaded or deleted are recognised and
  don't cause another transfer.
- **One sync per vault at a time.** Event passes and scheduled passes never overlap; events that arrive meanwhile wait.
- **Messages that can't be read** are not acknowledged: after several deliveries they move to the dead-letter queue.

### Objects Uploaded Directly To The Bucket

Objects Vaulthalla writes carry Vaulthalla metadata (and, with upstream encryption on, are encrypted with the vault
key). An object some other tool uploaded has none and is plaintext:

- With `--foreign-objects import` (the default) it is imported as a vault file and sealed locally, including when it
  overwrites a file the vault already has. Each import into a vault that encrypts upstream is logged.
- With `--foreign-objects ignore`, new objects without Vaulthalla metadata are skipped (one HEAD each to tell them
  apart) and counted in the status, and a metadata-free object over an encrypted file is treated as below.
- Without an importing subscription, a vault that encrypts upstream treats a metadata-free object over one of its
  encrypted files as tampering: it fails authentication and the vault keeps its copy. An object that claims to be
  Vaulthalla-encrypted but fails authentication is never imported.

## Status And Repair

```bash
vh upstream events status
vh upstream events status <vault>
```

Status shows the subscription state (`pending`, `active`, `failed`, `removing`), the queue and its health (last poll,
last event, backlog, consecutive failures and the last error), and the inbox (pending, applied, failed, handled and own
writes in the last 24 hours). The same appears in the vault's **Settings** → **Event-driven sync**.

- **Queue or provider outage:** Vaulthalla backs off (up to 5 minutes between polls), marks the queue `degraded`
  after repeated failures, and recovers by itself. Messages stay in the queue meanwhile.
- **Failed provisioning** (a missing permission, a conflicting rule): fix the cause, then

  ```bash
  vh upstream events repair <vault>
  ```

  Repair re-creates whatever is missing and re-arms the subscription; it is safe to run any time.
- **Missed events** (a queue deleted outside Vaulthalla, retention expired): run a full reconcile, which is always
  available as recovery:

  ```bash
  vh vault sync reconcile <vault> --allow-list-scan
  ```

## Turn It Off

```bash
vh upstream events disable <vault>
```

This removes Vaulthalla's rule from the bucket and, when no other subscription uses it and Vaulthalla created it, the
queue. Scheduled sync continues as before. Deleting a vault turns its subscription off; restoring the vault turns it
back on.

## Protected Buckets

Event subscriptions can't be created on [protected buckets](/vaults/upstream-buckets#protection-locks). Protecting a
bucket that already has one stops all processing for it; its events stay in the inbox, unapplied.

## Importing Event Files By Hand

`vh vault sync events <vault> --file s3-events.json` feeds saved S3 event notifications (or an SQS message dump)
through the same pipeline. See [Sync](/vaults/sync#ingest-s3-events).
