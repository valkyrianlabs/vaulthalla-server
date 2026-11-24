## Upstream buckets

- **Backblaze B2 accounts can be administered.** Provider administration, until now for AWS S3 and Cloudflare R2
  credentials, also works for a Backblaze B2 application key whose endpoint is the account's S3 endpoint
  (`https://s3.<region>.backblazeb2.com`). After `vh upstream admin enable <api-key>`, Vaulthalla lists the account's
  buckets (`vh upstream buckets`), inspects them, runs the adoption check, and creates or adopts a bucket together
  with a vault: `vh vault create <name> --s3 --api-key <key> --bucket-mode create|adopt`, or **Create a new bucket**
  in the web console. Detach and cleanup work as on the other providers; cleanup deletes every object version, which
  B2 requires before a bucket can go.
  - New B2 buckets are private and are created in the account's own region (the one in the endpoint); another
    region is refused.
  - B2 bucket names have 6 to 63 characters, can't start with `b2-`, and are shared by every Backblaze account. The
    length and prefix are checked before anything is sent, and a name another account holds is reported as taken
    (on AWS S3 too) instead of pointing at adoption.
  - Backblaze's S3-compatible API has no lifecycle or event-notification calls, and B2 buckets are always versioned.
    `vh upstream admin status <api-key> --probe` lists `lifecycle`, `versioning` and the `events` capabilities as
    missing for a B2 key, `vh upstream lifecycle` and `--abort-multipart-days` are refused with that reason, and
    event-driven sync stays AWS S3 and Cloudflare R2 only. Set B2 lifecycle rules in the Backblaze console.
  - The application key must be a standard key (not the master key) with access to all buckets.
  - A credential for a B2 S3 endpoint must use the `backblaze-b2` provider: saving one under another provider is
    refused, as for AWS and R2 endpoints. Protection locks on B2 buckets follow the endpoint, and the upgrade moves
    existing locks and bucket records to the new identity so that every lock keeps applying.
  - A credential that managed storage issued for a vault can't be turned into an administrative one.

See [Managed Upstream Buckets](/vaults/upstream-buckets#backblaze-b2).
