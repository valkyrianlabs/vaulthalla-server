## Recovery

- **Backblaze B2: versioning off really is off, and provider versioning works.** Every Backblaze B2 bucket keeps
  every version of every file (and of every deleted one) unless a lifecycle rule removes them. Vaulthalla now sets
  that rule from the vault's recovery mode:

  - A bucket Vaulthalla creates on B2 keeps **only the latest version**: old versions are deleted a day after they
    are replaced or deleted.
  - `--mode provider-versioning --retention 30d` keeps them 30 days (any 1 to 36500, or `indefinite`), with the same
    cost disclosure as on AWS. Nothing has to propagate, and there is nothing to suspend on B2.
  - For an encrypted vault the rule covers only its files (`o/`), never `.vaulthalla/`, where its manifest keeps
    older roots as versions. A `--no-encrypt` vault's rule covers the whole bucket.
  - Rules other applications set are kept as they are, and `vh vault recovery status --refresh` shows Vaulthalla's
    rule, the others, and a warning when one of them deletes sooner.

  **Buckets created by 1.25.0 keep every version until you choose.** Run one of these per vault (on the server; the
  web console asks for a step-up, agents can't run them because they delete history):

  ```bash
  vh vault recovery status <vault> --refresh
  vh vault recovery set <vault> --mode off --accept-retention-shortening          # keep only the latest version
  vh vault recovery set <vault> --mode provider-versioning --retention 30d \
      --yes --accept-unpriced --accept-retention-shortening                       # keep 30 days of history
  ```

  The vault's API key must be enabled for provider administration and have Backblaze's `writeBuckets` capability.
  `vh vault recovery suspend` is refused on B2: use `--mode off`.

- **S3 gateway upstream profiles take a versioning default.** `vh s3-gateway upstream create|update <profile>
  --versioning off|<N>d|indefinite --accept-versioning` sets what every bucket created through the profile keeps;
  without it, buckets keep only the latest version. Only Backblaze B2 profiles accept anything but `off`. A change
  applies to buckets created afterwards.

- **Shortening provider retention now asks for a step-up** in the web console (data.destroy), on AWS S3 as on
  Backblaze B2, like `vh upstream lifecycle` already did. The `vh` CLI on the server is unchanged; agents are refused.
