## Security

- **Optional: bind sealed secrets to Secure Boot (Linux, TPM PCR 7).**
  - Off by default. With `secrets.tpm_pcr_policy: pcr7` in config.yaml, secrets sealed from then on open only while the TPM's PCR 7 (the secure-boot state) is unchanged. The setting alone never rebinds existing secrets.
  - `sudo vh secret reseal --pcr7` binds the existing ones. It refuses unless a hardware TPM seals the secrets, every vault's keys have a confirmed backup and a `vh secret export all` is under 24 hours old. Each secret is sealed again beside the old one, opened and compared before it replaces it; no secret changes and nothing is re-encrypted.
  - After a firmware or Secure Boot change the bound secrets do not open. Vaulthalla refuses to start with an error naming PCR 7 and the recovery paths (the exports, or a recovery boot and `vh secret reseal --none`), and never creates replacements. The docs describe the update drill.
  - `vh secret policy`, `vh status` and health show the policy, and warn when secrets are PCR-bound and no export is newer than 30 days. macOS is unaffected: the Secure Enclave has no PCRs.
