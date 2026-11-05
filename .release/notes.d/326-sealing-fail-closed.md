## Security

- **A lost master secret is never replaced silently.**
  - If the sealed secret that protects vault keys, provider API keys or S3 gateway credentials is missing while those records exist, Vaulthalla now refuses to generate a new one and says how to recover.
  - Before, it generated a new secret, which left every existing key undecryptable.
- **macOS: no silent fallback to unprotected files.**
  - Without a usable Secure Enclave, sealing refuses and health reports the backend as `unavailable`.
  - Breaking: a Mac that was running on the file fallback (an Intel Mac without T2, or a daemon outside launchd) must either move to a Mac with a Secure Enclave or set `secrets.allow_development_file_backend: true` in config.yaml. That setting is for development only. Existing secrets are kept as they are.
- **The sealing posture is visible.** `vh status`, health and the console show whether secrets are protected by `hardware` (a TPM or the Secure Enclave), `software` (swtpm) or `development` (files). The new `secrets.require_hardware: true` setting refuses anything but hardware sealing.
