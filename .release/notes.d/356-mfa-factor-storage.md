## Security

- **Groundwork for multi-factor sign-in: factor storage.** The server can now store authenticator-app (TOTP) factors and one-time recovery codes, and keep passkeys on record. Nothing asks for a second factor yet: sign-in with passkeys and authenticator codes comes in a later release.
  - Authenticator seeds are sealed under a new internal key, `mfa_seal`, protected by this host's master key and bound to the account and factor they belong to. Recovery codes are stored only as keyed hashes under `mfa_pepper`, and each works once.
  - Neither key is ever regenerated while anything depends on it. If one can't be unsealed (for example a database restored without this host's sealed master), only that kind of factor stops working; passkeys and the local CLI recovery are unaffected.
  - Back them up with the other internal secrets: `vh secret export mfa-seal` and `vh secret export mfa-pepper` (both are included in `vh secret export all` once they exist).
