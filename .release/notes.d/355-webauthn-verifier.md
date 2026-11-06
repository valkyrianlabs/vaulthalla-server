## Security

- **Groundwork for passkeys and security keys (not MFA yet).** The server now contains a WebAuthn verifier for
  registering passkeys and checking sign-in assertions (ES256, Ed25519 and RS256 keys of 2048 bits or more). Nothing
  uses it yet: passkey sign-in and enrollment arrive in a later release, and until then Vaulthalla has no multi-factor
  authentication.
- **New settings: `auth.webauthn.rp_id`, `rp_name` and `origins`** (**Settings › Security › Passkeys / security
  keys**, or `config.yaml`). Passkeys are tied to the host name people open the console at, so it is set explicitly
  and never taken from request headers. Leave `rp_id` empty (the default) until passkeys ship. `rp_id` must be a
  host name, never an IP address, and each origin must be exactly `https://host[:port]` under it
  (`http://localhost:<port>` for development). The daemon refuses to start, and the settings page refuses to save,
  when the values break these rules. Changing `rp_id` later makes passkeys registered for the old one unusable; the
  settings page warns before you save such a change.
