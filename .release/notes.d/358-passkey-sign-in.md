## Security

- **Sign in with a passkey alone.** The sign-in page has a **Sign in with passkey** button, and browsers that support it offer your passkeys right in the username field. Pick the passkey, unlock it (Touch ID, Windows Hello, your security key's PIN, or 1Password), and you're in: no username or password. It works with any passkey already added to your account (1Password, your device's passkey manager, or a security key), and counts as a full second-factor sign-in.
  - The passkey must be unlocked with a PIN or biometric (user verification). A passkey made for another server address is never accepted, and a failed attempt says only that the passkey couldn't sign you in.
  - Passkeys synced across devices (1Password, iCloud Keychain, Google Password Manager) work from every device that holds them.
  - Needs the server's address configured for passkeys (Settings › Security, `auth.webauthn.rp_id` and `origins`); without it passkey sign-in is unavailable and the password sign-in works as before. Paired Desktop devices are not affected.
