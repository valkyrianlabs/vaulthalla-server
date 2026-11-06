## Security

- **See and sign out your sessions.**
  - **Account › Security › Sessions** lists every browser signed in to your account: where it signed in from, when, how, and when it was last used.
  - Sign out any one of them, or every other one at once. A signed-out browser loses access immediately, including previews, downloads and uploads already open in it.
- **Session fixation is closed.**
  - A connection now signs in once. Signing in again on a connection that is already signed in is refused (`already_signed_in`), and a session cookie is only ever adopted from its stored record, never from another open connection.
  - A sign-in cookie planted in someone's browser can no longer turn into their session when they sign in.
- **Groundwork for multi-factor sign-in.** Each session now records how its sign-in was proven (a password today), and every use of the session is checked against the account's sign-in policy. Nothing is required yet: this prepares the coming passkey and authenticator-code sign-in.
