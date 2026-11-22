## AI apps

- **Groundwork for remote AI connectors (`vh connector`).** A super admin can now set up how hosted AI apps (Claude,
  ChatGPT) and AI tools on other computers will be allowed to connect to this server: the switch and the public
  https address (`vh connector enable --url https://<host>`), the widest access a connection may get (read and change
  by default, `vh connector set --max-scope`), and clients registered by hand. Connected apps are listed and
  disconnected with `vh connector list` and `vh connector revoke`. Nothing answers remote sign-ins yet: the sign-in
  endpoints come in a later release, so switching it on today exposes nothing. Off by default; agents can never use
  these commands.
