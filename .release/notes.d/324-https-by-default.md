- **HTTPS by default on Linux.** A new install (and an upgraded host still on the unmodified packaged site) serves
  the web console over HTTPS with a certificate generated for the host, and `http://` redirects to `https://`.
  Browsers ask you to accept that certificate once; `sudo vh setup nginx` prints its SHA-256 fingerprint to compare.
  The package renews it on upgrades, and `sudo vh setup local-tls` does so on demand. For a certificate browsers
  trust right away, use `vh setup nginx --certbot` (now with HSTS) or `--certbot-dns-cloudflare`. A host behind
  another TLS terminator keeps plain HTTP with `vh setup nginx --plain-http`. A site you edited, or one
  `vh setup nginx` generated without a certificate, isn't changed on upgrade; the upgrade prints a reminder.
- The console and its file lanes now send `X-Content-Type-Options`, `Referrer-Policy: no-referrer` (share links
  carry their token in the address), `X-Frame-Options: DENY` and `frame-ancestors 'none'`.
- The web socket refuses connections opened by pages on other sites. If you serve the console from a different host
  than the daemon, list it under `websocket_server.allowed_origins`.
- **The S3 gateway now listens on loopback by default** (`127.0.0.1:39000`), and a config without a `host` setting
  never binds every interface. Remote S3 clients use the HTTPS S3 hostname (`vh setup nginx --s3-domain` or Caddy).
  Existing `config.yaml` files keep their settings.
