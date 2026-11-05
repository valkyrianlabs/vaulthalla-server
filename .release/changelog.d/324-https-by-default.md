- TLS by default (#324): `vh setup nginx` without a certificate mode renders HTTPS with a local self-signed
  certificate (`/etc/vaulthalla/tls/local.{crt,key}`; ECDSA P-256, 825 days; SAN: host names, `localhost`,
  loopback and the host's addresses) and a 308 redirect; new `vh setup local-tls [--force]` creates or renews it
  (postinst runs it on install and upgrade). `--plain-http` keeps HTTP. `--certbot` passes `--hsts`; the
  Cloudflare DNS-01 site sends HSTS. The packaged site (`deploy/nginx/vaulthalla.conf`) is HTTPS; postinst
  replaces an installed site byte-identical to any earlier packaged plain-HTTP template and warns about other
  plain-HTTP sites. Its verification probe follows the redirect to `https://127.0.0.1/`.
- Security headers from nginx (all managed sites) and from the console itself (`next.config.ts` `headers()`):
  nosniff, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, a restrictive
  `Permissions-Policy`.
- ws handshake refuses a browser `Origin` whose host differs from `Host`/`X-Forwarded-Host` and isn't in the new
  `websocket_server.allowed_origins` (403 before hydration; `ws/OriginPolicy.hpp`).
- Listener host defaults are `127.0.0.1` (ws, HTTP, S3 gateway: compiled, YAML and JSON decoders, lifecycle
  projection); the shipped `s3_gateway.host` is `127.0.0.1`.
- Tests: `WsOrigin.*`, `ListenerDefaults.*`, lifecycle `HttpsByDefaultTests`/`LocalCertificateTests` (real
  openssl), `PostinstNginxTlsUpgradeTests`.
