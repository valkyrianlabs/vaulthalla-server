<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Vaulthalla moves to the Valkyrian Labs organization

Vaulthalla's source, issues and roadmap now live under Valkyrian Labs LLC on GitHub:
[valkyrianlabs/vaulthalla-server](https://github.com/valkyrianlabs/vaulthalla-server) and
[valkyrianlabs/vaulthalla-desktop](https://github.com/valkyrianlabs/vaulthalla-desktop). Old `vaulthalla/server` links
redirect. Nothing changes for installs: the APT repository, `apt.vaulthalla.sh` and `brew install --cask
vaulthalla/tap/vaulthalla` keep working.

## S3 gateway behind Cloudflare

The S3 gateway now works through a proxied Cloudflare record with the AWS CLI's CRT transfer client. Cloudflare drops
`Content-Length: 0` from GET, HEAD and DELETE requests that the client signed with it, which failed with
`SignatureDoesNotMatch`; the gateway now treats the missing header as `0` when the request had no body. Every gateway
response also carries `Cache-Control: private, no-store`, so a CDN never caches an object or a presigned GET. See
[Behind Cloudflare Or Another CDN](/s3-gateway/setup#behind-cloudflare-or-another-cdn).
