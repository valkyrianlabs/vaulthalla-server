## Security

- **Thumbnail URLs no longer carry file names.** `POST /preview/batch` now answers with `entry=<id>` URLs instead of `path=` URLs, for vaults and share links, so file names stop leaving through thumbnail requests in proxy access logs, browser history and Referer headers. The ids resolve through the same permission checks as paths, and a share link still only reaches entries inside its scope.
