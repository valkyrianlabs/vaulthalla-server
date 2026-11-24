## macOS

- Upgrading or uninstalling the `vaulthalla-server` cask no longer spends about 25 seconds removing the previous
  version's files: they are deleted in batches instead of one at a time. The "Waiting for … to stop" message now
  appears only when a service really takes more than a couple of seconds to stop, instead of on almost every run.
