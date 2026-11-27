## Linked servers (experimental, off by default)

- **Mirror status in one read.** Each row of `mirror.list` and `mirror.get` now includes what the web console used to
  gather from other commands: how many changes are not confirmed yet, the first copy's progress, whether the link is
  up, when the last position was acknowledged, and the settings that apply (a mirror's versions setting, and this
  server's accept-all, keep-removed and mirror-all settings for that linked server).
