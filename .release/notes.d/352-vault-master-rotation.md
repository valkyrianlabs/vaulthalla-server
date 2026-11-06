## Security

- **The vault master can be rotated.** `vh secret master rotate` replaces the installation secret that wraps every vault key, without re-encrypting any file.
  - The new wraps are staged and verified against each key's recorded key check before anything switches, and every key row switches in one step. An interrupted rotation resumes where it stopped.
  - The previous master is kept for a 7-day recovery window: `vh secret master rollback` returns to it, `vh secret master finalize` ends the window sooner. When the window ends, every key is verified again before the previous master is deleted.
  - Super admins only, from a terminal (never agents or the console), and every step is audited. `vh secret master status` shows the version and any rotation in progress.
  - A database backup taken before a rotation needs the previous master: after the window ends, restore it through the vault key exports.
