# Linked servers and the server mirror

Design documents, never published (they live outside `docs/`). Phase 0 of the server mirror plan of 2026-11-25.
Phase 1a, the link (link.md), is built, experimental and off by default (`peers.experimental`); nothing else here is.

| Document | One line |
|---|---|
| [link.md](link.md) | Two servers pair, directly or through a Desktop paired with both, and keep one mutually authenticated connection. A linked server is its own kind of principal |
| [identity.md](identity.md) | Permanent ids for accounts, remote accounts, who owns and may use a mirrored vault, making two servers one deployment, audits across both |
| [mirror.md](mirror.md) | One vault on two servers: the core commits every change first, the mirror follows its replication log; changes made on the mirror; read-only while the link is down; moving the core; leaving a mirror; remotes |
| [spikes/](spikes/README.md) | What was checked in the code first, including a test run on dev |

Related: [`../storage/remotes.md`](../storage/remotes.md) (several equal remotes per vault) and
[`../cloud/mirrors.md`](../cloud/mirrors.md) (the older, experimental bucket-based replicas, which are a different
feature).

Order of work: the link and the identity foundation, then mirroring local vaults, then vaults with a remote and
forced promotion, then the full deployment mirror. Several remotes per vault is a separate track.
