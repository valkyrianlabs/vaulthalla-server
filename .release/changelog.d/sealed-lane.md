- Sealed file contents between linked servers (migration 161_mirror_contents.sql; design/peers/mirror.md "As built:
  sealed contents"): the device listener's sealed lane, GET|HEAD /peer/object/<vault uid>/<object uid>/<generation>,
  serves a file generation's backing bytes as they are (ETag = generation, one byte range) to a vault's linked server
  only, only while peers.experimental is on, VHF1 only, refusing with not_found, peer_revoked,
  generation_not_current, format_not_portable and not_held; unlinking closes its connections.
  - peer::object::fetch, the pinned client (the link's TLS context and pin check, resume by range, deadlines); peer::Transfers,
    4 transfers per peer with one kept for interactive opens. mirror_content_pending records what a mirror still expects
    (generation, key version, size, BLAKE2b, mtime; three failures mark a file failed); mirror::contents::receive
    verifies size, hash and authentication before a compare-and-set and the link into place.
  - Opening a not-yet-received file on a mirror fetches it first (15 s at most); otherwise 503 mirror_link_down |
    mirror_fetch_timeout | mirror_fetch_failed on the HTTP lanes and ENOLINK | ETIMEDOUT | ENODATA through the mount.
    Internal API only: no ws, CLI or peer command marks a file as expected.
