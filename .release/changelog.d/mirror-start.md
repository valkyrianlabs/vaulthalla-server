- Starting a mirror (migration 163_mirror_start.sql; design/peers/mirror.md "As built: starting a mirror"): the control
  plane of the server mirror, experimental and off by default (peers.experimental).
  - mirror_offer (one row per start on each side, shared offer_uid; states offered/pending/accepted/keys_acked/
    installed/started and declined/cancelled/expired/failed; a notify flag for what the other server must still be
    told; 7-day expiry of unanswered offers; finished rows swept after 30 days, never a started one whose mirror lives),
    peer.accept_vaults (+ set_by, set_at), vault_key_origin.anchor gains 'peer'.
  - ops::mirrors (vh mirror add|pending|accept|decline|cancel|list|info|accept-all; ws mirror.add, mirror.pending,
    mirror.accept, mirror.decline, mirror.cancel, mirror.list, mirror.get, mirror.accept_all.set; keys step-up on
    mirror.add in the console; peer_forbidden for agents, scoped and relayed devices; MCP catalog excludes mirror).
  - Wire on a Peer session: peer.mirror.offer, .answer, .keys (KEV1 X25519 to the peer wrap key, the core's key check
    and attestation; proven with vault::recover::prove against the pinned attestation keys; one unprovable version
    refuses the start), .begin, .grant, .cancel. LinkService::request sends a request over a link and waits.
  - The mirror's vault: local, the core's vault uid and root folder uid, owner a remote account (home node, id),
    keys sealed under this host's vault master with provenance over the new vault id and their origin, the mirror row
    with no grant, all in one transaction. MirrorVaults::startCore runs on the core only after the keys are
    acknowledged.
  - Services MirrorStarter (tells, asks, retries, expires, sweeps; keeps every mirror's grant current from
    PeerVault::role, at begin, on link-up and on every change) and MirrorContents (fetches a mirror's pending contents
    in the background on the link's background transfer slots, bounded, with jittered backoff).
  - Key rotation and key salvage refused on a vault that is mirrored (any role) or whose start runs
    (vault_mirrored): EncryptionManager::prepare_key_rotation, mintSalvageKey, vh vault keys rotate.
