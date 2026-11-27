- Linked servers (design/peers/link.md), on by default with no setting (a `peers:` section left in config.yaml is
  ignored); a server that has linked nothing loads, dials and runs nothing for them (`Peers::anyRecorded`). Two
  servers pair by number matching (`vh peer pair` / `vh peer link`, ws `peer.pairing.*` and `peer.link.*`, domain
  `vh/peer/sas/v1` over both keys, nonces and peer cards; `expect_spki` for a brokered pairing), keep one pinned,
  mutually authenticated websocket (the device listener's identity both ways; peer.hello, peer.ping, peer.endpoints;
  tie-break on node id; capped jittered reconnect), and unlink (`vh peer unlink`, peer.unlinked). A linked server is a
  `Peer` ws session that runs only the peer wire set. Migration 157 (`peer` table) and a sealed `peer_wrap` key,
  created by the first window.
- `vh secret device-identity rotate` announces the new key to connected linked servers before the switch and revokes
  the links that didn't store it; `--revoke-peers` drops every link.
- The MCP catalog excludes `vh peer`; scoped and relayed devices can't reach `peer.*`.
