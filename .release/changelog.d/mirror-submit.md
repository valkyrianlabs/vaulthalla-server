- Server mirror (experimental, behind peers.experimental): a change made on the mirror. ops::fs applies mkdir, move,
  rename and remove on a Live mirror as pending (migration 166: mirror_pending, mirror_dirty, mirror_held), submits them
  in order with peer.mirror.submit, and the core executes them as the person under the linked server's vault role
  (mirror_submission: answered once per request id, executed on the sync pool, logged with the request id in origin).
  The applier confirms a change from its own groups without applying it twice and settles the entries it held; a name
  clash becomes a conflict copy, any other refusal a held change. Copy is submitted only. Log rows carry origin on the
  wire.
