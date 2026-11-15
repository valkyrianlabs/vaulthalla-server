- Managed storage groundwork, from its first end-to-end drill against the account service (not offered yet):
  `vh vault recover --from-cloud --vault-uid <uid>` without `--api-key` restores a vault kept in managed storage
  with a bucket key of this server's own, adopted only after the restore succeeds; the service asks for a new bucket
  key when access returns after a suspension; the client reads the account service's contract under one name each
  (`account_key_offline_copy_confirmed`, `ejection_portal_url`, base64url envelopes, `moved_to {deployment_id,
  name}`); an address the account service gives to open (billing, leaving managed storage) is https, or http only to
  this host.
