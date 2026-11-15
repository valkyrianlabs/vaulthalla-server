- Experimental replicated vaults: `vh vault join --from-cloud` refuses (flag off, an agent, a browser session, not a
  super admin) before its restore request reaches Vaulthalla Cloud, so the cloud never adds a replica this server then
  refuses.
- `vh vault replica remove` on a linked server reports the removed writer to Vaulthalla Cloud and says whether the
  cloud still lists that server (the account holder removes it there); `vh vault sync info` and `storage.vault.get`
  show each writer's standing at the cloud (`manifest.replicas[].cloud`) and the servers the cloud lists that aren't
  writers (`manifest.cloud_only`). Former replicas are matched to the manifest's writers by the node id the cloud now
  sends.
