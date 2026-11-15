- Console: the cloud page (`/managed-storage`) gains the relay switch for web browsers (`cloud.relay.status|enable|
  disable`, shown with the `cloud.relay` capability to super admins and the admin cloud View permission; only super
  admins switch it, enabling through the device.trust step-up): the state in words, the last error, who switched it on
  and when, relayed connections, and what switching it on does and what the relay can see. The cloud features aren't
  offered yet, so there is no release note. The nav item now also shows on a linked server without a storage plan.
- Console: pairing requests with `via: relay` read "Web browser via Vaulthalla Cloud" and say the browser will be
  read-only; devices with `paired_via: relay` are marked Read-only in the device lists and revoke like any device.
- Console: panel header actions wrap inside the panel on narrow screens instead of running past its edge (the managed
  storage plan panel's "Leave managed storage" did at 390 px).
- The encryption-claims lint allows the relay's two console names ("Vaulthalla Cloud's relay", "Web browser via
  Vaulthalla Cloud") only in sentences that say nothing of recovery, custody, escrow or availability.
