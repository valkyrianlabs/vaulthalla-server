- Step-up: a full-access paired device's own session (not scoped, not relayed) satisfies the `secrets` family
  (S3 gateway keys, provider credentials) with no approval and no recovery cooldown; RBAC decides. Audited as
  `auth.stepup.grant` with `method: device_session`. Other families are unchanged (`stepup::deviceSessionSatisfies`).
- S3 gateway: error responses to `HEAD` carry no body (one was left on kept-alive connections and read as the next
  response).
