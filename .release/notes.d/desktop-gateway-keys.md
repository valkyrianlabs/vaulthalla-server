## S3 gateway

- **Vaulthalla Desktop can create, rotate and delete S3 gateway keys.** A paired Mac with full access no longer gets
  "approve it on this device or in the web console" for gateway keys: its device key already proves who it is, so
  your account's permissions are the only check, as for any other action you take in Desktop. The same applies to
  the other `secrets` operations (provider credentials). Scoped devices, devices reached through the relay and AI
  apps still can't do these, and the web console still asks for a step-up. Each one is recorded in the audit trail.
- **HEAD errors no longer carry a body.** A `HEAD` that failed (a missing key, for example) answered with an XML
  error body, which clients that keep the connection open (rclone, Go's HTTP client) read as the answer to their
  next request. It now answers with the status and `x-amz-request-id` only, as S3 does.
