- S3 gateway: upstream profiles (migration 154_s3_gateway_upstream_profiles.sql: s3_gateway_upstream_profile, the
  credential's upstream_profile_id / upstream_server_default / upstream_reapply, the bucket's
  created_by_credential_id / upstream_profile_id, and the allowlist s3_gateway_credential_upstream_profile: a profile
  a request names must be the credential's own or listed, else Denied). A gateway CreateBucket resolves a profile
  (ops::s3_gateway::profileForCreate: LocationConstraint, signing region, the credential's profile, the server default
  it follows) and creates the bucket through ops::vaults::create with the new provisioning mode
  ops::upstream::BucketMode::CreateOrAdoptEmpty: create the upstream bucket, or adopt this account's own while it
  lists empty; a bucket that holds objects or a name another account holds is a Conflict and nothing is changed.
  - The gateway answers ops refusals as S3 errors: Conflict 409 BucketAlreadyExists, Denied 403 AccessDenied, other
    refusals 400 InvalidArgument, a provider failure 503 ServiceUnavailable; a malformed CreateBucketConfiguration is
    400 MalformedXML. A bucket subresource PUT is answered as before.
  - CLI: `vh s3-gateway upstream list|show|create|update|delete`; `creds scope <credential> set --upstream
    <profile>|server-default|local [--reapply on|off|inherit] [--allow-upstream <profile>|none]...`; `creds scope <credential> show` and `creds list`
    report it (JSON: `upstream`).
  - ws: s3.gateway.upstreamProfiles.list|create|update|delete, s3.gateway.credentials.upstream.set (step-up family
    secrets); S3GatewayCredential gains `upstream`, S3GatewayBucket `created_by_credential_id` and
    `upstream_profile_id`; new models S3GatewayUpstreamProfile and S3GatewayCredentialUpstream.
  - Config: s3_gateway.default_upstream_profile (validated on settings.update) and
    s3_gateway.reapply_upstream_profile_changes.
  - ops::api_keys::remove refuses a key an upstream profile uses (the foreign key is ON DELETE RESTRICT).
- Web console: an Upstream tab on the S3 gateway page (profiles), a "New buckets" block on a key, and the two server
  settings.
