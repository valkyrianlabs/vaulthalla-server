## S3 gateway

- **Bucket configuration calls get real answers, and never create or delete a bucket.** Every bucket request with a
  subresource the gateway did not handle was taken for something else. A GET such as `get_bucket_versioning`,
  `get_bucket_lifecycle_configuration` or `get_bucket_location` was answered with a key listing, which clients read as
  an empty, successful answer, and `list_object_versions` listed no versions for a bucket full of objects. A PUT such as
  `put_bucket_versioning` was CreateBucket: it reported success without changing anything, and created the bucket when
  it did not exist. A DELETE such as `delete_bucket_lifecycle` or `delete_bucket_policy` was DeleteBucket and deleted
  the bucket when it was empty.
- Now a GET answers what S3 answers for a bucket that never had the feature configured: `?location` and `?versioning`
  answer an empty `LocationConstraint` (us-east-1) and `VersioningConfiguration` (never enabled), `?lifecycle`,
  `?policy`, `?cors`, `?tagging`, `?encryption`, `?object-lock`, `?website`, `?replication`, `?publicAccessBlock` and
  `?ownershipControls` answer their S3 "not found" errors, and ListObjectVersions (`?versions`), `?acl`,
  `?policyStatus` and any subresource the gateway does not know answer `NotImplemented`. Every PUT, DELETE or POST
  of a configuration answers `NotImplemented` and changes nothing. These calls are authorized as a listing of the
  bucket is. The full table is in the S3 gateway semantics page.

Nothing to do after upgrading. A tool that relied on `put_bucket_versioning` or a similar call appearing to succeed
now sees `NotImplemented`, which is what the gateway has always done: it never kept bucket configuration.
