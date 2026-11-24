- S3 gateway: bucket subresource requests (`/<bucket>?versioning`, `?lifecycle`, `?policy`, ...) are configuration calls,
  routed before CreateBucket, DeleteBucket and the listing. A config PUT created a missing bucket and a config DELETE
  deleted an empty one; every unhandled GET was answered with a key listing. GETs now answer S3's defaults for an
  unconfigured bucket (`?location`, `?versioning`, `?notification`, `?logging`, `?accelerate`, `?requestPayment`) or its
  404 (`NoSuchLifecycleConfiguration`, `NoSuchBucketPolicy`, ...); `?versions`, `?acl`, `?policyStatus`, unknown
  subresources and every write answer 501 `NotImplemented`. Authorised as a listing.
- `tools/smoke/s3_gateway_bucket_subresources.py`: read-only boto3 check of a bucket's configuration answers, run by
  `S3GatewayDbTest.Boto3HearsS3sAnswersForBucketConfiguration`.
