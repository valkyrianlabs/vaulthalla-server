- S3 gateway: ListObjectsV2 continuation tokens are opaque (`vh1.` + base64url of the last item, `protocols/s3/Listing.hpp`)
  and never percent-encoded under `EncodingType=url`; they were the URL-encoded last key, which no client decodes, so
  every second page was the first again. Unknown tokens answer `InvalidArgument`.
- S3 gateway: object listings sort and resume by UTF-8 bytes (`~<~`/`~>~` on `idx_s3_gateway_object_vault_key`) instead
  of the database collation, for local, `remote_cache` and `remote_proxy` buckets; ListMultipartUploads too.
- S3 gateway: bucket GET without `list-type=2` is ListObjects v1 (`marker`, `Marker`, `NextMarker`, no `KeyCount`);
  `start-after`/`marker` inside a common prefix still list that prefix; listing parameters that are not UTF-8 answer
  `InvalidArgument`. ListObjectsV2 echoes `StartAfter` and `ContinuationToken`.
- `tools/smoke/s3_gateway_list_paging.py`: read-only boto3 paginator check of a gateway bucket (order, v1, StartAfter,
  delimiter), run by `S3GatewayDbTest.Boto3PaginatorsListABucketLargerThanOnePage` over 2,500 keys.
