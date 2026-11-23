## S3 gateway

- **Listings of more than one page work with every S3 client.** The continuation token of ListObjectsV2 was the last
  key, percent-encoded whenever the client asked for `EncodingType=url`, which boto3, the AWS CLI and most SDKs always
  do. Clients send a token back untouched, so the second request listed the first page again: boto3 stopped with
  "The same next token was received twice", and no bucket with more than 1,000 keys (or any listing with a smaller
  page size) could be listed. The token is now opaque and never encoded. A token the gateway did not issue is refused
  with `InvalidArgument`; a listing in flight across the upgrade starts over.
- **Keys are listed in S3's order.** Listings followed the locale of the PostgreSQL cluster (`big.bin` before
  `big-single.bin`, case mixed together). They are now in ascending UTF-8 byte order on every install, and
  `start-after`, `marker` and continuation tokens resume with the same comparison, so paging can't skip or repeat a
  key. Tools that merge or diff listings by comparing keys (sync and backup clients) get what they expect. In-progress
  multipart uploads list in the same order.
- **ListObjects (v1) pages.** A bucket GET without `list-type=2` now answers as ListObjects: it honors `marker` and
  returns `Marker` and `NextMarker`. It used to answer in the ListObjectsV2 shape and ignore `marker`, so a v1 client
  never got past the first page.
- **`start-after` with a delimiter** lists the common prefix that the named key lies in when keys after it remain
  there, as S3 does, and the answer echoes `StartAfter` and `ContinuationToken`.

Nothing to do after upgrading. Clients that paged with `start-after` to work around the token keep working.
