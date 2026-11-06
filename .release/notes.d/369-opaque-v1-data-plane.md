- **Very large uploads to S3 and R2 no longer stop at about 48.8 GiB.** Multipart uploads now grow their part size
  with the object (5 MiB parts up to 48.8 GiB, larger parts above), so a single file can use the provider's full
  object size within the 10,000-part limit. Smaller uploads are unchanged.
