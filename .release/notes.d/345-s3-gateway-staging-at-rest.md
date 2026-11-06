## Security

- **The S3 gateway no longer writes object data to disk as plaintext.**
  - Request bodies of streamed PUT and UploadPart requests are staged encrypted under a key that exists only in the daemon's memory, and deleted once the request is answered. Nothing a crash leaves behind can be read.
  - Multipart upload parts are stored encrypted under the vault's key, each bound to its vault, upload and part number, so an upload in progress can still be resumed after a restart or a vault key rotation. CompleteMultipartUpload streams the parts into the object without writing a plaintext copy.
  - A stored part that fails its integrity check makes CompleteMultipartUpload answer `InvalidPart`. Nothing is written, the upload stays open, and the client can upload that part again.
  - Part ETags, part sizes and object ETags are unchanged.
- **Upgrading converts what older versions left behind.**
  - On the first start, the daemon encrypts every part of in-progress multipart uploads that an older version stored as plaintext, after checking it against its recorded checksum, and then deletes the plaintext. Uploads in progress keep working.
  - A plaintext part that no longer matches its checksum is left as it is and logged. CompleteMultipartUpload refuses it, and it is deleted when the upload is aborted or expires.
  - Leftover plaintext request bodies (`<state dir>/s3-request-body/`) and the plaintext temporary file of an interrupted completion are deleted.
  - No operator action is needed. Downgrading after the conversion isn't supported: older versions can't read the encrypted parts, so complete or abort in-progress multipart uploads first.
