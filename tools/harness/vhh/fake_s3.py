"""A small S3-compatible object store for harness drills (path-style addressing, plain HTTP on loopback).

It implements what a Vaulthalla daemon sends to a bucket: bucket create/head/delete, versioning (Enabled, Suspended,
or never enabled), PUT with If-Match / If-None-Match, CopyObject, multipart uploads (initiate, parts, complete, abort,
list), GET and HEAD (Range, versionId, If-Match, If-None-Match), DELETE (delete markers when versioned, ?versionId),
DeleteObjects, ListObjectsV2 and ListObjectVersions (paged), and the bucket subresources the upstream control plane
reads (location, lifecycle, notification, object-lock) as "not configured". Signatures are not verified: it binds to
127.0.0.1 only and serves one drill.

Every request is logged (method, bucket, key, query, Range, status, body bytes sent), so a drill can prove what a
restore downloaded. A side channel under /__vhh/ (never an S3 path) lets the drill inspect and damage the bucket the
way an untrusted provider could: raw reads and writes, deleting a key, purging its versions, snapshots of the whole
store and seeding an incomplete multipart upload. Nothing here reads credentials.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

PAGE = 1000


@dataclass
class Version:
    version_id: str
    body: bytes = b""
    etag: str = ""
    last_modified: float = 0.0
    delete_marker: bool = False
    meta: dict = field(default_factory=dict)
    storage_class: str | None = None


@dataclass
class Bucket:
    versioning: str | None = None  # None (never enabled), "Enabled", "Suspended"
    objects: dict = field(default_factory=dict)  # key -> [Version] (oldest first)
    uploads: dict = field(default_factory=dict)  # upload id -> {"key": str, "parts": {n: bytes}, "meta": dict}
    config: dict = field(default_factory=dict)   # subresource -> body


def _iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(t))


def _etag(body: bytes) -> str:
    return '"' + hashlib.md5(body).hexdigest() + '"'


class Store:
    def __init__(self):
        self.lock = threading.RLock()
        self.buckets: dict[str, Bucket] = {}
        self.log: list[dict] = []
        self.snapshots: dict[str, dict] = {}
        self._seq = 0

    def next_version_id(self) -> str:
        self._seq += 1
        return f"v{self._seq:08d}-{uuid.uuid4().hex[:8]}"

    def latest(self, b: Bucket, key: str) -> Version | None:
        stack = b.objects.get(key)
        return stack[-1] if stack else None

    def find(self, b: Bucket, key: str, version_id: str) -> Version | None:
        for v in b.objects.get(key, []):
            if v.version_id == version_id:
                return v
        return None

    def write(self, b: Bucket, key: str, v: Version) -> Version:
        stack = b.objects.setdefault(key, [])
        if b.versioning == "Enabled":
            v.version_id = self.next_version_id()
            stack.append(v)
        else:
            v.version_id = "null"
            stack[:] = [x for x in stack if x.version_id != "null"]
            stack.append(v)
        return v

    def delete(self, b: Bucket, key: str) -> Version | None:
        if b.versioning is None:
            b.objects.pop(key, None)
            return None
        marker = Version(version_id="", delete_marker=True, last_modified=time.time())
        return self.write(b, key, marker)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "vhh-fake-s3"
    store: Store = None  # set by serve()

    def log_message(self, *args):  # quiet
        pass

    # ---------------------------------------------------------------- plumbing
    def _body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            out = bytearray()
            while True:
                size = int(self.rfile.readline().strip().split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                out += self.rfile.read(size)
                self.rfile.readline()
            raw = bytes(out)
        else:
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if "aws-chunked" in self.headers.get("Content-Encoding", "") or \
                self.headers.get("x-amz-content-sha256", "").startswith("STREAMING-"):
            raw = self._decode_aws_chunked(raw)
        return raw

    @staticmethod
    def _decode_aws_chunked(raw: bytes) -> bytes:
        out, i = bytearray(), 0
        while i < len(raw):
            nl = raw.index(b"\r\n", i)
            size = int(raw[i:nl].split(b";")[0], 16)
            i = nl + 2
            if size == 0:
                break
            out += raw[i:i + size]
            i += size + 2
        return bytes(out)

    def _send(self, status: int, body: bytes = b"", headers: dict | None = None, head: bool = False,
              ctype: str = "application/xml"):
        self.send_response(status)
        hdrs = {"Content-Type": ctype, "Content-Length": str(len(body)), "x-amz-request-id": uuid.uuid4().hex[:16]}
        hdrs.update(headers or {})
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.end_headers()
        if body and not head:
            self.wfile.write(body)
        self._entry["status"] = status
        self._entry["bytes_out"] = 0 if head else len(body)

    def _error(self, status: int, code: str, message: str = "", head: bool = False, headers: dict | None = None):
        body = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code>"
                f"<Message>{escape(message or code)}</Message></Error>").encode()
        self._send(status, body, headers, head=head)

    def _xml(self, root: str, inner: str, status: int = 200):
        body = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><{root} xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                f"{inner}</{root}>").encode()
        self._send(status, body)

    def _route(self):
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        segs = path.lstrip("/").split("/", 1)
        bucket = segs[0] if segs and segs[0] else ""
        key = segs[1] if len(segs) > 1 else ""
        return bucket, key, query

    def _dispatch(self, method: str):
        bucket, key, query = self._route()
        self._entry = {"t": time.time(), "method": method, "bucket": bucket, "key": key,
                       "query": sorted(query.keys()), "range": self.headers.get("Range"), "status": 0, "bytes_out": 0}
        try:
            if bucket == "__vhh":
                return self._admin(method, key, query)
            with self.store.lock:
                if not bucket:
                    return self._list_buckets()
                if not key:
                    return self._bucket(method, bucket, query)
                return self._object(method, bucket, key, query)
        except Exception as e:  # pragma: no cover - surfaced as a 500 the client reports
            self._error(500, "InternalError", str(e))
        finally:
            if bucket != "__vhh":
                with self.store.lock:
                    self.store.log.append(self._entry)

    def do_GET(self): self._dispatch("GET")
    def do_HEAD(self): self._dispatch("HEAD")
    def do_PUT(self): self._dispatch("PUT")
    def do_POST(self): self._dispatch("POST")
    def do_DELETE(self): self._dispatch("DELETE")

    # ---------------------------------------------------------------- service / bucket
    def _list_buckets(self):
        inner = "<Owner><ID>vhh</ID></Owner><Buckets>" + "".join(
            f"<Bucket><Name>{escape(n)}</Name><CreationDate>{_iso(time.time())}</CreationDate></Bucket>"
            for n in sorted(self.store.buckets)) + "</Buckets>"
        self._xml("ListAllMyBucketsResult", inner)

    def _bucket(self, method: str, name: str, query: dict):
        b = self.store.buckets.get(name)
        if method == "PUT" and not query:
            self._body()
            if b is None:
                self.store.buckets[name] = Bucket()
            return self._send(200, b"", {"Location": "/" + name})
        if b is None:
            self._body()
            return self._error(404, "NoSuchBucket", head=method == "HEAD")
        if method == "HEAD":
            return self._send(200, b"", {"x-amz-bucket-region": "us-east-1"}, head=True)
        if method == "DELETE" and not query:
            if any(b.objects.values()):
                return self._error(409, "BucketNotEmpty")
            del self.store.buckets[name]
            return self._send(204)
        if "versioning" in query:
            if method == "PUT":
                body = self._body().decode()
                status = "Enabled" if "<Status>Enabled</Status>" in body else "Suspended"
                if b.versioning is not None or status == "Enabled":
                    b.versioning = status
                return self._send(200)
            status = f"<Status>{b.versioning}</Status>" if b.versioning else ""
            return self._xml("VersioningConfiguration", status)
        if "location" in query:
            return self._xml("LocationConstraint", "")
        if "versions" in query:
            return self._list_versions(b, query)
        if "uploads" in query:
            inner = "".join(f"<Upload><Key>{escape(u['key'])}</Key><UploadId>{uid}</UploadId>"
                            f"<Initiated>{_iso(u['t'])}</Initiated></Upload>" for uid, u in b.uploads.items())
            return self._xml("ListMultipartUploadsResult", f"<Bucket>{escape(name)}</Bucket><IsTruncated>false"
                                                          f"</IsTruncated>{inner}")
        if "delete" in query and method == "POST":
            return self._delete_objects(b, self._body())
        for sub, missing in (("lifecycle", "NoSuchLifecycleConfiguration"),
                             ("object-lock", "ObjectLockConfigurationNotFoundError"), ("tagging", "NoSuchTagSet"),
                             ("policy", "NoSuchBucketPolicy"), ("cors", "NoSuchCORSConfiguration"),
                             ("encryption", "ServerSideEncryptionConfigurationNotFoundError")):
            if sub in query:
                if method == "PUT":
                    b.config[sub] = self._body()
                    return self._send(200)
                if method == "DELETE":
                    b.config.pop(sub, None)
                    return self._send(204)
                if sub in b.config:
                    return self._send(200, b.config[sub])
                return self._error(404, missing)
        if "notification" in query:
            if method == "PUT":
                b.config["notification"] = self._body()
                return self._send(200)
            return self._send(200, b.config.get("notification") or
                              b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><NotificationConfiguration/>")
        if method == "GET":
            return self._list_objects(b, name, query)
        self._body()
        return self._error(400, "NotImplemented", f"{method} on a bucket with {sorted(query)}")

    def _list_objects(self, b: Bucket, name: str, query: dict):
        prefix = query.get("prefix", "")
        token = query.get("continuation-token") or query.get("start-after") or ""
        limit = min(int(query.get("max-keys", PAGE) or PAGE), PAGE)
        keys = sorted(k for k, s in b.objects.items() if k.startswith(prefix) and s and not s[-1].delete_marker
                      and k > token)
        page, more = keys[:limit], len(keys) > limit
        inner = (f"<Name>{escape(name)}</Name><Prefix>{escape(prefix)}</Prefix><KeyCount>{len(page)}</KeyCount>"
                 f"<MaxKeys>{limit}</MaxKeys><IsTruncated>{'true' if more else 'false'}</IsTruncated>")
        if more:
            inner += f"<NextContinuationToken>{escape(page[-1])}</NextContinuationToken>"
        for k in page:
            v = b.objects[k][-1]
            inner += (f"<Contents><Key>{escape(k)}</Key><LastModified>{_iso(v.last_modified)}</LastModified>"
                      f"<ETag>{escape(v.etag)}</ETag><Size>{len(v.body)}</Size>"
                      f"<StorageClass>{v.storage_class or 'STANDARD'}</StorageClass></Contents>")
        self._xml("ListBucketResult", inner)

    def _list_versions(self, b: Bucket, query: dict):
        prefix = query.get("prefix", "")
        key_marker, vid_marker = query.get("key-marker", ""), query.get("version-id-marker", "")
        limit = min(int(query.get("max-keys", PAGE) or PAGE), PAGE)
        rows = []
        for k in sorted(b.objects):
            if not k.startswith(prefix):
                continue
            stack = b.objects[k]
            for i, v in enumerate(reversed(stack)):
                rows.append((k, v, i == 0))
        if key_marker:
            idx = 0
            for idx, (k, v, _) in enumerate(rows):
                if (k, v.version_id) == (key_marker, vid_marker) or (not vid_marker and k > key_marker):
                    break
            else:
                idx = len(rows)
            rows = rows[idx + (1 if vid_marker else 0):]
        page, more = rows[:limit], len(rows) > limit
        inner = (f"<Prefix>{escape(prefix)}</Prefix><MaxKeys>{limit}</MaxKeys>"
                 f"<IsTruncated>{'true' if more else 'false'}</IsTruncated>")
        if more:
            inner += (f"<NextKeyMarker>{escape(page[-1][0])}</NextKeyMarker>"
                      f"<NextVersionIdMarker>{escape(page[-1][1].version_id)}</NextVersionIdMarker>")
        for k, v, latest in page:
            common = (f"<Key>{escape(k)}</Key><VersionId>{escape(v.version_id)}</VersionId>"
                      f"<IsLatest>{'true' if latest else 'false'}</IsLatest><LastModified>{_iso(v.last_modified)}"
                      f"</LastModified>")
            if v.delete_marker:
                inner += f"<DeleteMarker>{common}</DeleteMarker>"
            else:
                inner += (f"<Version>{common}<ETag>{escape(v.etag)}</ETag><Size>{len(v.body)}</Size>"
                          f"<StorageClass>{v.storage_class or 'STANDARD'}</StorageClass></Version>")
        self._xml("ListVersionsResult", inner)

    def _delete_objects(self, b: Bucket, body: bytes):
        root = ET.fromstring(body)
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        inner = ""
        for obj in list(root.iter(ns + "Object")) + list(root.iter("Object")):
            k = (obj.findtext(ns + "Key") or obj.findtext("Key") or "")
            vid = obj.findtext(ns + "VersionId") or obj.findtext("VersionId")
            if vid:
                b.objects[k] = [v for v in b.objects.get(k, []) if v.version_id != vid]
                if not b.objects[k]:
                    b.objects.pop(k)
            else:
                self.store.delete(b, k)
            inner += f"<Deleted><Key>{escape(k)}</Key></Deleted>"
        self._xml("DeleteResult", inner)

    # ---------------------------------------------------------------- objects
    def _object(self, method: str, name: str, key: str, query: dict):
        b = self.store.buckets.get(name)
        if b is None:
            self._body()
            return self._error(404, "NoSuchBucket", head=method == "HEAD")
        if method == "POST" and "uploads" in query:
            self._body()
            uid = uuid.uuid4().hex
            b.uploads[uid] = {"key": key, "parts": {}, "meta": self._meta(), "t": time.time()}
            return self._xml("InitiateMultipartUploadResult",
                             f"<Bucket>{escape(name)}</Bucket><Key>{escape(key)}</Key><UploadId>{uid}</UploadId>")
        if "uploadId" in query:
            return self._multipart(method, b, key, query)
        if method == "PUT":
            return self._put(b, key)
        if method in ("GET", "HEAD"):
            return self._get(b, key, query, head=method == "HEAD")
        if method == "DELETE":
            self._body()
            if "versionId" in query:
                vid = query["versionId"]
                b.objects[key] = [v for v in b.objects.get(key, []) if v.version_id != vid]
                if not b.objects[key]:
                    b.objects.pop(key)
                return self._send(204, b"", {"x-amz-version-id": vid})
            marker = self.store.delete(b, key)
            hdrs = {"x-amz-delete-marker": "true", "x-amz-version-id": marker.version_id} if marker else {}
            return self._send(204, b"", hdrs)
        self._body()
        return self._error(400, "NotImplemented")

    def _meta(self) -> dict:
        return {k.lower(): v for k, v in self.headers.items() if k.lower().startswith("x-amz-meta-")}

    def _precondition(self, current: Version | None) -> str | None:
        none_match, match = self.headers.get("If-None-Match"), self.headers.get("If-Match")
        live = current if current and not current.delete_marker else None
        if none_match == "*" and live:
            return "PreconditionFailed"
        if match is not None and (not live or match.strip() not in (live.etag, live.etag.strip('"'))):
            return "PreconditionFailed"
        return None

    def _put(self, b: Bucket, key: str):
        source = self.headers.get("x-amz-copy-source")
        body = self._body()
        if self._precondition(self.store.latest(b, key)):
            return self._error(412, "PreconditionFailed")
        if source:
            src = unquote(source.lstrip("/"))
            sbucket, _, rest = src.partition("/")
            skey, _, sq = rest.partition("?")
            sb = self.store.buckets.get(sbucket)
            svid = parse_qs(sq).get("versionId", [None])[0]
            sv = (self.store.find(sb, skey, svid) if svid else self.store.latest(sb, skey)) if sb else None
            if not sv or sv.delete_marker:
                return self._error(404, "NoSuchKey")
            if (m := self.headers.get("x-amz-copy-source-if-match")) and m.strip() not in (sv.etag, sv.etag.strip('"')):
                return self._error(412, "PreconditionFailed")
            directive = self.headers.get("x-amz-metadata-directive", "COPY")
            v = Version("", sv.body, sv.etag, time.time(), meta=dict(sv.meta) if directive == "COPY" else self._meta(),
                        storage_class=self.headers.get("x-amz-storage-class") or sv.storage_class)
            v = self.store.write(b, key, v)
            hdrs = {"x-amz-version-id": v.version_id} if b.versioning == "Enabled" else {}
            return self._xml_with("CopyObjectResult", f"<LastModified>{_iso(v.last_modified)}</LastModified>"
                                                      f"<ETag>{escape(v.etag)}</ETag>", hdrs)
        v = Version("", body, _etag(body), time.time(), meta=self._meta(),
                    storage_class=self.headers.get("x-amz-storage-class"))
        v = self.store.write(b, key, v)
        hdrs = {"ETag": v.etag}
        if b.versioning == "Enabled":
            hdrs["x-amz-version-id"] = v.version_id
        return self._send(200, b"", hdrs)

    def _xml_with(self, root: str, inner: str, headers: dict):
        body = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><{root}>{inner}</{root}>").encode()
        self._send(200, body, headers)

    def _get(self, b: Bucket, key: str, query: dict, head: bool):
        vid = query.get("versionId")
        v = self.store.find(b, key, vid) if vid else self.store.latest(b, key)
        if v is None:
            return self._error(404, "NoSuchKey" if not vid else "NoSuchVersion", head=head)
        if v.delete_marker:
            return self._error(404 if not vid else 405, "NoSuchKey" if not vid else "MethodNotAllowed", head=head,
                               headers={"x-amz-delete-marker": "true", "x-amz-version-id": v.version_id})
        if (m := self.headers.get("If-Match")) and m.strip() not in (v.etag, v.etag.strip('"')):
            return self._error(412, "PreconditionFailed", head=head)
        if (m := self.headers.get("If-None-Match")) and m.strip() in (v.etag, v.etag.strip('"')):
            return self._send(304, b"", {"ETag": v.etag}, head=True)
        body, status = v.body, 200
        hdrs = {"ETag": v.etag, "Last-Modified": formatdate(v.last_modified, usegmt=True),
                "Accept-Ranges": "bytes", "x-amz-storage-class": v.storage_class or "STANDARD"}
        if b.versioning is not None:
            hdrs["x-amz-version-id"] = v.version_id
        hdrs.update(v.meta)
        rng = self.headers.get("Range")
        if rng and rng.startswith("bytes="):
            a, _, z = rng[6:].partition("-")
            size = len(body)
            if a == "":
                start, end = max(0, size - int(z)), size - 1
            else:
                start, end = int(a), min(int(z) if z else size - 1, size - 1)
            if start >= size:
                return self._error(416, "InvalidRange", head=head)
            hdrs["Content-Range"] = f"bytes {start}-{end}/{size}"
            body, status = body[start:end + 1], 206
        self._send(status, body, hdrs, head=head, ctype="application/octet-stream")

    def _multipart(self, method: str, b: Bucket, key: str, query: dict):
        uid = query["uploadId"]
        up = b.uploads.get(uid)
        if up is None:
            self._body()
            return self._error(404, "NoSuchUpload")
        if method == "PUT":
            n = int(query.get("partNumber", "0"))
            data = self._body()
            up["parts"][n] = data
            return self._send(200, b"", {"ETag": _etag(data)})
        if method == "DELETE":
            self._body()
            del b.uploads[uid]
            return self._send(204)
        if method == "POST":
            root = ET.fromstring(self._body())
            nums = [int(e.text) for e in root.iter() if e.tag.endswith("PartNumber")]
            body = b"".join(up["parts"][n] for n in nums)
            digest = hashlib.md5(b"".join(hashlib.md5(up["parts"][n]).digest() for n in nums)).hexdigest()
            if self._precondition(self.store.latest(b, key)):
                return self._error(412, "PreconditionFailed")
            v = Version("", body, f'"{digest}-{len(nums)}"', time.time(), meta=up["meta"],
                        storage_class=self.headers.get("x-amz-storage-class"))
            v = self.store.write(b, key, v)
            del b.uploads[uid]
            hdrs = {"x-amz-version-id": v.version_id} if b.versioning == "Enabled" else {}
            return self._xml_with("CompleteMultipartUploadResult",
                                  f"<Key>{escape(key)}</Key><ETag>{escape(v.etag)}</ETag>", hdrs)
        if method == "GET":
            inner = "".join(f"<Part><PartNumber>{n}</PartNumber><ETag>{_etag(p)}</ETag><Size>{len(p)}</Size></Part>"
                            for n, p in sorted(up["parts"].items()))
            return self._xml("ListPartsResult", f"<UploadId>{uid}</UploadId><IsTruncated>false</IsTruncated>{inner}")
        self._body()
        return self._error(400, "NotImplemented")

    # ---------------------------------------------------------------- side channel (the drill's, never S3)
    def _admin(self, method: str, op: str, query: dict):
        st = self.store
        body = self._body() if method in ("PUT", "POST") else b""
        with st.lock:
            b = st.buckets.get(query.get("bucket", ""))
            key = query.get("key", "")
            if op == "log":
                return self._send(200, json.dumps(st.log).encode(), ctype="application/json")
            if op == "log/clear":
                st.log.clear()
                return self._send(200)
            if op == "snapshot":
                st.snapshots[query["name"]] = copy.deepcopy(st.buckets)
                return self._send(200)
            if op == "restore":
                st.buckets = copy.deepcopy(st.snapshots[query["name"]])
                return self._send(200)
            if b is None:
                return self._error(404, "NoSuchBucket")
            if op == "keys":
                out = {k: [{"version_id": v.version_id, "size": len(v.body), "delete_marker": v.delete_marker,
                            "etag": v.etag} for v in reversed(s)] for k, s in sorted(b.objects.items())}
                return self._send(200, json.dumps(out).encode(), ctype="application/json")
            if op == "get":
                vid = query.get("version")
                v = st.find(b, key, vid) if vid else st.latest(b, key)
                if not v or v.delete_marker:
                    return self._error(404, "NoSuchKey")
                return self._send(200, v.body, ctype="application/octet-stream")
            if op == "put":
                st.write(b, key, Version("", body, _etag(body), time.time()))
                return self._send(200)
            if op == "delete":
                st.delete(b, key)
                return self._send(200)
            if op == "purge":
                b.objects.pop(key, None)
                return self._send(200)
            if op == "abandon-upload":
                uid = uuid.uuid4().hex
                b.uploads[uid] = {"key": key, "parts": {1: body or b"\0" * 16}, "meta": {}, "t": time.time()}
                return self._send(200, uid.encode(), ctype="text/plain")
            if op == "versioning":
                b.versioning = query.get("status") or None
                return self._send(200)
        return self._error(404, "NoSuchAdminOperation")


class FakeS3:
    """Runs the store on 127.0.0.1:<port> in a background thread."""

    def __init__(self, port: int = 0):
        self.store = Store()
        handler = type("BoundHandler", (Handler,), {"store": self.store})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="vhh-fake-s3", daemon=True)

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self) -> "FakeS3":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def create_bucket(self, name: str, versioning: str | None = "Enabled") -> None:
        with self.store.lock:
            self.store.buckets[name] = Bucket(versioning=versioning)

    def requests(self) -> list[dict]:
        with self.store.lock:
            return list(self.store.log)

    def clear_requests(self) -> None:
        with self.store.lock:
            self.store.log.clear()


def content_downloads(log: list[dict], header_bytes: int = 120) -> list[dict]:
    """GETs of o/<uid> objects that fetched more than a header: what a lazy restore must not do."""
    return [r for r in log if r["method"] == "GET" and r["key"].startswith("o/") and r["status"] in (200, 206)
            and r["bytes_out"] > header_bytes]


def quote_key(key: str) -> str:
    return quote(key, safe="/")
