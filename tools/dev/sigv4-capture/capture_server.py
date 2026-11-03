#!/usr/bin/env python3
"""Records S3 requests exactly as real clients send them (method, raw target, ordered headers, body) and answers
with just enough S3 XML for the client to carry on. One JSON object per line in the output file."""
import base64
import json
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUT = sys.argv[1]
PORT = int(sys.argv[2])
TLS = len(sys.argv) > 3 and sys.argv[3] == "tls"
CERT = sys.argv[4] if TLS else None
KEY = sys.argv[5] if TLS else None
LABEL = {"value": ""}
LOCK = threading.Lock()

NS = 'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            out = b""
            while True:
                line = self.rfile.readline().strip()
                size = int(line.split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return out, True
                out += self.rfile.read(size)
                self.rfile.read(2)
        n = int(self.headers.get("Content-Length", "0") or 0)
        return (self.rfile.read(n) if n else b""), False

    def reply(self, status, body=b"", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if self.command != "HEAD":
            self.send_header("Content-Length", str(len(body)))
        else:
            self.send_header("Content-Length", (headers or {}).get("X-Len", "0"))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def handle_any(self):
        body, http_chunked = self.read_body()
        record = {
            "label": LABEL["value"],
            "tls": TLS,
            "method": self.command,
            "target": self.path,
            "headers": [[k, v] for k, v in self.headers.items()],
            "body_b64": base64.b64encode(body).decode(),
            "http_chunked": http_chunked,
        }
        if self.path.startswith("/__label/"):
            LABEL["value"] = self.path[len("/__label/"):]
            return self.reply(200, b"ok")
        with LOCK, open(OUT, "a") as f:
            f.write(json.dumps(record) + "\n")
        path, _, query = self.path.partition("?")
        parts = [p for p in path.split("/") if p]
        xml = {"Content-Type": "application/xml", "ETag": '"5d41402abc4b2a76b9719d911017c592"',
               "x-amz-request-id": "capture"}
        if self.command == "GET" and not parts:
            return self.reply(200, f'<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult {NS}><Owner><ID>o</ID>'
                                   f'<DisplayName>o</DisplayName></Owner><Buckets><Bucket><Name>vh-bucket</Name>'
                                   f'<CreationDate>2026-11-02T00:00:00.000Z</CreationDate></Bucket></Buckets>'
                                   f'</ListAllMyBucketsResult>'.encode(), xml)
        if "uploads" in query.split("&") and self.command == "POST":
            return self.reply(200, f'<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult {NS}>'
                                   f'<Bucket>{parts[0]}</Bucket><Key>{"/".join(parts[1:])}</Key>'
                                   f'<UploadId>capture-upload-1</UploadId></InitiateMultipartUploadResult>'.encode(), xml)
        if "uploadId=" in query and self.command == "POST":
            return self.reply(200, f'<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult {NS}>'
                                   f'<Bucket>{parts[0]}</Bucket><Key>{"/".join(parts[1:])}</Key>'
                                   f'<ETag>"abc-1"</ETag></CompleteMultipartUploadResult>'.encode(), xml)
        if self.command == "DELETE":
            return self.reply(204, b"", {"x-amz-request-id": "capture"})
        if "x-amz-copy-source" in {k.lower() for k in self.headers.keys()}:
            return self.reply(200, f'<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult {NS}>'
                                   f'<LastModified>2026-11-02T00:00:00.000Z</LastModified><ETag>"abc"</ETag>'
                                   f'</CopyObjectResult>'.encode(), xml)
        if self.command == "PUT":
            return self.reply(200, b"", {"ETag": '"5d41402abc4b2a76b9719d911017c592"', "x-amz-request-id": "capture"})
        if len(parts) == 1 and self.command == "GET":
            if "location" in query.split("&"):
                return self.reply(200, f'<?xml version="1.0" encoding="UTF-8"?><LocationConstraint {NS}/>'.encode(), xml)
            return self.reply(200, f'<?xml version="1.0" encoding="UTF-8"?><ListBucketResult {NS}><Name>{parts[0]}</Name>'
                                   f'<Prefix></Prefix><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys>'
                                   f'<IsTruncated>false</IsTruncated></ListBucketResult>'.encode(), xml)
        if len(parts) == 1 and self.command == "HEAD":
            return self.reply(200, b"", {"x-amz-request-id": "capture"})
        obj = {"ETag": '"5d41402abc4b2a76b9719d911017c592"', "Last-Modified": "Mon, 02 Nov 2026 00:00:00 GMT",
               "Content-Type": "text/plain", "x-amz-request-id": "capture", "X-Len": "5", "Accept-Ranges": "bytes"}
        if self.command == "HEAD":
            return self.reply(200, b"", obj)
        if self.headers.get("Range"):
            obj["Content-Range"] = "bytes 0-1/5"
            return self.reply(206, b"he", obj)
        return self.reply(200, b"hello", obj)

    do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = handle_any


server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
if TLS:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
