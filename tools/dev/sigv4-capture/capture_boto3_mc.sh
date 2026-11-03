#!/usr/bin/env bash
# boto3/botocore and mc (MinIO client) (run where they are installed: dev).
# Records what a real S3 client sends (method, raw target, ordered headers, body) through capture_server.py on
# 127.0.0.1, over HTTP and HTTPS (a throwaway self-signed certificate), with the TEST-ONLY credential that
# core/tests/unit/test_s3_gateway_auth.cpp (S3GatewayClientCaptures) verifies against. Nothing leaves the host, and the
# client configuration comes from the environment only (no ~/.aws, rclone or mc config is read or written).
# Regenerate the fixture with every capture file:
#   tools/dev/sigv4-capture/to_fixture.py awscli-rclone.jsonl boto3-mc.jsonl > core/test-assets/sigv4/client-requests.jsonl
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:?usage: $0 <out.jsonl>}"
: > "$OUT"
WORK="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 1 -subj /CN=127.0.0.1 \
  -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
python3 "$DIR/capture_server.py" "$OUT" 47111 >/dev/null 2>&1 &
P1=$!
python3 "$DIR/capture_server.py" "$OUT" 47112 tls "$WORK/cert.pem" "$WORK/key.pem" >/dev/null 2>&1 &
P2=$!
trap 'kill $P1 $P2 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 1
AK=VHCAPTUREFIXTUREKEY00000A
SK=VHcaptureSecretKey0123456789abcdefghijkl
label() { curl -sk "$1/__label/$2" >/dev/null; }
printf 'hello vaulthalla\n' > "$WORK/small.txt"
head -c 300000 /dev/zero | tr '\0' 'v' > "$WORK/big.txt"

for EP in http://127.0.0.1:47111 https://127.0.0.1:47112; do
  scheme="${EP%%:*}"
  EP="$EP" AK="$AK" SK="$SK" SCHEME="$scheme" python3 - <<'PY'
import os, ssl, urllib.request, warnings
warnings.filterwarnings("ignore")
import boto3
from botocore.config import Config
ep, scheme = os.environ["EP"], os.environ["SCHEME"]
ctx = ssl._create_unverified_context()
def label(name):
    urllib.request.urlopen(f"{ep}/__label/boto3/{scheme}/{name}", context=ctx).read()
s3 = boto3.client("s3", endpoint_url=ep, aws_access_key_id=os.environ["AK"], aws_secret_access_key=os.environ["SK"],
                  region_name="us-east-1", verify=False,
                  config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 1}))
def run(name, fn):
    label(name)
    try: fn()
    except Exception: pass
run("list-buckets", lambda: s3.list_buckets())
run("put-object", lambda: s3.put_object(Bucket="vh-bucket", Key="notes/hello world+a=b~c.txt", Body=b"hello vaulthalla\n", Metadata={"owner": "Cooper  Larson"}))
run("put-object-utf8", lambda: s3.put_object(Bucket="vh-bucket", Key="café/résumé.pdf", Body=b"x"))
run("get-object", lambda: s3.get_object(Bucket="vh-bucket", Key="dir one/a b+c=d~e%f.txt")["Body"].read())
run("get-object-range", lambda: s3.get_object(Bucket="vh-bucket", Key="a.txt", Range="bytes=0-1")["Body"].read())
run("get-object-version", lambda: s3.get_object(Bucket="vh-bucket", Key="a.txt", VersionId="3/L4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo=")["Body"].read())
run("head-object", lambda: s3.head_object(Bucket="vh-bucket", Key="a.txt"))
run("list-objects-v2", lambda: s3.list_objects_v2(Bucket="vh-bucket", Prefix="dir one/", ContinuationToken="1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J+wm36Hy4vbOwM="))
run("copy-object", lambda: s3.copy_object(Bucket="vh-bucket", Key="copy/dst.txt", CopySource={"Bucket": "vh-bucket", "Key": "src key+1.txt"}))
run("delete-object", lambda: s3.delete_object(Bucket="vh-bucket", Key="a.txt"))
run("create-multipart", lambda: s3.create_multipart_upload(Bucket="vh-bucket", Key="big/movie.m2ts"))
run("upload-part", lambda: s3.upload_part(Bucket="vh-bucket", Key="big/movie.m2ts", PartNumber=1, UploadId="capture-upload-1", Body=b"part one"))
run("abort-multipart", lambda: s3.abort_multipart_upload(Bucket="vh-bucket", Key="big/movie.m2ts", UploadId="capture-upload-1"))
run("head-bucket", lambda: s3.head_bucket(Bucket="vh-bucket"))
run("upload-fileobj", lambda: s3.upload_file(os.devnull, "vh-bucket", "empty.txt"))
for name, method, params in [
    ("presign-get", "get_object", {"Bucket": "vh-bucket", "Key": "dir one/a b+c.txt"}),
    ("presign-get-response-override", "get_object", {"Bucket": "vh-bucket", "Key": "a.txt", "ResponseContentDisposition": "attachment; filename=\"a b.txt\""}),
    ("presign-put", "put_object", {"Bucket": "vh-bucket", "Key": "upload/a b.txt"}),
]:
    label(name)
    url = s3.generate_presigned_url(method, Params=params, ExpiresIn=600)
    req = urllib.request.Request(url, method="PUT" if method == "put_object" else "GET", data=b"presigned body" if method == "put_object" else None)
    try: urllib.request.urlopen(req, context=ctx).read()
    except Exception: pass
PY

  export MC_CONFIG_DIR="$WORK/mc" MC_INSECURE=true
  hostpart="${EP#*://}"
  export MC_HOST_cap="$scheme://$AK:$SK@$hostpart"
  label "$EP" "mc/$scheme/cp"; timeout 20 mc --insecure cp "$WORK/small.txt" "cap/vh-bucket/mc dir/a b.txt" >/dev/null 2>&1
  label "$EP" "mc/$scheme/ls"; timeout 20 mc --insecure ls "cap/vh-bucket/mc dir/" >/dev/null 2>&1
  label "$EP" "mc/$scheme/cat"; timeout 20 mc --insecure cat "cap/vh-bucket/mc dir/a.txt" >/dev/null 2>&1
  label "$EP" "mc/$scheme/share"
  URL="$(timeout 20 mc --insecure share download --expire 10m --json "cap/vh-bucket/mc dir/a b.txt" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("share",""))' 2>/dev/null)"
  [[ -n "$URL" ]] && curl -sk -o /dev/null "$URL"
done
sleep 1
wc -l "$OUT"
