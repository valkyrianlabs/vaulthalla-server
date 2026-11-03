#!/usr/bin/env bash
# aws-cli v2 and rclone (run where they are installed: the Mac).
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
python3 "$DIR/capture_server.py" "$OUT" 47101 >/dev/null 2>&1 &
P1=$!
python3 "$DIR/capture_server.py" "$OUT" 47102 tls "$WORK/cert.pem" "$WORK/key.pem" >/dev/null 2>&1 &
P2=$!
trap 'kill $P1 $P2 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 1

export AWS_ACCESS_KEY_ID=VHCAPTUREFIXTUREKEY00000A
export AWS_SECRET_ACCESS_KEY=VHcaptureSecretKey0123456789abcdefghijkl
export AWS_DEFAULT_REGION=us-east-1
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
printf 'hello vaulthalla\n' > "$WORK/small.txt"
head -c 300000 /dev/zero | tr '\0' 'v' > "$WORK/big.txt"

label() { curl -sk "$1/__label/$2" >/dev/null; }

for EP in http://127.0.0.1:47101 https://127.0.0.1:47102; do
  scheme="${EP%%:*}"
  A=(aws --endpoint-url "$EP" --no-verify-ssl)
  label "$EP" "aws-cli/$scheme/list-buckets"; "${A[@]}" s3api list-buckets >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/put-object"; "${A[@]}" s3api put-object --bucket vh-bucket --key "notes/hello world+a=b~c.txt" --body "$WORK/small.txt" --content-type text/plain --metadata owner="Cooper Larson" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/put-object-utf8"; "${A[@]}" s3api put-object --bucket vh-bucket --key "café/résumé.pdf" --body "$WORK/small.txt" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/get-object"; "${A[@]}" s3api get-object --bucket vh-bucket --key "notes/hello world+a=b~c.txt" "$WORK/out" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/get-object-range"; "${A[@]}" s3api get-object --bucket vh-bucket --key "notes/a.txt" --range bytes=0-1 "$WORK/out" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/head-object"; "${A[@]}" s3api head-object --bucket vh-bucket --key "notes/a.txt" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/list-objects-v2"; "${A[@]}" s3api list-objects-v2 --bucket vh-bucket --prefix "dir one/" --starting-after "dir one/a b" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/copy-object"; "${A[@]}" s3api copy-object --bucket vh-bucket --key "copy/dst.txt" --copy-source "vh-bucket/notes/src key+1.txt" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/delete-object"; "${A[@]}" s3api delete-object --bucket vh-bucket --key "notes/a.txt" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/delete-objects"; "${A[@]}" s3api delete-objects --bucket vh-bucket --delete 'Objects=[{Key=a.txt},{Key=b.txt}]' >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/create-multipart"; "${A[@]}" s3api create-multipart-upload --bucket vh-bucket --key "big/movie.m2ts" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/upload-part"; "${A[@]}" s3api upload-part --bucket vh-bucket --key "big/movie.m2ts" --part-number 1 --upload-id capture-upload-1 --body "$WORK/small.txt" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/complete-multipart"; "${A[@]}" s3api complete-multipart-upload --bucket vh-bucket --key "big/movie.m2ts" --upload-id capture-upload-1 --multipart-upload 'Parts=[{ETag="abc",PartNumber=1}]' >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/s3-cp-upload"; "${A[@]}" s3 cp "$WORK/big.txt" "s3://vh-bucket/dir one/big file.txt" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/s3-ls"; "${A[@]}" s3 ls "s3://vh-bucket/dir one/" >/dev/null 2>&1
  label "$EP" "aws-cli/$scheme/presign-get"
  URL="$("${A[@]}" s3 presign "s3://vh-bucket/dir one/a b+c.txt" --expires-in 600 2>/dev/null)"
  [[ -n "$URL" ]] && curl -sk -o /dev/null "$URL"

  R=":s3,provider=Other,access_key_id=$AWS_ACCESS_KEY_ID,secret_access_key=$AWS_SECRET_ACCESS_KEY,region=us-east-1,endpoint='$EP',force_path_style=true,no_check_bucket=true:"
  RC=(rclone --config /dev/null --no-check-certificate --retries 1 --low-level-retries 1)
  label "$EP" "rclone/$scheme/copyto"; "${RC[@]}" copyto "$WORK/small.txt" "${R}vh-bucket/rclone dir/a b+c.txt" >/dev/null 2>&1
  label "$EP" "rclone/$scheme/copyto-multipart"; "${RC[@]}" --s3-upload-cutoff 0 --s3-chunk-size 5M copyto "$WORK/big.txt" "${R}vh-bucket/rclone dir/big.txt" >/dev/null 2>&1
  label "$EP" "rclone/$scheme/lsf"; "${RC[@]}" lsf "${R}vh-bucket/rclone dir" >/dev/null 2>&1
  label "$EP" "rclone/$scheme/cat"; "${RC[@]}" cat "${R}vh-bucket/rclone dir/café.txt" >/dev/null 2>&1
  label "$EP" "rclone/$scheme/deletefile"; "${RC[@]}" deletefile "${R}vh-bucket/rclone dir/a b+c.txt" >/dev/null 2>&1
  label "$EP" "rclone/$scheme/link"
  URL="$("${RC[@]}" link --expire 10m "${R}vh-bucket/rclone dir/a b+c.txt" 2>/dev/null)"
  [[ -n "$URL" ]] && curl -sk -o /dev/null "$URL"
done
sleep 1
wc -l "$OUT"
