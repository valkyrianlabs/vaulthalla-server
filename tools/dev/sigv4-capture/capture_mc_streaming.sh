#!/usr/bin/env bash
# mc (MinIO client) uploads over plain HTTP, which minio-go signs chunk by chunk (STREAMING-AWS4-HMAC-SHA256-PAYLOAD,
# and with --checksum STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER: a signed trailing x-amz-checksum-* header). Run where
# mc is installed (dev). Records the requests through capture_server.py on 127.0.0.1 with the TEST-ONLY credential that
# core/tests/unit/test_s3_gateway_auth.cpp (S3GatewayClientCaptures) verifies against. Nothing leaves the host, and the
# mc configuration comes from the environment only (a throwaway MC_CONFIG_DIR).
# Append the records to the fixture:
#   tools/dev/sigv4-capture/to_fixture.py mc-streaming.jsonl >> core/test-assets/sigv4/client-requests.jsonl
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:?usage: $0 <out.jsonl>}"
: > "$OUT"
WORK="$(mktemp -d)"
python3 "$DIR/capture_server.py" "$OUT" 47121 >/dev/null 2>&1 &
P1=$!
trap 'kill $P1 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 1
AK=VHCAPTUREFIXTUREKEY00000A
SK=VHcaptureSecretKey0123456789abcdefghijkl
EP=http://127.0.0.1:47121
label() { curl -s "$EP/__label/$1" >/dev/null; }
printf 'hello vaulthalla\n' > "$WORK/small.txt"
head -c 150000 /dev/zero | tr '\0' 'v' > "$WORK/big.txt"   # three 64 KiB chunks (65536, 65536, 18928) and the final one

export MC_CONFIG_DIR="$WORK/mc"
export MC_HOST_cap="http://$AK:$SK@127.0.0.1:47121"
label "mc/http/cp-multi-chunk"; timeout 20 mc cp "$WORK/big.txt" "cap/vh-bucket/mc dir/big.txt" >/dev/null 2>&1
label "mc/http/cp-checksum-crc32c"; timeout 20 mc cp --checksum CRC32C "$WORK/small.txt" "cap/vh-bucket/mc dir/sum.txt" >/dev/null 2>&1
label "mc/http/cp-checksum-sha256-multi-chunk"; timeout 20 mc cp --checksum SHA256 "$WORK/big.txt" "cap/vh-bucket/mc dir/big-sum.txt" >/dev/null 2>&1
sleep 1
wc -l "$OUT"
