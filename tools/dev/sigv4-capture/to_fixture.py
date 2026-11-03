#!/usr/bin/env python3
"""Turns capture_server.py records into core/test-assets/sigv4/client-requests.jsonl: one request per line with the
SHA-256 of the body the gateway would hash (aws-chunked decoded, as Session does), the body itself when small and not
aws-chunked, and the expected verdict ("ok", or "NotImplemented" for signed chunks). Exact duplicates are dropped."""
import json, hashlib, base64, sys
def decode_aws_chunked(b):
    out=b""; i=0
    while True:
        j=b.index(b"\r\n",i); line=b[i:j]; size=int(line.split(b";")[0],16); i=j+2
        if size==0: return out
        out+=b[i:i+size]; i+=size+2
seen=set(); recs=[]
for f in sys.argv[1:]:
    for l in open(f):
        r=json.loads(l); body=base64.b64decode(r["body_b64"])
        h={k.lower():v for k,v in r["headers"]}
        chunked="aws-chunked" in h.get("content-encoding","")
        dec=decode_aws_chunked(body) if chunked else body
        key=(r["label"],r["method"],r["target"],tuple(map(tuple,r["headers"])))
        if key in seen: continue
        seen.add(key)
        rec={"client":r["label"],"method":r["method"],"target":r["target"],"headers":r["headers"],
             "body_sha256":hashlib.sha256(dec).hexdigest()}
        if not chunked and len(body)<=2048:
            try: rec["body"]=body.decode()
            except UnicodeDecodeError: pass
        pay=h.get("x-amz-content-sha256","")
        rec["expect"]="NotImplemented" if pay.startswith("STREAMING-AWS4-HMAC-SHA256-PAYLOAD") else "ok"
        recs.append(rec)
print(len(recs), file=sys.stderr)
sys.stdout.write("".join(json.dumps(r, ensure_ascii=False)+"\n" for r in recs))
