#!/usr/bin/env python3
"""Turns capture_server.py records into core/test-assets/sigv4/client-requests.jsonl: one request per line with the
SHA-256 of the body the gateway would hash (aws-chunked decoded), the body itself when small and not aws-chunked, an
aws-chunked body as received (raw deflate, base64: "body_deflate_b64", replayed through the gateway's decoder and, for signed
chunks, its chunk verifier) and the expected verdict ("ok"). A body is aws-chunked when Content-Encoding says so or
x-amz-content-sha256 is a STREAMING-* mode (mc sends signed chunks without Content-Encoding). Exact duplicates are
dropped."""
import json, hashlib, base64, sys, zlib
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
        pay=h.get("x-amz-content-sha256","")
        chunked="aws-chunked" in h.get("content-encoding","") or pay.startswith("STREAMING-")
        dec=decode_aws_chunked(body) if chunked else body
        key=(r["label"],r["method"],r["target"],tuple(map(tuple,r["headers"])))
        if key in seen: continue
        seen.add(key)
        rec={"client":r["label"],"method":r["method"],"target":r["target"],"headers":r["headers"],
             "body_sha256":hashlib.sha256(dec).hexdigest()}
        if not chunked and len(body)<=2048:
            try: rec["body"]=body.decode()
            except UnicodeDecodeError: pass
        if chunked and body:
            z=zlib.compressobj(9, zlib.DEFLATED, -15)
            rec["body_deflate_b64"]=base64.b64encode(z.compress(body)+z.flush()).decode()
        rec["expect"]="ok"
        recs.append(rec)
print(len(recs), file=sys.stderr)
sys.stdout.write("".join(json.dumps(r, ensure_ascii=False)+"\n" for r in recs))
