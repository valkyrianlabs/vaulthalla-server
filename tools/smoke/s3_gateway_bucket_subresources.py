#!/usr/bin/env python3
"""Ask an S3 gateway bucket about its configuration the way SDK users do, and check the answers. Read-only.

    S3_GATEWAY_ENDPOINT=http://127.0.0.1:39000 AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \\
        tools/smoke/s3_gateway_bucket_subresources.py --bucket archive [--expect-keys N]

The gateway has no versioning, lifecycle rules or bucket policies (docs/s3-gateway/semantics.md, "Bucket
subresources"). boto3 must hear what S3 says for a bucket that never had them configured, not a key listing:

  1. get_bucket_location: LocationConstraint None (us-east-1).
  2. get_bucket_versioning: no Status and no MFADelete (never enabled).
  3. get_bucket_lifecycle_configuration raises NoSuchLifecycleConfiguration; get_bucket_policy NoSuchBucketPolicy.
  4. list_object_versions raises NotImplemented instead of listing no versions.
  5. list_objects_v2 still lists the bucket (--expect-keys asserts the count).

Exit status 0 when every check holds, 1 with the first difference otherwise. Only GETs are sent. The credentials come
from the environment and are never printed. tests/unit/test_s3_gateway.cpp runs this against an in-process gateway.
"""

import argparse
import os
import sys

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
except ImportError:  # the caller decides whether a missing SDK is a skip
    print("boto3 is not installed", file=sys.stderr)
    sys.exit(3)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def answer(response):
    return {k: v for k, v in response.items() if k != "ResponseMetadata"}


def require_error(what, call, code, status):
    try:
        response = call()
    except ClientError as e:
        got = e.response.get("Error", {}).get("Code")
        got_status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if got != code or got_status != status:
            fail(f"{what}: {got_status} {got}, expected {status} {code}")
        return
    fail(f"{what} succeeded with {answer(response)!r}, expected {status} {code}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--expect-keys", type=int)
    parser.add_argument("--endpoint", default=os.environ.get("S3_GATEWAY_ENDPOINT", "http://127.0.0.1:39000"))
    args = parser.parse_args()

    client = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 1}),
    )
    bucket = args.bucket

    location = answer(client.get_bucket_location(Bucket=bucket))
    if location.get("LocationConstraint") is not None:
        fail(f"get_bucket_location: {location!r}, expected LocationConstraint None (us-east-1)")

    versioning = answer(client.get_bucket_versioning(Bucket=bucket))
    if versioning:
        fail(f"get_bucket_versioning: {versioning!r}, expected nothing (versioning never enabled)")

    require_error("get_bucket_lifecycle_configuration",
                  lambda: client.get_bucket_lifecycle_configuration(Bucket=bucket), "NoSuchLifecycleConfiguration", 404)
    require_error("get_bucket_policy", lambda: client.get_bucket_policy(Bucket=bucket), "NoSuchBucketPolicy", 404)
    require_error("list_object_versions", lambda: client.list_object_versions(Bucket=bucket), "NotImplemented", 501)

    listed = client.list_objects_v2(Bucket=bucket).get("KeyCount")
    if args.expect_keys is not None and listed != args.expect_keys:
        fail(f"list_objects_v2 listed {listed} keys, expected {args.expect_keys}")

    print(f"ok: location, versioning, lifecycle, policy and versions answer as S3 does; {listed} keys listed")


if __name__ == "__main__":
    main()
