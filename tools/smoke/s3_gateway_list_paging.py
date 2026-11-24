#!/usr/bin/env python3
"""List an S3 gateway bucket the way SDK users do and check the listing against S3's rules. Read-only.

    S3_GATEWAY_ENDPOINT=http://127.0.0.1:39000 AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \\
        tools/smoke/s3_gateway_list_paging.py --bucket archive [--prefix p/] [--page-size 100] [--expect-keys N]

boto3's paginators are the client here (path-style, SigV4, EncodingType=url on every ListObjectsV2, as boto3 sends it):
they stop with PaginationError when a page hands back the token that fetched it, which is what a gateway that mangles
its continuation token does. Checked:

  1. ListObjectsV2 at the default page size lists every key once, in ascending UTF-8 byte order.
  2. The same listing at --page-size (more page boundaries), by ListObjects (v1, Marker) and by StartAfter alone.
  3. With Delimiter=/ every common prefix comes once, and prefixes and keys are what the flat listing folds into.

The bucket should hold more keys than one page (1000) for check 1 to cross a page boundary; --expect-keys asserts
the count. Exit status 0 when every check holds, 1 with the first difference otherwise. The credentials come from the
environment and are never printed. tests/unit/test_s3_gateway.cpp runs this against an in-process gateway.
"""

import argparse
import os
import sys

try:
    import boto3
    from botocore.config import Config
except ImportError:  # the caller decides whether a missing SDK is a skip
    print("boto3 is not installed", file=sys.stderr)
    sys.exit(3)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def byte_order(keys):
    return sorted(keys, key=lambda k: k.encode("utf-8"))


def first_difference(got, expected):
    for i, (a, b) in enumerate(zip(got, expected)):
        if a != b:
            return f"item {i}: got {a!r}, expected {b!r}"
    return f"{len(got)} items, expected {len(expected)}"


def require_same(what, got, expected):
    if got != expected:
        fail(f"{what}: {first_difference(got, expected)}")


def v2_keys(client, bucket, prefix, page_size=None, delimiter=None):
    config = {"PageSize": page_size} if page_size else {}
    arguments = {"Bucket": bucket, "Prefix": prefix}
    if delimiter:
        arguments["Delimiter"] = delimiter
    keys, prefixes, pages = [], [], 0
    for page in client.get_paginator("list_objects_v2").paginate(PaginationConfig=config, **arguments):
        pages += 1
        contents = [o["Key"] for o in page.get("Contents", [])]
        common = [p["Prefix"] for p in page.get("CommonPrefixes", [])]
        if page.get("KeyCount") != len(contents) + len(common):
            fail(f"page {pages}: KeyCount {page.get('KeyCount')} for {len(contents)} keys and {len(common)} prefixes")
        keys += contents
        prefixes += common
    return keys, prefixes, pages


def v1_keys(client, bucket, prefix, page_size):
    keys = []
    for page in client.get_paginator("list_objects").paginate(
        Bucket=bucket, Prefix=prefix, PaginationConfig={"PageSize": page_size}
    ):
        keys += [o["Key"] for o in page.get("Contents", [])]
    return keys


def start_after_keys(client, bucket, prefix, page_size):
    keys, after = [], None
    while True:
        arguments = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": page_size}
        if after is not None:
            arguments["StartAfter"] = after
        page = client.list_objects_v2(**arguments)
        contents = [o["Key"] for o in page.get("Contents", [])]
        keys += contents
        if not page.get("IsTruncated"):
            return keys
        if not contents:
            fail("a truncated page with no keys")
        after = contents[-1]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--prefix", default="")
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--expect-keys", type=int)
    parser.add_argument("--endpoint", default=os.environ.get("S3_GATEWAY_ENDPOINT", "http://127.0.0.1:39000"))
    args = parser.parse_args()

    client = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 1}),
    )

    keys, _, pages = v2_keys(client, args.bucket, args.prefix)
    if len(set(keys)) != len(keys):
        fail(f"ListObjectsV2 repeated {len(keys) - len(set(keys))} keys over {pages} pages")
    require_same("ListObjectsV2 is not in UTF-8 byte order", keys, byte_order(keys))
    if args.expect_keys is not None and len(keys) != args.expect_keys:
        fail(f"ListObjectsV2 listed {len(keys)} keys over {pages} pages, expected {args.expect_keys}")

    paged, _, small_pages = v2_keys(client, args.bucket, args.prefix, page_size=args.page_size)
    require_same(f"ListObjectsV2 at {args.page_size} keys a page differs from the default page size", paged, keys)
    require_same("ListObjects (v1) differs from ListObjectsV2", v1_keys(client, args.bucket, args.prefix, args.page_size), keys)
    require_same("paging by StartAfter differs from paging by token",
                 start_after_keys(client, args.bucket, args.prefix, args.page_size), keys)

    folded_keys, folded_prefixes, _ = v2_keys(client, args.bucket, args.prefix, page_size=args.page_size, delimiter="/")
    expected_keys, expected_prefixes = [], []
    for key in keys:
        cut = key.find("/", len(args.prefix))
        if cut < 0:
            expected_keys.append(key)
        elif not expected_prefixes or expected_prefixes[-1] != key[: cut + 1]:
            expected_prefixes.append(key[: cut + 1])
    require_same("keys of the Delimiter=/ listing", folded_keys, expected_keys)
    require_same("common prefixes of the Delimiter=/ listing", folded_prefixes, expected_prefixes)

    print(f"ok: {len(keys)} keys in byte order over {pages} pages ({small_pages} at {args.page_size} a page); "
          f"v1, StartAfter and Delimiter=/ ({len(folded_prefixes)} prefixes, {len(folded_keys)} keys) agree")


if __name__ == "__main__":
    main()
