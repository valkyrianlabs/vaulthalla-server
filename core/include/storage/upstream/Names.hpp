#pragma once

#include <string>

// Names that reach provider URLs, signed requests, XML and IAM policy documents (#237). Every bucket name, region and
// location hint an operator supplies is checked here before it is used: an unchecked name such as "x/../prod" or
// "prod/configuration?" could address another (protected) bucket through Cloudflare's bearer-token REST API, whose
// paths are not covered by a signature, and a region string ends up in a host name.
namespace vh::storage::upstream {

// S3 bucket naming (AWS rules, which R2 also satisfies): 3-63 characters of a-z 0-9 . -, starting and ending with a
// letter or digit, no "..", not an IP address, no xn-- / sthree- / amzn-s3-demo- prefix, no -s3alias / --ol-s3 /
// .mrap / --x-s3 / --table-s3 suffix.
[[nodiscard]] bool validBucketName(const std::string& name, std::string& why);
// Throws std::invalid_argument("invalid bucket name '…': <why>").
void requireValidBucketName(const std::string& name);

// AWS region codes ("us-east-2", "eu-central-1", "ap-southeast-4", "us-gov-west-1", "cn-north-1").
[[nodiscard]] bool validAwsRegion(const std::string& region);
// Cloudflare R2 location hints accepted by CreateBucket ("wnam", "enam", "weur", "eeur", "apac", "oc"), or "auto".
[[nodiscard]] bool validR2LocationHint(const std::string& hint);

// RFC 3986 percent-encoding of one path segment (everything but A-Z a-z 0-9 - . _ ~), for URLs that no signature
// covers.
[[nodiscard]] std::string encodePathSegment(const std::string& segment);

}
