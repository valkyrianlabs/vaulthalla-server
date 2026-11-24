#pragma once

#include "db/query/s3/Gateway.hpp"

#include <cstdint>
#include <ctime>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace vh::protocols::s3::xml {

struct Bucket {
    std::string name;
    std::time_t created_at{};
};

struct DeletedObject {
    std::string key;
};

struct DeleteError {
    std::string key;
    std::string code;
    std::string message;
};

// What a ListObjects request asked for, which its answer echoes.
struct ListObjectsRequest {
    std::string prefix;
    std::optional<std::string> delimiter;
    uint32_t max_keys{1000};
    std::optional<std::string> encoding_type;        // "url" or none
    std::optional<std::string> marker;               // v1
    std::optional<std::string> start_after;          // v2
    std::optional<std::string> continuation_token;   // v2, as the client sent it
};

std::string escape(std::string_view value);
std::string error(const std::string& code, const std::string& message,
                  const std::string& resource, const std::string& requestId);
std::string listBuckets(const std::vector<Bucket>& buckets, const std::string& ownerName = "vaulthalla");
// ListObjects (v1) and ListObjectsV2 answers. EncodingType=url percent-encodes the fields that hold key text (Key,
// Prefix, Delimiter, CommonPrefixes, and v1's Marker and NextMarker or v2's StartAfter): clients decode exactly
// those. A continuation token is never one of them. It is opaque, clients send it back as they received it, and
// encoding it made every second page the first one again.
std::string listObjects(const std::string& bucketName, const db::query::s3::ObjectListResult& result,
                        const ListObjectsRequest& request);
std::string listObjectsV2(const std::string& bucketName, const db::query::s3::ObjectListResult& result,
                          const ListObjectsRequest& request);
std::string deleteResult(const std::vector<DeletedObject>& deleted,
                         const std::vector<DeleteError>& errors,
                         bool quiet = false);
std::string initiateMultipartUpload(const std::string& bucket, const std::string& key, const std::string& uploadId);
std::string completeMultipartUpload(const std::string& location, const std::string& bucket,
                                    const std::string& key, const std::string& etag);
std::string listMultipartUploads(const std::string& bucket, const std::vector<db::query::s3::MultipartUpload>& uploads);
std::string listParts(const std::string& bucket, const std::string& key, const std::string& uploadId,
                      const std::vector<db::query::s3::MultipartPart>& parts);

std::string httpDate(std::time_t ts);
std::string iso8601(std::time_t ts);

}
