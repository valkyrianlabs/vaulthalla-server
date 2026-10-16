#pragma once

#include "storage/s3/curl/Http.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/s3/sigv4/Signer.hpp"

#include <chrono>
#include <ctime>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// Building blocks shared by the AWS and Cloudflare R2 admin adapters, public for the provider-contract tests
// (core/tests/unit/test_upstream_providers.cpp). Not an API for anything else.
namespace vh::storage::s3::provider::admin::detail {

// ---- secrets ---------------------------------------------------------------------------------------------------

// Removes every known secret, Authorization/Bearer material, SigV4 signatures and credential scopes from `text`, then
// caps it at `max` characters. Anything that reaches an exception message or a log line goes through this.
[[nodiscard]] std::string redact(std::string text, const std::vector<std::string>& secrets, std::size_t max = 400);

// ---- signed requests -----------------------------------------------------------------------------------------------

struct Endpoint {
    std::string host;        // "s3.us-east-2.amazonaws.com", "<acct>.r2.cloudflarestorage.com", "sqs.us-east-2.amazonaws.com"
    std::string region;      // signing region ("auto" for R2)
    std::string service;     // s3 | sqs | sts
};

struct SignedCall {
    std::string method = "GET";
    std::string path = "/";
    std::vector<std::pair<std::string, std::string>> query;
    std::map<std::string, std::string> headers;
    std::string body;
    std::chrono::seconds timeout{60};
};

// A call with only a method, query and path set (the rest default).
[[nodiscard]] inline SignedCall call(std::string method, std::vector<std::pair<std::string, std::string>> query = {},
                                     std::string path = "/") {
    SignedCall c;
    c.method = std::move(method);
    c.query = std::move(query);
    c.path = std::move(path);
    return c;
}

[[nodiscard]] curl::http::Response send(const Endpoint& endpoint, const SignedCall& call,
                                        const sigv4::Credentials& credentials);

// "https://host/a?b" → "host"; host[:port] kept as written.
[[nodiscard]] std::string hostOf(const std::string& url);
[[nodiscard]] std::string md5Base64(const std::string& data);
[[nodiscard]] std::optional<std::time_t> parseIsoTime(const std::string& value);

// ---- errors ----------------------------------------------------------------------------------------------------

// The provider code + message of an error response: S3 XML <Error><Code>, SQS JSON __type / x-amzn-query-error,
// Cloudflare's envelope errors[0].code. Empty code when there is none.
struct ErrorInfo {
    std::string code;
    std::string message;
};
[[nodiscard]] ErrorInfo s3Error(const curl::http::Response& response);
[[nodiscard]] ErrorInfo sqsError(const curl::http::Response& response);
[[nodiscard]] ErrorInfo cloudflareError(const curl::http::Response& response);

// "<operation> failed (HTTP 403 AccessDenied): <message>", redacted. Transport failures carry code "Transport".
[[nodiscard]] ProviderError makeError(const std::string& operation, const curl::http::Response& response,
                                      const ErrorInfo& info, const std::vector<std::string>& secrets);

// ---- S3 XML --------------------------------------------------------------------------------------------------------

[[nodiscard]] BucketPage parseListBuckets(const std::string& xml);
[[nodiscard]] ObjectPage parseListObjectsV2(const std::string& xml);
[[nodiscard]] ObjectPage parseListObjectVersions(const std::string& xml);
[[nodiscard]] Versioning parseVersioning(const std::string& xml);
[[nodiscard]] std::optional<std::string> parseLocation(const std::string& xml);   // "" (us-east-1) → "us-east-1"

[[nodiscard]] std::vector<LifecycleRule> parseLifecycle(const std::string& xml);
// Foreign rules are written back from raw_xml verbatim; ours from their fields. Throws std::invalid_argument for a
// rule of ours without any action, or with a field `allowNoncurrent` forbids.
[[nodiscard]] std::string buildLifecycle(const std::vector<LifecycleRule>& rules, bool allowNoncurrent);

[[nodiscard]] std::string buildDeleteObjects(const std::vector<ObjectSummary>& objects);
[[nodiscard]] std::vector<std::pair<std::string, std::string>> parseDeleteObjectsErrors(const std::string& xml);

// The bucket's notification document split into elements: each with its Id (empty for EventBridgeConfiguration),
// kind, events, filter and verbatim XML.
struct NotificationElement {
    std::string kind;                 // QueueConfiguration | TopicConfiguration | CloudFunctionConfiguration | EventBridgeConfiguration
    NotificationRule rule;            // rule.raw = verbatim element XML
};
[[nodiscard]] std::vector<NotificationElement> parseNotification(const std::string& xml);
// The document with every element except those whose Id is in `dropIds`, plus `add` (our QueueConfigurations).
[[nodiscard]] std::string buildNotification(const std::vector<NotificationElement>& existing,
                                            const std::vector<std::string>& dropIds,
                                            const std::vector<NotificationRule>& add);
// True when two rules would both fire for some object on some shared event type (S3 and R2 reject such overlaps).
[[nodiscard]] bool overlaps(const NotificationRule& a, const NotificationRule& b);

// The S3 event types Vaulthalla subscribes to.
[[nodiscard]] const std::vector<std::string>& awsEventTypes();
[[nodiscard]] const std::vector<std::string>& r2Actions();

// ---- SQS queue policy ----------------------------------------------------------------------------------------------

inline constexpr const char* kPolicySid = "vaulthalla-s3-publish";

// Adds (add=true) or removes the bucket from our publish statement in `policyJson` (empty = no policy), keeping every
// other statement. Returns the new policy JSON, or "" when no statement is left.
[[nodiscard]] std::string mergeQueuePolicy(const std::string& policyJson, const std::string& queueArn,
                                           const std::string& accountId, const std::string& bucket, bool add);
// Buckets our statement currently grants.
[[nodiscard]] std::vector<std::string> policyBuckets(const std::string& policyJson);

}
