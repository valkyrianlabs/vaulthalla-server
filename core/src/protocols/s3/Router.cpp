#include "protocols/s3/Router.hpp"

#include "config/Registry.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "protocols/s3/Xml.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "db/query/fs/File.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/Action.hpp"
#include "storage/s3/pricing/GatewayPriceEstimate.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "storage/s3/pricing/PriceEstimate.hpp"

#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <pugixml.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <functional>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "crypto/util/digest.hpp"
#include <optional>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>
#include <zlib.h>

namespace vh::protocols::s3 {

namespace {
using S3Action = rbac::s3::policy::S3Action;
using Decimal = boost::multiprecision::cpp_dec_float_50;

std::string requestId() {
    return boost::uuids::to_string(boost::uuids::random_generator()());
}

std::string targetPath(const std::string& target) {
    const auto pos = target.find('?');
    return pos == std::string::npos ? target : target.substr(0, pos);
}

std::string targetQuery(const std::string& target) {
    const auto pos = target.find('?');
    return pos == std::string::npos ? "" : target.substr(pos + 1);
}

std::string pctDecode(const std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%' && i + 2 < value.size()) {
            const auto hex = std::string(value.substr(i + 1, 2));
            char* end = nullptr;
            const auto v = std::strtoul(hex.c_str(), &end, 16);
            if (end && *end == '\0') {
                out.push_back(static_cast<char>(v));
                i += 2;
                continue;
            }
        }
        out.push_back(value[i]);
    }
    return out;
}

std::map<std::string, std::string> parseQuery(const std::string& query) {
    std::map<std::string, std::string> out;
    std::stringstream ss(query);
    std::string part;
    while (std::getline(ss, part, '&')) {
        if (part.empty()) continue;
        const auto eq = part.find('=');
        out[pctDecode(part.substr(0, eq))] = eq == std::string::npos ? "" : pctDecode(part.substr(eq + 1));
    }
    return out;
}

bool hasQuery(const std::map<std::string, std::string>& query, const std::string& key) {
    return query.find(key) != query.end();
}

bool looksLikeIpAddressOrLocalhost(const std::string& host) {
    if (host == "localhost") return true;
    return std::ranges::all_of(host, [](const unsigned char c) {
        return std::isdigit(c) || c == '.' || c == ':';
    });
}

std::optional<std::string> virtualHostedBucket(const Router::Request& request) {
    const auto& cfg = config::Registry::get().s3_gateway;
    if (!cfg.allow_virtual_hosted_style) return std::nullopt;

    const auto it = request.find(http::field::host);
    if (it == request.end()) return std::nullopt;

    auto host = std::string(it->value());
    const auto colon = host.find(':');
    if (colon != std::string::npos) host.erase(colon);
    std::ranges::transform(host, host.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    auto configuredHost = cfg.host;
    if (const auto cfgColon = configuredHost.find(':'); cfgColon != std::string::npos)
        configuredHost.erase(cfgColon);
    std::ranges::transform(configuredHost, configuredHost.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (host.empty() || host == configuredHost || looksLikeIpAddressOrLocalhost(host)) return std::nullopt;
    const auto dot = host.find('.');
    if (dot == std::string::npos || dot == 0) return std::nullopt;
    return host.substr(0, dot);
}

bool pathStyleOnlyProxy(const Router::Request& request) {
    const auto marker = request.find("X-Vaulthalla-S3-Path-Style-Only");
    if (marker == request.end()) return false;

    auto value = std::string(marker->value());
    std::ranges::transform(value, value.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value.empty() || value == "1" || value == "true" || value == "yes" || value == "on";
}

Router::Response makeResponse(
    const Router::Request& request,
    const http::status status,
    std::string body = {},
    const std::string& contentType = "application/xml") {
    Router::Response response{status, request.version()};
    response.set(http::field::server, "VaulthallaS3Gateway");
    response.set(http::field::content_type, contentType);
    response.set(http::field::cache_control, Router::kCacheControl);
    response.body() = std::move(body);
    response.keep_alive(request.keep_alive());
    response.prepare_payload();
    return response;
}

std::vector<uint8_t> bodyBytes(const Router::Request& request, const Router::BodyPayload& payload) {
    if (payload.temp_file) {
        std::ifstream in(*payload.temp_file, std::ios::binary);
        if (!in) throw invalidArgument("Unable to read streamed request body", payload.temp_file->string());
        return {std::istreambuf_iterator<char>(in), {}};
    }
    return {request.body().begin(), request.body().end()};
}

std::string routerMd5Base64(const std::vector<uint8_t>& bytes) {
    const auto digest = crypto::util::EvpDigest::of(EVP_md5(), bytes.data(), bytes.size());
    std::array<unsigned char, EVP_ENCODE_LENGTH(MD5_DIGEST_LENGTH)> encoded{};
    const auto len = EVP_EncodeBlock(encoded.data(), digest.data(), static_cast<int>(digest.size()));
    return {reinterpret_cast<char*>(encoded.data()), static_cast<std::size_t>(len)};
}

std::map<std::string, std::string> userMetadata(const Router::Request& request) {
    std::map<std::string, std::string> out;
    for (const auto& field : request) {
        auto name = std::string(field.name_string());
        std::ranges::transform(name, name.begin(), [](const unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (name.starts_with("x-amz-meta-"))
            out[name.substr(std::string("x-amz-meta-").size())] = std::string(field.value());
    }
    return out;
}

std::string headerOr(const Router::Request& request, const http::field field, const std::string& fallback = {}) {
    const auto it = request.find(field);
    return it == request.end() ? fallback : std::string(it->value());
}

std::string headerOrName(const Router::Request& request, const std::string& name, const std::string& fallback = {}) {
    const auto it = request.find(name);
    return it == request.end() ? fallback : std::string(it->value());
}

void validateContentMd5(const Router::Request& request, const Router::BodyPayload& payload) {
    const auto expected = headerOrName(request, "content-md5");
    if (expected.empty()) return;
    if (!payload.md5_base64)
        throw invalidArgument("Content-MD5 validation is unavailable for this request", std::string(request.target()));
    if (*payload.md5_base64 != expected)
        throw S3Error{"BadDigest", "The Content-MD5 header does not match the request body",
                      http::status::bad_request, std::string(request.target())};
}

void validateContentMd5(const Router::Request& request, const std::vector<uint8_t>& body) {
    const auto expected = headerOrName(request, "content-md5");
    if (expected.empty()) return;
    if (routerMd5Base64(body) != expected)
        throw S3Error{"BadDigest", "The Content-MD5 header does not match the request body",
                      http::status::bad_request, std::string(request.target())};
}

void validateChecksumHeader(
    const Router::Request& request,
    const std::string& header,
    const std::optional<std::string>& actual,
    const std::optional<std::string>& trailer = std::nullopt) {
    auto expected = headerOrName(request, header);
    if (expected.empty() && trailer) expected = *trailer;
    if (expected.empty()) return;
    if (!actual || *actual != expected)
        throw S3Error{"BadDigest", "The " + header + " header does not match the request body",
                      http::status::bad_request, std::string(request.target())};
}

void validateS3Checksums(const Router::Request& request, const Router::BodyPayload& payload) {
    const auto shaTrailer = payload.trailer_headers.find("x-amz-checksum-sha256");
    const auto crcTrailer = payload.trailer_headers.find("x-amz-checksum-crc32");
    std::optional<std::string> shaTrailerValue;
    std::optional<std::string> crcTrailerValue;
    if (shaTrailer != payload.trailer_headers.end()) shaTrailerValue = shaTrailer->second;
    if (crcTrailer != payload.trailer_headers.end()) crcTrailerValue = crcTrailer->second;
    validateChecksumHeader(
        request,
        "x-amz-checksum-sha256",
        payload.sha256_base64,
        shaTrailerValue);
    validateChecksumHeader(
        request,
        "x-amz-checksum-crc32",
        payload.crc32_base64,
        crcTrailerValue);
}

void validateS3Checksums(const Router::Request& request, const std::vector<uint8_t>& body) {
    if (!headerOrName(request, "x-amz-checksum-sha256").empty())
        validateChecksumHeader(request, "x-amz-checksum-sha256", Router::checksumSha256Base64(body));
    if (!headerOrName(request, "x-amz-checksum-crc32").empty())
        validateChecksumHeader(request, "x-amz-checksum-crc32", Router::checksumCrc32Base64(body));
}

std::string trimCopy(std::string value) {
    const auto notSpace = [](const unsigned char c) { return !std::isspace(c); };
    value.erase(value.begin(), std::ranges::find_if(value, notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

bool etagListMatches(const std::string& condition, const std::string& etag) {
    std::stringstream ss(condition);
    std::string item;
    while (std::getline(ss, item, ',')) {
        item = trimCopy(item);
        if (item == "*" || item == etag) return true;
        if (!item.empty() && item.front() != '"' && ("\"" + item + "\"") == etag) return true;
    }
    return false;
}

void enforceIfMatch(const Router::Request& request, const db::query::s3::ObjectState& state,
                    const std::string& resource) {
    const auto condition = headerOr(request, http::field::if_match);
    if (!condition.empty() && !etagListMatches(condition, state.etag))
        throw preconditionFailed(resource);
}

bool ifNoneMatchMatches(const Router::Request& request, const db::query::s3::ObjectState& state) {
    const auto condition = headerOr(request, http::field::if_none_match);
    return !condition.empty() && etagListMatches(condition, state.etag);
}

Router::Response notModifiedResponse(const Router::Request& request, const db::query::s3::ObjectState& state) {
    auto response = makeResponse(request, http::status::not_modified, {});
    response.set(http::field::etag, state.etag);
    response.set(http::field::last_modified, xml::httpDate(state.last_modified));
    response.body().clear();
    response.prepare_payload();
    return response;
}

void enforceCopySourcePreconditions(const Router::Request& request,
                                    const db::query::s3::ObjectState& state,
                                    const std::string& resource) {
    const auto ifMatch = headerOrName(request, "x-amz-copy-source-if-match");
    if (!ifMatch.empty() && !etagListMatches(ifMatch, state.etag))
        throw preconditionFailed(resource);

    const auto ifNoneMatch = headerOrName(request, "x-amz-copy-source-if-none-match");
    if (!ifNoneMatch.empty() && etagListMatches(ifNoneMatch, state.etag))
        throw preconditionFailed(resource);
}

PutObjectOptions putOptionsFromRequest(const Router::Request& request) {
    const auto contentType = headerOr(request, http::field::content_type);
    return {
        .content_type = contentType.empty() ? "application/octet-stream" : contentType,
        .content_type_explicit = !contentType.empty(),
        .storage_class = headerOrName(request, "x-amz-storage-class").empty()
            ? std::optional<std::string>{}
            : std::make_optional(headerOrName(request, "x-amz-storage-class")),
        .metadata = userMetadata(request),
        .metadata_directive = MetadataDirective::Replace,
        .multipart = false,
        .part_count = std::nullopt,
        .etag_override = std::nullopt
    };
}

PutObjectOptions copyOptionsFromRequest(const Router::Request& request) {
    auto options = putOptionsFromRequest(request);
    auto directive = headerOrName(request, "x-amz-metadata-directive", "COPY");
    std::ranges::transform(directive, directive.begin(), [](const unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });

    if (directive == "COPY") {
        options.metadata_directive = MetadataDirective::Copy;
        return options;
    }
    if (directive == "REPLACE") {
        options.metadata_directive = MetadataDirective::Replace;
        return options;
    }
    throw invalidArgument("Unsupported x-amz-metadata-directive", directive);
}

uint32_t parsePartNumber(const std::map<std::string, std::string>& query) {
    const auto it = query.find("partNumber");
    if (it == query.end() || it->second.empty() || !std::ranges::all_of(it->second, [](const unsigned char c) {
            return std::isdigit(c);
        }))
        throw invalidArgument("partNumber must be an integer between 1 and 10000", it == query.end() ? "" : it->second);
    try {
        const auto value = std::stoul(it->second);
        if (value == 0 || value > 10000)
            throw invalidArgument("partNumber must be between 1 and 10000", it->second);
        return static_cast<uint32_t>(value);
    } catch (const std::invalid_argument&) {
        throw invalidArgument("partNumber must be an integer between 1 and 10000", it->second);
    } catch (const std::out_of_range&) {
        throw invalidArgument("partNumber must be between 1 and 10000", it->second);
    }
}

std::optional<ByteRange> parseRange(const Router::Request& request) {
    const auto raw = headerOr(request, http::field::range);
    if (raw.empty()) return std::nullopt;
    const auto parsed = protocols::http::range::parse(raw);
    if (parsed.multi) throw notImplemented("Multipart byte ranges are not supported", std::string(request.target()));
    if (parsed.malformed || !parsed.spec) throw invalidRange(std::string(request.target()));
    return parsed.spec;
}

uint32_t parseMaxKeys(const std::map<std::string, std::string>& query) {
    const auto it = query.find("max-keys");
    if (it == query.end()) return 1000;
    if (it->second.empty() || !std::ranges::all_of(it->second, [](const unsigned char c) {
            return std::isdigit(c);
        }))
        throw invalidArgument("max-keys must be a non-negative integer", it->second);

    try {
        const auto value = std::stoull(it->second);
        if (value > std::numeric_limits<uint32_t>::max())
            throw invalidArgument("max-keys is too large", it->second);
        return static_cast<uint32_t>(value);
    } catch (const std::invalid_argument&) {
        throw invalidArgument("max-keys must be a non-negative integer", it->second);
    } catch (const std::out_of_range&) {
        throw invalidArgument("max-keys is too large", it->second);
    }
}

std::optional<std::string> parseEncodingType(const std::map<std::string, std::string>& query) {
    const auto it = query.find("encoding-type");
    if (it == query.end() || it->second.empty()) return std::nullopt;
    if (it->second == "url") return it->second;
    throw invalidArgument("encoding-type must be url when specified", it->second);
}

std::vector<std::string> parseDeleteObjects(const std::string& body, bool& quiet) {
    pugi::xml_document doc;
    if (!doc.load_string(body.c_str())) throw invalidArgument("Malformed DeleteObjects XML");
    std::vector<std::string> out;
    const auto root = doc.child("Delete");
    quiet = std::string(root.child("Quiet").text().as_string()) == "true";
    for (const auto object : root.children("Object")) {
        const auto key = object.child("Key").text().as_string();
        if (key && *key) out.emplace_back(key);
    }
    return out;
}

std::vector<std::pair<uint32_t, std::string>> parseCompleteParts(const std::string& body) {
    pugi::xml_document doc;
    if (!doc.load_string(body.c_str())) throw invalidArgument("Malformed CompleteMultipartUpload XML");
    std::vector<std::pair<uint32_t, std::string>> out;
    for (const auto part : doc.child("CompleteMultipartUpload").children("Part")) {
        auto etag = std::string(part.child("ETag").text().as_string());
        if (!etag.empty() && etag.front() != '"') etag = "\"" + etag + "\"";
        out.emplace_back(part.child("PartNumber").text().as_uint(), etag);
    }
    return out;
}

std::string copyObjectResult(const std::string& etag, const std::time_t lastModified) {
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
           "<CopyObjectResult><LastModified>" + xml::iso8601(lastModified) + "</LastModified>"
           "<ETag>" + xml::escape(etag) + "</ETag></CopyObjectResult>";
}

xml::DeleteError deleteErrorFromMessage(const std::string& key, const std::string& raw) {
    const auto split = raw.find(": ");
    if (split == std::string::npos)
        return {.key = key, .code = "InternalError", .message = raw};
    return {
        .key = key,
        .code = raw.substr(0, split),
        .message = raw.substr(split + 2)
    };
}

struct GatewayBudgetReservation {
    storage::s3::pricing::PriceBudgetPreflightRequest request;
    storage::s3::pricing::PriceEstimateReport estimate;
    storage::s3::pricing::PriceBudgetDecision decision;
};

using GatewayUsage = storage::s3::S3GatewayUpstreamUsage;

std::pair<std::string, bool> providerBudgetIdentity(const std::shared_ptr<storage::CloudEngine>& cloud) {
    const auto profile = cloud ? cloud->s3ProviderProfile() : nullptr;
    const auto costProfileId = profile ? profile->costProfileId() : std::optional<std::string>{};
    return {
        costProfileId ? *costProfileId : (profile ? profile->id() : std::string{"unknown"}),
        costProfileId && storage::s3::pricing::isSupportedPriceBudgetProvider(*costProfileId)
    };
}

bool shouldEnforceLocalGatewayUsage(const AuthContext& auth) {
    return auth.enforce_budget_for_local_requests ||
        auth.credential.enforce_budget_for_local_requests;
}

bool usageHasBudgetImpact(const GatewayUsage& usage) {
    return !usage.empty();
}

GatewayUsage syntheticUsageForGatewayOperation(
    const storage::s3::pricing::S3GatewayOperation operation,
    const uint64_t uploadBytes = 0,
    const uint64_t downloadBytes = 0,
    const uint64_t objectCount = 1,
    std::string source = "synthetic_local") {
    GatewayUsage usage;
    usage.synthetic = true;
    usage.source = std::move(source);
    const auto count = std::max<uint64_t>(1, objectCount);

    switch (operation) {
    case storage::s3::pricing::S3GatewayOperation::ListBuckets:
    case storage::s3::pricing::S3GatewayOperation::ListObjectsV2:
    case storage::s3::pricing::S3GatewayOperation::ListMultipartUploads:
    case storage::s3::pricing::S3GatewayOperation::ListParts:
        usage.list_requests = 1;
        break;
    case storage::s3::pricing::S3GatewayOperation::CreateBucket:
    case storage::s3::pricing::S3GatewayOperation::HeadBucket:
    case storage::s3::pricing::S3GatewayOperation::HeadObject:
        usage.head_requests = 1;
        break;
    case storage::s3::pricing::S3GatewayOperation::GetObject:
        usage.get_requests = 1;
        usage.downloaded_bytes = downloadBytes;
        break;
    case storage::s3::pricing::S3GatewayOperation::PutObject:
    case storage::s3::pricing::S3GatewayOperation::CreateMultipartUpload:
    case storage::s3::pricing::S3GatewayOperation::UploadPart:
    case storage::s3::pricing::S3GatewayOperation::CompleteMultipartUpload:
        usage.put_requests = 1;
        usage.uploaded_bytes = uploadBytes;
        break;
    case storage::s3::pricing::S3GatewayOperation::CopyObject:
        usage.copy_requests = 1;
        usage.downloaded_bytes = downloadBytes;
        usage.uploaded_bytes = uploadBytes;
        break;
    case storage::s3::pricing::S3GatewayOperation::DeleteBucket:
    case storage::s3::pricing::S3GatewayOperation::DeleteObject:
    case storage::s3::pricing::S3GatewayOperation::AbortMultipartUpload:
        usage.delete_requests = 1;
        break;
    case storage::s3::pricing::S3GatewayOperation::DeleteObjects:
        usage.delete_requests = count;
        break;
    }

    return usage;
}

vh::sync::model::S3CostEstimate s3CostEstimateFromUsage(const GatewayUsage& usage) {
    vh::sync::model::S3CostEstimate estimate;
    estimate.list_requests = usage.list_requests;
    estimate.head_requests = usage.head_requests;
    estimate.get_requests = usage.get_requests;
    estimate.put_requests = usage.put_requests;
    estimate.copy_requests = usage.copy_requests;
    estimate.delete_requests = usage.delete_requests;
    estimate.planned_body_download_bytes = usage.downloaded_bytes;
    estimate.planned_upload_bytes = usage.uploaded_bytes;
    estimate.remote_index_objects = 1;
    return estimate;
}

Decimal syntheticCostDecimal(const std::string& value) {
    return Decimal(value.empty() ? "0" : value);
}

std::string formatSyntheticCost(const Decimal& value) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(8) << (value == Decimal("0") ? Decimal("0") : value);
    auto text = out.str();
    if (text == "-0.00000000") return "0.00000000";
    return text;
}

Decimal requestCost(const uint64_t count, const std::string& unitCost) {
    return Decimal(count) * syntheticCostDecimal(unitCost);
}

Decimal byteGbCost(const uint64_t bytes, const std::string& gbCost) {
    if (bytes == 0) return Decimal("0");
    constexpr uint64_t gib = 1024ull * 1024ull * 1024ull;
    return (Decimal(bytes) / Decimal(gib)) * syntheticCostDecimal(gbCost);
}

storage::s3::pricing::PriceEstimateReport estimateSyntheticLocalGatewayUsage(const GatewayUsage& usage) {
    const auto& cfg = config::Registry::get().s3_gateway.synthetic_local_request_cost_usd;

    Decimal total{"0"};
    total += requestCost(usage.list_requests, cfg.list);
    total += requestCost(usage.head_requests, cfg.head);
    total += requestCost(usage.get_requests, cfg.get);
    total += requestCost(usage.put_requests, cfg.put);
    total += requestCost(usage.delete_requests, cfg.delete_);
    total += requestCost(usage.copy_requests, cfg.copy);
    total += byteGbCost(usage.downloaded_bytes, cfg.downloaded_gb);
    total += byteGbCost(usage.uploaded_bytes, cfg.uploaded_gb);

    storage::s3::pricing::PriceEstimateReport report;
    report.available = true;
    report.supported = true;
    report.stale = false;
    report.target = {
        .provider = "gateway-local",
        .region = "local",
        .storage_class = "synthetic"
    };
    report.estimated_cost = formatSyntheticCost(total);
    report.currency = "USD";
    report.price_profile_id = "gateway-local/local/synthetic";
    report.catalog_version = "configured";
    report.catalog_source = "s3_gateway.synthetic_local_request_cost_usd";
    report.catalog_verified = true;
    report.catalog_age_seconds = 0;
    report.confidence_level = "configured";
    report.estimate_mode = "budget_conservative";
    report.free_tier_policy = "ignore_account_wide_free_tiers";
    report.free_tiers_applied = false;
    return report;
}

storage::s3::pricing::PriceEstimateReport estimateGatewayUsage(
    const storage::CloudEngine& cloud,
    const GatewayUsage& usage,
    const std::optional<std::string>& storageClass) {
    storage::s3::pricing::PriceEstimateOptions options{
        .mode = storage::s3::pricing::PriceEstimateMode::BudgetConservative
    };
    if (storageClass) {
        const auto profile = cloud.s3ProviderProfile();
        if (!profile)
            return storage::s3::pricing::PriceEstimateReport::unsupported("S3 provider has no price-bot profile");
        const auto resolution = profile->normalizeStorageTier(*storageClass);
        if (!resolution.ok)
            return storage::s3::pricing::PriceEstimateReport::unsupported(resolution.error);
        options.storage_tier_override = resolution.resolved;
    }
    return storage::s3::pricing::estimatePlannedS3Sync(
        cloud,
        s3CostEstimateFromUsage(usage),
        options);
}

std::string localUsageSource(const ResolvedBucket& bucket) {
    return ObjectStore::isRemoteBacked(bucket) ? "local_cache" : "local_file";
}

bool hasLocalMaterializedObject(const ResolvedBucket& bucket, const std::string& key) {
    if (!key.empty() && key.back() == '/') return true;
    return static_cast<bool>(db::query::fs::File::getFileByPath(bucket.vault_id, ObjectStore::keyToVaultPath(key)));
}

std::string formatGatewayRequestBudgetDenialForS3(
    const std::string& kind,
    const ResolvedBucket& bucket,
    const AuthContext& auth,
    const std::string& rid,
    const storage::s3::pricing::S3GatewayOperation operation,
    const std::string& providerKey) {
    std::ostringstream out;
    out << "S3 gateway request budget exceeded: "
        << "kind=" << kind
        << ", vault_id=" << bucket.vault_id
        << ", provider_key=" << providerKey
        << ", gateway_credential_id=" << (auth.credential_id == 0 ? std::string{"none"} : std::to_string(auth.credential_id))
        << ", operation=" << storage::s3::pricing::toString(operation)
        << ", request_uuid=" << rid;
    return out.str();
}

std::optional<GatewayBudgetReservation> preflightGatewayBudget(
    const ResolvedBucket& bucket,
    const AuthContext& auth,
    const std::string& rid,
    const storage::s3::pricing::S3GatewayOperation operation,
    const GatewayUsage& usage,
    const bool gatewayScopesOnly = false,
    const std::optional<std::string>& storageClass = std::nullopt,
    const std::optional<std::string>& objectKey = std::nullopt) {
    if (!usageHasBudgetImpact(usage)) return std::nullopt;

    std::string providerKey;
    bool providerSupported = false;
    storage::s3::pricing::PriceEstimateReport estimate;
    if (gatewayScopesOnly && usage.synthetic) {
        providerKey = "gateway-local";
        providerSupported = true;
        estimate = estimateSyntheticLocalGatewayUsage(usage);
    } else if (ObjectStore::isRemoteBacked(bucket)) {
        const auto cloud = ObjectStore::cloudEngine(bucket);
        if (!cloud) throw invalidArgument("Bucket is not backed by a CloudEngine", bucket.bucket_name);

        std::tie(providerKey, providerSupported) = providerBudgetIdentity(cloud);
        estimate = estimateGatewayUsage(*cloud, usage, storageClass);
    } else {
        return std::nullopt;
    }

    storage::s3::pricing::PriceBudgetPreflightRequest budgetRequest{
        .vault_id = bucket.vault_id,
        .run_uuid = rid,
        .provider_key = providerKey,
        .provider_supported = providerSupported,
        .estimate = estimate,
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = auth.credential_id == 0 ? std::optional<uint32_t>{} : std::make_optional(auth.credential_id),
        .request_uuid = rid,
        .operation = storage::s3::pricing::toString(operation),
        .object_key = objectKey,
        .gateway_scopes_only = gatewayScopesOnly,
        .synthetic = usage.synthetic,
        .usage_source = usage.source.empty() ? std::optional<std::string>{} : std::make_optional(usage.source)
    };

    storage::s3::pricing::PriceBudgetService service;
    auto decision = service.preflight(budgetRequest);
    service.recordPreflightNotifications(budgetRequest, decision);
    if (!decision.allowed) {
        throw S3Error{
            "AccessDenied",
            storage::s3::pricing::formatGatewayBudgetDenialForS3(decision, budgetRequest),
            http::status::forbidden,
            bucket.bucket_name};
    }

    return GatewayBudgetReservation{
        .request = std::move(budgetRequest),
        .estimate = std::move(estimate),
        .decision = std::move(decision)
    };
}

std::optional<GatewayBudgetReservation> preflightSyntheticGatewayBudget(
    const ResolvedBucket& bucket,
    const AuthContext& auth,
    const std::string& rid,
    const storage::s3::pricing::S3GatewayOperation operation,
    const uint64_t uploadBytes = 0,
    const uint64_t downloadBytes = 0,
    const uint64_t objectCount = 1,
    const std::optional<std::string>& storageClass = std::nullopt,
    const std::optional<std::string>& objectKey = std::nullopt,
    const std::string& source = "synthetic_local") {
    if (!shouldEnforceLocalGatewayUsage(auth)) return std::nullopt;
    return preflightGatewayBudget(
        bucket,
        auth,
        rid,
        operation,
        syntheticUsageForGatewayOperation(operation, uploadBytes, downloadBytes, objectCount, source),
        true,
        storageClass,
        objectKey);
}

void commitGatewayBudget(const std::optional<GatewayBudgetReservation>& budget, const bool finalCostKnown = true) {
    if (!budget) return;
    storage::s3::pricing::PriceBudgetService{}.commit(
        budget->decision.reservations,
        finalCostKnown && budget->estimate.available
            ? std::make_optional(budget->estimate.estimated_cost)
            : std::optional<std::string>{});
}

void commitGatewayBudget(
    const std::optional<GatewayBudgetReservation>& budget,
    const std::optional<std::string>& finalCostOverride) {
    if (!budget) return;
    storage::s3::pricing::PriceBudgetService{}.commit(
        budget->decision.reservations,
        finalCostOverride ? finalCostOverride : (
            budget->estimate.available
                ? std::make_optional(budget->estimate.estimated_cost)
                : std::optional<std::string>{}));
}

void releaseGatewayBudget(const std::optional<GatewayBudgetReservation>& budget) {
    if (!budget) return;
    storage::s3::pricing::PriceBudgetService{}.release(budget->decision.reservations);
}

std::optional<std::string> estimatedCostForGatewayUsage(
    const ResolvedBucket& bucket,
    const GatewayUsage& usage,
    const std::optional<std::string>& storageClass) {
    if (!ObjectStore::isRemoteBacked(bucket) || usage.empty()) return std::nullopt;
    const auto cloud = ObjectStore::cloudEngine(bucket);
    if (!cloud) return std::nullopt;
    const auto estimate = estimateGatewayUsage(*cloud, usage, storageClass);
    if (!estimate.available) return std::nullopt;
    return estimate.estimated_cost;
}

std::optional<storage::s3::S3RequestBudget> requestBudgetForBucket(const ResolvedBucket& bucket) {
    const auto cloud = ObjectStore::cloudEngine(bucket);
    if (!cloud) return std::nullopt;
    const auto policy = cloud->remote_policy();
    if (!policy) return std::nullopt;
    return policy->s3_request_budget;
}

S3Error requestBudgetExceededForGateway(
    const storage::s3::RequestBudgetExceeded& error,
    const ResolvedBucket& bucket,
    const AuthContext& auth,
    const std::string& rid,
    const storage::s3::pricing::S3GatewayOperation operation) {
    const auto cloud = ObjectStore::cloudEngine(bucket);
    const auto [providerKey, providerSupported] = providerBudgetIdentity(cloud);
    (void)providerSupported;
    return S3Error{
        "SlowDown",
        formatGatewayRequestBudgetDenialForS3(
            error.kind().empty() ? std::string{"unknown"} : error.kind(),
            bucket,
            auth,
            rid,
            operation,
            providerKey),
        http::status::service_unavailable,
        bucket.bucket_name};
}

template <typename Fn>
auto executeWithActualUsageCapture(
    const ResolvedBucket& bucket,
    const AuthContext& auth,
    const std::string& rid,
    const storage::s3::pricing::S3GatewayOperation operation,
    Fn&& fn) {
    using Result = std::invoke_result_t<Fn>;

    const auto cloud = ObjectStore::cloudEngine(bucket);
    if (!cloud) {
        try {
            if constexpr (std::is_void_v<Result>) {
                fn();
                return GatewayUsage{};
            } else {
                return std::pair<Result, GatewayUsage>{fn(), GatewayUsage{}};
            }
        } catch (const storage::s3::RequestBudgetExceeded& e) {
            throw requestBudgetExceededForGateway(e, bucket, auth, rid, operation);
        }
    }

    // S3 gateway provider calls are synchronous on the current session worker thread,
    // so thread-local capture does not mix concurrent sessions. The capture object
    // itself still snapshots usage behind a mutex.
    storage::ScopedS3RequestUsageCapture capture(*cloud, requestBudgetForBucket(bucket));
    try {
        if constexpr (std::is_void_v<Result>) {
            fn();
            return capture.usage();
        } else {
            auto value = fn();
            return std::pair<Result, GatewayUsage>{std::move(value), capture.usage()};
        }
    } catch (const storage::s3::RequestBudgetExceeded& e) {
        throw requestBudgetExceededForGateway(e, bucket, auth, rid, operation);
    }
}

void recordGatewaySyncOrigin(
    const ResolvedBucket& bucket,
    const AuthContext& auth,
    const std::string& rid,
    const std::string& operation,
    const std::string& objectKey) {
    if (!ObjectStore::isRemoteBacked(bucket)) return;
    db::query::s3::Gateway::recordSyncOrigin(
        bucket.vault_id,
        objectKey,
        operation,
        auth.credential_id == 0 ? std::optional<uint32_t>{} : std::make_optional(auth.credential_id),
        rid);
}
}

Router::Router()
    : auth_(config::Registry::get().s3_gateway.require_sigv4) {}

std::string Router::checksumSha256Base64(const std::vector<uint8_t>& bytes) {
    const auto digest = crypto::util::EvpDigest::of(EVP_sha256(), bytes.data(), bytes.size());
    std::array<unsigned char, EVP_ENCODE_LENGTH(SHA256_DIGEST_LENGTH)> encoded{};
    const auto len = EVP_EncodeBlock(encoded.data(), digest.data(), static_cast<int>(digest.size()));
    return {reinterpret_cast<char*>(encoded.data()), static_cast<std::size_t>(len)};
}

std::string Router::checksumCrc32Base64(const std::vector<uint8_t>& bytes) {
    const auto crc = static_cast<uint32_t>(crc32(0L, bytes.data(), static_cast<uInt>(bytes.size())));
    const std::array<unsigned char, 4> raw{
        static_cast<unsigned char>((crc >> 24) & 0xff),
        static_cast<unsigned char>((crc >> 16) & 0xff),
        static_cast<unsigned char>((crc >> 8) & 0xff),
        static_cast<unsigned char>(crc & 0xff)
    };
    std::array<unsigned char, EVP_ENCODE_LENGTH(raw.size())> encoded{};
    const auto len = EVP_EncodeBlock(encoded.data(), raw.data(), static_cast<int>(raw.size()));
    return {reinterpret_cast<char*>(encoded.data()), static_cast<std::size_t>(len)};
}

Router::ParsedTarget Router::parseRequestTarget(const Request& request) {
    const auto path = targetPath(std::string(request.target()));
    const auto query = parseQuery(targetQuery(std::string(request.target())));
    std::string decoded = pctDecode(path);
    while (!decoded.empty() && decoded.front() == '/') decoded.erase(decoded.begin());

    ParsedTarget out;
    out.query = query;
    if (!pathStyleOnlyProxy(request)) {
        if (const auto virtualBucket = virtualHostedBucket(request)) {
            out.bucket = *virtualBucket;
            out.key = decoded;
            return out;
        }
    }

    if (!config::Registry::get().s3_gateway.allow_path_style)
        throw invalidArgument("Path-style bucket addressing is disabled", path);

    const auto slash = decoded.find('/');
    if (slash == std::string::npos) {
        out.bucket = decoded;
        return out;
    }
    out.bucket = decoded.substr(0, slash);
    out.key = decoded.substr(slash + 1);
    return out;
}

Router::ParsedCopySource Router::parseCopySource(std::string raw) {
    while (!raw.empty() && raw.front() == '/') raw.erase(raw.begin());

    const auto queryStart = raw.find('?');
    const auto rawPath = queryStart == std::string::npos ? raw : raw.substr(0, queryStart);
    const auto rawQuery = queryStart == std::string::npos ? std::string{} : raw.substr(queryStart + 1);

    const auto slash = rawPath.find('/');
    if (slash == std::string::npos || slash == 0)
        throw invalidArgument("Invalid copy source", raw);

    return {
        .bucket = pctDecode(rawPath.substr(0, slash)),
        .key = pctDecode(rawPath.substr(slash + 1)),
        .query = parseQuery(rawQuery)
    };
}

Router::Response Router::route(Request&& request) const {
    return route(std::move(request), BodyPayload{});
}

Router::Response Router::route(Request&& request, BodyPayload payload) const {
    const auto rid = requestId();
    try {
        auto input = sigv4::inputFromRequest(request, request.body());
        input.body_sha256 = payload.sha256_hex;
        const auto auth = auth_.authenticate(input);
        auto response = routeAuthenticated(std::move(request), auth, rid, payload);
        response.set("x-amz-request-id", rid);
        return response;
    } catch (const S3Error& e) {
        return errorResponse(request, e, rid);
    } catch (const storage::s3::RequestBudgetExceeded& e) {
        return errorResponse(
            request,
            S3Error{
                "SlowDown",
                std::string{"S3 gateway request budget exceeded: kind="} +
                    (e.kind().empty() ? std::string{"unknown"} : e.kind()) +
                    ", request_uuid=" + rid,
                http::status::service_unavailable,
                std::string(request.target())},
            rid);
    } catch (const std::exception& e) {
        log::Registry::runtime()->error("[S3Gateway] Request failed: {}", e.what());
        return errorResponse(request, S3Error{"InternalError", e.what(), http::status::internal_server_error, std::string(request.target())}, rid);
    }
}

Router::Response Router::errorResponse(const Request& request, const S3Error& error, const std::string& rid) {
    auto response = makeResponse(
        request,
        error.status,
        xml::error(error.code, error.what(), error.resource, rid));
    response.set("x-amz-request-id", rid);
    return response;
}

Router::Response Router::routeAuthenticated(
    Request&& request,
    const AuthContext& auth,
    const std::string& rid,
    const BodyPayload& payload) const {
    const auto parsed = parseRequestTarget(request);

    if (parsed.bucket.empty()) {
        if (request.method() != http::verb::get) throw notImplemented("Only GET / is supported at service root", "/");
        std::vector<xml::Bucket> buckets;
        for (const auto& bucket : objects_.listBuckets(auth))
            buckets.push_back({.name = bucket.bucket_name, .created_at = bucket.created_at});
        return makeResponse(request, http::status::ok, xml::listBuckets(buckets, auth.user->name()));
    }

    if (parsed.key.empty()) {
        if (request.method() == http::verb::put) {
            objects_.createBucket(parsed.bucket, auth, config::Registry::get().s3_gateway.default_bucket_mode);
            return makeResponse(request, http::status::ok, {});
        }
        if (request.method() == http::verb::head) {
            auto bucket = objects_.headBucket(parsed.bucket, auth);
            auto budget = preflightSyntheticGatewayBudget(
                bucket,
                auth,
                rid,
                storage::s3::pricing::S3GatewayOperation::HeadBucket,
                0,
                0,
                1,
                std::nullopt,
                std::nullopt,
                "metadata");
            commitGatewayBudget(budget);
            auto response = makeResponse(request, http::status::ok, {});
            response.body().clear();
            response.prepare_payload();
            return response;
        }
        if (request.method() == http::verb::delete_) {
            auto bucket = objects_.resolveBucket(parsed.bucket, auth);
            if (!ObjectStore::credentialAllowsAdmin(bucket)) throw accessDenied(parsed.bucket);
            auto budget = preflightSyntheticGatewayBudget(
                bucket,
                auth,
                rid,
                storage::s3::pricing::S3GatewayOperation::DeleteBucket);
            try {
                objects_.deleteBucket(parsed.bucket, auth);
                commitGatewayBudget(budget);
            } catch (...) {
                releaseGatewayBudget(budget);
                throw;
            }
            return makeResponse(request, http::status::no_content, {});
        }

        auto bucket = objects_.headBucket(parsed.bucket, auth);
        if (request.method() == http::verb::get && hasQuery(parsed.query, "uploads"))
        {
            objects_.requireS3Permission(bucket, auth, S3Action::ListMultipartUploads);
            auto budget = preflightSyntheticGatewayBudget(
                bucket,
                auth,
                rid,
                storage::s3::pricing::S3GatewayOperation::ListMultipartUploads,
                0,
                0,
                1,
                std::nullopt,
                std::nullopt,
                "metadata");
            try {
                auto response = makeResponse(request, http::status::ok, xml::listMultipartUploads(parsed.bucket, multipart_.listUploads(bucket, parsed.query.contains("prefix") ? parsed.query.at("prefix") : "")));
                commitGatewayBudget(budget);
                return response;
            } catch (...) {
                releaseGatewayBudget(budget);
                throw;
            }
        }

        if (request.method() == http::verb::get) {
            db::query::s3::ObjectListParams params;
            params.prefix = parsed.query.contains("prefix") ? parsed.query.at("prefix") : "";
            if (parsed.query.contains("delimiter")) params.delimiter = parsed.query.at("delimiter");
            if (parsed.query.contains("start-after")) params.start_after = parsed.query.at("start-after");
            if (parsed.query.contains("continuation-token")) params.continuation_token = parsed.query.at("continuation-token");
            params.max_keys = parseMaxKeys(parsed.query);
            const auto encodingType = parseEncodingType(parsed.query);
            auto budget = preflightSyntheticGatewayBudget(
                bucket,
                auth,
                rid,
                storage::s3::pricing::S3GatewayOperation::ListObjectsV2,
                0,
                0,
                1,
                std::nullopt,
                std::nullopt,
                "metadata");
            try {
                auto result = objects_.listObjects(bucket, params);
                auto response = makeResponse(
                    request,
                    http::status::ok,
                    xml::listObjectsV2(parsed.bucket, result, params.prefix, params.delimiter, params.max_keys, encodingType));
                if (objects_.remoteIndexStale(bucket))
                    response.set("x-vaulthalla-index-stale", "true");
                commitGatewayBudget(budget);
                return response;
            } catch (...) {
                releaseGatewayBudget(budget);
                throw;
            }
        }

        if (request.method() == http::verb::post && hasQuery(parsed.query, "delete")) {
            bool quiet = false;
            const auto keys = parseDeleteObjects(request.body(), quiet);
            for (const auto& key : keys)
                objects_.requireS3Permission(bucket, auth, S3Action::DeleteObjects, key);
            auto budget = preflightSyntheticGatewayBudget(
                bucket,
                auth,
                rid,
                storage::s3::pricing::S3GatewayOperation::DeleteObjects,
                0,
                0,
                keys.size(),
                std::nullopt,
                std::nullopt,
                "sync_deferred");
            std::vector<std::pair<std::string, std::optional<std::string>>> results;
            try {
                results = objects_.deleteObjects(bucket, keys);
            } catch (...) {
                releaseGatewayBudget(budget);
                throw;
            }
            for (const auto& [key, error] : results)
                if (!error) recordGatewaySyncOrigin(bucket, auth, rid, "delete", key);
            std::vector<xml::DeletedObject> deleted;
            std::vector<xml::DeleteError> errors;
            for (const auto& [key, error] : results) {
                if (!error) deleted.push_back({.key = key});
                else errors.push_back(deleteErrorFromMessage(key, *error));
            }
            auto response = makeResponse(request, http::status::ok, xml::deleteResult(deleted, errors, quiet));
            commitGatewayBudget(budget);
            return response;
        }

        throw notImplemented("Unsupported bucket operation", parsed.bucket);
    }

    auto bucket = objects_.resolveBucket(parsed.bucket, auth);

    if (request.method() == http::verb::post && hasQuery(parsed.query, "uploads")) {
        objects_.requireS3Permission(bucket, auth, S3Action::CreateMultipartUpload, parsed.key);
        const auto options = putOptionsFromRequest(request);
        auto budget = preflightSyntheticGatewayBudget(
            bucket,
            auth,
            rid,
            storage::s3::pricing::S3GatewayOperation::CreateMultipartUpload,
            0,
            0,
            1,
            options.storage_class,
            parsed.key,
            "sync_deferred");
        try {
            const auto uploadId = multipart_.createUpload(bucket, parsed.key, options);
            commitGatewayBudget(budget);
            return makeResponse(request, http::status::ok, xml::initiateMultipartUpload(parsed.bucket, parsed.key, uploadId));
        } catch (...) {
            releaseGatewayBudget(budget);
            throw;
        }
    }

    if (request.method() == http::verb::put && hasQuery(parsed.query, "partNumber") && hasQuery(parsed.query, "uploadId")) {
        objects_.requireS3Permission(bucket, auth, S3Action::UploadPart, parsed.key);
        const auto partNumber = parsePartNumber(parsed.query);
        auto budget = preflightSyntheticGatewayBudget(
            bucket,
            auth,
            rid,
            storage::s3::pricing::S3GatewayOperation::UploadPart,
            payload.size,
            0,
            1,
            std::nullopt,
            parsed.key,
            "sync_deferred");
        db::query::s3::MultipartPart part;
        try {
            if (payload.temp_file) {
                validateContentMd5(request, payload);
                validateS3Checksums(request, payload);
                part = multipart_.uploadPartFromFile(bucket, parsed.key, parsed.query.at("uploadId"), partNumber,
                                                     *payload.temp_file, payload.size);
            } else {
                auto body = bodyBytes(request, payload);
                validateContentMd5(request, body);
                validateS3Checksums(request, body);
                part = multipart_.uploadPart(bucket, parsed.key, parsed.query.at("uploadId"), partNumber, body);
            }
            commitGatewayBudget(budget);
        } catch (...) {
            releaseGatewayBudget(budget);
            throw;
        }
        auto response = makeResponse(request, http::status::ok, {});
        response.set(http::field::etag, part.etag);
        return response;
    }

    if (request.method() == http::verb::post && hasQuery(parsed.query, "uploadId")) {
        objects_.requireS3Permission(bucket, auth, S3Action::CompleteMultipartUpload, parsed.key);
        uint64_t totalSize = 0;
        for (const auto& part : multipart_.listParts(bucket, parsed.key, parsed.query.at("uploadId")))
            totalSize += part.size_bytes;
        const auto completeParts = parseCompleteParts(request.body());
        auto budget = preflightSyntheticGatewayBudget(
            bucket,
            auth,
            rid,
            storage::s3::pricing::S3GatewayOperation::CompleteMultipartUpload,
            totalSize,
            0,
            1,
            std::nullopt,
            parsed.key,
            "sync_deferred");
        try {
            const auto state = multipart_.completeUpload(bucket, parsed.key, parsed.query.at("uploadId"), completeParts);
            recordGatewaySyncOrigin(bucket, auth, rid, "multipart_complete", parsed.key);
            commitGatewayBudget(budget);
            return makeResponse(
                request,
                http::status::ok,
                xml::completeMultipartUpload("/" + parsed.bucket + "/" + parsed.key, parsed.bucket, parsed.key, state.etag));
        } catch (...) {
            releaseGatewayBudget(budget);
            throw;
        }
    }

    if (request.method() == http::verb::delete_ && hasQuery(parsed.query, "uploadId")) {
        objects_.requireS3Permission(bucket, auth, S3Action::AbortMultipartUpload, parsed.key);
        auto budget = preflightSyntheticGatewayBudget(
            bucket,
            auth,
            rid,
            storage::s3::pricing::S3GatewayOperation::AbortMultipartUpload,
            0,
            0,
            1,
            std::nullopt,
            parsed.key,
            "sync_deferred");
        try {
            multipart_.abortUpload(bucket, parsed.key, parsed.query.at("uploadId"));
            commitGatewayBudget(budget);
            return makeResponse(request, http::status::no_content, {});
        } catch (...) {
            releaseGatewayBudget(budget);
            throw;
        }
    }

    if (request.method() == http::verb::get && hasQuery(parsed.query, "uploadId")) {
        objects_.requireS3Permission(bucket, auth, S3Action::ListParts, parsed.key);
        auto budget = preflightSyntheticGatewayBudget(
            bucket,
            auth,
            rid,
            storage::s3::pricing::S3GatewayOperation::ListParts,
            0,
            0,
            1,
            std::nullopt,
            parsed.key,
            "metadata");
        try {
            auto response = makeResponse(
                request,
                http::status::ok,
                xml::listParts(parsed.bucket, parsed.key, parsed.query.at("uploadId"),
                               multipart_.listParts(bucket, parsed.key, parsed.query.at("uploadId"))));
            commitGatewayBudget(budget);
            return response;
        } catch (...) {
            releaseGatewayBudget(budget);
            throw;
        }
    }

    if (request.method() == http::verb::head) {
        objects_.requireS3Permission(bucket, auth, S3Action::HeadObject, parsed.key);
        auto budget = preflightSyntheticGatewayBudget(
            bucket,
            auth,
            rid,
            storage::s3::pricing::S3GatewayOperation::HeadObject,
            0,
            0,
            1,
            std::nullopt,
            parsed.key,
            "metadata");
        db::query::s3::ObjectState state;
        try {
            state = objects_.headObject(bucket, parsed.key);
            enforceIfMatch(request, state, parsed.key);
            if (ifNoneMatchMatches(request, state)) {
                commitGatewayBudget(budget);
                return notModifiedResponse(request, state);
            }
            const auto objectKey = ObjectStore::vaultPathToKey(ObjectStore::keyToVaultPath(parsed.key));
            const auto metadata = db::query::s3::Gateway::listObjectMetadata(bucket.vault_id, objectKey);
            auto response = makeResponse(request, http::status::ok, {});
            response.set(http::field::etag, state.etag);
            response.set(http::field::content_length, std::to_string(state.size_bytes));
            response.set(http::field::content_type, state.content_type.value_or("application/octet-stream"));
            response.set(http::field::last_modified, xml::httpDate(state.last_modified));
            for (const auto& [name, value] : metadata)
                response.set("x-amz-meta-" + name, value);
            // Do not call prepare_payload() again: HEAD must advertise object size, not empty-body size.
            response.body().clear();
            commitGatewayBudget(budget);
            return response;
        } catch (...) {
            releaseGatewayBudget(budget);
            throw;
        }
    }

    if (request.method() == http::verb::get) {
        const auto state = objects_.headObject(bucket, parsed.key);
        enforceIfMatch(request, state, parsed.key);
        if (ifNoneMatchMatches(request, state)) return notModifiedResponse(request, state);
        const auto range = parseRange(request);
        const auto localMaterialized = hasLocalMaterializedObject(bucket, parsed.key);
        std::optional<GatewayBudgetReservation> budget;
        if (ObjectStore::isRemoteBacked(bucket) && !localMaterialized) {
            GatewayUsage expected;
            expected.get_requests = 1;
            expected.downloaded_bytes = state.size_bytes;
            expected.touched_upstream = true;
            expected.source = "remote_download";
            budget = preflightGatewayBudget(
                bucket,
                auth,
                rid,
                storage::s3::pricing::S3GatewayOperation::GetObject,
                expected,
                false,
                state.storage_class,
                parsed.key);
        } else {
            budget = preflightSyntheticGatewayBudget(
                bucket,
                auth,
                rid,
                storage::s3::pricing::S3GatewayOperation::GetObject,
                0,
                state.size_bytes,
                1,
                state.storage_class,
                parsed.key,
                localUsageSource(bucket));
        }
        ObjectBody object;
        std::optional<std::string> finalBudgetCost;
        try {
            auto captured = executeWithActualUsageCapture(
                bucket,
                auth,
                rid,
                storage::s3::pricing::S3GatewayOperation::GetObject,
                [&] {
                    return objects_.getObject(bucket, parsed.key, range);
                });
            object = std::move(captured.first);
            auto actual = captured.second;
            if (actual.touched_upstream) {
                actual.source = actual.source.empty() ? "remote_download" : actual.source;
                finalBudgetCost = estimatedCostForGatewayUsage(bucket, actual, object.state.storage_class);
                if (!budget) {
                    budget = preflightGatewayBudget(
                        bucket,
                        auth,
                        rid,
                        storage::s3::pricing::S3GatewayOperation::GetObject,
                        actual,
                        false,
                        object.state.storage_class,
                        parsed.key);
                }
            } else if (budget && !budget->request.synthetic) {
                releaseGatewayBudget(budget);
                budget = preflightSyntheticGatewayBudget(
                    bucket,
                    auth,
                    rid,
                    storage::s3::pricing::S3GatewayOperation::GetObject,
                    0,
                    object.state.size_bytes,
                    1,
                    object.state.storage_class,
                    parsed.key,
                    localUsageSource(bucket));
            }
        } catch (...) {
            releaseGatewayBudget(budget);
            throw;
        }
        auto response = makeResponse(
            request,
            range ? http::status::partial_content : http::status::ok,
            std::string(object.bytes.begin(), object.bytes.end()),
            object.state.content_type.value_or("application/octet-stream"));
        response.set(http::field::etag, object.state.etag);
        response.set(http::field::last_modified, xml::httpDate(object.state.last_modified));
        if (object.content_range) {
            const auto [first, last] = *object.content_range;
            response.set(http::field::content_range,
                         "bytes " + std::to_string(first) + "-" + std::to_string(last) + "/" +
                         std::to_string(object.state.size_bytes));
        }
        for (const auto& [name, value] : object.metadata)
            response.set("x-amz-meta-" + name, value);
        response.prepare_payload();
        commitGatewayBudget(budget, finalBudgetCost);
        return response;
    }

    if (request.method() == http::verb::put) {
        objects_.requireS3Permission(bucket, auth, S3Action::PutObject, parsed.key);
        const auto ifMatch = headerOr(request, http::field::if_match);
        const auto ifNoneMatch = headerOr(request, http::field::if_none_match);
        if (!ifMatch.empty()) {
            try {
                const auto current = objects_.headObject(bucket, parsed.key);
                enforceIfMatch(request, current, parsed.key);
            } catch (const S3Error& e) {
                if (e.code == "NoSuchKey") throw preconditionFailed(parsed.key);
                throw;
            }
        }
        if (!ifNoneMatch.empty()) {
            try {
                const auto current = objects_.headObject(bucket, parsed.key);
                if (etagListMatches(ifNoneMatch, current.etag)) throw preconditionFailed(parsed.key);
            } catch (const S3Error& e) {
                if (e.code != "NoSuchKey") throw;
            }
        }

        const auto copySource = headerOrName(request, "x-amz-copy-source");
        if (!copySource.empty()) {
            const auto source = parseCopySource(copySource);
            if (source.query.contains("versionId"))
                throw notImplemented("Versioned CopyObject sources are not supported", copySource);
            const auto sourceBucket = objects_.resolveBucket(source.bucket, auth);
            objects_.requireS3Permission(sourceBucket, auth, S3Action::CopyObjectSource, source.key);
            objects_.requireS3Permission(bucket, auth, S3Action::CopyObjectDestination, parsed.key);
            const auto sourceState = objects_.headObject(sourceBucket, source.key);
            enforceCopySourcePreconditions(
                request,
                sourceState,
                source.bucket + "/" + source.key);
            const auto copyOptions = copyOptionsFromRequest(request);
            std::optional<GatewayBudgetReservation> sourceBudget;
            std::optional<GatewayBudgetReservation> destBudget;
            std::optional<std::string> sourceFinalBudgetCost;
            const auto sourceLocal = hasLocalMaterializedObject(sourceBucket, source.key);
            try {
                if (ObjectStore::isRemoteBacked(sourceBucket) && !sourceLocal) {
                    GatewayUsage expected;
                    expected.get_requests = 1;
                    expected.downloaded_bytes = sourceState.size_bytes;
                    expected.touched_upstream = true;
                    expected.source = "remote_download";
                    sourceBudget = preflightGatewayBudget(
                        sourceBucket,
                        auth,
                        rid,
                        storage::s3::pricing::S3GatewayOperation::CopyObject,
                        expected,
                        false,
                        sourceState.storage_class,
                        source.key);
                } else {
                    destBudget = preflightSyntheticGatewayBudget(
                        bucket,
                        auth,
                        rid,
                        storage::s3::pricing::S3GatewayOperation::CopyObject,
                        sourceState.size_bytes,
                        sourceState.size_bytes,
                        1,
                        copyOptions.storage_class,
                        parsed.key,
                        localUsageSource(sourceBucket));
                }
                auto captured = executeWithActualUsageCapture(
                    sourceBucket,
                    auth,
                    rid,
                    storage::s3::pricing::S3GatewayOperation::CopyObject,
                    [&] {
                        return objects_.copyObject(
                            sourceBucket,
                            source.key,
                            bucket,
                            parsed.key,
                            copyOptions);
                    });
                const auto state = std::move(captured.first);
                auto actual = captured.second;
                if (actual.touched_upstream) {
                    actual.source = actual.source.empty() ? "remote_download" : actual.source;
                    sourceFinalBudgetCost = estimatedCostForGatewayUsage(sourceBucket, actual, sourceState.storage_class);
                    if (!sourceBudget) {
                        sourceBudget = preflightGatewayBudget(
                            sourceBucket,
                            auth,
                            rid,
                            storage::s3::pricing::S3GatewayOperation::CopyObject,
                            actual,
                            false,
                            sourceState.storage_class,
                            source.key);
                    }
                } else if (sourceBudget && !sourceBudget->request.synthetic) {
                    releaseGatewayBudget(sourceBudget);
                    sourceBudget.reset();
                    destBudget = preflightSyntheticGatewayBudget(
                        bucket,
                        auth,
                        rid,
                        storage::s3::pricing::S3GatewayOperation::CopyObject,
                        sourceState.size_bytes,
                        sourceState.size_bytes,
                        1,
                        copyOptions.storage_class,
                        parsed.key,
                        localUsageSource(sourceBucket));
                }
                recordGatewaySyncOrigin(bucket, auth, rid, "copy", parsed.key);
                commitGatewayBudget(sourceBudget, sourceFinalBudgetCost);
                commitGatewayBudget(destBudget);
                return makeResponse(request, http::status::ok, copyObjectResult(state.etag, state.last_modified));
            } catch (...) {
                releaseGatewayBudget(sourceBudget);
                releaseGatewayBudget(destBudget);
                throw;
            }
        }
        db::query::s3::ObjectState state;
        const auto options = putOptionsFromRequest(request);
        std::optional<std::vector<uint8_t>> bufferedBody;
        if (payload.temp_file) {
            validateContentMd5(request, payload);
            validateS3Checksums(request, payload);
        } else {
            bufferedBody = bodyBytes(request, payload);
            validateContentMd5(request, *bufferedBody);
            validateS3Checksums(request, *bufferedBody);
        }
        auto budget = preflightSyntheticGatewayBudget(
            bucket,
            auth,
            rid,
            storage::s3::pricing::S3GatewayOperation::PutObject,
            payload.temp_file ? payload.size : bufferedBody->size(),
            0,
            1,
            options.storage_class,
            parsed.key,
            "sync_deferred");
        if (payload.temp_file) {
            auto fileOptions = options;
            if (payload.md5_hex) fileOptions.etag_override = "\"" + *payload.md5_hex + "\"";
            try {
                state = objects_.putObjectFromFile(bucket, parsed.key, *payload.temp_file, payload.size, fileOptions);
                recordGatewaySyncOrigin(bucket, auth, rid, "put", parsed.key);
                commitGatewayBudget(budget);
            } catch (...) {
                releaseGatewayBudget(budget);
                throw;
            }
        } else {
            try {
                state = objects_.putObject(bucket, parsed.key, *bufferedBody, options);
                recordGatewaySyncOrigin(bucket, auth, rid, "put", parsed.key);
                commitGatewayBudget(budget);
            } catch (...) {
                releaseGatewayBudget(budget);
                throw;
            }
        }
        auto response = makeResponse(request, http::status::ok, {});
        response.set(http::field::etag, state.etag);
        return response;
    }

    if (request.method() == http::verb::delete_) {
        objects_.requireS3Permission(bucket, auth, S3Action::DeleteObject, parsed.key);
        const auto ifMatch = headerOr(request, http::field::if_match);
        if (!ifMatch.empty()) {
            try {
                const auto current = objects_.headObject(bucket, parsed.key);
                enforceIfMatch(request, current, parsed.key);
            } catch (const S3Error& e) {
                if (e.code == "NoSuchKey") throw preconditionFailed(parsed.key);
                throw;
            }
        }
        auto budget = preflightSyntheticGatewayBudget(
            bucket,
            auth,
            rid,
            storage::s3::pricing::S3GatewayOperation::DeleteObject,
            0,
            0,
            1,
            std::nullopt,
            parsed.key,
            "sync_deferred");
        try {
            objects_.deleteObject(bucket, parsed.key);
            recordGatewaySyncOrigin(bucket, auth, rid, "delete", parsed.key);
            commitGatewayBudget(budget);
        } catch (...) {
            releaseGatewayBudget(budget);
            throw;
        }
        return makeResponse(request, http::status::no_content, {});
    }

    throw notImplemented("Unsupported object operation", parsed.bucket + "/" + parsed.key);
}

} // namespace vh::protocols::s3
