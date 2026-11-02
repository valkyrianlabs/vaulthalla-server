#include "email/providers/SesProvider.hpp"
#include "email/providers/SesSigning.hpp"

#include "crypto/secrets/Manager.hpp"

#include <nlohmann/json.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <map>
#include <sstream>
#include <utility>

namespace vh::email::providers {

namespace {

constexpr const char* kSesPath = "/v2/email/outbound-emails";
constexpr const char* kAwsAlgorithm = "AWS4-HMAC-SHA256";
constexpr const char* kAwsService = "ses";

std::string sesSafeSummary(const std::string& value) {
    constexpr std::size_t kMax = 300;
    std::string out = value;
    out.erase(std::remove(out.begin(), out.end(), '\n'), out.end());
    out.erase(std::remove(out.begin(), out.end(), '\r'), out.end());
    if (out.size() > kMax) out = out.substr(0, kMax) + "...";
    return out;
}

std::string sesResponseErrorSummary(const HttpResponse& response) {
    const auto parsed = nlohmann::json::parse(response.body, nullptr, false);
    if (!parsed.is_discarded()) {
        if (parsed.contains("message") && parsed["message"].is_string())
            return sesSafeSummary(parsed["message"].get<std::string>());
        if (parsed.contains("Message") && parsed["Message"].is_string())
            return sesSafeSummary(parsed["Message"].get<std::string>());
        if (parsed.contains("error") && parsed["error"].is_string())
            return sesSafeSummary(parsed["error"].get<std::string>());
    }

    if (!response.body.empty()) return sesSafeSummary(response.body);
    return "HTTP " + std::to_string(response.status);
}

std::string sha256Hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);

    std::ostringstream out;
    for (const unsigned char c : hash)
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    return out.str();
}

std::string hmacSha256Raw(const std::string& key, const std::string& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest, nullptr);
    return {reinterpret_cast<char*>(digest), SHA256_DIGEST_LENGTH};
}

std::string hmacSha256HexFromRaw(const std::string& rawKey, const std::string& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), rawKey.data(), static_cast<int>(rawKey.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest, nullptr);

    std::ostringstream out;
    for (const unsigned char c : digest)
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    return out.str();
}

std::string formatUtcBasic(const char* format, const std::time_t now) {
    std::tm utc{};
    gmtime_r(&now, &utc);

    std::ostringstream out;
    out << std::put_time(&utc, format);
    return out.str();
}

std::string endpointHost(const std::string& endpoint) {
    auto host = endpoint;
    if (const auto scheme = host.find("://"); scheme != std::string::npos)
        host = host.substr(scheme + 3);
    if (const auto slash = host.find('/'); slash != std::string::npos)
        host = host.substr(0, slash);
    return host;
}

std::string trimTrailingSlashes(std::string value) {
    while (!value.empty() && value.back() == '/') value.pop_back();
    return value;
}

}

detail::SigningResult detail::signAwsV4(
    const std::string& accessKey,
    const std::string& secretKey,
    const std::string& region,
    const std::string& method,
    const std::string& path,
    const std::string& query,
    const std::map<std::string, std::string>& headers,
    const std::string& payload,
    const std::time_t now
) {
    const auto payloadHash = sha256Hex(payload);
    const auto amzDate = formatUtcBasic("%Y%m%dT%H%M%SZ", now);
    const auto dateStamp = formatUtcBasic("%Y%m%d", now);

    std::ostringstream canonicalHeaders;
    std::ostringstream signedHeaders;
    for (auto it = headers.begin(); it != headers.end(); ++it) {
        canonicalHeaders << it->first << ":" << it->second << "\n";
        signedHeaders << it->first;
        if (std::next(it) != headers.end()) signedHeaders << ";";
    }

    std::ostringstream canonicalRequest;
    canonicalRequest << method << "\n"
                     << path << "\n"
                     << query << "\n"
                     << canonicalHeaders.str() << "\n"
                     << signedHeaders.str() << "\n"
                     << payloadHash;

    const auto credentialScope = dateStamp + "/" + region + "/" + kAwsService + "/aws4_request";
    std::ostringstream stringToSign;
    stringToSign << kAwsAlgorithm << "\n"
                 << amzDate << "\n"
                 << credentialScope << "\n"
                 << sha256Hex(canonicalRequest.str());

    const auto kDate = hmacSha256Raw("AWS4" + secretKey, dateStamp);
    const auto kRegion = hmacSha256Raw(kDate, region);
    const auto kService = hmacSha256Raw(kRegion, kAwsService);
    const auto kSigning = hmacSha256Raw(kService, "aws4_request");
    const auto signature = hmacSha256HexFromRaw(kSigning, stringToSign.str());

    std::ostringstream authorization;
    authorization << kAwsAlgorithm << " "
                  << "Credential=" << accessKey << "/" << credentialScope << ", "
                  << "SignedHeaders=" << signedHeaders.str() << ", "
                  << "Signature=" << signature;

    return {
        .authorization = authorization.str(),
        .amzDate = amzDate,
        .payloadHash = payloadHash,
        .canonicalRequest = canonicalRequest.str(),
        .stringToSign = stringToSign.str()
    };
}

SesProvider::SesProvider(
    config::SesEmailConfig config,
    std::shared_ptr<crypto::secrets::Manager> secretsManager,
    std::unique_ptr<Transport> transport
) : config_(std::move(config)),
    secretsManager_(std::move(secretsManager)),
    transport_(std::move(transport)) {}

std::string SesProvider::endpointForConfig(const config::SesEmailConfig& config) {
    if (config.endpoint && !config.endpoint->empty())
        return trimTrailingSlashes(*config.endpoint);
    return "https://email." + config.region + ".amazonaws.com";
}

SendResult SesProvider::send(const Message& message) {
    try {
        validateMessage(message);
    } catch (const std::exception& e) {
        SendResult result;
        result.errorSummary = e.what();
        return result;
    }

    if (!secretsManager_) {
        SendResult result;
        result.errorSummary = "secrets manager unavailable";
        return result;
    }
    if (!transport_) {
        SendResult result;
        result.errorSummary = "email transport unavailable";
        return result;
    }
    if (config_.region.empty()) {
        SendResult result;
        result.errorSummary = "missing SES region";
        return result;
    }

    const auto accessKey = secretsManager_->getSecret(kAccessKeySecret);
    const auto secretKey = secretsManager_->getSecret(kSecretKeySecret);
    if (!accessKey || accessKey->empty()) {
        SendResult result;
        result.errorSummary = "missing SES access key secret";
        return result;
    }
    if (!secretKey || secretKey->empty()) {
        SendResult result;
        result.errorSummary = "missing SES secret access key secret";
        return result;
    }

    nlohmann::json body{
        {"FromEmailAddress", formatAddress(message.from)},
        {"Destination", {{"ToAddresses", nlohmann::json::array()}}},
        {"Content", {
            {"Simple", {
                {"Subject", {{"Data", message.subject}, {"Charset", "UTF-8"}}},
                {"Body", {
                    {"Html", {{"Data", message.html}, {"Charset", "UTF-8"}}},
                    {"Text", {{"Data", message.text}, {"Charset", "UTF-8"}}}
                }}
            }}
        }}
    };

    for (const auto& recipient : message.to)
        body["Destination"]["ToAddresses"].push_back(formatAddress(recipient));
    if (message.replyTo)
        body["ReplyToAddresses"] = nlohmann::json::array({formatAddress(*message.replyTo)});
    if (!message.tags.empty()) {
        body["EmailTags"] = nlohmann::json::array();
        for (const auto& [name, value] : message.tags)
            body["EmailTags"].push_back({{"Name", name}, {"Value", value}});
    }

    const auto payload = body.dump();
    const auto endpoint = endpointForConfig(config_);
    const auto host = endpointHost(endpoint);

    const auto now = std::time(nullptr);
    const auto payloadHash = sha256Hex(payload);
    const auto amzDate = formatUtcBasic("%Y%m%dT%H%M%SZ", now);
    const std::map<std::string, std::string> canonicalHeaders{
        {"content-type", "application/json"},
        {"host", host},
        {"x-amz-content-sha256", payloadHash},
        {"x-amz-date", amzDate}
    };
    const auto signedRequest = detail::signAwsV4(
        *accessKey,
        *secretKey,
        config_.region,
        "POST",
        kSesPath,
        "",
        canonicalHeaders,
        payload,
        now
    );

    HttpRequest request;
    request.method = "POST";
    request.url = endpoint + kSesPath;
    request.headers = {
        "Content-Type: application/json",
        "Host: " + host,
        "X-Amz-Date: " + signedRequest.amzDate,
        "X-Amz-Content-Sha256: " + signedRequest.payloadHash,
        "Authorization: " + signedRequest.authorization
    };
    request.body = payload;

    const auto response = transport_->send(request);
    if (response.status < 200 || response.status >= 300) {
        SendResult result;
        result.errorSummary = sesResponseErrorSummary(response);
        result.httpStatus = response.status;
        return result;
    }

    SendResult result;
    result.ok = true;
    result.httpStatus = response.status;
    const auto parsed = nlohmann::json::parse(response.body, nullptr, false);
    if (!parsed.is_discarded() && parsed.contains("MessageId") && parsed["MessageId"].is_string())
        result.providerMessageId = parsed["MessageId"].get<std::string>();
    return result;
}

}
