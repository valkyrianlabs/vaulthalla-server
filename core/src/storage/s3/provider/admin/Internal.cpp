#include "storage/s3/provider/admin/Internal.hpp"

#include "crypto/util/encrypt.hpp"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <pugixml.hpp>

#include <array>
#include <cstdio>
#include <ctime>
#include <regex>

namespace vh::storage::s3::provider::admin::detail {

std::string redact(std::string text, const std::vector<std::string>& secrets, const std::size_t max) {
    for (const auto& secret : secrets) {
        if (secret.size() < 6) continue;   // too short to be a credential; replacing it would shred the text
        for (auto pos = text.find(secret); pos != std::string::npos; pos = text.find(secret, pos))
            text.replace(pos, secret.size(), "[redacted]");
    }
    static const std::regex authLine(R"((?:^|\n)\s*authorization\s*:[^\r\n]*)", std::regex::icase);
    static const std::regex bearer(R"(Bearer\s+[A-Za-z0-9._~+/=-]+)", std::regex::icase);
    static const std::regex signature(R"(Signature=[0-9a-fA-F]+)");
    static const std::regex credential(R"(Credential=[A-Za-z0-9/_-]+)");
    static const std::regex stringToSign(R"(<StringToSign(?:Bytes)?>[^<]*</StringToSign(?:Bytes)?>)");
    static const std::regex canonical(R"(<CanonicalRequest(?:Bytes)?>[^<]*</CanonicalRequest(?:Bytes)?>)");
    static const std::regex securityToken(R"(x-amz-security-token[:=]\s*[^\s&"<]+)", std::regex::icase);
    text = std::regex_replace(text, authLine, "\n[authorization redacted]");
    text = std::regex_replace(text, bearer, "Bearer [redacted]");
    text = std::regex_replace(text, signature, "Signature=[redacted]");
    text = std::regex_replace(text, credential, "Credential=[redacted]");
    text = std::regex_replace(text, stringToSign, "<StringToSign>[redacted]</StringToSign>");
    text = std::regex_replace(text, canonical, "<CanonicalRequest>[redacted]</CanonicalRequest>");
    text = std::regex_replace(text, securityToken, "x-amz-security-token=[redacted]");
    if (text.size() > max) text = text.substr(0, max) + "…";
    return text;
}

std::string hostOf(const std::string& url) {
    auto rest = url;
    if (const auto scheme = rest.find("://"); scheme != std::string::npos) rest = rest.substr(scheme + 3);
    if (const auto slash = rest.find_first_of("/?"); slash != std::string::npos) rest = rest.substr(0, slash);
    return rest;
}

std::string md5Base64(const std::string& data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    EVP_Digest(data.data(), data.size(), digest.data(), &length, EVP_md5(), nullptr);
    return crypto::util::b64_encode(std::vector<uint8_t>(digest.begin(), digest.begin() + length));
}

std::optional<std::time_t> parseIsoTime(const std::string& value) {
    std::tm tm{};
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    if (std::sscanf(value.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6) return std::nullopt;
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
    return timegm(&tm);
}

curl::http::Response send(const Endpoint& endpoint, const SignedCall& call, const sigv4::Credentials& credentials) {
    sigv4::Request request{
        .method = call.method,
        .host = endpoint.host,
        .path = call.path,
        .query = call.query,
        .headers = call.headers,
        .payload_hash = sigv4::sha256Hex(call.body),
    };
    const auto signedRequest = sigv4::sign(request, credentials, endpoint.region, endpoint.service, std::time(nullptr));

    curl::http::Request http;
    http.method = call.method;
    http.url = "https://" + endpoint.host + signedRequest.encoded_path +
               (signedRequest.query_string.empty() ? std::string{} : "?" + signedRequest.query_string);
    http.body = call.body;
    http.timeout = call.timeout;
    for (const auto& [name, value] : signedRequest.headers)
        if (name != "host") http.headers.emplace_back(name, value);
    return curl::http::perform(http);
}

ErrorInfo s3Error(const curl::http::Response& response) {
    ErrorInfo info;
    pugi::xml_document doc;
    if (!response.body.empty() && doc.load_string(response.body.c_str())) {
        const auto error = doc.child("Error");
        info.code = error.child_value("Code");
        info.message = error.child_value("Message");
    }
    if (info.code.empty()) {
        // HEAD has no body: the status is all there is.
        switch (response.status) {
        case 301: info.code = "PermanentRedirect"; break;
        case 403: info.code = "AccessDenied"; break;
        case 404: info.code = "NotFound"; break;
        default: break;
        }
    }
    return info;
}

ErrorInfo sqsError(const curl::http::Response& response) {
    ErrorInfo info;
    if (const auto query = response.header("x-amzn-query-error")) info.code = query->substr(0, query->find(';'));
    try {
        const auto j = nlohmann::json::parse(response.body);
        if (j.is_object()) {
            if (info.code.empty() && j.contains("__type") && j["__type"].is_string()) {
                auto type = j["__type"].get<std::string>();
                if (const auto hash = type.rfind('#'); hash != std::string::npos) type = type.substr(hash + 1);
                info.code = type;
            }
            for (const auto* field : {"message", "Message"})
                if (j.contains(field) && j[field].is_string()) info.message = j[field].get<std::string>();
        }
    } catch (const nlohmann::json::exception&) {
        info.message = response.body;
    }
    // Normalize the access-denied family so callers can test one code.
    if (info.code == "AccessDeniedException" || info.code == "AccessDenied" ||
        info.code == "AWS.SimpleQueueService.AccessDenied")
        info.code = "AccessDenied";
    if (info.code == "QueueDoesNotExist" || info.code == "AWS.SimpleQueueService.NonExistentQueue")
        info.code = "NonExistentQueue";
    return info;
}

ErrorInfo cloudflareError(const curl::http::Response& response) {
    ErrorInfo info;
    try {
        const auto j = nlohmann::json::parse(response.body);
        if (j.is_object() && j.contains("errors") && j["errors"].is_array() && !j["errors"].empty()) {
            const auto& e = j["errors"][0];
            if (e.contains("code")) info.code = e["code"].is_number() ? std::to_string(e["code"].get<long long>())
                                                                       : e["code"].dump();
            if (e.contains("message") && e["message"].is_string()) info.message = e["message"].get<std::string>();
        }
    } catch (const nlohmann::json::exception&) {
        info.message = response.body;
    }
    return info;
}

ProviderError makeError(const std::string& operation, const curl::http::Response& response, const ErrorInfo& info,
                        const std::vector<std::string>& secrets) {
    if (!response.transport_ok)
        return {redact(operation + " failed: " + response.transport_error, secrets), "Transport", 0};
    std::string text = operation + " failed (HTTP " + std::to_string(response.status) +
                       (info.code.empty() ? std::string{} : " " + info.code) + ")";
    if (!info.message.empty()) text += ": " + info.message;
    return {redact(text, secrets), info.code, response.status};
}

}
