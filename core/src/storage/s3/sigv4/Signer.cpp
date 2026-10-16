#include "storage/s3/sigv4/Signer.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <sstream>

namespace vh::storage::s3::sigv4 {

namespace {

std::string hex(const unsigned char* data, const std::size_t size) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0x0f]);
    }
    return out;
}

std::string hmacRaw(const std::string& key, const std::string& data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char*>(data.data()),
         data.size(), digest.data(), &length);
    return {reinterpret_cast<const char*>(digest.data()), length};
}

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Trim, and collapse runs of spaces to one (SigV4 canonical header values).
std::string canonicalValue(const std::string& value) {
    std::string out;
    bool space = false;
    for (const char c : value) {
        if (c == ' ' || c == '\t') {
            space = true;
            continue;
        }
        if (space && !out.empty()) out.push_back(' ');
        space = false;
        out.push_back(c);
    }
    return out;
}

std::string dateStamp(const std::time_t t) { return amzDate(t).substr(0, 8); }

}

std::string uriEncode(const std::string_view value, const bool encodeSlash) {
    std::string out;
    out.reserve(value.size() * 3);
    for (const char ch : value) {
        const auto c = static_cast<unsigned char>(ch);
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || (c == '/' && !encodeSlash)) {
            out.push_back(static_cast<char>(c));
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", c);
            out += buf;
        }
    }
    return out;
}

std::string sha256Hex(const std::string_view data) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest.data());
    return hex(digest.data(), digest.size());
}

std::string amzDate(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[17];
    std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &tm);
    return buf;
}

Signed sign(const Request& request, const Credentials& credentials, const std::string& region,
            const std::string& service, const std::time_t now) {
    Signed out;
    const bool s3 = service == "s3";
    const auto date = amzDate(now);

    std::map<std::string, std::string> headers;
    for (const auto& [name, value] : request.headers) headers[lower(name)] = canonicalValue(value);
    headers["host"] = request.host;
    headers["x-amz-date"] = date;
    if (s3) headers["x-amz-content-sha256"] = request.payload_hash;
    if (!credentials.session_token.empty()) headers["x-amz-security-token"] = credentials.session_token;

    // Canonical URI.
    const auto path = request.path.empty() ? std::string("/") : request.path;
    out.encoded_path = uriEncode(path, false);
    const auto canonicalUri = s3 ? out.encoded_path : uriEncode(out.encoded_path, false);

    // Canonical query.
    std::vector<std::pair<std::string, std::string>> query;
    query.reserve(request.query.size());
    for (const auto& [name, value] : request.query) query.emplace_back(uriEncode(name, true), uriEncode(value, true));
    std::ranges::sort(query);
    for (std::size_t i = 0; i < query.size(); ++i) {
        if (i) out.query_string.push_back('&');
        out.query_string += query[i].first + "=" + query[i].second;
    }

    std::string canonicalHeaders, signedHeaders;
    for (const auto& [name, value] : headers) {
        canonicalHeaders += name + ":" + value + "\n";
        if (!signedHeaders.empty()) signedHeaders.push_back(';');
        signedHeaders += name;
    }

    out.canonical_request = request.method + "\n" + canonicalUri + "\n" + out.query_string + "\n" + canonicalHeaders +
                            "\n" + signedHeaders + "\n" + request.payload_hash;

    const auto scope = dateStamp(now) + "/" + region + "/" + service + "/aws4_request";
    out.string_to_sign = "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + sha256Hex(out.canonical_request);

    const auto kDate = hmacRaw("AWS4" + credentials.secret_key, dateStamp(now));
    const auto kRegion = hmacRaw(kDate, region);
    const auto kService = hmacRaw(kRegion, service);
    const auto kSigning = hmacRaw(kService, "aws4_request");
    const auto signature = hmacRaw(kSigning, out.string_to_sign);

    out.authorization = "AWS4-HMAC-SHA256 Credential=" + credentials.access_key + "/" + scope +
                        ", SignedHeaders=" + signedHeaders + ", Signature=" +
                        hex(reinterpret_cast<const unsigned char*>(signature.data()), signature.size());
    out.headers = std::move(headers);
    out.headers["authorization"] = out.authorization;
    return out;
}

}
