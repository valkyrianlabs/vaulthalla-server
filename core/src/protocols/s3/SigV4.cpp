#include "protocols/s3/SigV4.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sstream>
#include <string_view>

namespace vh::protocols::s3::sigv4 {

namespace {
constexpr std::string_view kAlgorithm = "AWS4-HMAC-SHA256";

std::string lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string trimAndCompress(std::string value) {
    const auto notSpace = [](const unsigned char c) { return !std::isspace(c); };
    value.erase(value.begin(), std::ranges::find_if(value, notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());

    std::string out;
    out.reserve(value.size());
    bool inSpace = false;
    for (const unsigned char c : value) {
        if (std::isspace(c)) {
            if (!inSpace) out.push_back(' ');
            inSpace = true;
        } else {
            out.push_back(static_cast<char>(c));
            inSpace = false;
        }
    }
    return out;
}

std::string hex(const unsigned char* data, const std::size_t n) {
    std::ostringstream out;
    for (std::size_t i = 0; i < n; ++i)
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    return out.str();
}

bool unreserved(const unsigned char c) {
    return std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~';
}

std::string pctEncode(const std::string_view value, const bool slashSafe = false) {
    std::ostringstream out;
    out << std::uppercase << std::hex;
    for (const unsigned char c : value) {
        if (unreserved(c) || (slashSafe && c == '/')) out << static_cast<char>(c);
        else out << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return out.str();
}

std::string pctDecode(const std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%' && i + 2 < value.size()) {
            const auto hexByte = std::string(value.substr(i + 1, 2));
            char* end = nullptr;
            const auto v = std::strtoul(hexByte.c_str(), &end, 16);
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

std::vector<std::string> split(const std::string& value, const char delim) {
    std::vector<std::string> out;
    std::string item;
    std::istringstream in(value);
    while (std::getline(in, item, delim)) out.push_back(item);
    return out;
}

// A request with neither Content-Length nor Transfer-Encoding has no body (RFC 9112 section 6.3), and the gateway
// read none. Only then may an absent Content-Length be taken to be 0.
bool framedWithoutBody(const VerificationInput& input, const std::map<std::string, std::string>& headers) {
    if (headers.contains("content-length") || headers.contains("transfer-encoding")) return false;
    if (!input.body.empty()) return false;
    return !input.body_sha256 || *input.body_sha256 == sha256Hex("");
}

std::map<std::string, std::string> normalizedHeaders(const VerificationInput& input) {
    std::map<std::string, std::string> out;
    for (const auto& [name, value] : input.headers)
        out[lower(name)] = trimAndCompress(value);
    if (!input.host.empty() && !out.contains("host")) out["host"] = input.host;
    // Proxies and CDNs (Cloudflare) drop "Content-Length: 0" from bodiless requests (GET, HEAD, DELETE, an empty
    // POST), while clients that sign content-length (the AWS CLI CRT transfer client) signed it as 0. Canonicalize the
    // missing header as the length the request was actually framed with, as MinIO does. The value is the true body
    // length, so it lets no request through that the client did not sign; a request with a body never gets one.
    if (framedWithoutBody(input, out)) out["content-length"] = "0";
    return out;
}

std::string queryValue(const std::string& rawQuery, const std::string& name) {
    for (const auto& part : split(rawQuery, '&')) {
        const auto eq = part.find('=');
        const auto k = pctDecode(part.substr(0, eq));
        if (k == name) return eq == std::string::npos ? "" : pctDecode(part.substr(eq + 1));
    }
    return {};
}

std::optional<uint64_t> queryUInt64(const std::string& rawQuery, const std::string& name, std::string& error) {
    const auto raw = queryValue(rawQuery, name);
    if (raw.empty()) {
        error = "Missing " + name;
        return std::nullopt;
    }
    if (!std::ranges::all_of(raw, [](const unsigned char c) { return std::isdigit(c); })) {
        error = "Invalid " + name;
        return std::nullopt;
    }
    try {
        return static_cast<uint64_t>(std::stoull(raw));
    } catch (const std::exception&) {
        error = "Invalid " + name;
        return std::nullopt;
    }
}

std::map<std::string, std::string> authParams(std::string value) {
    constexpr std::string_view prefix = "AWS4-HMAC-SHA256";
    if (value.starts_with(prefix)) value.erase(0, prefix.size());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());

    std::map<std::string, std::string> out;
    for (auto part : split(value, ',')) {
        part = trimAndCompress(part);
        const auto eq = part.find('=');
        if (eq == std::string::npos) continue;
        out[part.substr(0, eq)] = part.substr(eq + 1);
    }
    return out;
}

std::string payloadSha256Hex(const VerificationInput& input) {
    return input.body_sha256.value_or(sha256Hex(input.body));
}

std::string getHeader(const VerificationInput& input, const std::string& name) {
    const auto headers = normalizedHeaders(input);
    const auto it = headers.find(lower(name));
    return it == headers.end() ? std::string{} : it->second;
}

bool constantTimeEqual(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

bool payloadHashSkipsBodyVerification(const std::string& payloadHash) {
    return payloadHash == "UNSIGNED-PAYLOAD" ||
           payloadHash == "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
}

bool signedHeadersPresent(const VerificationInput& input, const std::string& signedHeaders, std::string& error) {
    const auto headers = normalizedHeaders(input);
    for (const auto& rawName : split(signedHeaders, ';')) {
        const auto name = lower(trimAndCompress(rawName));
        if (name.empty()) continue;
        if (!headers.contains(name)) {
            error = "Signed header missing from request: " + name;
            return false;
        }
    }
    return true;
}

std::optional<std::time_t> parseAmzDate(const std::string& value) {
    if (value.size() < 16) return std::nullopt;
    std::tm tm{};
    std::istringstream in(value);
    in >> std::get_time(&tm, "%Y%m%dT%H%M%SZ");
    if (in.fail()) return std::nullopt;
    return timegm(&tm);
}

bool dateAcceptable(const ParsedAuth& auth) {
    const auto parsed = parseAmzDate(auth.amz_date);
    if (!parsed) return false;
    const auto now = std::time(nullptr);
    constexpr auto maxSkewSeconds = 15ll * 60ll;

    if (auth.presigned) {
        if (static_cast<long long>(*parsed - now) > maxSkewSeconds) return false;
        if (auth.expires_seconds > 0 && now > *parsed + static_cast<std::time_t>(auth.expires_seconds))
            return false;
        return true;
    }

    return std::llabs(static_cast<long long>(now - *parsed)) <= maxSkewSeconds;
}

std::string pathPart(const std::string& target) {
    const auto q = target.find('?');
    if (q == std::string::npos) return target.empty() ? "/" : target;
    return q == 0 ? "/" : target.substr(0, q);
}

std::string queryPart(const std::string& target) {
    const auto q = target.find('?');
    if (q == std::string::npos) return {};
    return target.substr(q + 1);
}

std::optional<CredentialScope> parseCredentialScope(const std::string& value, std::string& error) {
    const auto parts = split(value, '/');
    if (parts.size() != 5 || parts[4] != "aws4_request") {
        error = "Invalid credential scope";
        return std::nullopt;
    }
    if (parts[3] != "s3") {
        error = "Unsupported SigV4 service";
        return std::nullopt;
    }
    return CredentialScope{
        .access_key = parts[0],
        .date = parts[1],
        .region = parts[2],
        .service = parts[3]
    };
}
}

std::string sha256Hex(const std::string_view data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    return hex(hash, SHA256_DIGEST_LENGTH);
}

std::string hmacSha256Raw(const std::string_view key, const std::string_view data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest, nullptr);
    return {reinterpret_cast<char*>(digest), SHA256_DIGEST_LENGTH};
}

std::string hmacSha256HexFromRaw(const std::string_view rawKey, const std::string_view data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), rawKey.data(), static_cast<int>(rawKey.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest, nullptr);
    return hex(digest, SHA256_DIGEST_LENGTH);
}

std::string canonicalUri(const std::string_view path) {
    const auto decoded = pctDecode(path.empty() ? "/" : path);
    const auto encoded = pctEncode(decoded, true);
    return encoded.empty() || encoded.front() != '/' ? "/" + encoded : encoded;
}

std::string canonicalQueryString(const std::string_view rawQuery, const bool omitSignature) {
    std::vector<std::pair<std::string, std::string>> items;
    for (const auto& part : split(std::string(rawQuery), '&')) {
        if (part.empty()) continue;
        const auto eq = part.find('=');
        auto key = pctDecode(part.substr(0, eq));
        auto value = eq == std::string::npos ? std::string{} : pctDecode(part.substr(eq + 1));
        if (omitSignature && key == "X-Amz-Signature") continue;
        items.emplace_back(pctEncode(key), pctEncode(value));
    }
    std::ranges::sort(items);
    std::ostringstream out;
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i) out << '&';
        out << items[i].first << '=' << items[i].second;
    }
    return out.str();
}

std::string canonicalHeaders(const std::map<std::string, std::string>& headers, const std::string& signedHeaders) {
    std::ostringstream out;
    for (const auto& name : split(signedHeaders, ';')) {
        const auto it = headers.find(lower(name));
        if (it == headers.end()) continue;
        out << lower(name) << ':' << trimAndCompress(it->second) << '\n';
    }
    return out.str();
}

std::string makeCanonicalRequest(const VerificationInput& input, const ParsedAuth& auth) {
    const auto headers = normalizedHeaders(input);
    std::ostringstream out;
    out << input.method << '\n'
        << canonicalUri(pathPart(input.target)) << '\n'
        << canonicalQueryString(queryPart(input.target), true) << '\n'
        << canonicalHeaders(headers, auth.signed_headers) << '\n'
        << auth.signed_headers << '\n'
        << auth.payload_hash;
    return out.str();
}

std::string signingKey(const std::string& secret, const CredentialScope& scope) {
    const auto kDate = hmacSha256Raw("AWS4" + secret, scope.date);
    const auto kRegion = hmacSha256Raw(kDate, scope.region);
    const auto kService = hmacSha256Raw(kRegion, scope.service);
    return hmacSha256Raw(kService, "aws4_request");
}

std::string signatureFor(const VerificationInput& input, const ParsedAuth& auth, const std::string& secret) {
    const auto canonical = makeCanonicalRequest(input, auth);
    const auto hashedCanonical = sha256Hex(canonical);
    const auto scope = auth.credential.date + "/" + auth.credential.region + "/" + auth.credential.service + "/aws4_request";
    std::ostringstream stringToSign;
    stringToSign << kAlgorithm << '\n'
                 << auth.amz_date << '\n'
                 << scope << '\n'
                 << hashedCanonical;
    return hmacSha256HexFromRaw(signingKey(secret, auth.credential), stringToSign.str());
}

std::optional<ParsedAuth> parseAuthorization(const VerificationInput& input, std::string& error) {
    const auto rawQuery = queryPart(input.target);
    const auto presignedAlgorithm = queryValue(rawQuery, "X-Amz-Algorithm");

    if (!presignedAlgorithm.empty()) {
        if (presignedAlgorithm != kAlgorithm) {
            error = "Unsupported presigned algorithm";
            return std::nullopt;
        }
        auto scope = parseCredentialScope(queryValue(rawQuery, "X-Amz-Credential"), error);
        if (!scope) return std::nullopt;
        const auto expires = queryUInt64(rawQuery, "X-Amz-Expires", error);
        if (!expires) return std::nullopt;
        if (*expires > 604800) {
            error = "X-Amz-Expires exceeds maximum allowed value";
            return std::nullopt;
        }
        return ParsedAuth{
            .credential = *scope,
            .signed_headers = queryValue(rawQuery, "X-Amz-SignedHeaders"),
            .signature = queryValue(rawQuery, "X-Amz-Signature"),
            .amz_date = queryValue(rawQuery, "X-Amz-Date"),
            .payload_hash = "UNSIGNED-PAYLOAD",
            .presigned = true,
            .expires_seconds = *expires
        };
    }

    const auto auth = getHeader(input, "authorization");
    if (auth.empty()) {
        error = "Missing Authorization header";
        return std::nullopt;
    }
    if (!auth.starts_with(kAlgorithm)) {
        error = "Unsupported authorization algorithm";
        return std::nullopt;
    }

    const auto params = authParams(auth);
    if (!params.contains("Credential") || !params.contains("SignedHeaders") || !params.contains("Signature")) {
        error = "Malformed Authorization header";
        return std::nullopt;
    }

    auto scope = parseCredentialScope(params.at("Credential"), error);
    if (!scope) return std::nullopt;

    auto payloadHash = getHeader(input, "x-amz-content-sha256");
    if (payloadHash.empty()) payloadHash = payloadSha256Hex(input);

    return ParsedAuth{
        .credential = *scope,
        .signed_headers = params.at("SignedHeaders"),
        .signature = params.at("Signature"),
        .amz_date = getHeader(input, "x-amz-date"),
        .payload_hash = payloadHash,
        .presigned = false,
        .expires_seconds = 0
    };
}

VerificationResult verify(const VerificationInput& input, const std::string& secret) {
    std::string error;
    const auto parsed = parseAuthorization(input, error);
    if (!parsed) return {.ok = false, .access_key = {}, .error = error};

    if (parsed->amz_date.empty()) return {.ok = false, .access_key = parsed->credential.access_key, .error = "Missing x-amz-date"};
    if (!dateAcceptable(*parsed)) return {.ok = false, .access_key = parsed->credential.access_key, .error = "Signature date is outside allowed skew"};
    if (parsed->signed_headers.empty()) return {.ok = false, .access_key = parsed->credential.access_key, .error = "Missing signed headers"};
    if (parsed->signature.empty()) return {.ok = false, .access_key = parsed->credential.access_key, .error = "Missing signature"};
    if (!signedHeadersPresent(input, parsed->signed_headers, error))
        return {.ok = false, .access_key = parsed->credential.access_key, .error = error};
    if (!payloadHashSkipsBodyVerification(parsed->payload_hash) && parsed->payload_hash != payloadSha256Hex(input))
        return {.ok = false, .access_key = parsed->credential.access_key, .error = "Payload hash mismatch"};

    const auto expected = signatureFor(input, *parsed, secret);
    if (!constantTimeEqual(lower(parsed->signature), lower(expected)))
        return {.ok = false, .access_key = parsed->credential.access_key, .error = "Signature mismatch"};

    return {.ok = true, .access_key = parsed->credential.access_key, .error = {}};
}

} // namespace vh::protocols::s3::sigv4
