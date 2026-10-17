#include "storage/s3/curl/helpers.hpp"
#include "db/encoding/u8.hpp"
#include "db/encoding/timestamp.hpp"
#include "vault/model/APIKey.hpp"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <filesystem>
#include <mutex>
#include <curl/curl.h>

using namespace vh::db::encoding;

namespace vh::storage::s3::curl {
    void ensureCurlGlobalInit() {
        static std::once_flag once;
        std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
    }

    std::string sha256Hex(const std::string &data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char *>(data.data()), data.size(), hash);
        std::ostringstream oss;
        for (const unsigned char c: hash) oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        return oss.str();
    }

    std::string hmacSha256Hex(const std::string &key, const std::string &data) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char *>(data.data()), data.size(), digest, nullptr);

        std::ostringstream oss;
        for (const unsigned char i: digest) oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
        return oss.str();
    }

    std::string hmacSha256Raw(const std::string &key, const std::string &data) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char *>(data.data()), data.size(), digest, nullptr);
        return {reinterpret_cast<char *>(digest), SHA256_DIGEST_LENGTH};
    }

    std::string hmacSha256HexFromRaw(const std::string &rawKey, const std::string &data) {
        unsigned char sig[SHA256_DIGEST_LENGTH];
        HMAC(EVP_sha256(), rawKey.data(), static_cast<int>(rawKey.size()),
             reinterpret_cast<const unsigned char *>(data.data()), data.size(), sig, nullptr);

        std::ostringstream oss;
        for (unsigned char i: sig) oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
        return oss.str();
    }

    std::string escapeKeyPreserveSlashes(CURL *curl, const std::filesystem::path &p) {
        std::ostringstream out;
        bool first = true;
        for (const auto &part: p) {
            if (!first) out << '/';
            first = false;

            std::string seg = to_utf8_string(part.u8string());
            char *esc = curl_easy_escape(curl, seg.c_str(), seg.length());
            if (!esc) {
                curl_easy_cleanup(curl);
                throw std::runtime_error("escape failed");
            }
            out << esc;
            curl_free(esc);
        }
        return out.str();
    }

    std::string composeMultiPartUploadXMLBody(const std::vector<std::string> &etags) {
        std::ostringstream xml;

        xml << "<CompleteMultipartUpload>";

        for (size_t i = 0; i < etags.size(); ++i)
            xml << "<Part><PartNumber>" << (i + 1) << "</PartNumber><ETag>" << etags[i] << "</ETag></Part>";

        xml << "</CompleteMultipartUpload>";

        return xml.str();
    }

    size_t writeToString(const char *ptr, const size_t size, const size_t nmemb, void *userdata) {
        auto *out = static_cast<std::string *>(userdata);
        out->append(ptr, size * nmemb);
        return size * nmemb;
    }

    void parsePagination(const std::string &response, std::string &continuationToken, bool &moreResults) {
        moreResults = std::regex_search(response, std::regex("<IsTruncated>true</IsTruncated>"));
        std::smatch tokenMatch;
        if (moreResults && std::regex_search(response, tokenMatch,
                                             std::regex("<NextContinuationToken>([^<]+)</NextContinuationToken>")))
            continuationToken = tokenMatch[1].str();
        else moreResults = false;
    }

    bool extractETag(const std::string &respHdr, std::string &etagOut) {
        auto pos = respHdr.find("ETag:");
        if (pos == std::string::npos) return false;
        pos += 5; // Skip "ETag:"
        while (pos < respHdr.size() && (respHdr[pos] == ' ' || respHdr[pos] == '\t')) ++pos;
        auto end = respHdr.find_first_of("\r\n", pos);
        etagOut = respHdr.substr(pos, end - pos);
        while (!etagOut.empty() && (etagOut.back() == ' ' || etagOut.back() == '\t')) etagOut.pop_back();

        return !etagOut.empty();
    }

    std::string canonicalQueryString(const std::string &query) {
        if (query.empty()) return {};
        std::vector<std::pair<std::string, std::string>> params;
        std::size_t start = 0;
        while (start <= query.size()) {
            const auto amp = std::min(query.find('&', start), query.size());
            const auto part = query.substr(start, amp - start);
            if (!part.empty()) {
                const auto eq = part.find('=');
                if (eq == std::string::npos) params.emplace_back(part, std::string{});   // "?uploads" → "uploads="
                else params.emplace_back(part.substr(0, eq), part.substr(eq + 1));
            }
            start = amp + 1;
        }
        std::ranges::sort(params);   // by encoded name, then encoded value (SigV4)
        std::string out;
        for (const auto &[name, value] : params) {
            if (!out.empty()) out.push_back('&');
            out += name + "=" + value;
        }
        return out;
    }

    std::string buildAuthorizationHeader(const std::shared_ptr<vault::model::APIKey> &api_key,
                                         const std::string &method,
                                         const std::string &fullPath,
                                         const std::map<std::string, std::string> &headers,
                                         const std::string &payloadHash,
                                         const std::string &canonicalQuery /* = "" */) {
        std::string canonicalPath;
        std::string effectiveQuery;

        // Parse fullPath only if canonicalQuery is not explicitly given
        if (canonicalQuery.empty()) {
            const auto qpos = fullPath.find('?');
            if (qpos == std::string::npos) {
                canonicalPath = fullPath;
                effectiveQuery = "";
            } else {
                canonicalPath = fullPath.substr(0, qpos);
                effectiveQuery = canonicalQueryString(fullPath.substr(qpos + 1));
            }
        } else {
            canonicalPath = fullPath;
            effectiveQuery = canonicalQueryString(canonicalQuery);
        }

        const std::string service = "s3";
        const std::string algorithm = "AWS4-HMAC-SHA256";
        const std::string amzDate = headers.at("x-amz-date");
        const std::string dateStamp = getDate(); // YYYYMMDD

        // Build canonical headers and signed headers
        std::string canonicalHeaders, signedHeaders;
        for (auto it = headers.begin(); it != headers.end(); ++it) {
            canonicalHeaders += it->first + ":" + it->second + "\n";
            signedHeaders += it->first;
            if (std::next(it) != headers.end())
                signedHeaders += ";";
        }

        // Canonical request block
        std::ostringstream canonicalRequestStream;
        canonicalRequestStream << method << "\n"
                << canonicalPath << "\n"
                << effectiveQuery << "\n"
                << canonicalHeaders << "\n"
                << signedHeaders << "\n"
                << payloadHash;
        const std::string canonicalRequest = canonicalRequestStream.str();
        const std::string hashedCanonicalRequest = sha256Hex(canonicalRequest);

        // String to sign
        const std::string credentialScope = dateStamp + "/" + api_key->region + "/" + service + "/aws4_request";
        std::ostringstream stringToSignStream;
        stringToSignStream << algorithm << "\n"
                << amzDate << "\n"
                << credentialScope << "\n"
                << hashedCanonicalRequest;
        const std::string stringToSign = stringToSignStream.str();

        // Key derivation
        const std::string kDate = hmacSha256Raw("AWS4" + api_key->secret_access_key, dateStamp);
        const std::string kRegion = hmacSha256Raw(kDate, api_key->region);
        const std::string kService = hmacSha256Raw(kRegion, service);
        const std::string kSigning = hmacSha256Raw(kService, "aws4_request");

        // Final signature
        const std::string signature = hmacSha256HexFromRaw(kSigning, stringToSign);

        // Compose auth header
        std::ostringstream authHeader;
        authHeader << algorithm << " "
                << "Credential=" << api_key->access_key << "/" << credentialScope << ", "
                << "SignedHeaders=" << signedHeaders << ", "
                << "Signature=" << signature;

        return authHeader.str();
    }

    void trimInPlace(std::string &s) {
        // Trim start
        s.erase(s.begin(), std::ranges::find_if(s.begin(), s.end(), [](const unsigned char ch) {
            return !std::isspace(ch);
        }));

        // Trim end
        s.erase(std::find_if(s.rbegin(), s.rend(), [](const unsigned char ch) {
            return !std::isspace(ch);
        }).base(), s.end());
    }
}