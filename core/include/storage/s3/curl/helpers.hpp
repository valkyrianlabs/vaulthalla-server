#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <istream>
#include <sstream>
#include <curl/curl.h>
#include <map>
#include "vault/Fwd.hpp"

#include <vl/sigv4/types.hpp>

// fmt >= 10 no longer formats unscoped enums implicitly; found by ADL (CURLcode is a global enum), so log lines that
// print a CURLcode keep the numeric code. fmt 9 (Ubuntu noble) ignores format_as and already prints the number.
inline int format_as(const CURLcode code) { return static_cast<int>(code); }

namespace vh::storage::s3::curl {

std::string sha256Hex(const std::string& data);
std::string hmacSha256Hex(const std::string& key, const std::string& data);
std::string hmacSha256Raw(const std::string& key, const std::string& data);
std::string hmacSha256HexFromRaw(const std::string& rawKey, const std::string& data);
std::string escapeKeyPreserveSlashes(CURL* curl, const std::filesystem::path& p);
std::string composeMultiPartUploadXMLBody(const std::vector<std::string>& etags);
size_t writeToString(const char* ptr, size_t size, size_t nmemb, void* userdata);
[[nodiscard]] bool extractETag(const std::string& respHdr, std::string& etagOut);
// The vault data path's SigV4 signer (object PUT/GET/HEAD/DELETE, copy-in-place metadata, multipart, ListObjectsV2
// pages, the credential probe): vl-sigv4's primitives (the vl-sigv4 library, subprojects/vl-sigv4.wrap) over a request
// the caller has already built. It returns the Authorization value and leaves the URL and every other header to the
// caller, so what goes on the wire is exactly what the caller builds.
//
//  - Time: sets headers["x-amz-date"] from `now` (replacing any value already there) and takes the credential-scope
//    date from the same instant, so the two always agree. Callers don't set x-amz-date (Controller::buildHeaderMap
//    leaves it out) and send `headers` after signing.
//  - Path: fullPath's path part is the canonical URI as the URL carries it (already encoded: constructPaths escapes
//    each key segment), signed as is.
//  - Query: after '?' in fullPath, or canonicalQuery; RFC 3986 encoded the way the URL carries it. It is signed in
//    SigV4 canonical order (sorted by name, then value; a bare "flag" → "flag=") without re-encoding
//    (vl::sigv4::sortEncodedQuery). The URL may keep any order: S3 canonicalizes what it receives the same way.
//  - Headers: every entry is signed: names lower-cased, values trimmed with inner runs of whitespace collapsed to one
//    space (SigV4), which is what the server computes from the line the caller sends.
//  - Service "s3", region and keys from the API key.
struct DataPathSignature {
    std::string canonical_request;
    std::string string_to_sign;
    std::string authorization;
};
[[nodiscard]] DataPathSignature signDataPathRequest(const vault::model::APIKey& api_key, const std::string& method,
                                                    const std::string& fullPath,
                                                    std::map<std::string, std::string>& headers,
                                                    const std::string& payloadHash, const std::string& canonicalQuery,
                                                    vl::sigv4::TimePoint now);
// signDataPathRequest(...).authorization, at `now` (the current time unless a test pins it).
[[nodiscard]] std::string buildAuthorizationHeader(const std::shared_ptr<vault::model::APIKey>& api_key,
                                                   const std::string& method, const std::string& fullPath,
                                                   std::map<std::string, std::string>& headers,
                                                   const std::string& payloadHash,
                                                   const std::string& canonicalQuery = "",
                                                   vl::sigv4::TimePoint now = vl::sigv4::Clock::now());

// RETIRED from production: the data path's former SigV4 signer, which buildAuthorizationHeader ran with the scope
// date read from the wall clock (db::encoding::getDate()) while x-amz-date was the caller's header, so a request
// signed across UTC midnight could carry two different dates. It stays only as the reference the SigV4 goldens
// compare signDataPathRequest against (tests/unit/test_sigv4_goldens.cpp), until a release with vl-sigv4 is verified on
// the VPS; then it is deleted (shared-infrastructure extraction, Phase 1 step 5). Don't add callers.
//
// It signs header values verbatim (untrimmed: wrong for values with leading, trailing or repeated whitespace, which
// no data-path caller sends) and header names as given (callers lower-case them). The credential-scope date
// (YYYYMMDD) is a parameter; the x-amz-date header is the caller's.
struct LegacySigningTrace {
    std::string canonical_request;
    std::string string_to_sign;
    std::string authorization;
};
[[nodiscard]] LegacySigningTrace buildAuthorizationTrace(const std::shared_ptr<vault::model::APIKey>& api_key,
                                                         const std::string& method, const std::string& fullPath,
                                                         const std::map<std::string, std::string>& headers,
                                                         const std::string& payloadHash,
                                                         const std::string& canonicalQuery,
                                                         const std::string& dateStamp);
// "b=2&a=1&flag" → "a=1&b=2&flag=": already-encoded parameters in SigV4 canonical order (no re-encoding).
[[nodiscard]] std::string canonicalQueryString(const std::string& query);
// Value of the last `name:` line (case-insensitive) of the final response block in raw curl header text.
[[nodiscard]] std::optional<std::string> lastHeaderValue(const std::string& raw, std::string_view name);
void trimInPlace(std::string& s);

void ensureCurlGlobalInit();

inline std::string slurp(const std::istream& in) {
    std::ostringstream oss;
    oss << in.rdbuf();          // copy entire buffer
    return oss.str();
}

/** Build a curl_slist from stable heap‑stored strings */
struct HeaderList {
    std::vector<std::string> store; // owns the memory
    curl_slist* list = nullptr;     // raw list pointer
    ~HeaderList() { if (list) curl_slist_free_all(list); }

    void add(const std::string& h) {
        store.push_back(h);
        list = curl_slist_append(list, store.back().c_str());
    }
};

}
