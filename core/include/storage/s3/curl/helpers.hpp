#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <istream>
#include <sstream>
#include <curl/curl.h>
#include <map>
#include "vault/Fwd.hpp"

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
void parsePagination(const std::string& response, std::string& continuationToken, bool& moreResults);
[[nodiscard]] bool extractETag(const std::string& respHdr, std::string& etagOut);
std::string buildAuthorizationHeader(const std::shared_ptr<vault::model::APIKey>& api_key,
                                     const std::string& method, const std::string& fullPath,
                                     const std::map<std::string, std::string>& headers,
                                     const std::string& payloadHash, const std::string& canonicalQuery = "");
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
