#pragma once

#include <ctime>
#include <map>
#include <string>

// SesProvider's AWS Signature Version 4 signer, public for the SigV4 characterization goldens
// (core/tests/unit/test_sigv4_goldens.cpp). Not an API for anything else.
//
// It signs exactly what it is given: `headers` must already be lower-cased, trimmed and complete (host, x-amz-date,
// x-amz-content-sha256 as SesProvider sends them), and `path` and `query` already canonical. The service is "ses".
namespace vh::email::providers::detail {

struct SigningResult {
    std::string authorization;
    std::string amzDate;
    std::string payloadHash;
    std::string canonicalRequest;
    std::string stringToSign;
};

[[nodiscard]] SigningResult signAwsV4(const std::string& accessKey, const std::string& secretKey,
                                      const std::string& region, const std::string& method, const std::string& path,
                                      const std::string& query, const std::map<std::string, std::string>& headers,
                                      const std::string& payload, std::time_t now);

}
