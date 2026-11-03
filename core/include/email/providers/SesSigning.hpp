#pragma once

#include <ctime>
#include <map>
#include <string>

// SesProvider's former AWS Signature Version 4 signer, public for the SigV4 characterization goldens
// (core/tests/unit/test_sigv4_goldens.cpp). Not an API for anything else.
//
// RETIRED from production: SesProvider::send signs with vl::sigv4::sign (the vl-sigv4 library,
// subprojects/vl-sigv4.wrap), which reproduces this signer byte for byte for SendEmail (SigV4Goldens.VlSigv4*Ses*).
// This copy stays only as the reference the goldens compare against, until a release with vl-sigv4 is verified on
// the VPS; then it is deleted (shared-infrastructure extraction, Phase 1 step 5). Don't add callers.
//
// Where it differs from SigV4 (and from vl-sigv4) for inputs SesProvider never sends: it signs the query as given,
// unsorted and with flag parameters bare; it signs header values untrimmed; and it never double-encodes the path.
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
