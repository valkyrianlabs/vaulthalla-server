#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

// Vaulthalla Cloud's installation request signatures, VHC1-Ed25519 (valkyrianlabs/vaulthalla-cloud
// docs/design/installation-requests.md): every request this server makes as a linked installation carries
//
//   Authorization: VHC1-Ed25519 Installation=<id>, Timestamp=<unix s>, Nonce=<base64url>, Signature=<base64url>
//   X-VHC-Content-SHA256: <hex SHA-256 of the body>
//
// signed over the nine lines of stringToSign(). The cloud's documented vector is pinned by
// CloudSigning.MatchesTheCloudsDocumentedVector; the cloud tests the same values.
namespace vh::cloud {

inline constexpr std::string_view kContentHashHeader = "X-VHC-Content-SHA256";
inline constexpr std::size_t kSeedSize = 32;


using PublicKey = std::array<uint8_t, 32>;

struct SignedFields {
    std::string method;        // upper case
    std::string path;          // exactly as sent, still percent-encoded
    std::string query;         // exactly as sent, without '?'
    std::string host;          // lower case, without :443
    std::string installation;  // the cloud's id for this installation
    int64_t timestamp = 0;     // unix seconds
    std::string nonce;         // base64url of 16 random bytes
    std::string body_sha256;   // lower-case hex
};

[[nodiscard]] std::string stringToSign(const SignedFields& f);

struct SignedHeaders {
    std::string authorization;
    std::string content_sha256;
};
[[nodiscard]] SignedHeaders sign(const SignedFields& f, std::span<const uint8_t> seed);

// Helpers shared with the linking ceremony.
[[nodiscard]] PublicKey publicKeyOf(std::span<const uint8_t> seed);
[[nodiscard]] std::string signDetached(std::string_view message, std::span<const uint8_t> seed);  // base64url signature
[[nodiscard]] std::string base64url(std::span<const uint8_t> bytes);
[[nodiscard]] std::string sha256Hex(std::string_view bytes);
// The first 8 bytes of SHA-256(public key) as xxxx-xxxx-xxxx-xxxx: what the installation and the approver compare.
[[nodiscard]] std::string fingerprint(const PublicKey& publicKey);
[[nodiscard]] std::string newNonce();

}
