#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace vh::share {

enum class TokenKind { PublicShare, ShareSession };

struct ParsedToken {
    TokenKind kind{};
    std::string lookup_id;
    std::string secret;
};

struct GeneratedToken {
    TokenKind kind{};
    std::string lookup_id;
    std::string secret;
    std::string raw;
    std::vector<uint8_t> hash;
};

class Token {
  public:
    static GeneratedToken generate(TokenKind kind);
    static ParsedToken parse(std::string_view raw);
    static std::vector<uint8_t> hashSecret(TokenKind kind, std::string_view secret);
    static std::vector<uint8_t> hashForDomain(std::string_view domain, std::string_view value);
    static bool verify(const std::vector<uint8_t>& expected_hash, TokenKind kind, std::string_view secret);
    static std::string redact(std::string_view raw_or_lookup);

    static void setPepperForTesting(std::vector<uint8_t> pepper);
    static void clearPepperForTesting();

    // The pepper is sealed under the host's master key (crypto::secrets::Manager) as kSealedPepperKey. Releases
    // before #322 stored it in plaintext as kLegacyPepperKey; the first load converts it, keeping its value so every
    // existing link keeps working, and deletes the plaintext only after the sealed copy reads back identical.
    // Fails closed: a sealed pepper that can't be unsealed, or a plaintext one that disagrees with it, makes every
    // token operation throw. A pepper is generated only when neither exists.
    static constexpr const char* kSealedPepperKey = "share.token.pepper.sealed.v1";
    static constexpr const char* kLegacyPepperKey = "share.token.pepper.v1";
    // Tests only: forget the loaded pepper so the next use runs the load/convert path again.
    static void resetPepperCacheForTesting();
};

[[nodiscard]] std::string to_string(TokenKind kind);

}
