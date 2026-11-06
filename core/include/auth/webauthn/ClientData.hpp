#pragma once

// clientDataJSON (WebAuthn L3 section 5.8.1), parsed strictly with a full JSON parser (never the spec's limited
// prefix match): one UTF-8 JSON object of at most 4 KiB, no byte-order mark, no comments, no trailing bytes, no
// duplicate keys at any level, nesting at most 8 deep. `type`, `challenge` and `origin` must be strings,
// `crossOrigin` a boolean and `topOrigin` a string when present. Other members are allowed (the spec reserves them
// for future fields) and ignored.

#include "auth/webauthn/Types.hpp"

namespace vh::auth::webauthn::clientdata {

inline constexpr std::size_t kMaxBytes = 4096;
inline constexpr std::size_t kMaxDepth = 8;

struct ClientData {
    std::string type;
    std::string challenge;  // base64url, as sent
    std::string origin;
    std::optional<bool> crossOrigin;
    std::optional<std::string> topOrigin;
};

[[nodiscard]] std::optional<ClientData> parse(ByteView json);

}
