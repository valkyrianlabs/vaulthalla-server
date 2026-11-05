#pragma once

#include <cstdint>
#include <string>

namespace vh::protocols::ws {

// The Set-Cookie value for a refresh token (`refresh`, or `share_refresh` on the share lane). Max-Age follows the
// token's own lifetime, auth.refresh_token_expiry_days (#320): it used to be a fixed 7 days whatever was configured.
inline std::string refreshCookie(const std::string& name, const std::string& token, const unsigned int expiryDays,
                                 const bool secure) {
    const auto maxAge = static_cast<std::uint64_t>(expiryDays) * 24u * 60u * 60u;
    std::string cookie = name + "=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + std::to_string(maxAge);
    if (secure) cookie += "; Secure";
    return cookie;
}

}
