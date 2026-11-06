#include "auth/webauthn/RelyingParty.hpp"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace vh::auth::webauthn {

namespace {

bool isLabelChar(const char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; }

bool isHostName(const std::string_view host) {
    if (host.empty() || host.size() > 253) return false;
    std::size_t start = 0;
    std::string_view last;
    while (true) {
        const auto dot = host.find('.', start);
        const auto label = host.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
        if (!std::ranges::all_of(label, isLabelChar)) return false;
        last = label;
        if (dot == std::string_view::npos) break;
        start = dot + 1;
    }
    // A numeric last label is an IPv4 address (or nothing a browser would accept as an RP ID).
    return !std::ranges::all_of(last, [](const char c) { return c >= '0' && c <= '9'; });
}

bool isPort(const std::string_view p) {
    if (p.empty() || p.size() > 5 || p.front() == '0') return false;
    if (!std::ranges::all_of(p, [](const char c) { return c >= '0' && c <= '9'; })) return false;
    return std::stoul(std::string(p)) <= 65535;
}

bool validUtf8Name(const std::string_view s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x20 || c == 0x7F) return false;
        std::size_t len = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3 : (c & 0xF8) == 0xF0 ? 4 : 0;
        if (len == 0 || s.size() - i < len) return false;
        std::uint32_t cp = len == 1 ? c : len == 2 ? (c & 0x1F) : len == 3 ? (c & 0x0F) : (c & 0x07);
        for (std::size_t k = 1; k < len; ++k) {
            const auto cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return false;
        if ((cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF || (cp >= 0x80 && cp <= 0x9F)) return false;
        i += len;
    }
    return true;
}

[[noreturn]] void invalidRp(const std::string& why) { throw std::invalid_argument("auth.webauthn: " + why); }

void checkOrigin(const std::string& origin, const std::string_view rpId) {
    const auto bad = [&](const std::string& why) { invalidRp("origin '" + origin + "' " + why); };
    std::string_view rest;
    bool https = false;
    if (origin.starts_with("https://")) { https = true; rest = std::string_view(origin).substr(8); }
    else if (origin.starts_with("http://")) rest = std::string_view(origin).substr(7);
    else bad("must start with https:// (or http:// for localhost)");
    if (rest.find_first_of("/?#@\\") != std::string_view::npos)
        bad("must be scheme://host[:port] only (no path, query, fragment or user info)");
    std::string_view host = rest;
    if (const auto colon = rest.find(':'); colon != std::string_view::npos) {
        host = rest.substr(0, colon);
        const auto port = rest.substr(colon + 1);
        if (!isPort(port)) bad("has an invalid port");
        if ((https && port == "443") || (!https && port == "80"))
            bad("must not spell out the default port (browsers serialize the origin without it)");
    }
    if (!isHostName(host)) bad("must name a lowercase host name (never an IP address)");
    if (!https && host != "localhost") bad("may use http:// only for localhost");
    if (host != rpId && !(host.size() > rpId.size() && host.ends_with(rpId) && host[host.size() - rpId.size() - 1] == '.'))
        bad("is not rp_id '" + std::string(rpId) + "' or a subdomain of it");
}

}

bool isValidRpId(const std::string_view rpId) { return isHostName(rpId); }

void validateRelyingParty(const std::string_view rpId, const std::span<const std::string> origins,
                          const std::string_view rpName) {
    if (rpName.empty() || rpName.size() > kMaxRpNameBytes || !validUtf8Name(rpName))
        invalidRp("rp_name must be 1..64 bytes of text without control characters");
    if (rpId.empty()) {
        if (!origins.empty()) invalidRp("origins are set but rp_id is empty; set rp_id or remove the origins");
        return;
    }
    if (!isHostName(rpId))
        invalidRp("rp_id '" + std::string(rpId) +
                  "' must be a lowercase host name such as vault.example.com (never an IP address, no port or scheme)");
    if (origins.empty()) invalidRp("rp_id is set, so origins needs at least one origin, e.g. https://" + std::string(rpId));
    if (origins.size() > kMaxOrigins) invalidRp("at most 16 origins");
    std::vector<std::string> seen;
    for (const auto& origin : origins) {
        checkOrigin(origin, rpId);
        if (std::ranges::find(seen, origin) != seen.end()) invalidRp("origin '" + origin + "' is listed twice");
        seen.push_back(origin);
    }
}

}
