#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

// Cross-site WebSocket hijacking guard (#324). A browser always sends Origin on a websocket upgrade; the console
// connects to its own host, so a different origin is another site trying to ride the visitor's refresh cookie.
// Requests without Origin are not from a browser page (CLI tools, the lab clients) and carry no ambient cookie risk.
namespace vh::protocols::ws::origin {

inline std::string lowercase(std::string_view in) {
    std::string out(in);
    std::ranges::transform(out, out.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// The host of "host", "host:port", "[v6]" or "[v6]:port", lowercased; empty when malformed.
inline std::string hostOf(std::string_view authority) {
    while (!authority.empty() && authority.back() == '.') authority.remove_suffix(1);
    if (authority.empty()) return {};
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string_view::npos) return {};
        return lowercase(authority.substr(0, close + 1));
    }
    const auto colon = authority.find(':');
    return lowercase(colon == std::string_view::npos ? authority : authority.substr(0, colon));
}

// "https://host:port" -> authority "host:port"; empty when not an http(s) origin.
inline std::string_view authorityOf(std::string_view origin) {
    for (const std::string_view scheme : {std::string_view{"https://"}, std::string_view{"http://"}}) {
        if (origin.size() > scheme.size() && lowercase(origin.substr(0, scheme.size())) == scheme) {
            auto rest = origin.substr(scheme.size());
            if (const auto slash = rest.find('/'); slash != std::string_view::npos) rest = rest.substr(0, slash);
            return rest;
        }
    }
    return {};
}

inline std::string normalized(std::string_view origin) {
    while (!origin.empty() && origin.back() == '/') origin.remove_suffix(1);
    return lowercase(origin);
}

// True when a websocket upgrade with this Origin may proceed: no Origin (not a browser), the same host the request is
// addressed to (Host, or X-Forwarded-Host from a proxy), or an origin listed in websocket_server.allowed_origins.
// Ports are not compared: the proxy (443) and the daemon (36969) differ for the same site.
inline bool allowed(const std::string_view originHeader, const std::string_view host, const std::string_view forwardedHost,
                    const std::vector<std::string>& allowedOrigins) {
    if (originHeader.empty()) return true;
    if (std::ranges::any_of(allowedOrigins, [&](const std::string& o) { return normalized(o) == normalized(originHeader); }))
        return true;
    const auto authority = authorityOf(originHeader);
    if (authority.empty()) return false;  // "null", file://, chrome-extension:// ...
    const auto originHost = hostOf(authority);
    if (originHost.empty()) return false;
    for (const auto candidate : {host, forwardedHost}) {
        auto first = candidate.substr(0, candidate.find(','));  // X-Forwarded-Host may list hops
        while (!first.empty() && first.front() == ' ') first.remove_prefix(1);
        if (!first.empty() && hostOf(first) == originHost) return true;
    }
    return false;
}

}
