#include "connector/Urls.hpp"

#include <algorithm>
#include <cctype>

namespace vh::connector::urls {

// Named, not anonymous: the unity build joins this file with others that have helpers of the same names.
namespace connector_urls_detail {

std::string lower(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool fail(std::string* why, const char* text) {
    if (why) *why = text;
    return false;
}

struct Parts {
    std::string scheme;     // lowercase
    std::string authority;  // as written
    std::string rest;       // path, query (fragment refused before)
};

std::optional<Parts> split(const std::string_view uri) {
    const auto colon = uri.find("://");
    if (colon == std::string_view::npos) return std::nullopt;
    Parts p{.scheme = lower(uri.substr(0, colon)), .authority = {}, .rest = {}};
    const auto after = uri.substr(colon + 3);
    const auto end = after.find_first_of("/?");
    p.authority = std::string(after.substr(0, end));
    if (end != std::string_view::npos) p.rest = std::string(after.substr(end));
    return p;
}

// host[:port] -> host (brackets kept for IPv6), port ("" when absent); false when the port is not digits.
bool hostPort(const std::string& authority, std::string& host, std::string& port) {
    if (authority.starts_with("[")) {
        const auto close = authority.find(']');
        if (close == std::string::npos) return false;
        host = authority.substr(0, close + 1);
        const auto tail = authority.substr(close + 1);
        if (tail.empty()) return true;
        if (!tail.starts_with(":")) return false;
        port = tail.substr(1);
    } else {
        const auto c = authority.rfind(':');
        host = authority.substr(0, c);
        if (c != std::string::npos) port = authority.substr(c + 1);
        else return true;
    }
    return !port.empty() && port.size() <= 5 && std::ranges::all_of(port, [](const unsigned char ch) { return std::isdigit(ch); });
}

bool printableAscii(const std::string_view s) {
    return std::ranges::all_of(s, [](const unsigned char c) { return c > 0x20 && c < 0x7f; });
}

}

bool isDnsName(const std::string_view host) {
    if (host.empty() || host.size() > 253) return false;
    std::size_t labels = 0;
    std::string_view last;
    std::size_t start = 0;
    while (start <= host.size()) {
        const auto dot = host.find('.', start);
        const auto label = host.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
        if (!std::ranges::all_of(label, [](const unsigned char c) { return std::isalnum(c) || c == '-'; })) return false;
        ++labels;
        last = label;
        if (dot == std::string_view::npos) break;
        start = dot + 1;
    }
    return labels >= 2 && !std::ranges::all_of(last, [](const unsigned char c) { return std::isdigit(c); });
}

std::optional<std::string> canonicalOrigin(const std::string_view url, std::string* why) {
    namespace d = connector_urls_detail;
    if (url.size() > 300 || !d::printableAscii(url)) {
        d::fail(why, "the address must be plain ASCII, at most 300 characters");
        return std::nullopt;
    }
    const auto p = d::split(url);
    if (!p || p->scheme != "https") {
        d::fail(why, "the address must start with https://");
        return std::nullopt;
    }
    if (!p->rest.empty() && p->rest != "/") {
        d::fail(why, "the address is the origin only (https://host): no path, query or fragment");
        return std::nullopt;
    }
    if (p->authority.find('@') != std::string::npos) {
        d::fail(why, "the address can't carry a user name");
        return std::nullopt;
    }
    std::string host, port;
    if (!d::hostPort(p->authority, host, port) || (!port.empty() && port != "443")) {
        d::fail(why, "hosted AI clients connect on the standard HTTPS port: no port other than 443");
        return std::nullopt;
    }
    if (!isDnsName(host)) {
        d::fail(why, "the address needs a public host name (not an IP address), e.g. https://vault.example.com");
        return std::nullopt;
    }
    return "https://" + d::lower(host);
}

bool validRedirectUri(const std::string_view uri, std::string* why) {
    namespace d = connector_urls_detail;
    if (uri.empty() || uri.size() > 512 || !d::printableAscii(uri))
        return d::fail(why, "a redirect URI is 1-512 printable ASCII characters");
    if (uri.find('#') != std::string_view::npos) return d::fail(why, "a redirect URI has no fragment");
    const auto p = d::split(uri);
    if (!p) return d::fail(why, "a redirect URI is an absolute https URL, or http to a loopback address");
    if (p->authority.find('@') != std::string::npos) return d::fail(why, "a redirect URI can't carry a user name");
    std::string host, port;
    if (!d::hostPort(p->authority, host, port)) return d::fail(why, "the redirect URI's host or port is malformed");
    const auto h = d::lower(host);
    if (p->scheme == "https") {
        if (!isDnsName(host)) return d::fail(why, "an https redirect URI needs a host name");
        return true;
    }
    if (p->scheme == "http") {
        if (h == "127.0.0.1" || h == "[::1]" || h == "localhost") return true;
        return d::fail(why, "plain http is allowed only to this computer (127.0.0.1, [::1] or localhost)");
    }
    return d::fail(why, "a redirect URI is an https URL, or http to a loopback address");
}

bool isLoopbackRedirect(const std::string_view uri) {
    namespace d = connector_urls_detail;
    const auto p = d::split(uri);
    if (!p || p->scheme != "http") return false;
    const auto h = hostOf(uri);
    return h == "127.0.0.1" || h == "[::1]" || h == "localhost";
}

std::string hostOf(const std::string_view uri) {
    namespace d = connector_urls_detail;
    const auto p = d::split(uri);
    if (!p) return {};
    std::string host, port;
    if (!d::hostPort(p->authority, host, port)) return {};
    const auto at = host.rfind('@');
    return d::lower(at == std::string::npos ? host : host.substr(at + 1));
}

}
