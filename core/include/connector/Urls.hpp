#pragma once

#include <optional>
#include <string>
#include <string_view>

// The URL rules of remote connectors (design/core/mcp-remote-signin.md), DB-free. No normalization beyond what is
// written here: the public origin is lowercased and stripped of a default port and a bare "/", and a redirect URI is
// kept byte for byte (it is compared by exact match).
namespace vh::connector::urls {

// The node's public origin: https, a DNS name (not an IP literal, at least one dot), port 443 or none, nothing after
// the host but an optional "/". Answers "https://<lowercase host>", or nullopt with `why` set.
[[nodiscard]] std::optional<std::string> canonicalOrigin(std::string_view url, std::string* why = nullptr);

// A redirect URI a client may register: at most 512 printable ASCII characters, no fragment, no userinfo; https with a
// DNS name, or http to a loopback host (127.0.0.1, [::1], localhost: RFC 8252 7.3, any port).
[[nodiscard]] bool validRedirectUri(std::string_view uri, std::string* why = nullptr);
// http to a loopback host: matched on any port, and the consent page warns about it.
[[nodiscard]] bool isLoopbackRedirect(std::string_view uri);
// The lowercase host of an http(s) URI ("" when it has none).
[[nodiscard]] std::string hostOf(std::string_view uri);

// A DNS name as the origin and client rules want it: labels of [a-z0-9-] (any case), 1-63 characters, not starting or
// ending with '-', at least two labels, at most 253 characters, and a last label that is not all digits.
[[nodiscard]] bool isDnsName(std::string_view host);

}
