#pragma once

// A document the `vh` client reads on the caller's side and attaches to its request, so the daemon never opens a path
// the caller names: `vh vault keys import <vault> --file <path|->` (a key export). Header-only, shared by the client
// (core/main/cli.cpp) and the daemon (shell/Server.cpp).
//
//   request frame: {..., "input": {"v": 1, "text": "<the file's contents>"}}
//
// The text is at most kMaxBytes (the server's request frame limit is 1 MiB). The daemon hands it to the command as
// CommandCall::input; a command that needs one and gets none refuses (an older client, or an alias the client didn't
// recognize: fails closed).

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace vh::protocols::shell::client_input {

inline constexpr int kVersion = 1;
inline constexpr std::size_t kMaxBytes = 512 * 1024;

struct Plan {
    bool active = false;       // this command takes a client-side document
    std::string path{};        // "-" = stdin
    std::string error{};       // a usage error to print instead of connecting
};

namespace detail {
inline std::string lower(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}
}

// argv after the program name, as the client normalized it ({"vault", "keys", "import", "12", "--file", "k.json"}).
[[nodiscard]] inline Plan plan(const std::vector<std::string>& argv) {
    Plan p;
    if (argv.size() < 3) return p;
    const auto a = detail::lower(argv[0]), b = detail::lower(argv[1]), c = detail::lower(argv[2]);
    if (!(a == "vault" || a == "vaults" || a == "v") || !(b == "key" || b == "keys" || b == "k") || c != "import")
        return p;
    p.active = true;
    for (std::size_t i = 3; i < argv.size(); ++i) {
        if (argv[i] != "--file" && argv[i] != "-f") continue;
        if (i + 1 >= argv.size() || argv[i + 1].empty()) {
            p.error = "--file needs a file name (or - for stdin)";
            return p;
        }
        p.path = argv[i + 1];
    }
    if (p.path.empty()) p.error = "usage: vh vault keys import <vault> --file <export.json|-> [--confirm-name <name>]";
    return p;
}

}
