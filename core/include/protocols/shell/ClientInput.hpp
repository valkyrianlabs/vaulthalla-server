#pragma once

// A document the `vh` client reads on the caller's side and attaches to its request, so the daemon never opens a path
// the caller names: `vh vault keys import <vault> --file <path|->` (a key export) or `--recovery-kit <path|->` (a
// recovery kit, #370), and `vh vault recover --kit <path|-> --export <path|->` (#371: both, bundled as one JSON
// document, kBundleType). Header-only, shared by the client (core/main/cli.cpp) and the daemon (shell/Server.cpp).
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

// `vh vault recover`'s documents travel as one text: {"type": kBundleType, "kit": "<text>"|null, "export": ...}.
inline constexpr std::string_view kBundleType = "vh.cli-input-bundle";

struct Plan {
    bool active = false;       // this command takes a client-side document
    std::string path{};        // "-" = stdin
    std::string error{};       // a usage error to print instead of connecting
    // A bundle (vault recover): the documents by name ("kit", "export"), each a path or "-" (at most one may be "-").
    std::vector<std::pair<std::string, std::string>> bundle{};
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
    if ((a == "vault" || a == "vaults" || a == "v") && b == "recover") {
        p.active = true;
        bool fromCloud = false;
        for (std::size_t i = 2; i < argv.size(); ++i) {
            if (argv[i] == "--from-cloud") fromCloud = true;
            const bool isKit = argv[i] == "--kit" || argv[i] == "--recovery-kit";
            const bool isExport = argv[i] == "--export" || argv[i] == "--key-file";
            if (!isKit && !isExport) continue;
            if (i + 1 >= argv.size() || argv[i + 1].empty()) {
                p.error = argv[i] + " needs a file name (or - for stdin)";
                return p;
            }
            const std::string name = isKit ? "kit" : "export";
            if (std::ranges::any_of(p.bundle, [&](const auto& d) { return d.first == name; })) {
                p.error = "--" + name + " given twice";
                return p;
            }
            p.bundle.emplace_back(name, argv[i + 1]);
        }
        // --from-cloud: the keys come through the daemon, from the linked account; nothing is read here.
        if (fromCloud) {
            if (!p.bundle.empty()) p.error = "--from-cloud replaces --kit and --export";
            else p.active = false;
            return p;
        }
        if (std::ranges::count_if(p.bundle, [](const auto& d) { return d.second == "-"; }) > 1)
            p.error = "only one of --kit and --export can read standard input";
        else if (p.bundle.empty())
            p.error = "usage: vh vault recover --api-key <key> --bucket <bucket> --kit <kit.json|-> [--export "
                      "<keys.json|->] [--into <name>] [--dry-run]  (or --vault-uid <uid> --from-cloud)";
        return p;
    }
    if (!(a == "vault" || a == "vaults" || a == "v") || !(b == "key" || b == "keys" || b == "k") || c != "import")
        return p;
    p.active = true;
    bool file = false, kit = false;
    for (std::size_t i = 3; i < argv.size(); ++i) {
        const bool isFile = argv[i] == "--file" || argv[i] == "-f";
        const bool isKit = argv[i] == "--recovery-kit" || argv[i] == "--kit";
        if (!isFile && !isKit) continue;
        if (i + 1 >= argv.size() || argv[i + 1].empty()) {
            p.error = argv[i] + " needs a file name (or - for stdin)";
            return p;
        }
        (isFile ? file : kit) = true;
        p.path = argv[i + 1];
    }
    if (file && kit) p.error = "--file and --recovery-kit can't be combined: an import reads one or the other";
    else if (p.path.empty())
        p.error = "usage: vh vault keys import <vault> --file <export.json|-> | --recovery-kit <kit.json|-> "
                  "[--confirm-name <name>]";
    return p;
}

}
