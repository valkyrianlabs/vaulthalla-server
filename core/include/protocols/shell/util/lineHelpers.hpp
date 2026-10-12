#pragma once

#include <sys/ioctl.h>
#include <unistd.h>
#include <string>
#include <fmt/format.h>
#include <cstdint>

namespace vh::protocols::shell {

inline int term_width() {
    if (!isatty(STDOUT_FILENO)) return 80;
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
    if (const char* c = std::getenv("COLUMNS"); c) {
        char* c_end{};
        if (const auto n = std::strtol(c, &c_end, 10); n > 0) return static_cast<int>(n);
    }
    return 80;
}

inline std::string human_bytes(const uint64_t b) {
    static const char* kUnits[] = {"B","KiB","MiB","GiB","TiB","PiB"};
    int u = 0;
    auto v = static_cast<double>(b);
    while (v >= 1024.0 && u < 5) { v /= 1024.0; ++u; }
    // show 0 decimals for B/KiB, 1 for others
    if (u <= 1) return fmt::format("{} {}", static_cast<uint64_t>(u==0 ? b : static_cast<uint64_t>(v)), kUnits[u]);
    return fmt::format("{:.1f} {}", v, kUnits[u]);
}

inline std::string snake_case_to_title(const std::string& s) {
    // converts ex. "snake_case_string" to "Snake Case String"
    std::string out;
    out.reserve(s.size());
    bool next_upper = true;
    for (char c : s) {
        if (c == '_') {
            out.push_back(' ');
            next_upper = true;
            continue;
        }

        if (next_upper) {
            out.push_back(static_cast<char>(std::toupper(c)));
            next_upper = false;
        } else out.push_back(static_cast<char>(std::tolower(c)));
    }

    return out;
}

}
