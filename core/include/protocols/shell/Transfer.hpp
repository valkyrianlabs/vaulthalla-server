#pragma once

// `vh fs get` / `vh fs put`: file bytes over the CLI socket (#229). Header-only, so the `vh` client (built from
// main/cli.cpp alone) and the daemon share one definition of the frames, the limits and the codec.
//
// The bytes ride in the socket's existing frames (4-byte big-endian length + JSON), never a second channel:
//
//   request  {"cmd", "args", "line", ..., "transfer": {"v": 1}}                     get
//            {"cmd", "args", "line", ..., "transfer": {"v": 1, "put_size": N}}      put
//   get      daemon: {"type":"transfer","size":N}, then {"type":"data","seq":0..,"b64":...}*, then the usual
//            {"type":"result",...}. The client keeps the bytes only if the result is ok and exactly N arrived.
//   put      daemon: {"type":"transfer-ready","size":N}; client: data frames, then {"type":"transfer-end","bytes":N}
//            (or {"type":"transfer-abort"}); daemon: the usual result, after the file is sealed and committed.
//
// Every frame is bounded before anything is allocated for it: a data frame carries at most kChunkBytes decoded
// (kMaxChunkEncoded base64 characters) and, during a transfer, a whole frame is at most kMaxTransferFrameBytes, far
// below the socket's general 1 MiB request limit. The daemon only ever sees vault paths: `put` reads the local file
// in the client and `get` writes it there.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vh::protocols::shell::transfer {

inline constexpr int kVersion = 1;

// Decoded bytes per data frame (the HTTP lane's chunk size).
inline constexpr std::size_t kChunkBytes = 256 * 1024;
// Its padded base64 length.
inline constexpr std::size_t kMaxChunkEncoded = 4 * ((kChunkBytes + 2) / 3);
// Any frame while bytes are moving, JSON included.
inline constexpr std::uint32_t kMaxTransferFrameBytes = 512 * 1024;
static_assert(kMaxChunkEncoded + 128 < kMaxTransferFrameBytes, "a full data frame must fit a transfer frame");
static_assert(kMaxTransferFrameBytes <= (1u << 20), "a transfer frame must fit the socket's 1 MiB request limit");

// Exit codes (sysexits.h), shared by the daemon's results and the client's own failures.
namespace exitcode {
inline constexpr int kUsage = 64;       // EX_USAGE: bad arguments (e.g. binary data to a terminal)
inline constexpr int kDataErr = 65;     // EX_DATAERR: a malformed or out-of-order frame, a size mismatch
inline constexpr int kNoInput = 66;     // EX_NOINPUT: the local input or the vault path doesn't exist
inline constexpr int kCantCreat = 73;   // EX_CANTCREAT: the vault path exists (no --overwrite), or the local output
inline constexpr int kIoErr = 74;       // EX_IOERR: reading or writing a local file failed
inline constexpr int kTempFail = 75;    // EX_TEMPFAIL: too many transfers in flight, or the connection dropped
inline constexpr int kNoPerm = 77;      // EX_NOPERM: RBAC said no (also when revoked mid-transfer)
}

namespace detail {
inline constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline constexpr std::array<std::int8_t, 256> decodeTable() {
    std::array<std::int8_t, 256> t{};
    for (auto& v : t) v = -1;
    for (int i = 0; i < 64; ++i) t[static_cast<unsigned char>(kAlphabet[i])] = static_cast<std::int8_t>(i);
    return t;
}
}

[[nodiscard]] inline std::string encode(const std::span<const std::uint8_t> in) {
    std::string out;
    out.reserve(4 * ((in.size() + 2) / 3));
    std::size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        const std::uint32_t v = (std::uint32_t{in[i]} << 16) | (std::uint32_t{in[i + 1]} << 8) | in[i + 2];
        out.push_back(detail::kAlphabet[(v >> 18) & 63]);
        out.push_back(detail::kAlphabet[(v >> 12) & 63]);
        out.push_back(detail::kAlphabet[(v >> 6) & 63]);
        out.push_back(detail::kAlphabet[v & 63]);
    }
    if (const auto rest = in.size() - i; rest > 0) {
        const std::uint32_t v = (std::uint32_t{in[i]} << 16) | (rest == 2 ? std::uint32_t{in[i + 1]} << 8 : 0);
        out.push_back(detail::kAlphabet[(v >> 18) & 63]);
        out.push_back(detail::kAlphabet[(v >> 12) & 63]);
        out.push_back(rest == 2 ? detail::kAlphabet[(v >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

// Strict: canonical padded base64 of at most kChunkBytes, nothing else (no whitespace, no stray padding, no non-zero
// trailing bits). nullopt for anything that isn't; the length is checked before any output is allocated.
[[nodiscard]] inline std::optional<std::vector<std::uint8_t>> decodeChunk(const std::string_view in) {
    if (in.size() % 4 != 0 || in.size() > kMaxChunkEncoded) return std::nullopt;
    static constexpr auto table = detail::decodeTable();
    std::vector<std::uint8_t> out;
    out.reserve(in.size() / 4 * 3);
    for (std::size_t i = 0; i < in.size(); i += 4) {
        const bool last = i + 4 == in.size();
        const int pad = last ? (in[i + 3] == '=') + (in[i + 2] == '=') : 0;
        if (pad == 1 && in[i + 2] == '=') return std::nullopt;  // "x=y=" style
        std::uint32_t v = 0;
        for (int k = 0; k < 4; ++k) {
            const auto c = static_cast<unsigned char>(in[i + k]);
            if (k >= 4 - pad) { v <<= 6; continue; }
            const auto d = table[c];
            if (d < 0) return std::nullopt;
            v = (v << 6) | static_cast<std::uint32_t>(d);
        }
        if (pad == 2 && (v & 0xFFFF) != 0) return std::nullopt;
        if (pad == 1 && (v & 0xFF) != 0) return std::nullopt;
        out.push_back(static_cast<std::uint8_t>(v >> 16));
        if (pad < 2) out.push_back(static_cast<std::uint8_t>(v >> 8));
        if (pad < 1) out.push_back(static_cast<std::uint8_t>(v));
    }
    if (out.size() > kChunkBytes) return std::nullopt;
    return out;
}

// What the client does locally for `vh fs get|put` (the daemon is never told how to open a local file). Parsed from
// the same argv the request line is built from; mirrors the usage book (core/usage/src/usages/fs.cpp).
struct LocalPlan {
    enum class Kind { None, Get, Put } kind{Kind::None};
    std::string local;          // put: the file to read ("-": stdin); get: the --output file ("-" or "": stdout)
    bool explicitStdout{false}; // get: -o - (binary to a terminal is refused unless asked for)
    std::string error;          // a usage error the client reports before connecting
};

[[nodiscard]] inline bool isGetAlias(const std::string_view s) { return s == "get" || s == "download"; }
[[nodiscard]] inline bool isPutAlias(const std::string_view s) { return s == "put" || s == "upload"; }
[[nodiscard]] inline bool isFsAlias(const std::string_view s) { return s == "fs" || s == "files"; }

namespace detail {
// The daemon's tokenizer (protocols/shell/Token.hpp, Parser.hpp) over the client's normalized argv, reduced to what
// decides positionals: a token is a flag if it starts with '-' (but isn't "-", "--", a negative number, or something
// the client quotes); a flag takes the next token as its value when that token is a word; "--" ends the flags.
[[nodiscard]] inline bool quoted(const std::string_view t) {
    return t.empty() || t.find_first_of(" \t\"\\") != std::string_view::npos;
}
[[nodiscard]] inline bool negativeNumber(const std::string_view t) {
    if (t.size() < 2 || t[0] != '-') return false;
    bool digit = false;
    for (std::size_t i = 1; i < t.size(); ++i) {
        if (t[i] >= '0' && t[i] <= '9') digit = true;
        else if (t[i] != '.') return false;
    }
    return digit;
}
[[nodiscard]] inline bool isFlag(const std::string_view t) {
    return t.size() >= 2 && t[0] == '-' && t != "--" && !negativeNumber(t) && !quoted(t);
}
}

// argv after the program name, as the client normalized it ({"fs", "get", "42", "/a.bin", "-o", "a.bin"}). The
// output option is --output/-o; everything else the daemon validates against the usage book.
[[nodiscard]] inline LocalPlan planLocal(const std::vector<std::string>& argv) {
    LocalPlan plan;
    if (argv.size() < 2 || !isFsAlias(argv[0])) return plan;
    if (isGetAlias(argv[1])) plan.kind = LocalPlan::Kind::Get;
    else if (isPutAlias(argv[1])) plan.kind = LocalPlan::Kind::Put;
    else return plan;

    std::vector<std::string> positionals;
    std::optional<std::string> output;
    bool flagsDone = false;
    for (std::size_t i = 2; i < argv.size(); ++i) {
        const std::string& a = argv[i];
        if (!flagsDone && a == "--") { flagsDone = true; continue; }
        if (flagsDone || !detail::isFlag(a)) { positionals.push_back(a); continue; }
        std::optional<std::string> value;
        if (i + 1 < argv.size() && !detail::isFlag(argv[i + 1])) value = argv[++i];
        if (a == "--output" || a == "-o") {
            if (!value || value->empty() || *value == "--") { plan.error = a + " needs a file name (or - for stdout)"; return plan; }
            output = value;
        }
    }

    if (plan.kind == LocalPlan::Kind::Get) {
        if (positionals.size() != 2) { plan.error = "usage: vh fs get <vault> <path> [-o <file>|-]"; return plan; }
        plan.explicitStdout = output && *output == "-";
        plan.local = output && *output != "-" ? *output : std::string{};
    } else {
        if (positionals.size() != 3) {
            plan.error = "usage: vh fs put <vault> <local-file|-> <path> [--overwrite]";
            return plan;
        }
        if (output) { plan.error = "vh fs put has no --output"; return plan; }
        plan.local = positionals[1];
    }
    return plan;
}

}
