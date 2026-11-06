#pragma once

// Byte helpers the crypto, format and recovery suites each kept a copy of: text <-> bytes, hex, deterministic and
// random bytes, whole-file reads and writes, and the golden vectors (design/encryption/vectors/vectors.json).

#include <nlohmann/json.hpp>
#include <sodium.h>
#include <sys/stat.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace vh::test::bin {

using Bytes = std::vector<uint8_t>;

inline Bytes bytes(const std::string& s) { return {s.begin(), s.end()}; }
inline std::string str(const Bytes& b) { return {b.begin(), b.end()}; }

inline Bytes fromHex(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::invalid_argument("odd hex length");
    Bytes out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<uint8_t>(std::stoul(hex.substr(2 * i, 2), nullptr, 16));
    return out;
}

inline std::string toHex(const std::span<const uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out += kDigits[b >> 4];
        out += kDigits[b & 0xF];
    }
    return out;
}

// The same bytes for the same seed, every run (std::mt19937).
inline Bytes randomBytes(const std::size_t n, const unsigned seed) {
    std::mt19937 rng(seed);
    Bytes out(n);
    for (auto& b : out) b = static_cast<uint8_t>(rng());
    return out;
}

// Fresh random bytes (libsodium).
inline Bytes randomBytes(const std::size_t n) {
    Bytes out(n);
    randombytes_buf(out.data(), out.size());
    return out;
}

inline Bytes slurp(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

inline std::string slurpText(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Writes `bytes` over `p`, creating its parent directories.
inline void spit(const std::filesystem::path& p, const std::span<const uint8_t> bytes) {
    std::filesystem::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

inline void spit(const std::filesystem::path& p, const std::string& text) {
    spit(p, std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

inline ino_t inodeOf(const std::filesystem::path& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 ? st.st_ino : 0;
}

// design/encryption/vectors/vectors.json, parsed once.
inline const nlohmann::json& goldenVectors() {
    static const nlohmann::json doc = [] {
        const auto path = std::filesystem::path(VH_TEST_VECTORS_DIR) / "vectors.json";
        std::ifstream in(path);
        if (!in) throw std::runtime_error("missing golden vectors: " + path.string());
        return nlohmann::json::parse(in);
    }();
    return doc;
}

}
