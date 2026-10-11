#pragma once

// Stable, counter-based seed derivation shared with the Python engine (tools/harness/vhh/seeds.py):
//
//   h64(parts...) = BLAKE2b with an 8-byte digest over each part encoded as `uint32 little-endian length || bytes`,
//                   the digest read as a little-endian uint64.
//
// Integers are encoded as their decimal text (Python's str()), so h64(root, "label", 3) means the same thing on both
// sides and a seed printed by either tier reproduces the same choices. libsodium refuses digests under 16 bytes, so
// BLAKE2b (RFC 7693) is implemented here; it is checked against Python vectors by test_integration_seed_h64.cpp.
//
// Header-only and free of daemon dependencies on purpose: the unit tests include it directly.

#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>

namespace vh::test::integration::seed {

namespace detail {

class Blake2b {
public:
    explicit Blake2b(const std::size_t outlen) : outlen_(outlen) {
        h_ = kIV;
        h_[0] ^= 0x01010000ULL ^ static_cast<uint64_t>(outlen_);
    }

    void update(const void* data, std::size_t len) {
        const auto* p = static_cast<const uint8_t*>(data);
        while (len > 0) {
            // The last block is compressed by final() with the finalization flag, so a full buffer is only flushed
            // once more input arrives.
            if (buflen_ == kBlock) {
                t_ += kBlock;
                compress(false);
                buflen_ = 0;
            }
            const auto n = std::min(len, kBlock - buflen_);
            std::memcpy(buf_.data() + buflen_, p, n);
            buflen_ += n;
            p += n;
            len -= n;
        }
    }

    [[nodiscard]] std::array<uint8_t, 64> final() {
        t_ += buflen_;
        std::memset(buf_.data() + buflen_, 0, kBlock - buflen_);
        compress(true);
        std::array<uint8_t, 64> out{};
        for (std::size_t i = 0; i < 8; ++i)
            for (std::size_t j = 0; j < 8; ++j) out[i * 8 + j] = static_cast<uint8_t>(h_[i] >> (8 * j));
        return out;
    }

private:
    static constexpr std::size_t kBlock = 128;
    static constexpr std::array<uint64_t, 8> kIV{
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
    };
    static constexpr uint8_t kSigma[10][16]{
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    };

    std::array<uint64_t, 8> h_{};
    std::array<uint8_t, kBlock> buf_{};
    std::size_t buflen_ = 0;
    uint64_t t_ = 0;  // inputs here never exceed 2^64 bytes, so the high counter word stays 0
    std::size_t outlen_;

    static uint64_t rotr(const uint64_t x, const int n) { return (x >> n) | (x << (64 - n)); }

    static void g(std::array<uint64_t, 16>& v, const int a, const int b, const int c, const int d, const uint64_t x,
                  const uint64_t y) {
        v[a] = v[a] + v[b] + x;
        v[d] = rotr(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = rotr(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = rotr(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = rotr(v[b] ^ v[c], 63);
    }

    void compress(const bool last) {
        std::array<uint64_t, 16> m{};
        for (std::size_t i = 0; i < 16; ++i) {
            uint64_t w = 0;
            for (std::size_t j = 0; j < 8; ++j) w |= static_cast<uint64_t>(buf_[i * 8 + j]) << (8 * j);
            m[i] = w;
        }
        std::array<uint64_t, 16> v{};
        for (std::size_t i = 0; i < 8; ++i) {
            v[i] = h_[i];
            v[i + 8] = kIV[i];
        }
        v[12] ^= t_;
        if (last) v[14] = ~v[14];
        for (std::size_t r = 0; r < 12; ++r) {
            const auto* s = kSigma[r % 10];
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (std::size_t i = 0; i < 8; ++i) h_[i] ^= v[i] ^ v[i + 8];
    }
};

inline void appendPart(Blake2b& b, const std::string_view bytes) {
    const auto n = static_cast<uint32_t>(bytes.size());
    const uint8_t len[4]{static_cast<uint8_t>(n), static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n >> 16),
                         static_cast<uint8_t>(n >> 24)};
    b.update(len, sizeof(len));
    b.update(bytes.data(), bytes.size());
}

template <typename T>
void appendAny(Blake2b& b, const T& part) {
    if constexpr (std::is_same_v<std::decay_t<T>, bool>) {
        static_assert(!std::is_same_v<std::decay_t<T>, bool>, "h64: encode booleans explicitly");
    } else if constexpr (std::integral<T>) {
        appendPart(b, std::to_string(part));  // Python str(int)
    } else {
        appendPart(b, std::string_view(part));
    }
}

}

// BLAKE2b-64 over length-prefixed parts; integers are hashed as decimal text.
template <typename... Parts>
[[nodiscard]] uint64_t h64(const Parts&... parts) {
    detail::Blake2b b(8);
    (detail::appendAny(b, parts), ...);
    const auto digest = b.final();
    uint64_t out = 0;
    for (std::size_t i = 0; i < 8; ++i) out |= static_cast<uint64_t>(digest[i]) << (8 * i);
    return out;
}

// "0x%016x", as tools/harness/vhh/seeds.py fmt_seed prints it.
[[nodiscard]] inline std::string fmtSeed(const uint64_t seed) {
    char buf[19];
    std::snprintf(buf, sizeof(buf), "0x%016llx", static_cast<unsigned long long>(seed));
    return buf;
}

// Decimal or 0x-hex, the whole string; nullopt when it isn't a 64-bit number.
[[nodiscard]] inline std::optional<uint64_t> parseSeed(const std::string_view text) {
    if (text.empty()) return std::nullopt;
    int base = 10;
    std::string_view digits = text;
    if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        base = 16;
        digits.remove_prefix(2);
    }
    if (digits.empty()) return std::nullopt;
    uint64_t value = 0;
    for (const char c : digits) {
        uint64_t d = 0;
        if (c >= '0' && c <= '9') d = static_cast<uint64_t>(c - '0');
        else if (base == 16 && c >= 'a' && c <= 'f') d = static_cast<uint64_t>(c - 'a' + 10);
        else if (base == 16 && c >= 'A' && c <= 'F') d = static_cast<uint64_t>(c - 'A' + 10);
        else return std::nullopt;
        if (value > (UINT64_MAX - d) / static_cast<uint64_t>(base)) return std::nullopt;
        value = value * static_cast<uint64_t>(base) + d;
    }
    return value;
}

}
