#include "protocols/s3/Listing.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace vh::protocols::s3::listing {

namespace {

constexpr std::string_view kTokenTag = "vh1.";
constexpr std::string_view kBase64Url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

constexpr std::array<int8_t, 256> kBase64UrlValues = [] {
    std::array<int8_t, 256> values{};
    values.fill(-1);
    for (std::size_t i = 0; i < kBase64Url.size(); ++i)
        values[static_cast<unsigned char>(kBase64Url[i])] = static_cast<int8_t>(i);
    return values;
}();

}

std::string encodeContinuationToken(const std::string_view position) {
    std::string out(kTokenTag);
    out.reserve(kTokenTag.size() + (position.size() * 4 + 2) / 3);
    uint32_t buffer = 0;
    int bits = 0;
    for (const unsigned char c : position) {
        buffer = (buffer << 8) | c;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(kBase64Url[(buffer >> bits) & 0x3F]);
        }
    }
    if (bits > 0) out.push_back(kBase64Url[(buffer << (6 - bits)) & 0x3F]);
    return out;
}

std::optional<std::string> decodeContinuationToken(std::string_view token) {
    if (!token.starts_with(kTokenTag)) return std::nullopt;
    token.remove_prefix(kTokenTag.size());
    if (token.empty() || token.size() % 4 == 1) return std::nullopt;

    std::string position;
    position.reserve(token.size() * 3 / 4);
    uint32_t buffer = 0;
    int bits = 0;
    for (const unsigned char c : token) {
        const auto value = kBase64UrlValues[c];
        if (value < 0) return std::nullopt;
        buffer = (buffer << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            position.push_back(static_cast<char>((buffer >> bits) & 0xFF));
        }
    }
    // One spelling per position: the bits left over after the last whole byte are zero.
    if ((buffer & ((1u << bits) - 1)) != 0) return std::nullopt;
    if (!isKeyText(position)) return std::nullopt;
    return position;
}

bool isKeyText(const std::string_view value) {
    const auto continuation = [&](const std::size_t i) {
        return i < value.size() && (static_cast<unsigned char>(value[i]) & 0xC0) == 0x80;
    };
    for (std::size_t i = 0; i < value.size();) {
        const auto lead = static_cast<unsigned char>(value[i]);
        if (lead == 0x00) return false;
        if (lead < 0x80) {
            i += 1;
        } else if (lead >= 0xC2 && lead <= 0xDF) {
            if (!continuation(i + 1)) return false;
            i += 2;
        } else if (lead >= 0xE0 && lead <= 0xEF) {
            if (!continuation(i + 1) || !continuation(i + 2)) return false;
            const auto second = static_cast<unsigned char>(value[i + 1]);
            if (lead == 0xE0 && second < 0xA0) return false;   // overlong
            if (lead == 0xED && second > 0x9F) return false;   // UTF-16 surrogates
            i += 3;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            if (!continuation(i + 1) || !continuation(i + 2) || !continuation(i + 3)) return false;
            const auto second = static_cast<unsigned char>(value[i + 1]);
            if (lead == 0xF0 && second < 0x90) return false;   // overlong
            if (lead == 0xF4 && second > 0x8F) return false;   // past U+10FFFF
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

}
