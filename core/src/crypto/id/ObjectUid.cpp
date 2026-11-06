#include "crypto/id/ObjectUid.hpp"
#include "crypto/util/uuid.hpp"

#include <sodium.h>

#include <stdexcept>

namespace vh::crypto::id {

namespace {

constexpr std::string_view kUidAlphabet = "0123456789abcdefghjkmnpqrstvwxyz";
constexpr std::size_t kUidBase32Length = 26;   // ceil(128 / 5)

int uidHexDigit(const char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}

ObjectUid newObjectUid() {
    util::ensure_sodium_init();
    ObjectUid uid{};
    randombytes_buf(uid.data(), uid.size());
    return uid;
}

std::string toUuid(const ObjectUid& uid) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (std::size_t i = 0; i < uid.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out.push_back('-');
        out.push_back(kHex[uid[i] >> 4]);
        out.push_back(kHex[uid[i] & 0x0f]);
    }
    return out;
}

ObjectUid fromUuid(const std::string_view text) {
    if (text.size() != 36) throw std::invalid_argument("object uid: not a UUID");
    ObjectUid uid{};
    std::size_t byte = 0;
    for (std::size_t i = 0; i < text.size();) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (text[i] != '-') throw std::invalid_argument("object uid: not a UUID");
            ++i;
            continue;
        }
        const int hi = uidHexDigit(text[i]), lo = uidHexDigit(text[i + 1]);
        if (hi < 0 || lo < 0) throw std::invalid_argument("object uid: not a UUID");
        uid[byte++] = static_cast<uint8_t>(hi << 4 | lo);
        i += 2;
    }
    return uid;
}

std::string_view to_string(const Base32Error error) {
    switch (error) {
    case Base32Error::BadLength: return "bad_length";
    case Base32Error::BadSymbol: return "bad_symbol";
    case Base32Error::NonCanonical: return "non_canonical";
    }
    return "bad_symbol";
}

std::string toBase32(const ObjectUid& uid) {
    std::string out;
    out.reserve(kUidBase32Length);
    uint32_t buffer = 0;
    int bits = 0;
    for (const auto b : uid) {
        buffer = buffer << 8 | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kUidAlphabet[buffer >> bits & 0x1f]);
        }
    }
    if (bits > 0) out.push_back(kUidAlphabet[buffer << (5 - bits) & 0x1f]);
    return out;
}

std::optional<ObjectUid> fromBase32(const std::string_view text, Base32Error* error) {
    const auto fail = [&](const Base32Error e) -> std::optional<ObjectUid> {
        if (error) *error = e;
        return std::nullopt;
    };
    // Symbols first: an upper-case or out-of-alphabet id of the wrong length is still a bad symbol.
    for (const auto c : text)
        if (kUidAlphabet.find(c) == std::string_view::npos) return fail(Base32Error::BadSymbol);
    if (text.size() != kUidBase32Length) return fail(Base32Error::BadLength);

    ObjectUid uid{};
    uint32_t buffer = 0;
    int bits = 0;
    std::size_t byte = 0;
    for (const auto c : text) {
        buffer = buffer << 5 | static_cast<uint32_t>(kUidAlphabet.find(c));
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            uid[byte++] = static_cast<uint8_t>(buffer >> bits & 0xff);
        }
    }
    if ((buffer & ((1u << bits) - 1)) != 0) return fail(Base32Error::NonCanonical);
    return uid;
}

}
