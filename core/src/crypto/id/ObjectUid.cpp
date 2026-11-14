#include "crypto/id/ObjectUid.hpp"
#include "crypto/util/uuid.hpp"

#include <sodium.h>

#include <stdexcept>

namespace vh::crypto::id {

namespace {

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

}
