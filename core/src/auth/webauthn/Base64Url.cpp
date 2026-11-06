#include "auth/webauthn/Base64Url.hpp"

#include <sodium.h>

namespace vh::auth::webauthn {

std::string base64urlEncode(const ByteView bytes) {
    if (bytes.empty()) return {};
    std::string out(sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(out.size() - 1);  // the terminating NUL
    return out;
}

std::optional<Bytes> base64urlDecode(const std::string_view text) {
    if (text.empty()) return Bytes{};
    if (sodium_init() < 0) return std::nullopt;
    Bytes out(text.size() * 3 / 4 + 3);
    std::size_t len = 0;
    const char* end = nullptr;
    if (sodium_base642bin(out.data(), out.size(), text.data(), text.size(), nullptr, &len, &end,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
        || end != text.data() + text.size())
        return std::nullopt;
    out.resize(len);
    return out;
}

}
