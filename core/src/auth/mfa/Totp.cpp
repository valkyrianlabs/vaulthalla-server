#include "auth/mfa/Totp.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sodium.h>
#include <paths.h>

#include <atomic>

#include <array>
#include <cctype>
#include <stdexcept>

namespace vh::auth::mfa::totp {

namespace {

constexpr std::array<uint32_t, 9> kTotpPow10{1, 10, 100, 1'000, 10'000, 100'000, 1'000'000, 10'000'000, 100'000'000};

uint32_t totpHotp(const std::span<const uint8_t> secret, const int64_t step, const int digits) {
    if (secret.empty()) throw std::invalid_argument("TOTP secret is empty");
    if (digits < 6 || digits > 8) throw std::invalid_argument("TOTP digits must be 6..8");
    if (step < 0) throw std::invalid_argument("TOTP step is negative");

    std::array<uint8_t, 8> counter{};
    auto c = static_cast<uint64_t>(step);
    for (int i = 7; i >= 0; --i) {
        counter[static_cast<std::size_t>(i)] = static_cast<uint8_t>(c & 0xff);
        c >>= 8;
    }
    std::array<uint8_t, EVP_MAX_MD_SIZE> mac{};
    unsigned int macLen = 0;
    if (!HMAC(EVP_sha1(), secret.data(), static_cast<int>(secret.size()), counter.data(), counter.size(), mac.data(),
              &macLen) || macLen != 20)
        throw std::runtime_error("HMAC-SHA1 failed");

    const auto offset = static_cast<std::size_t>(mac[19] & 0x0f);
    const uint32_t binary = (static_cast<uint32_t>(mac[offset] & 0x7f) << 24) |
                            (static_cast<uint32_t>(mac[offset + 1]) << 16) |
                            (static_cast<uint32_t>(mac[offset + 2]) << 8) | static_cast<uint32_t>(mac[offset + 3]);
    sodium_memzero(mac.data(), mac.size());
    return binary % kTotpPow10[static_cast<std::size_t>(digits)];
}

void appendTotpPercentEncoded(std::string& out, const std::string_view text) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    for (const unsigned char ch : text) {
        if (std::isalnum(ch) || ch == '-' || ch == '.' || ch == '_' || ch == '~') {
            out.push_back(static_cast<char>(ch));
        } else {
            out.push_back('%');
            out.push_back(kHex[ch >> 4]);
            out.push_back(kHex[ch & 0x0f]);
        }
    }
}

}

crypto::SecretBytes generateSecret() { return crypto::SecretBytes::random(kSecretBytes); }

namespace {
std::atomic<int64_t> clockOffsetSecondsForTesting{0};
}

std::chrono::system_clock::time_point now() {
    return std::chrono::system_clock::now() + std::chrono::seconds(clockOffsetSecondsForTesting.load());
}

void advanceClockForTesting(const std::chrono::seconds by) {
    if (!paths::isTestMode()) throw std::logic_error("totp::advanceClockForTesting: refused outside test mode");
    clockOffsetSecondsForTesting += by.count();
}

void resetClockForTesting() { clockOffsetSecondsForTesting = 0; }

int64_t stepAt(const std::chrono::system_clock::time_point t) {
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
    return seconds < 0 ? 0 : seconds / kPeriodSeconds;
}

std::string code(const std::span<const uint8_t> secret, const int64_t step, const int digits) {
    auto value = totpHotp(secret, step, digits);
    std::string out(static_cast<std::size_t>(digits), '0');
    for (int i = digits - 1; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = static_cast<char>('0' + value % 10);
        value /= 10;
    }
    return out;
}

std::optional<std::string> normalizeCode(const std::string_view input) {
    if (input.size() > 32) return std::nullopt;
    std::string out;
    for (const unsigned char ch : input) {
        if (ch == ' ') continue;
        if (ch < '0' || ch > '9') return std::nullopt;
        out.push_back(static_cast<char>(ch));
    }
    if (out.size() != static_cast<std::size_t>(kDigits)) return std::nullopt;
    return out;
}

std::optional<int64_t> match(const std::span<const uint8_t> secret, const std::string_view input,
                             const int64_t currentStep, const int64_t lastStep) {
    auto normalized = normalizeCode(input);
    if (!normalized) return std::nullopt;

    std::optional<int64_t> accepted;
    for (int64_t step = currentStep - kWindowSteps; step <= currentStep + kWindowSteps; ++step) {
        if (step < 0) continue;
        auto candidate = code(secret, step);
        const bool equal = sodium_memcmp(candidate.data(), normalized->data(), candidate.size()) == 0;
        sodium_memzero(candidate.data(), candidate.size());
        // The latest matching step: a code that happens to repeat inside the window claims the most recent step.
        if (equal && step > lastStep) accepted = step;
    }
    sodium_memzero(normalized->data(), normalized->size());
    return accepted;
}

std::string base32(const std::span<const uint8_t> bytes) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    out.reserve((bytes.size() * 8 + 4) / 5);
    uint32_t buffer = 0;
    int bits = 0;
    for (const uint8_t b : bytes) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kAlphabet[(buffer >> bits) & 0x1f]);
        }
    }
    if (bits > 0) out.push_back(kAlphabet[(buffer << (5 - bits)) & 0x1f]);
    buffer = 0;
    return out;
}

std::string otpauthUri(const std::string_view issuer, const std::string_view account,
                       const std::string_view secretBase32) {
    std::string out = "otpauth://totp/";
    appendTotpPercentEncoded(out, issuer);
    out += ':';
    appendTotpPercentEncoded(out, account);
    out += "?secret=";
    out += secretBase32;
    out += "&issuer=";
    appendTotpPercentEncoded(out, issuer);
    out += "&algorithm=SHA1&digits=" + std::to_string(kDigits) + "&period=" + std::to_string(kPeriodSeconds);
    return out;
}

}
