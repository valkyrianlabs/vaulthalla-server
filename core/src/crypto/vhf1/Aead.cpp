#include "crypto/vhf1/Aead.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>

namespace vh::crypto::vhf1 {

namespace aead_detail {

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

// OpenSSL lengths are ints; feed large spans in bounded steps.
constexpr std::size_t kMaxEvpStep = 1u << 30;

[[nodiscard]] CipherCtx newCtx(const Key& key, const std::span<const uint8_t, kAeadNonceSize> nonce,
                               const bool encrypt) {
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("Failed to allocate an OpenSSL cipher context");
    auto* c = ctx.get();
    const int enc = encrypt ? 1 : 0;
    if (EVP_CipherInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr, enc) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kAeadNonceSize), nullptr) != 1 ||
        EVP_CipherInit_ex(c, nullptr, nullptr, key.bytes().data(), nonce.data(), enc) != 1)
        throw std::runtime_error("AES-GCM initialization failed");
    return ctx;
}

// AAD when out is nullptr, else the message body (out.size() >= in.size()).
void update(EVP_CIPHER_CTX* ctx, const std::span<const uint8_t> in, uint8_t* out) {
    std::size_t done = 0;
    while (done < in.size()) {
        const auto step = std::min(in.size() - done, kMaxEvpStep);
        int outLen = 0;
        if (EVP_CipherUpdate(ctx, out ? out + done : nullptr, &outLen, in.data() + done, static_cast<int>(step)) != 1 ||
            (out && static_cast<std::size_t>(outLen) != step))
            throw std::runtime_error("AES-GCM update failed");
        done += step;
    }
}

}

void aeadSeal(const Key& key, const std::span<const uint8_t, kAeadNonceSize> nonce, const std::span<const uint8_t> aad,
              const std::span<const uint8_t> plaintext, const std::span<uint8_t> out) {
    if (out.size() != plaintext.size() + kAeadTagSize) throw std::invalid_argument("AES-GCM: sealed buffer size");
    const auto ctx = aead_detail::newCtx(key, nonce, true);
    aead_detail::update(ctx.get(), aad, nullptr);
    aead_detail::update(ctx.get(), plaintext, out.data());
    std::array<uint8_t, 16> tail{};
    int outLen = 0;
    if (EVP_CipherFinal_ex(ctx.get(), tail.data(), &outLen) != 1 || outLen != 0)
        throw std::runtime_error("AES-GCM encryption finalization failed");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kAeadTagSize),
                            out.data() + plaintext.size()) != 1)
        throw std::runtime_error("AES-GCM tag retrieval failed");
}

bool aeadOpen(const Key& key, const std::span<const uint8_t, kAeadNonceSize> nonce, const std::span<const uint8_t> aad,
              const std::span<const uint8_t> sealed, const std::span<uint8_t> out) {
    if (sealed.size() < kAeadTagSize || out.size() != sealed.size() - kAeadTagSize)
        throw std::invalid_argument("AES-GCM: opened buffer size");
    const auto body = sealed.first(out.size());
    const auto ctx = aead_detail::newCtx(key, nonce, false);
    aead_detail::update(ctx.get(), aad, nullptr);
    aead_detail::update(ctx.get(), body, out.data());
    std::array<uint8_t, kAeadTagSize> tag{};
    std::ranges::copy(sealed.last(kAeadTagSize), tag.begin());
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kAeadTagSize), tag.data()) != 1)
        throw std::runtime_error("AES-GCM tag setup failed");
    std::array<uint8_t, 16> tail{};
    int outLen = 0;
    if (EVP_CipherFinal_ex(ctx.get(), tail.data(), &outLen) != 1) {
        if (!out.empty()) OPENSSL_cleanse(out.data(), out.size());
        return false;
    }
    return true;
}

}
