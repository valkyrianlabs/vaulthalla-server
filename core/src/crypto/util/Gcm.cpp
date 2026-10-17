#include "crypto/util/Gcm.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace vh::crypto::util {

namespace gcm_detail {

struct EvpCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
};
using EvpCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCtxDeleter>;

}

namespace {

using gcm_detail::EvpCtx;

constexpr uint64_t kGcmMaxPlaintextBytes = (uint64_t{1} << 32) * 16 - 32;  // (2^32 - 2) blocks

[[nodiscard]] EvpCtx newCtx() {
    EvpCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("Failed to allocate an OpenSSL cipher context");
    return ctx;
}

// OpenSSL lengths are ints; feed large spans in bounded steps.
constexpr std::size_t kMaxEvpStep = 1u << 30;

void addAad(EVP_CIPHER_CTX* ctx, const std::span<const uint8_t> aad, const bool encrypt) {
    std::size_t done = 0;
    while (done < aad.size()) {
        const auto step = std::min(aad.size() - done, kMaxEvpStep);
        int outLen = 0;
        const int ok = encrypt
            ? EVP_EncryptUpdate(ctx, nullptr, &outLen, aad.data() + done, static_cast<int>(step))
            : EVP_DecryptUpdate(ctx, nullptr, &outLen, aad.data() + done, static_cast<int>(step));
        if (ok != 1) throw std::runtime_error("AES-GCM AAD update failed");
        done += step;
    }
}

}

void gcmCtrDecryptAt(const GcmKey key, const GcmIv iv, const uint64_t plaintextOffset,
                     const std::span<const uint8_t> ciphertext, const std::span<uint8_t> out) {
    if (out.size() < ciphertext.size()) throw std::invalid_argument("gcmCtrDecryptAt: output buffer too small");
    if (ciphertext.empty()) return;
    if (plaintextOffset > kGcmMaxPlaintextBytes || ciphertext.size() > kGcmMaxPlaintextBytes - plaintextOffset)
        throw std::out_of_range("gcmCtrDecryptAt: range exceeds the AES-GCM message limit");

    const uint64_t block = plaintextOffset / 16;
    const auto skip = static_cast<std::size_t>(plaintextOffset % 16);

    std::array<uint8_t, 16> counter{};
    std::copy(iv.begin(), iv.end(), counter.begin());
    const auto ctr = static_cast<uint32_t>(2 + block);  // < 2^32 by the message limit above
    counter[12] = static_cast<uint8_t>(ctr >> 24);
    counter[13] = static_cast<uint8_t>(ctr >> 16);
    counter[14] = static_cast<uint8_t>(ctr >> 8);
    counter[15] = static_cast<uint8_t>(ctr);

    const auto ctx = newCtx();
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr, key.data(), counter.data()) != 1)
        throw std::runtime_error("AES-CTR initialization failed");

    // Discard the keystream bytes before the requested offset inside its first block.
    if (skip > 0) {
        std::array<uint8_t, 16> zeros{};
        std::array<uint8_t, 16> sink{};
        int outLen = 0;
        if (EVP_DecryptUpdate(ctx.get(), sink.data(), &outLen, zeros.data(), static_cast<int>(skip)) != 1)
            throw std::runtime_error("AES-CTR keystream skip failed");
    }

    std::size_t done = 0;
    while (done < ciphertext.size()) {
        const auto step = std::min(ciphertext.size() - done, kMaxEvpStep);
        int outLen = 0;
        if (EVP_DecryptUpdate(ctx.get(), out.data() + done, &outLen, ciphertext.data() + done,
                              static_cast<int>(step)) != 1 || static_cast<std::size_t>(outLen) != step)
            throw std::runtime_error("AES-CTR decryption failed");
        done += step;
    }
}

struct GcmStreamEncryptor::Ctx {
    gcm_detail::EvpCtx evp;
};

GcmStreamEncryptor::GcmStreamEncryptor(const GcmKey key, const GcmIv iv, const std::span<const uint8_t> aad)
    : ctx_(std::make_unique<Ctx>(Ctx{newCtx()})) {
    auto* c = ctx_->evp.get();
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(AES_IV_SIZE), nullptr) != 1 ||
        EVP_EncryptInit_ex(c, nullptr, nullptr, key.data(), iv.data()) != 1)
        throw std::runtime_error("AES-GCM encryption initialization failed");
    addAad(c, aad, true);
}

GcmStreamEncryptor::~GcmStreamEncryptor() = default;

void GcmStreamEncryptor::update(const std::span<const uint8_t> in, const std::span<uint8_t> out) {
    if (finished_) throw std::logic_error("GcmStreamEncryptor used after finish()");
    if (out.size() < in.size()) throw std::invalid_argument("GcmStreamEncryptor: output buffer too small");
    std::size_t done = 0;
    while (done < in.size()) {
        const auto step = std::min(in.size() - done, kMaxEvpStep);
        int outLen = 0;
        if (EVP_EncryptUpdate(ctx_->evp.get(), out.data() + done, &outLen, in.data() + done,
                              static_cast<int>(step)) != 1 || static_cast<std::size_t>(outLen) != step)
            throw std::runtime_error("AES-GCM encryption failed");
        done += step;
    }
}

GcmTag GcmStreamEncryptor::finish() {
    if (finished_) throw std::logic_error("GcmStreamEncryptor finished twice");
    finished_ = true;
    std::array<uint8_t, 16> tail{};
    int outLen = 0;
    if (EVP_EncryptFinal_ex(ctx_->evp.get(), tail.data(), &outLen) != 1 || outLen != 0)
        throw std::runtime_error("AES-GCM encryption finalization failed");
    GcmTag tag{};
    if (EVP_CIPHER_CTX_ctrl(ctx_->evp.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1)
        throw std::runtime_error("AES-GCM tag retrieval failed");
    return tag;
}

struct GcmStreamVerifier::Ctx {
    gcm_detail::EvpCtx evp;
};

GcmStreamVerifier::GcmStreamVerifier(const GcmKey key, const GcmIv iv, const std::span<const uint8_t> aad)
    : ctx_(std::make_unique<Ctx>(Ctx{newCtx()})) {
    auto* c = ctx_->evp.get();
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(AES_IV_SIZE), nullptr) != 1 ||
        EVP_DecryptInit_ex(c, nullptr, nullptr, key.data(), iv.data()) != 1)
        throw std::runtime_error("AES-GCM verification initialization failed");
    addAad(c, aad, false);
}

GcmStreamVerifier::~GcmStreamVerifier() {
    OPENSSL_cleanse(scratch_.data(), scratch_.size());
}

void GcmStreamVerifier::update(const std::span<const uint8_t> ciphertext) {
    if (finished_) throw std::logic_error("GcmStreamVerifier used after finish()");
    std::size_t done = 0;
    while (done < ciphertext.size()) {
        const auto step = std::min(ciphertext.size() - done, scratch_.size());
        int outLen = 0;
        if (EVP_DecryptUpdate(ctx_->evp.get(), scratch_.data(), &outLen, ciphertext.data() + done,
                              static_cast<int>(step)) != 1)
            throw std::runtime_error("AES-GCM verification update failed");
        done += step;
    }
}

bool GcmStreamVerifier::finish(const std::span<const uint8_t, AES_TAG_SIZE> tag) {
    if (finished_) throw std::logic_error("GcmStreamVerifier finished twice");
    finished_ = true;
    if (EVP_CIPHER_CTX_ctrl(ctx_->evp.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(AES_TAG_SIZE),
                            const_cast<uint8_t*>(tag.data())) != 1)
        throw std::runtime_error("AES-GCM tag setup failed");
    int outLen = 0;
    const bool ok = EVP_DecryptFinal_ex(ctx_->evp.get(), scratch_.data(), &outLen) == 1;
    OPENSSL_cleanse(scratch_.data(), scratch_.size());
    return ok;
}

struct GcmStreamDecryptor::Ctx {
    gcm_detail::EvpCtx evp;
};

GcmStreamDecryptor::GcmStreamDecryptor(const GcmKey key, const GcmIv iv, const std::span<const uint8_t> aad)
    : ctx_(std::make_unique<Ctx>(Ctx{newCtx()})) {
    auto* c = ctx_->evp.get();
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(AES_IV_SIZE), nullptr) != 1 ||
        EVP_DecryptInit_ex(c, nullptr, nullptr, key.data(), iv.data()) != 1)
        throw std::runtime_error("AES-GCM decryption initialization failed");
    addAad(c, aad, false);
}

GcmStreamDecryptor::~GcmStreamDecryptor() = default;

void GcmStreamDecryptor::update(const std::span<const uint8_t> ciphertext, const std::span<uint8_t> out) {
    if (finished_) throw std::logic_error("GcmStreamDecryptor used after finish()");
    if (out.size() < ciphertext.size()) throw std::invalid_argument("GcmStreamDecryptor: output buffer too small");
    std::size_t done = 0;
    while (done < ciphertext.size()) {
        const auto step = std::min(ciphertext.size() - done, kMaxEvpStep);
        int outLen = 0;
        if (EVP_DecryptUpdate(ctx_->evp.get(), out.data() + done, &outLen, ciphertext.data() + done,
                              static_cast<int>(step)) != 1 || static_cast<std::size_t>(outLen) != step)
            throw std::runtime_error("AES-GCM decryption failed");
        done += step;
    }
}

bool GcmStreamDecryptor::finish(const std::span<const uint8_t, AES_TAG_SIZE> tag) {
    if (finished_) throw std::logic_error("GcmStreamDecryptor finished twice");
    finished_ = true;
    if (EVP_CIPHER_CTX_ctrl(ctx_->evp.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(AES_TAG_SIZE),
                            const_cast<uint8_t*>(tag.data())) != 1)
        throw std::runtime_error("AES-GCM tag setup failed");
    std::array<uint8_t, 16> tail{};
    int outLen = 0;
    return EVP_DecryptFinal_ex(ctx_->evp.get(), tail.data(), &outLen) == 1;
}

bool gcmDecrypt(const GcmKey key, const GcmIv iv, const std::span<const uint8_t> body,
                const std::span<const uint8_t, AES_TAG_SIZE> tag, const std::span<uint8_t> out,
                const std::span<const uint8_t> aad) {
    if (out.size() < body.size()) throw std::invalid_argument("gcmDecrypt: output buffer too small");
    const auto ctx = newCtx();
    auto* c = ctx.get();
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(AES_IV_SIZE), nullptr) != 1 ||
        EVP_DecryptInit_ex(c, nullptr, nullptr, key.data(), iv.data()) != 1)
        throw std::runtime_error("AES-GCM decryption initialization failed");
    addAad(c, aad, false);
    std::size_t done = 0;
    while (done < body.size()) {
        const auto step = std::min(body.size() - done, kMaxEvpStep);
        int outLen = 0;
        if (EVP_DecryptUpdate(c, out.data() + done, &outLen, body.data() + done, static_cast<int>(step)) != 1 ||
            static_cast<std::size_t>(outLen) != step)
            throw std::runtime_error("AES-GCM decryption failed");
        done += step;
    }
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, static_cast<int>(AES_TAG_SIZE),
                            const_cast<uint8_t*>(tag.data())) != 1)
        throw std::runtime_error("AES-GCM tag setup failed");
    std::array<uint8_t, 16> tail{};
    int outLen = 0;
    if (EVP_DecryptFinal_ex(c, tail.data(), &outLen) != 1) {
        OPENSSL_cleanse(out.data(), body.size());
        return false;
    }
    return true;
}

bool gcmVerifyFd(const int fd, const uint64_t dataOffset, const uint64_t plaintextSize, const GcmKey key,
                 const GcmIv iv, const std::span<const uint8_t> aad) {
    GcmStreamVerifier verifier(key, iv, aad);
    std::vector<uint8_t> buffer(1u << 20);
    uint64_t offset = 0;
    while (offset < plaintextSize) {
        const auto want = static_cast<std::size_t>(std::min<uint64_t>(buffer.size(), plaintextSize - offset));
        const auto got = ::pread(fd, buffer.data(), want, static_cast<off_t>(dataOffset + offset));
        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "pread during AES-GCM verification");
        }
        if (got == 0) return false;  // truncated
        verifier.update({buffer.data(), static_cast<std::size_t>(got)});
        offset += static_cast<uint64_t>(got);
    }

    std::array<uint8_t, AES_TAG_SIZE> tag{};
    std::size_t tagRead = 0;
    while (tagRead < tag.size()) {
        const auto got = ::pread(fd, tag.data() + tagRead, tag.size() - tagRead,
                                 static_cast<off_t>(dataOffset + plaintextSize + tagRead));
        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "pread of the AES-GCM tag");
        }
        if (got == 0) return false;
        tagRead += static_cast<std::size_t>(got);
    }

    // Trailing bytes after the tag mean the file is not exactly this message.
    uint8_t extra = 0;
    const auto more = ::pread(fd, &extra, 1, static_cast<off_t>(dataOffset + plaintextSize + AES_TAG_SIZE));
    if (more > 0) return false;

    return verifier.finish(tag);
}

}
