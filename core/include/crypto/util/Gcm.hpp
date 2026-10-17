#pragma once

#include "crypto/util/encrypt.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace vh::crypto::util {

using GcmKey = std::span<const uint8_t, AES_KEY_SIZE>;
using GcmIv = std::span<const uint8_t, AES_IV_SIZE>;
using GcmTag = std::array<uint8_t, AES_TAG_SIZE>;

// AES-256-GCM with a 96-bit IV ("v1", every vault file): J0 = IV‖0^31‖1 and plaintext block i is XORed with
// E_K(IV‖BE32(2 + i)). There is no header, so plaintext offset o is ciphertext offset o (plus the caller's data
// offset) and the 16-byte tag sits after the body. A message holds at most 2^32-2 blocks (~64 GiB), so the
// 32-bit counter never wraps and AES-CTR with a 128-bit counter yields the identical keystream.
//
// Decrypts `ciphertext`, the bytes found at plaintext offset `plaintextOffset`, into `out` (same length, may
// alias). This is positioned decryption WITHOUT authentication: callers pair it with a whole-message
// verification (crypto::IntegrityRegistry) before trusting the bytes.
void gcmCtrDecryptAt(GcmKey key, GcmIv iv, uint64_t plaintextOffset,
                     std::span<const uint8_t> ciphertext, std::span<uint8_t> out);

// Incremental AES-256-GCM encryption (OpenSSL EVP). Feed the plaintext in order, then finish() for the tag.
class GcmStreamEncryptor {
public:
    GcmStreamEncryptor(GcmKey key, GcmIv iv, std::span<const uint8_t> aad = {});
    ~GcmStreamEncryptor();
    GcmStreamEncryptor(const GcmStreamEncryptor&) = delete;
    GcmStreamEncryptor& operator=(const GcmStreamEncryptor&) = delete;

    // out.size() must be >= in.size().
    void update(std::span<const uint8_t> in, std::span<uint8_t> out);
    [[nodiscard]] GcmTag finish();

private:
    struct Ctx;
    std::unique_ptr<Ctx> ctx_;
    bool finished_{false};
};

// Incremental AES-256-GCM authentication of a ciphertext body (the plaintext is computed and discarded, never
// stored). finish() returns whether the tag matches.
class GcmStreamVerifier {
public:
    GcmStreamVerifier(GcmKey key, GcmIv iv, std::span<const uint8_t> aad = {});
    ~GcmStreamVerifier();
    GcmStreamVerifier(const GcmStreamVerifier&) = delete;
    GcmStreamVerifier& operator=(const GcmStreamVerifier&) = delete;

    void update(std::span<const uint8_t> ciphertext);
    [[nodiscard]] bool finish(std::span<const uint8_t, AES_TAG_SIZE> tag);

private:
    struct Ctx;
    std::unique_ptr<Ctx> ctx_;
    std::array<uint8_t, 64 * 1024> scratch_{};
    bool finished_{false};
};

// Incremental AES-256-GCM decryption (OpenSSL EVP). The plaintext update() releases is NOT authenticated until
// finish() returns true: callers keep it from anything durable or visible until then (and wipe it on failure).
class GcmStreamDecryptor {
public:
    GcmStreamDecryptor(GcmKey key, GcmIv iv, std::span<const uint8_t> aad = {});
    ~GcmStreamDecryptor();
    GcmStreamDecryptor(const GcmStreamDecryptor&) = delete;
    GcmStreamDecryptor& operator=(const GcmStreamDecryptor&) = delete;

    // out.size() must be >= ciphertext.size().
    void update(std::span<const uint8_t> ciphertext, std::span<uint8_t> out);
    [[nodiscard]] bool finish(std::span<const uint8_t, AES_TAG_SIZE> tag);

private:
    struct Ctx;
    std::unique_ptr<Ctx> ctx_;
    bool finished_{false};
};

// One-pass authenticated decryption of an in-memory message: writes body.size() plaintext bytes to out and
// returns true only if the tag matches; on mismatch the output is wiped and false is returned.
[[nodiscard]] bool gcmDecrypt(GcmKey key, GcmIv iv, std::span<const uint8_t> body,
                              std::span<const uint8_t, AES_TAG_SIZE> tag, std::span<uint8_t> out,
                              std::span<const uint8_t> aad = {});

// Authenticates a whole sealed file (body ‖ tag, after dataOffset header bytes) by streaming it through a
// GcmStreamVerifier. Reads with pread from fd; never writes plaintext anywhere. Returns false on tag mismatch
// or truncation; throws std::system_error on I/O failure.
[[nodiscard]] bool gcmVerifyFd(int fd, uint64_t dataOffset, uint64_t plaintextSize, GcmKey key, GcmIv iv,
                               std::span<const uint8_t> aad = {});

}
