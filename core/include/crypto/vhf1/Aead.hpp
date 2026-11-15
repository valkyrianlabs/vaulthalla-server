#pragma once

#include "crypto/vhf1/Key.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

// AES-256-GCM with a 96-bit nonce and a 128-bit tag, one message at a time, as VHF1 seals a chunk (spec 02 §3.5).
// OpenSSL's EVP interface; nothing here implements a primitive.
namespace vh::crypto::vhf1 {

inline constexpr std::size_t kAeadNonceSize = 12;
inline constexpr std::size_t kAeadTagSize = 16;

// out (plaintext.size() + kAeadTagSize bytes) = ciphertext ‖ tag. Throws std::invalid_argument for any other out
// size and std::runtime_error when OpenSSL fails.
void aeadSeal(const Key& key, std::span<const uint8_t, kAeadNonceSize> nonce, std::span<const uint8_t> aad,
              std::span<const uint8_t> plaintext, std::span<uint8_t> out);

// Opens ciphertext ‖ tag into out (sealed.size() - kAeadTagSize bytes). Returns false when the tag does not verify,
// with out wiped: the plaintext written while decrypting is never left for the caller. Throws std::invalid_argument
// for sizes that don't fit.
[[nodiscard]] bool aeadOpen(const Key& key, std::span<const uint8_t, kAeadNonceSize> nonce,
                            std::span<const uint8_t> aad, std::span<const uint8_t> sealed, std::span<uint8_t> out);

}
