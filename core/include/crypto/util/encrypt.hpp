#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <filesystem>
#include <functional>
#include <span>

namespace vh::crypto::util {

constexpr size_t AES_KEY_SIZE = 32;      // 256-bit
constexpr size_t AES_IV_SIZE  = 12;      // GCM standard nonce
constexpr size_t AES_TAG_SIZE = 16;      // GCM auth tag

// Keys are spans: a caller passes a SecretKey's or KeyProvider's bytes where they live, without a vector copy (#350).
std::vector<uint8_t> encrypt_aes256_gcm(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> key,
    std::vector<uint8_t>& out_iv);

// The plaintext comes back in a plain vector; a caller unwrapping a key wipes it (crypto::WipedKeyCopy).
std::vector<uint8_t> decrypt_aes256_gcm(
    const std::vector<uint8_t>& ciphertext_with_tag,
    std::span<const uint8_t> key,
    const std::vector<uint8_t>& iv);

// Streams a ciphertext file (AES-256-GCM body followed by its 16-byte tag) into `sink`, 64 KiB at a time. What the
// sink receives is NOT authenticated until this returns: when the tag doesn't verify (or the input is truncated) it
// throws, and the caller discards everything it was given. Nothing is written to disk here.
void decrypt_aes256_gcm_file(
    const std::filesystem::path& ciphertextPath,
    const std::function<void(std::span<const uint8_t>)>& sink,
    std::span<const uint8_t> key,
    const std::vector<uint8_t>& iv);

std::vector<uint8_t> read_file(const std::filesystem::path& path);

std::string b64_encode(const std::vector<uint8_t>& data);

std::vector<uint8_t> b64_decode(const std::string& b64);

}
