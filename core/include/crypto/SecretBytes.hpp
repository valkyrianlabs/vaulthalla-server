#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vh::crypto {

// A secret of any length (a master secret, the DB password, the share-token pepper, a signing seed) in memory that is
// locked where the platform allows it and zeroed before it is freed (#350). SecretKey is the fixed 32-byte form used
// for vault keys. Immutable and move-only, so the bytes live in one place: callers read them through bytes() and
// keep no copies of their own.
class SecretBytes {
public:
    SecretBytes() noexcept = default;
    explicit SecretBytes(std::span<const uint8_t> bytes);
    ~SecretBytes();

    SecretBytes(SecretBytes&& other) noexcept;
    SecretBytes& operator=(SecretBytes&& other) noexcept;
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;

    [[nodiscard]] std::span<const uint8_t> bytes() const noexcept { return {data_, size_}; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

    // `n` bytes from libsodium's CSPRNG (the OS generator), written straight into locked memory. Throws when n is 0
    // or libsodium can't initialize.
    [[nodiscard]] static SecretBytes random(std::size_t n);

private:
    explicit SecretBytes(std::size_t n);  // locked, zero-filled
    void release() noexcept;

    uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

// A plain-vector copy of a secret for the moment an API needs one (what decrypt_aes256_gcm or a sealer returns, a
// buffer a dependent API takes), wiped when it leaves scope on every path, exceptions included.
struct WipedKeyCopy {
    explicit WipedKeyCopy(std::span<const uint8_t> from) : bytes(from.begin(), from.end()) {}
    explicit WipedKeyCopy(std::vector<uint8_t>&& adopt) noexcept : bytes(std::move(adopt)) {}
    ~WipedKeyCopy();
    WipedKeyCopy(const WipedKeyCopy&) = delete;
    WipedKeyCopy& operator=(const WipedKeyCopy&) = delete;

    std::vector<uint8_t> bytes;
};

// Zero a buffer that held a secret (sodium_memzero: not optimized away).
void wipeSecret(std::vector<uint8_t>& bytes) noexcept;
void wipeSecret(std::string& text) noexcept;

// The bytes of a string, without a copy (a password or token handed over as text).
[[nodiscard]] inline std::span<const uint8_t> viewBytes(const std::string_view text) noexcept {
    return {reinterpret_cast<const uint8_t*>(text.data()), text.size()};
}

// Tests only: called with each SecretBytes, SecretKey and WipedKeyCopy buffer right after it is zeroed and before it is
// freed (its address and its contents at that moment), so a test can prove a secret left no copy behind. Called from
// whichever thread releases the secret. nullptr (the default) turns it off.
using WipeObserver = void (*)(const void* where, std::span<const uint8_t> after);
void setWipeObserverForTesting(WipeObserver observer) noexcept;
// What the destructors above call.
void notifySecretWiped(const void* where, std::span<const uint8_t> after) noexcept;

}
