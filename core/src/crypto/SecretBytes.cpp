#include "crypto/SecretBytes.hpp"

#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <stdexcept>
#include <utility>

namespace vh::crypto {

namespace {
std::atomic<WipeObserver> wipeObserver{nullptr};
}

SecretBytes::SecretBytes(const std::size_t n) : data_(n ? new uint8_t[n]() : nullptr), size_(n) {
    // Keep it out of swap where the platform allows it (before any secret byte is written); failure is not fatal.
    if (data_) (void)sodium_mlock(data_, size_);
}

SecretBytes::SecretBytes(const std::span<const uint8_t> bytes) : SecretBytes(bytes.size()) {
    std::ranges::copy(bytes, data_);
}

SecretBytes::~SecretBytes() { release(); }

SecretBytes::SecretBytes(SecretBytes&& other) noexcept
    : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}

SecretBytes& SecretBytes::operator=(SecretBytes&& other) noexcept {
    if (this != &other) {
        release();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

void SecretBytes::release() noexcept {
    if (!data_) return;
    sodium_munlock(data_, size_);  // also zeroes the memory
    notifySecretWiped(data_, {data_, size_});
    delete[] data_;
    data_ = nullptr;
    size_ = 0;
}

SecretBytes SecretBytes::random(const std::size_t n) {
    if (n == 0) throw std::invalid_argument("a random secret needs at least one byte");
    // Idempotent and thread-safe; a secret is never generated from an uninitialized libsodium.
    if (sodium_init() < 0) throw std::runtime_error("libsodium initialization failed; refusing to generate a secret");
    SecretBytes out(n);
    randombytes_buf(out.data_, out.size_);
    return out;
}

WipedKeyCopy::~WipedKeyCopy() {
    sodium_memzero(bytes.data(), bytes.size());
    notifySecretWiped(bytes.data(), bytes);
}

void wipeSecret(std::vector<uint8_t>& bytes) noexcept { sodium_memzero(bytes.data(), bytes.size()); }

void wipeSecret(std::string& text) noexcept { sodium_memzero(text.data(), text.size()); }

void setWipeObserverForTesting(const WipeObserver observer) noexcept { wipeObserver.store(observer); }

void notifySecretWiped(const void* where, const std::span<const uint8_t> after) noexcept {
    if (const auto observer = wipeObserver.load(std::memory_order_relaxed)) observer(where, after);
}

}
