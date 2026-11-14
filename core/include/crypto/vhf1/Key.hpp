#pragma once

#include <vl/keykit/secret.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace vh::crypto::vhf1 {

inline constexpr std::size_t kKeySize = 32;  // AES-256, and every key the VHF1 schedule derives

// A 256-bit symmetric key (a vault key, or a key VHF1 derives from one) in memory that is locked where the platform
// allows it and wiped when the last holder releases it (vl::keykit::SecretBytes). Immutable once built, so a
// std::shared_ptr<const Key> snapshot can be read from any thread while rotation swaps in another one.
class Key {
public:
    // Throws std::invalid_argument unless `bytes` is exactly kKeySize long.
    explicit Key(std::span<const uint8_t> bytes);

    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;

    [[nodiscard]] std::span<const uint8_t, kKeySize> bytes() const {
        return std::span<const uint8_t, kKeySize>(secret_.bytes().data(), kKeySize);
    }

private:
    vl::keykit::SecretBytes secret_;
};

using KeyPtr = std::shared_ptr<const Key>;

}
