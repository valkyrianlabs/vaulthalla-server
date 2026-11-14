#include "crypto/vhf1/Key.hpp"

#include <stdexcept>

namespace vh::crypto::vhf1 {

namespace key_detail {

std::span<const uint8_t> checked(const std::span<const uint8_t> bytes) {
    if (bytes.size() != kKeySize) throw std::invalid_argument("AES-256 keys are 32 bytes");
    return bytes;
}

}

Key::Key(const std::span<const uint8_t> bytes) : secret_(key_detail::checked(bytes)) {}

}
