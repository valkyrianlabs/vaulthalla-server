#pragma once

#include "crypto/util/encrypt.hpp"
#include "crypto/vhf1/Key.hpp"

#include <memory>

namespace vh::crypto {

// The server's vault key: vhf1::Key (256 bits, locked where the platform allows it, wiped when the last holder
// releases it, immutable so a std::shared_ptr<const SecretKey> snapshot can be read from any thread while rotation
// swaps in another one) plus the generator. A thin adapter: it adds no state, and converts to vhf1::Key and
// vhf1::KeyPtr wherever the file format takes one.
class SecretKey final : public vhf1::Key {
public:
    using vhf1::Key::Key;

    [[nodiscard]] static std::shared_ptr<const SecretKey> random();
};

using SecretKeyPtr = std::shared_ptr<const SecretKey>;

static_assert(vhf1::kKeySize == util::AES_KEY_SIZE);

}
