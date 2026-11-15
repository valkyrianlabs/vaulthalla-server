#pragma once

#include <vl/keykit/secret.hpp>

#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

// Secrets in memory (#350). The secret type itself is vl-keykit's: vl::keykit::SecretBytes holds a secret of any
// length (a master secret, the DB password, the share-token pepper, a signing seed) in memory that is locked where the
// platform allows it and zeroed before it is freed; vl::keykit::wipe zeroes a buffer that held one. SecretKey is the
// fixed 32-byte form used for vault keys. What stays here is what only the server needs.
namespace vh::crypto {

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

// The bytes of a string, without a copy (a password or token handed over as text).
[[nodiscard]] inline std::span<const uint8_t> viewBytes(const std::string_view text) noexcept {
    return {reinterpret_cast<const uint8_t*>(text.data()), text.size()};
}

// Tests observe wipes through vl::keykit::setWipeObserverForTesting: it is called with each SecretBytes, SecretKey
// and WipedKeyCopy buffer right after it is zeroed and before it is freed, from whichever thread releases the secret.

}
