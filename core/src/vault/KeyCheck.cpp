#include "vault/KeyCheck.hpp"

#include <vl/keykit/attestation.hpp>

namespace vh::vault {

// One implementation for every producer and verifier: vl-keykit (attestation.hpp; spec 03 §6.5).
std::string keyCheck(const std::span<const uint8_t> key, const unsigned int vaultId, const unsigned int version) {
    return vl::keykit::provenance::keyCheck(key, vaultId, version);
}

bool keyCheckEquals(const std::string& a, const std::string& b) { return vl::keykit::provenance::keyCheckEquals(a, b); }

}
