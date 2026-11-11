#include "cloud/Identity.hpp"

#include "cloud/Signing.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "log/Registry.hpp"
#include <paths.h>

namespace vh::cloud::identity {

// Named, not anonymous: the unity build joins this file with others.
namespace identity_detail {

std::string slot() { return paths::testMode ? "test_cloud_identity" : "cloud_identity"; }

}

crypto::SecretBytes create() {
    auto seed = crypto::SecretBytes::random(kSeedSize);
    crypto::secrets::KeyProvider provider(identity_detail::slot());
    provider.updateMasterKey(seed.bytes());
    return seed;
}

std::optional<crypto::SecretBytes> load() {
    crypto::secrets::KeyProvider provider(identity_detail::slot());
    if (!provider.sealedExists()) return std::nullopt;
    try {
        provider.init();
    } catch (const std::exception& e) {
        log::Registry::crypto()->warn("[cloud] The Vaulthalla Cloud identity key doesn't unseal on this host ({}); "
                                      "unlink and link again", e.what());
        return std::nullopt;
    }
    if (provider.getMasterKey().size() != kSeedSize) return std::nullopt;
    return crypto::SecretBytes(provider.getMasterKey());
}

void destroy() {
    crypto::secrets::KeyProvider provider(identity_detail::slot());
    if (provider.sealedExists()) provider.destroySealed();
}

}
