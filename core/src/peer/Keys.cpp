#include "peer/Keys.hpp"

#include "crypto/secrets/KeyProvider.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/vault/Key.hpp"
#include "device/Device.hpp"
#include "vault/KeyAttestation.hpp"

#include <paths.h>
#include <sodium.h>
#include <version.h>

#include <unistd.h>

#include <algorithm>
#include <array>
#include <mutex>
#include <stdexcept>

namespace vh::peer::keys {

namespace {

struct WrapCache {
    std::mutex mutex;
    std::string sealedFor;  // the backing path the key was unsealed from (tests switch it)
    std::optional<Key32> publicKey;
};

WrapCache& wrapCache() {
    static WrapCache c;
    return c;
}

}

std::string wrapSlotName() { return paths::testMode ? "test_peer_wrap" : "peer_wrap"; }

Key32 wrapPublicKey() {
    auto& c = wrapCache();
    std::scoped_lock lock(c.mutex);
    const auto here = paths::getBackingPath().string();
    if (c.publicKey && c.sealedFor == here) return *c.publicKey;

    if (sodium_init() < 0) throw std::runtime_error("libsodium cannot initialize");
    crypto::secrets::KeyProvider provider(wrapSlotName());
    // Linked servers pinned the public half: a lost key is never replaced behind their backs.
    provider.initGuarded([]() -> std::optional<std::string> {
        const auto live = db::query::peer::Peers::countLive();
        if (live == 0) return std::nullopt;
        return std::to_string(live) + " linked server(s) that pinned this server's peer wrap key";
    });
    const auto secret = provider.getMasterKey();
    if (secret.size() != crypto_scalarmult_SCALARBYTES)
        throw std::runtime_error("the sealed peer wrap key is not a 32-byte X25519 key");
    Key32 pub{};
    if (crypto_scalarmult_base(pub.data(), secret.data()) != 0)
        throw std::runtime_error("cannot derive the peer wrap public key");
    c.publicKey = pub;
    c.sealedFor = here;
    return pub;
}

std::string serverName() {
    std::array<char, 256> host{};
    if (::gethostname(host.data(), host.size() - 1) != 0) return "vaulthalla";
    std::string name = host.data();
    if (const auto dot = name.find('.'); dot != std::string::npos && dot > 0) name.resize(dot);
    return vh::device::normalizeDeviceName(name).value_or("vaulthalla");
}

Card localCard() {
    Card card;
    card.node_id = db::query::device::Devices::nodeId();
    card.name = serverName();
    const auto current = vault::attestation::currentPublicKey();
    for (const auto& k : db::query::vault::Key::attestationKeys()) {
        if (k.public_key.size() != kKeyBytes) continue;
        Key32 key{};
        std::ranges::copy(k.public_key, key.begin());
        if (std::ranges::find(card.attest_public_keys, key) == card.attest_public_keys.end())
            card.attest_public_keys.push_back(key);
        if (card.attest_public_keys.size() == kMaxAttestKeys) break;
    }
    if (current.size() == kKeyBytes && card.attest_public_keys.empty()) {
        Key32 key{};
        std::ranges::copy(current, key.begin());
        card.attest_public_keys.push_back(key);
    }
    card.wrap_public_key = wrapPublicKey();
    card.peer_protocol = kPeerProtocol;
    card.product_version = VH_VERSION;
    return card;
}

}
