#include "device/Peer.hpp"

#include "db/query/device/Device.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"

#include <chrono>

namespace vh::device {

namespace {
int64_t steadySeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
constexpr int64_t kTouchEverySeconds = 300;
}

Authorization authorize(const crypto::PublicKey& key, const std::string& address) {
    auto peer = std::make_shared<Peer>();
    peer->spki = key.spkiSha256;
    peer->spkiHex = crypto::toHex(key.spkiSha256);
    peer->spkiDer = key.spkiDer;
    peer->address = address;

    Authorization out{.peer = peer, .user = nullptr};
    const auto row = db::query::device::Devices::byAnySpki(peer->spkiHex);
    if (!row || row->revoked()) return out;

    auto user = identities::manager().user(row->user_id);
    if (!user || user->systemOnly()) return out;

    peer->deviceRowId = row->id;
    peer->viaPreviousKey = row->spki_sha256 != peer->spkiHex;
    if (!peer->viaPreviousKey && row->previous_spki_sha256)
        db::query::device::Devices::clearPrevious(row->id, row->spki_sha256);
    db::query::device::Devices::touch(row->id, address);
    peer->lastTouchSeconds.store(steadySeconds(), std::memory_order_relaxed);
    out.user = std::move(user);
    return out;
}

void touch(const Peer& peer) {
    if (!peer.deviceRowId) return;
    const auto now = steadySeconds();
    auto last = peer.lastTouchSeconds.load(std::memory_order_relaxed);
    if (now - last < kTouchEverySeconds) return;
    if (!peer.lastTouchSeconds.compare_exchange_strong(last, now, std::memory_order_relaxed)) return;
    try {
        db::query::device::Devices::touch(*peer.deviceRowId, peer.address);
    } catch (const std::exception& e) {
        log::Registry::ws()->debug("[device] last_seen_at update for device {} failed: {}", peer.shortId(), e.what());
    }
}

}
