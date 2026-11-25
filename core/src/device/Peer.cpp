#include "device/Peer.hpp"

#include "config/Registry.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/peer/Peer.hpp"
#include "peer/Peer.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/BackupGrants.hpp"

#include <chrono>

namespace vh::device {

namespace {
int64_t steadySeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
constexpr int64_t kTouchEverySeconds = 300;
}

Authorization authorize(const crypto::PublicKey& key, const std::string& address, const bool relayed) {
    auto peer = std::make_shared<Peer>();
    peer->spki = key.spkiSha256;
    peer->spkiHex = crypto::toHex(key.spkiSha256);
    peer->spkiDer = key.spkiDer;
    peer->address = address;
    peer->relayed = relayed;

    Authorization out{.peer = peer, .user = nullptr};
    const auto row = db::query::device::Devices::byAnySpki(peer->spkiHex);
    if (!row) {
        // design/peers/link.md: a key no device has ever had may be a linked server's; never through the relay.
        if (relayed || !config::Registry::get().peers.experimental) return out;
        auto linked = db::query::peer::Peers::liveBySpki(peer->spkiHex);
        if (!linked) return out;
        // The key the peer announced is in use: it is the pin from now on, and the old key is no longer accepted.
        if (linked->spki_sha256 != peer->spkiHex && !db::query::peer::Peers::promoteNext(linked->id, peer->spkiHex))
            return out;
        auto principal = std::make_shared<vh::peer::Principal>();
        principal->peer_id = linked->id;
        principal->node_id = linked->node_id;
        principal->name = linked->name;
        principal->spki = peer->spki;
        principal->spki_hex = peer->spkiHex;
        principal->spki_der = peer->spkiDer;
        principal->address = address;
        principal->inbound = true;
        out.linked = std::move(principal);
        return out;
    }
    if (row->revoked()) return out;

    auto user = identities::manager().user(row->user_id);
    if (!user || user->systemOnly()) return out;

    peer->deviceRowId = row->id;
    peer->pairedViaRelay = row->paired_via == "relay";
    peer->scope = row->scope;
    // #362: a device that hasn't connected for 90 days loses its key-backup grant before this connection counts.
    try {
        (void)ops::backup_grants::revokeIfIdle(*row);
    } catch (const std::exception& e) {
        log::Registry::ws()->warn("[device] idle key-backup grant check for device {} failed: {}", peer->shortId(),
                                  e.what());
    }
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
