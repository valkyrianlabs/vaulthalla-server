#pragma once

#include "peer/Peer.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// The `peer` table (migration 157): linked servers. Trusted primitives: callers (ops::peers, the device listener's
// handshake, the link service) authorize.
namespace vh::db::query::peer {

using vh::peer::Record;

struct NewPeer {
    std::string node_id{};
    std::string name{};
    std::string spki_sha256{};
    std::vector<vh::peer::Key32> attest_public_keys{};
    vh::peer::Key32 wrap_public_key{};
    std::vector<vh::peer::Endpoint> endpoints{};
    std::optional<uint32_t> approved_by{};
    std::string compared_by{"person"};
    uint32_t peer_protocol{vh::peer::kPeerProtocol};
    std::string product_version{};
};

class Peers {
public:
    [[nodiscard]] static std::optional<Record> byId(uint32_t id);
    // The live row whose current or announced next key is `spkiHex` (the handshake's lookup); the current key wins.
    [[nodiscard]] static std::optional<Record> liveBySpki(const std::string& spkiHex);
    [[nodiscard]] static std::optional<Record> liveByNodeId(const std::string& nodeId);
    // Whether any row (live or revoked) has `spkiHex` as its key or announced next key: such a key is never a device.
    [[nodiscard]] static bool spkiKnown(const std::string& spkiHex);
    // Every row, revoked ones included, oldest first.
    [[nodiscard]] static std::vector<Record> listAll();
    [[nodiscard]] static std::vector<Record> listLive();
    [[nodiscard]] static std::size_t countLive();

    // ops::Conflict when a live row has this node id or key.
    [[nodiscard]] static Record insert(const NewPeer& p);
    [[nodiscard]] static std::optional<Record> rename(uint32_t id, const std::string& name);
    // Sets revoked_at once (a revoked row keeps its first time). The row, or nullopt when there is none.
    [[nodiscard]] static std::optional<Record> revoke(uint32_t id);
    // Live rows whose id is not in `keep` are revoked; returns how many.
    static std::size_t revokeAllExcept(const std::vector<uint32_t>& keep);

    // What the peer advertised (peer.endpoints), or the endpoint that just worked moved to the front.
    static void setEndpoints(uint32_t id, const std::vector<vh::peer::Endpoint>& endpoints);
    // last_seen_at = now, and the protocol and version the peer said it speaks (peer.hello).
    static void recordHello(uint32_t id, uint32_t peerProtocol, const std::string& productVersion);
    static void touch(uint32_t id);
    // A signed announcement of the peer's next key: stored when `counter` is above the last one accepted and the row
    // is live. False otherwise.
    [[nodiscard]] static bool announceNext(uint32_t id, const std::string& nextSpki, uint64_t counter);
    // The announced key is in use: it becomes the pin. False when `spkiHex` is not the row's next key.
    [[nodiscard]] static bool promoteNext(uint32_t id, const std::string& spkiHex);
};

}
