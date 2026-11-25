#pragma once

#include "device/Crypto.hpp"
#include "peer/Fwd.hpp"

#include <nlohmann/json_fwd.hpp>

#include <array>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Linked servers (design/peers/link.md): another Vaulthalla server this one is paired with. A peer is its own kind of
// principal, in its own table (`peer`, migration 157): never a device, never a user. What a peer session may run is
// the peer wire set alone (protocols::ws::Router); vault roles for peers come with the mirror (identity.md).
namespace vh::peer {

// The peer protocol this build speaks (peer.hello, the card). A peer on another major protocol stays connected and is
// reported incompatible; nothing is guessed across versions.
inline constexpr uint32_t kPeerProtocol = 1;

inline constexpr std::size_t kKeyBytes = 32;
using Key32 = std::array<uint8_t, kKeyBytes>;

// What a server says about itself while pairing, bound into the pairing code (crypto::cardHash): its node id, its name,
// every key-attestation public key it has signed vault keys with (Ed25519, current and retired), the X25519 key vault
// keys for it are wrapped to, the peer protocol and its product version.
struct Card {
    std::string node_id{};
    std::string name{};
    std::vector<Key32> attest_public_keys{};
    Key32 wrap_public_key{};
    uint32_t peer_protocol{kPeerProtocol};
    std::string product_version{};
};

inline constexpr std::size_t kMaxAttestKeys = 64;
inline constexpr std::size_t kMaxEndpoints = 32;

// {node_id, name, attest_public_keys: [base64], wrap_public_key: base64, peer_protocol, product_version}.
[[nodiscard]] nlohmann::json toJson(const Card& card);
// The same, validated (ops::Invalid naming the field): node_id 1-64 printable ASCII; name 1-64 characters without
// control characters (trimmed); at most kMaxAttestKeys distinct 32-byte keys; a 32-byte wrap key; peer_protocol
// 1..65535; product_version at most 64 printable ASCII.
[[nodiscard]] Card cardFromJson(const nlohmann::json& j);

// Where a server's device listener can be reached (a device::endpoints candidate, or what an admin typed).
struct Endpoint {
    std::string host{};
    uint16_t port{};
    std::string kind{"manual"};  // loopback | lan | vpn | wan | passthrough | manual
};
[[nodiscard]] nlohmann::json toJson(const std::vector<Endpoint>& endpoints);
// At most kMaxEndpoints, each {host, port, kind?}: host 1-253 characters with no whitespace, control characters, '/',
// '@' or '?'; port 1-65535. Duplicates (host lowercased, port) are dropped. ops::Invalid otherwise.
[[nodiscard]] std::vector<Endpoint> endpointsFromJson(const nlohmann::json& j);
// "host", "host:port", "[v6]" or "[v6]:port" (the default port when none is given). nullopt when malformed.
[[nodiscard]] std::optional<Endpoint> parseAddress(const std::string& text, uint16_t defaultPort);
[[nodiscard]] std::string toString(const Endpoint& e);

// One `peer` row.
struct Record {
    uint32_t id{};
    std::string node_id{};
    std::string name{};
    std::string spki_sha256{};
    std::optional<std::string> next_spki_sha256{};
    uint64_t rotate_counter{};
    std::vector<Key32> attest_public_keys{};
    Key32 wrap_public_key{};
    std::vector<Endpoint> endpoints{};
    std::string sharing{"identities"};
    std::optional<uint32_t> approved_by{};
    std::string compared_by{"person"};
    uint32_t peer_protocol{kPeerProtocol};
    std::string product_version{};
    std::time_t linked_at{};
    std::optional<std::time_t> last_seen_at{};
    std::optional<std::time_t> revoked_at{};

    [[nodiscard]] bool revoked() const noexcept { return revoked_at.has_value(); }
    [[nodiscard]] std::string shortId() const { return spki_sha256.substr(0, 16); }
};

// {id, node_id, name, spki_sha256, next_spki_sha256, attest_public_keys, wrap_public_key, endpoints, sharing,
//  approved_by, compared_by, peer_protocol, product_version, linked_at, last_seen_at, revoked_at, revoked}: keys base64,
// times Unix seconds or null.
void to_json(nlohmann::json& j, const Record& r);

// Who is on the other end of one peer connection, decided at its TLS handshake: the peer's identity key and the row it
// matched. Both ends of a link hold one (the accepting end from the client certificate, the dialling end from the
// server certificate it pinned).
struct Principal {
    uint32_t peer_id{};  // the `peer` row; 0 on a pairing connection this server dialled (no row yet)
    std::string node_id{};
    std::string name{};
    vh::device::crypto::Hash spki{};
    std::string spki_hex{};
    std::vector<uint8_t> spki_der{};  // verifies the peer's signed rotation announcements
    std::string address{};            // the endpoint dialled (host:port), or the peer's IP when it dialled this server
    bool inbound{false};              // the peer dialled this server
    // A pairing connection this server dialled (peer.link.start): it only reads answers to its own requests, and the
    // router runs nothing it is sent.
    bool pairing{false};

    // The first 16 hex digits of the key: how log lines name a peer.
    [[nodiscard]] std::string shortId() const { return spki_hex.substr(0, 16); }
};

}
