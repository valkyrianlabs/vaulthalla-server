#pragma once

#include "device/Pairing.hpp"
#include "peer/Crypto.hpp"
#include "peer/Peer.hpp"

#include <array>
#include <chrono>
#include <ctime>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// Link requests on the server that opened a window (design/peers/link.md, "Pairing", steps 1 and 3 to 7), held in
// memory only like device pairing's: a request lives at most 5 minutes past its confirm and never past its window,
// nothing secret (nonces, codes) touches disk, and a restart only makes the other server start over.
//
// The window itself is device::Pairing's (WindowKind::Peer): one window at a time, node-wide, for devices or a server.
// A request goes to the window's owner, who picks the code the dialling server shows among three choices; the
// limits per window and per address are device pairing's. ops::peers authorizes the owner's side and writes the `peer`
// row. Errors are ops:: refusals: no_pairing_window, rate_limited (Refused), not_found, invalid, conflict.
namespace vh::peer {

using PairingClock = vh::device::PairingClock;

struct LinkRequestInput {
    Card card{};               // the dialling server's card (validated)
    crypto::Hash commitment{};
};

struct LinkRequestReceipt {
    std::string request_id{};
    crypto::Hash nonce_b{};
    Card card{};               // this server's card, as bound into the code
    std::time_t expires_at{};
};

// A confirmed request as the window's owner sees it: the real code only ever as one of three code_choices.
struct PendingLink {
    std::string request_id{};
    std::string node_id{};
    std::string name{};
    std::string product_version{};
    uint32_t peer_protocol{};
    std::string spki_sha256{};  // the dialling server's key (its fingerprint)
    std::string source_ip{};
    std::array<std::string, 3> code_choices{};
    std::time_t created_at{};
    std::time_t expires_at{};
};

// An approval in progress (Approving until finish/abort).
struct LinkClaim {
    std::string request_id{};
    uint32_t owner_id{};
    std::string spki_sha256{};
    Card card{};
    std::string source_ip{};
};

struct LinkRequestStatus {
    vh::device::RequestState state{};
    std::optional<uint32_t> peer_row_id{};
};

class Pairing {
public:
    using time_point = PairingClock::time_point;

    [[nodiscard]] static Pairing& instance();

    // ---- the window owner's side

    [[nodiscard]] std::vector<PendingLink> pending(uint32_t ownerId, time_point now);
    // Number matching, and with `expectSpki` (the brokered path) the requesting key must be that one: either mismatch
    // denies the request (ops::Invalid). ops::NotFound for a request that isn't the owner's, pending, or there.
    [[nodiscard]] LinkClaim check(uint32_t ownerId, const std::string& requestId, const std::string& code,
                                  const std::optional<std::string>& expectSpki, time_point now);
    // check(), then holds the request (Approving) while ops::peers writes the row.
    [[nodiscard]] LinkClaim begin(uint32_t ownerId, const std::string& requestId, const std::string& code,
                                  const std::optional<std::string>& expectSpki, time_point now);
    void finish(const std::string& requestId, uint32_t peerRowId, time_point now);
    void abort(const std::string& requestId, time_point now);
    void deny(uint32_t ownerId, const std::string& requestId, time_point now);

    // ---- the dialling server's side (a pairing-only connection; `connection` is its key)

    [[nodiscard]] LinkRequestReceipt request(const vh::device::Peer& connection, const LinkRequestInput& input,
                                             const Card& own, time_point now);
    // Reveals nonce_a; the commitment must match (else the request is deleted: ops::Invalid). Only then is it shown to
    // the owner, with the code computed against `serverSpki` (the certificate this daemon presents). Returns its
    // new expiry.
    std::time_t confirm(const vh::device::Peer& connection, const std::string& requestId, const crypto::Hash& nonceA,
                        const crypto::Hash& serverSpki, time_point now);
    [[nodiscard]] LinkRequestStatus status(const vh::device::Peer& connection, const std::string& requestId,
                                           time_point now);

    // Drops every request in flight (a server identity rotation: they were bound to the old key).
    std::size_t abandonAll();

    [[nodiscard]] std::optional<std::string> codeForTesting(const std::string& requestId);
    void resetForTesting();

private:
    struct Request {
        std::string id{};
        uint32_t owner_id{};
        crypto::Hash spki{};
        Card card{}, own{};
        crypto::Hash commitment{}, nonce_b{};
        std::string source_ip{};
        std::string code{};
        std::array<std::string, 3> choices{};
        vh::device::RequestState state{vh::device::RequestState::AwaitingConfirm};
        time_point created_at{}, expires_at{};
    };
    struct Outcome {
        crypto::Hash spki{};
        vh::device::RequestState state{};
        std::optional<uint32_t> row{};
        time_point until{};
    };

    void expireLocked(const std::optional<vh::device::PairingWindow>& window, time_point now);
    void finishLocked(std::map<std::string, Request>::iterator it, vh::device::RequestState state,
                      std::optional<uint32_t> row, time_point now);
    [[nodiscard]] LinkClaim checkLocked(uint32_t ownerId, const std::string& requestId, const std::string& code,
                                        const std::optional<std::string>& expectSpki, time_point now);

    std::mutex mutex_;
    std::map<std::string, Request> requests_;
    std::map<std::string, Outcome> outcomes_;
    std::unordered_map<std::string, std::deque<time_point>> recentByAddress_;
};

}
