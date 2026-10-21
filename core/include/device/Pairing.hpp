#pragma once

#include "device/Crypto.hpp"
#include "device/Fwd.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// Pairing windows and requests (docs/pairing.md §3), held in memory only. A window lives 10 minutes, a request at
// most 5 minutes past its confirm (and never past its window), and both are only useful to the connections and
// owner that created them, so a restart dropping them costs a Desktop one "start over"; nothing secret (the nonces,
// the code) ever touches disk.
//
// One window at a time, node-wide: a request names no account, so it goes to the open window's owner. A second
// user's open() is refused (conflict) until that window closes or expires; the owner reopening extends it.
//
// This class keeps the protocol's state machine and its limits; ops::devices authorizes the owner side and writes
// the devices row. Errors are ops:: refusals (ws data.code): no_pairing_window, rate_limited (Refused), not_found,
// invalid, conflict.
namespace vh::device {

using PairingClock = std::chrono::system_clock;

inline constexpr std::chrono::minutes kPairingWindowLifetime{10};
inline constexpr std::chrono::minutes kPairingRequestLifetime{5};
inline constexpr std::size_t kMaxRequestsPerWindow = 5;
inline constexpr std::size_t kMaxRequestsPerAddressPerMinute = 10;

enum class RequestState { AwaitingConfirm, Pending, Approving, Approved, Denied, Expired };
[[nodiscard]] std::string to_string(RequestState state);

struct PairingWindow {
    uint32_t owner_id{};
    std::time_t opened_at{};
    std::time_t expires_at{};
};

// What device.pair.request carries (validated by the caller).
struct PairRequestInput {
    std::string name{};
    std::string platform{};
    std::string app_version{};
    crypto::Hash commitment{};
};

struct PairRequestReceipt {
    std::string request_id{};
    crypto::Hash nonce_server{};
    std::time_t expires_at{};
};

// A confirmed request as its window's owner sees it. The real code is never handed out on its own: it is one of the
// three code_choices (random order; the two decoys are fixed per request).
struct PendingRequest {
    std::string request_id{};
    std::string name{};
    std::string platform{};
    std::string app_version{};
    std::string source_ip{};
    std::string device_id{};  // the device key's SPKI hash (hex)
    std::array<std::string, 3> code_choices{};
    std::time_t created_at{};
    std::time_t expires_at{};
};

// An approval in progress: the request is held (Approving) until finishApproval/abortApproval.
struct ApprovalClaim {
    std::string request_id{};
    uint32_t owner_id{};
    std::string device_id{};
    std::string name{};
    std::string platform{};
    std::string app_version{};
    std::string source_ip{};
};

struct RequestStatus {
    RequestState state{};
    std::optional<uint32_t> device_row_id{};  // approved
    std::string device_id{};                  // approved
};

class Pairing {
public:
    using time_point = PairingClock::time_point;

    [[nodiscard]] static Pairing& instance();

    // ---- the owner's side

    // Opens (or, for its own owner, extends) the window. ops::Conflict while another user's window is open.
    PairingWindow open(uint32_t ownerId, time_point now);
    [[nodiscard]] std::optional<PairingWindow> window(time_point now);
    // Closes the open window when `ownerId` owns it, or whoever owns it when `any`; its requests expire. False when
    // there was nothing to close.
    bool close(uint32_t ownerId, bool any, time_point now);
    // The owner's confirmed requests, oldest first.
    [[nodiscard]] std::vector<PendingRequest> pending(uint32_t ownerId, time_point now);
    // Number matching: `code` must be the request's SAS (constant-time compare). Any other code denies the request
    // (ops::Invalid). ops::NotFound for a request that isn't the caller's, isn't pending, or is gone.
    [[nodiscard]] ApprovalClaim beginApproval(uint32_t ownerId, const std::string& requestId, const std::string& code,
                                              time_point now);
    void finishApproval(const std::string& requestId, uint32_t deviceRowId, time_point now);
    // The devices row could not be written: the request is denied (the device starts over).
    void abortApproval(const std::string& requestId, time_point now);
    void deny(uint32_t ownerId, const std::string& requestId, time_point now);

    // ---- the device's side (pairing-only connections; `peer` is the connection's key)

    [[nodiscard]] PairRequestReceipt request(const Peer& peer, const PairRequestInput& input, time_point now);
    // Reveals nonce_device. The commitment must match (else the request is deleted: ops::Invalid); only then is it
    // shown to the owner, with the SAS computed from `serverSpki` (the certificate this daemon presents). Returns the
    // request's new expiry.
    std::time_t confirm(const Peer& peer, const std::string& requestId, const crypto::Hash& nonceDevice,
                        const crypto::Hash& serverSpki, time_point now);
    [[nodiscard]] RequestStatus status(const Peer& peer, const std::string& requestId, time_point now);

    // The SAS of a confirmed request (tests only: the daemon never sends it anywhere).
    [[nodiscard]] std::optional<std::string> codeForTesting(const std::string& requestId);
    void resetForTesting();

private:
    struct Request {
        std::string id{};
        uint32_t owner_id{};
        crypto::Hash device_spki{};
        std::string name{}, platform{}, app_version{}, source_ip{};
        crypto::Hash commitment{}, nonce_server{};
        std::string code{};  // the SAS, once confirmed
        std::array<std::string, 3> choices{};
        RequestState state{RequestState::AwaitingConfirm};
        time_point created_at{}, expires_at{};
    };
    // A finished request, kept for a while so device.pair.status can tell Desktop how it ended.
    struct Outcome {
        crypto::Hash device_spki{};
        RequestState state{};
        std::optional<uint32_t> device_row_id{};
        time_point until{};
    };

    void expireLocked(time_point now);
    void finishLocked(std::map<std::string, Request>::iterator it, RequestState state, std::optional<uint32_t> rowId,
                      time_point now);
    std::map<std::string, Request>::iterator ownedLocked(uint32_t ownerId, const std::string& requestId);

    std::mutex mutex_;
    std::optional<PairingWindow> window_;
    std::map<std::string, Request> requests_;
    std::map<std::string, Outcome> outcomes_;
    std::unordered_map<std::string, std::deque<time_point>> recentByAddress_;
};

}
