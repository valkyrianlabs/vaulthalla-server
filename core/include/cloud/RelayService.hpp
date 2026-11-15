#pragma once

#include "concurrency/AsyncService.hpp"
#include "protocols/device/Listener.hpp"

#include <cstdint>
#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <string>

// The server's end of the Vaulthalla Cloud relay (design/cloud/relay.md, "As built"): one outbound WebSocket to the
// cloud's relay that browser streams arrive on. Nothing runs unless this server is linked, the local switch is on for
// this installation (`vh cloud relay enable`, a super admin), and the device listener is enabled; the account holder
// has a switch at the cloud too (its ticket answers 403 relay_disabled while that is off).
//
// Two threads of its own, never a FUSE, ws or HTTP thread: the service thread decides and makes the blocking calls (the
// signed POST /v1/relay/server-tickets, at connect and at each renewal midpoint), and an I/O thread runs the socket:
// TICKET, CHALLENGE, PROOF (the installation key), WELCOME, then per stream OPEN (the browser ticket re-checked: the
// ticket keys from the latest ticket answer, this link's account and deployment, jti once), a local socketpair handed
// to the device listener (protocols/device/Listener.hpp, startRelayedConnection), DATA and CREDIT within the
// relay's window, and CLOSE. Reconnects back off from 1 s to 5 min with full jitter; 401 or 404 on a ticket stops it
// until the switch is toggled or the link changes. Its status never claims more than it saw: `connected` only after
// WELCOME, and only until the socket ends.
namespace vh::cloud {

struct RelayStatus {
    // off: the local switch is off; not_linked; listener_off (device_server.enabled is false); connecting; connected;
    // backoff (retrying after a failure); waiting (the cloud refused for a reason that may clear: off at the cloud, no
    // entitlement, no relay configured; retried every 5 minutes); stopped (the cloud no longer knows this installation,
    // or refused it for good: toggle the switch to try again).
    std::string state{"off"};
    bool enabled = false;  // the local switch, for this installation
    std::optional<std::string> enabled_by{};
    std::optional<std::time_t> enabled_at{};
    std::optional<std::string> relay_url{};
    std::optional<std::time_t> connected_since{};
    std::optional<std::time_t> renew_by{};
    std::optional<std::time_t> last_ticket_at{};
    std::optional<std::time_t> next_attempt_at{};
    std::optional<std::string> last_error{};
    unsigned streams = 0;             // open now
    uint64_t streams_accepted = 0;    // since the daemon started
    uint64_t streams_refused = 0;
};

class RelayService final : public concurrency::AsyncService {
public:
    // How a stream reaches the device listener: the process's DeviceServer by default.
    using Acceptor = std::function<bool(int fd, protocols::device::RelayedOrigin origin)>;

    RelayService();
    ~RelayService() override;

    [[nodiscard]] RelayStatus snapshot() const;
    // The switch or the link changed: look again now. `reset`: the switch was turned on, so a service stopped by the
    // cloud's refusal tries again, without backoff.
    void wake(bool reset = false);

    // Tests: hand streams to `acceptor` instead of the process's DeviceServer.
    void setAcceptorForTesting(Acceptor acceptor);

    struct Impl;

protected:
    void runLoop() override;
    void onStop() override;

private:
    std::shared_ptr<Impl> impl_;
};

// The live service, for ops::cloud_relay (the latest one constructed, cleared by its destructor): its snapshot, or
// nullopt when there is none; wakeRelay() does nothing then.
[[nodiscard]] std::optional<RelayStatus> relaySnapshot();
void wakeRelay(bool reset = false);

}
