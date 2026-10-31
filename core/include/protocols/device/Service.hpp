#pragma once

#include "concurrency/AsyncService.hpp"
#include "device/Fwd.hpp"
#include "protocols/device/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace boost::asio { class io_context; }
namespace boost::asio::ssl { class context; }

namespace vh::protocols::device {

// What `vh device remote status` and ws device.remote.status report.
struct ListenerStatus {
    bool enabled = false;      // device_server.enabled
    bool remote = false;       // device_server.remote: every interface, else loopback only
    uint16_t port = 0;         // configured port
    bool listening = false;
    std::string address{};     // the first address it listens on ("[::]:36972", "127.0.0.1:36972"), empty when not
    std::vector<std::string> bind{};  // every address it listens on, same format
    uint16_t bound_port = 0;   // the port it listens on (differs from `port` only when that is 0), 0 when not
    bool ipv6 = false;         // an IPv6 socket is among them (IPv6 clients can connect)
    std::optional<std::string> error{};  // why it is not listening where configured (e.g. the port is taken)
    std::string server_spki_sha256{};    // the pin Desktop records; empty until the identity is loaded
    unsigned int connections = 0;
};

// The "DeviceServer" runtime service (started after ProtocolService): loads the server identity (generating and
// sealing it on first start), runs its own io_context and keeps the listener bound where device_server says:
// remote on, `[::]` dual-stack, falling back to `0.0.0.0` where IPv6 is unavailable; remote off, `127.0.0.1` and
// also `[::1]` when that binds (transfer-protocol.md §1.4).
// A bind failure (port in use) never stops the daemon: it is reported in the status and retried every 30 seconds.
// applyConfig() rebinds at once (remote connections on/off) without touching the other listeners; turning remote
// off also closes the device sessions that came from another host.
class Service final : public concurrency::AsyncService {
public:
    Service();
    ~Service() override;

    [[nodiscard]] ListenerStatus listenerStatus() const;
    // Rebinds to the configured endpoint now. Returns the status after.
    ListenerStatus applyConfig();

    // Tests: use this identity instead of unsealing (or generating and sealing) the daemon's.
    void setIdentityForTesting(std::shared_ptr<const vh::device::ServerIdentity> identity);

protected:
    void runLoop() override;
    void onStop() override;

private:
    void ensureIdentityLocked();
    void bindLocked(bool logFailure);
    void shutdown() noexcept;

    mutable std::mutex mutex_;
    std::shared_ptr<const vh::device::ServerIdentity> identity_;
    std::shared_ptr<boost::asio::ssl::context> tls_;
    std::shared_ptr<boost::asio::io_context> ioc_;
    std::vector<std::thread> threads_;
    std::shared_ptr<ws::Router> router_;
    std::shared_ptr<Listener> listener_;
    std::vector<std::string> bound_;  // "host:port" per listening socket, empty when not listening
    bool boundIpv6_ = false;
    uint16_t boundPort_ = 0;
    bool boundRemote_ = false;
    std::optional<std::string> error_;
};

// Device-listener sessions, closed at once (safe from any thread). Revocation closes one device's; turning remote
// connections off closes those that did not come from loopback; stopping the listener closes all of them.
// Each returns how many it closed.
// `spare`: a connection left open (the device revoking itself closes after its reply, Session::closeAfterReply).
std::size_t closeDeviceSessions(uint32_t deviceRowId, const vh::device::Peer* spare = nullptr);
std::size_t closeRemoteDeviceSessions();
std::size_t closeAllDeviceListenerSessions();

}
