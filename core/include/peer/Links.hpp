#pragma once

#include "concurrency/AsyncService.hpp"
#include "device/Fwd.hpp"
#include "peer/Peer.hpp"
#include "peer/Transfers.hpp"
#include "protocols/ws/Fwd.hpp"

#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace boost::asio { class io_context; }
namespace boost::asio::ssl { class context; }

// The server link (design/peers/link.md, "The connection"): one persistent, mutually authenticated websocket per pair
// of linked servers, carrying requests and answers both ways. Either side dials (endpoints last good first); when both
// connect at once the connection dialled by the lower node id is kept. Each end sends peer.hello (protocol and
// version), then peer.endpoints (where it can be reached), and peer.ping every 30 s; three missed pings end the
// connection, and it is dialled again with capped, jittered backoff. The accepting end is the device listener (a
// linked server's key makes a Peer session there); the dialling end presents this server's identity certificate and
// pins the peer's key (protocols::device::makeClientContext, protocols::ws::client::dial).
//
// Pairing's dialling side (peer.link.start) runs here too, one thread per attempt: dial (pinned with expect_spki,
// else trust on first use), peer.pair.request / confirm, show the code, poll peer.pair.status, and on approval write
// the `peer` row.
//
// Bulk data (design/peers/mirror.md "Contents") goes over separate connections to the same listener with the same pins
// (peer::object, the sealed lane), within this service's per-peer transfer slots (Transfers).
//
// Gate: while peers.experimental is off nothing dials, no attempt starts, and every connection closes. "PeerLinks"
// in runtime::Manager, started after the device listener.
namespace vh::peer {

using RequestType = boost::beast::http::request<boost::beast::http::string_body>;

inline constexpr std::chrono::seconds kPingInterval{30};
inline constexpr std::chrono::seconds kPingTimeout{10};
inline constexpr int kMaxMissedPings = 3;
inline constexpr std::chrono::seconds kBackoffFloor{1};
inline constexpr std::chrono::minutes kBackoffCap{2};
inline constexpr std::chrono::seconds kRequestTimeout{15};

// A link's state as peer.list reports it. Nothing is claimed that wasn't seen: connected only after peer.hello
// answered, and only until the socket ends.
struct Health {
    bool connected{false};
    std::optional<std::time_t> since{};
    std::optional<std::string> dialed_by{};  // "this_server" | "peer"
    std::optional<std::string> address{};
    std::optional<int64_t> rtt_ms{};
    std::optional<uint32_t> peer_protocol{};
    std::optional<std::string> peer_version{};
    std::optional<bool> protocol_compatible{};
    std::optional<std::string> last_error{};
    std::optional<std::time_t> last_error_at{};
    std::optional<std::time_t> next_attempt_at{};
};
[[nodiscard]] nlohmann::json toJson(const Health& h);

// One peer.link.start, as peer.link.status reports it.
struct LinkAttempt {
    std::string id{};
    uint32_t owner_id{};
    // connecting | awaiting_approval | linked | denied | expired | failed | cancelled
    std::string state{"connecting"};
    std::optional<std::string> code{};      // once both nonces are known: what this side shows
    std::optional<Card> peer_card{};
    std::string peer_spki_sha256{};
    std::optional<uint32_t> peer_id{};      // linked: the row written here
    std::optional<std::string> expect_spki{};
    // Who compares the code (person | desktop): from the channel of the peer.link.start call; the row gets it.
    std::string compared_by{"person"};
    std::string address{};                  // the endpoint that answered
    std::string error{};
    std::time_t created_at{}, updated_at{};
    [[nodiscard]] bool finished() const noexcept {
        return state != "connecting" && state != "awaiting_approval";
    }
};
[[nodiscard]] nlohmann::json toJson(const LinkAttempt& a);

class LinkService final : public concurrency::AsyncService {
public:
    LinkService();
    ~LinkService() override;

    // ---- the accepting end (protocols::device::Listener)

    // A linked server's key on the device listener's /ws: runs the Peer session, which holds the listener's
    // connection slot until it ends.
    void acceptInbound(std::shared_ptr<protocols::ws::TlsTransport> transport, const RequestType& request,
                       std::shared_ptr<const Principal> principal, std::unique_ptr<protocols::ws::ConnectionSlot> slot);

    // ---- the wire (the peer.* handlers, on a Peer session)

    // peer.hello: checks the other server is the row's, records what it speaks, keeps this connection (the tie-break)
    // and answers with this server's hello.
    [[nodiscard]] nlohmann::json helloReceived(const std::shared_ptr<protocols::ws::Session>& session,
                                               const nlohmann::json& payload);
    // peer.endpoints: stores what the other server advertised and answers this server's advertisement.
    [[nodiscard]] nlohmann::json endpointsReceived(const std::shared_ptr<protocols::ws::Session>& session,
                                                   const nlohmann::json& payload);
    // This server's own peer.hello payload and advertisement.
    [[nodiscard]] static nlohmann::json ownHello();
    [[nodiscard]] static nlohmann::json ownEndpoints();

    // ---- management

    [[nodiscard]] Health health(uint32_t peerId) const;
    // Closes the peer's connections now. With `notifyUnlinked`, sends peer.unlinked on each first (best effort: a
    // revoked key is refused at the handshake whether or not the notice arrives). Returns how many closed.
    // `spare` (the session handling the command that asked) closes once its reply is out instead.
    std::size_t disconnect(uint32_t peerId, bool notifyUnlinked, const protocols::ws::Session* spare = nullptr);
    // Every link connection, either end (identity rotation, the switch turned off, shutdown).
    std::size_t disconnectAll();
    // A row changed (linked, endpoints): look again now instead of at the next tick.
    void wake();

    // A request to a linked server over its kept connection (after peer.hello), waiting at most `timeout` for the
    // answer frame ({status, data, error}). For threads that may block: never this service's io threads, which deliver
    // the answer. nullopt when not connected, when the connection ended, or when no answer came in time.
    [[nodiscard]] std::optional<nlohmann::json> request(uint32_t peerId, const std::string& command,
                                                        nlohmann::json payload,
                                                        std::chrono::milliseconds timeout = kRequestTimeout);

    // peer.link.start: returns the attempt's id at once; the attempt runs on a thread of its own. `comparedBy`
    // (person | desktop) is who compares the code, from the starting call's channel; the row written here gets it.
    [[nodiscard]] std::string startLink(uint32_t ownerId, std::vector<Endpoint> endpoints,
                                        std::optional<std::string> expectSpki, std::string comparedBy);
    [[nodiscard]] std::optional<LinkAttempt> attempt(const std::string& id) const;
    // Stops an attempt that has not finished; false when there is none to stop.
    bool cancelLink(const std::string& id);

    // `vh secret device-identity rotate`: announces `nextSpki` to every connected peer, signed by `current` (the key
    // in use), with `counter` (the identity version it will be). Returns the peer rows that stored it; every other
    // link is revoked in the rotation's switch transaction.
    [[nodiscard]] std::vector<uint32_t> announceRotation(const vh::device::ServerIdentity& current,
                                                         const vh::device::crypto::Hash& nextSpki, uint64_t counter);

    // The client TLS context every connection this server dials to a linked server uses (the link's websocket, the
    // sealed lane): this server's identity certificate, TLS 1.3, no trust store (each connection checks its pin). A
    // rotated identity gets a new context; open connections keep the one they started with.
    [[nodiscard]] std::shared_ptr<boost::asio::ssl::context> clientTls();

    // Bulk transfers to linked servers (the sealed lane's fetches): slots per peer, and the threads they run on,
    // stopped and joined when this service stops.
    [[nodiscard]] Transfers& transfers() noexcept { return transfers_; }

    // ---- requests on a link (the server mirror's data plane: mirror::follow)

    struct Answer {
        bool ok{false};
        nlohmann::json data{};   // the answer's data (an object)
        std::string code{};      // a refusal's data.code
        std::string error{};     // a refusal's text
    };
    // Whether the peer's link is up (peer.hello answered).
    [[nodiscard]] bool connected(uint32_t peerId) const;
    // Sends `command` on the peer's link and waits at most `timeout` for its answer: nullopt when there is no link (or
    // it ended, or nothing came in time). Blocks the caller: never call it on an io thread or a request handler.
    [[nodiscard]] std::optional<Answer> request(uint32_t peerId, const std::string& command, nlohmann::json payload,
                                                std::chrono::milliseconds timeout = kRequestTimeout);
    // Sends a notice on the peer's link and does not wait for (or read) its answer. False without a link.
    bool notify(uint32_t peerId, const std::string& command, nlohmann::json payload);

    // Tests: dials started since construction (invariant 6: none without peer rows).
    [[nodiscard]] std::size_t dialsStarted() const noexcept { return dials_.load(std::memory_order_relaxed); }
    // Tests: one pass of the run loop (dial what needs dialling, ping, time out), without the thread.
    void tickForTesting();

    struct Connection;
    struct Rpc;

protected:
    void runLoop() override;
    void onStop() override;

private:
    struct PeerState {
        std::shared_ptr<Connection> active;
        bool dialing{false};
        unsigned attempt{0};
        std::chrono::steady_clock::time_point next_attempt{};
        std::optional<std::time_t> next_attempt_wall{};
        std::optional<std::string> last_error{};
        std::optional<std::time_t> last_error_at{};
        std::chrono::steady_clock::time_point last_audit{};
    };

    void ensureIo();
    void shutdown() noexcept;
    void tick();
    // Test instances only (paths::testMode): a sealed-lane fetch the Tier B drill asks for through a file
    // (VH_TEST_FAULT_DIR/peer-object-fetch.json), run with the real client; never in a packaged daemon.
    void pollTestFetch();
    void dialPeer(const Record& row);
    void onDialed(uint32_t peerId, std::shared_ptr<protocols::ws::TlsTransport> transport, std::string address,
                  std::shared_ptr<const Principal> principal);
    void dialFailed(uint32_t peerId, const std::string& why);
    std::shared_ptr<Connection> track(std::shared_ptr<protocols::ws::Session> session,
                                      std::shared_ptr<const Principal> principal, std::shared_ptr<Rpc> rpc);
    // The tie-break: keeps `conn` for its peer (true) or closes it (false).
    bool adopt(const std::shared_ptr<Connection>& conn);
    void connectionClosed(const std::shared_ptr<Connection>& conn);
    void auditConnection(uint32_t peerId, const std::string& nodeId, bool up, const std::string& detail);
    void ping(const std::shared_ptr<Connection>& conn);
    void runAttempt(const std::string& id, std::vector<Endpoint> endpoints);
    void updateAttempt(const std::string& id, const std::function<void(LinkAttempt&)>& change);
    bool attemptCancelled(const std::string& id) const;

    mutable std::mutex mutex_;
    std::map<uint32_t, PeerState> peers_;
    std::vector<std::shared_ptr<Connection>> connections_;  // every live one, kept or still saying hello
    std::shared_ptr<boost::asio::io_context> ioc_;
    std::vector<std::thread> ioThreads_;
    std::shared_ptr<protocols::ws::Router> router_;
    std::shared_ptr<boost::asio::ssl::context> clientTls_;
    std::string clientTlsSpki_;
    std::vector<std::shared_ptr<boost::asio::ssl::context>> retiredClientTls_;  // borrowed by open connections
    std::chrono::steady_clock::time_point lastRowLoad_{};
    std::vector<Record> rows_;
    bool wakeRequested_{false};

    mutable std::mutex attemptsMutex_;
    std::condition_variable attemptsCv_;
    std::map<std::string, LinkAttempt> attempts_;
    std::map<std::string, bool> cancelled_;
    std::vector<std::thread> attemptThreads_;
    bool stopping_{false};

    std::atomic<std::size_t> dials_{0};

    Transfers transfers_;
};

// The process's service (runtime::Manager's), or null before it exists.
[[nodiscard]] std::shared_ptr<LinkService> linkService();

}
