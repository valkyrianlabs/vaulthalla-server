#include "peer/Links.hpp"

#include "audit/Trail.hpp"
#include "concurrency/Backoff.hpp"
#include "config/Registry.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/peer/Peer.hpp"
#include "device/Crypto.hpp"
#include "device/ServerIdentity.hpp"
#include "fs/ops/file.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "peer/Crypto.hpp"
#include "peer/Keys.hpp"
#include "peer/ObjectClient.hpp"
#include "protocols/SessionLifetimes.hpp"
#include "protocols/device/Endpoints.hpp"
#include "protocols/device/Listener.hpp"
#include "protocols/device/PeerObject.hpp"
#include "protocols/ws/Client.hpp"
#include "protocols/ws/ConnectionLimit.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/TlsTransport.hpp"
#include "runtime/Manager.hpp"

#include <paths.h>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>

#include <fmt/format.h>
#include <openssl/x509.h>

#include <version.h>

#include <algorithm>
#include <filesystem>
#include <future>
#include <set>

namespace vh::peer {

namespace {

using json = nlohmann::json;
using SteadyClock = std::chrono::steady_clock;
namespace dc = vh::device::crypto;

constexpr auto kTick = std::chrono::seconds(1);
constexpr auto kRowReload = std::chrono::seconds(10);
constexpr auto kTouchEvery = std::chrono::minutes(5);
constexpr auto kAuditEvery = std::chrono::minutes(1);
constexpr auto kStatusPoll = std::chrono::seconds(2);
// How long a dialling attempt waits for the other server's approval: a window lives 10 minutes.
constexpr auto kAttemptLifetime = std::chrono::minutes(11);
constexpr unsigned kIoThreads = 2;

std::time_t wallNow() { return std::time(nullptr); }

bool experimental() { return config::Registry::get().peers.experimental; }

std::string errorText(const json& answer) {
    if (const auto e = answer.find("error"); e != answer.end() && e->is_string()) return e->get<std::string>();
    return answer.value("status", std::string("ERROR"));
}

std::string errorCode(const json& answer) {
    if (const auto d = answer.find("data"); d != answer.end() && d->is_object())
        if (const auto c = d->find("code"); c != d->end() && c->is_string()) return c->get<std::string>();
    return {};
}

bool answeredOk(const std::optional<json>& answer) { return answer && answer->value("status", "") == "OK"; }

json dataOf(const json& answer) {
    if (const auto d = answer.find("data"); d != answer.end() && d->is_object()) return *d;
    return json::object();
}

}

// ---- answers this end waits for -----------------------------------------------------------------------------------

struct LinkService::Rpc {
    using Done = std::function<void(std::optional<json>)>;
    struct Pending {
        SteadyClock::time_point deadline;
        Done done;
    };

    std::mutex mutex;
    std::map<std::string, Pending> pending;
    uint64_t counter = 0;
    bool closed = false;

    // Sends {command, payload, requestId}; `done` runs once: with the answer, or nullopt (timed out, connection gone).
    std::string call(protocols::ws::Session& session, const std::string& command, json payload,
                     const std::chrono::milliseconds timeout, Done done) {
        std::string id;
        {
            std::scoped_lock lock(mutex);
            if (!closed) {
                id = "p" + std::to_string(++counter);
                pending.emplace(id, Pending{SteadyClock::now() + timeout, std::move(done)});
            }
        }
        if (id.empty()) {
            done(std::nullopt);
            return id;
        }
        session.send(json{{"command", command}, {"payload", std::move(payload)}, {"requestId", id}});
        return id;
    }

    bool onResponse(const json& frame) {
        const auto rid = frame.find("requestId");
        if (rid == frame.end() || !rid->is_string()) return false;
        Done done;
        {
            std::scoped_lock lock(mutex);
            const auto it = pending.find(rid->get<std::string>());
            if (it == pending.end()) return false;
            done = std::move(it->second.done);
            pending.erase(it);
        }
        done(std::optional<json>(std::in_place, frame));
        return true;
    }

    void forget(const std::string& id) {
        std::scoped_lock lock(mutex);
        pending.erase(id);
    }

    void sweep(const SteadyClock::time_point now) {
        std::vector<Done> expired;
        {
            std::scoped_lock lock(mutex);
            for (auto it = pending.begin(); it != pending.end();) {
                if (it->second.deadline > now) {
                    ++it;
                    continue;
                }
                expired.push_back(std::move(it->second.done));
                it = pending.erase(it);
            }
        }
        for (auto& d : expired) d(std::nullopt);
    }

    void failAll() {
        std::map<std::string, Pending> all;
        {
            std::scoped_lock lock(mutex);
            closed = true;
            all.swap(pending);
        }
        for (auto& [_, p] : all) p.done(std::nullopt);
    }
};

namespace {

// Waits for one answer (threads that may block: a pairing attempt, a rotation's announcement).
std::optional<json> callAndWait(LinkService::Rpc& rpc, protocols::ws::Session& session, const std::string& command,
                                json payload, const std::chrono::milliseconds timeout) {
    auto promise = std::make_shared<std::promise<std::optional<json>>>();
    auto future = promise->get_future();
    const auto id = rpc.call(session, command, std::move(payload), timeout,
                             [promise](std::optional<json> answer) { promise->set_value(std::move(answer)); });
    if (future.wait_for(timeout + std::chrono::seconds(1)) != std::future_status::ready) {
        rpc.forget(id);
        return std::nullopt;
    }
    return future.get();
}

}

// ---- one connection -------------------------------------------------------------------------------------------------

struct LinkService::Connection {
    std::shared_ptr<protocols::ws::Session> session;
    std::shared_ptr<Rpc> rpc;
    std::shared_ptr<const Principal> principal;
    std::string dialed_by;  // the node id that dialled it
    std::time_t opened_wall{wallNow()};
    bool hello{false};
    bool closed{false};
    uint32_t peer_protocol{0};
    std::string peer_version{};
    std::optional<int64_t> rtt_ms{};
    int missed{0};
    bool ping_in_flight{false};
    SteadyClock::time_point last_ping{SteadyClock::now()};
    SteadyClock::time_point last_touch{};
};

json toJson(const Health& h) {
    const auto opt = [](const auto& v) { return v ? json(*v) : json(nullptr); };
    return {{"connected", h.connected},
            {"since", h.since ? json(static_cast<int64_t>(*h.since)) : json(nullptr)},
            {"dialed_by", opt(h.dialed_by)},
            {"address", opt(h.address)},
            {"rtt_ms", opt(h.rtt_ms)},
            {"peer_protocol", opt(h.peer_protocol)},
            {"peer_version", opt(h.peer_version)},
            {"protocol_compatible", opt(h.protocol_compatible)},
            {"last_error", opt(h.last_error)},
            {"last_error_at", h.last_error_at ? json(static_cast<int64_t>(*h.last_error_at)) : json(nullptr)},
            {"next_attempt_at", h.next_attempt_at ? json(static_cast<int64_t>(*h.next_attempt_at)) : json(nullptr)}};
}

json toJson(const LinkAttempt& a) {
    json peer = nullptr;
    if (a.peer_card)
        peer = {{"node_id", a.peer_card->node_id}, {"name", a.peer_card->name},
                {"product_version", a.peer_card->product_version}, {"spki_sha256", a.peer_spki_sha256}};
    return {{"link_id", a.id},
            {"state", a.state},
            {"code", a.code ? json(*a.code) : json(nullptr)},
            {"peer", std::move(peer)},
            {"peer_id", a.peer_id ? json(*a.peer_id) : json(nullptr)},
            {"expect_spki", a.expect_spki ? json(*a.expect_spki) : json(nullptr)},
            {"address", a.address.empty() ? json(nullptr) : json(a.address)},
            {"error", a.error.empty() ? json(nullptr) : json(a.error)},
            {"created_at", static_cast<int64_t>(a.created_at)},
            {"updated_at", static_cast<int64_t>(a.updated_at)}};
}

// ---- the service ----------------------------------------------------------------------------------------------------

LinkService::LinkService() : AsyncService("PeerLinks") {}

LinkService::~LinkService() {
    stop();
    shutdown();
}

void LinkService::shutdown() noexcept {
    try {
        // Transfers first: each stops within its client's cancellation slice, and holds no lock of this service.
        transfers_.shutdown();
        {
            std::scoped_lock lock(attemptsMutex_);
            stopping_ = true;
        }
        attemptsCv_.notify_all();
        std::vector<std::thread> attempts;
        {
            std::scoped_lock lock(attemptsMutex_);
            attempts.swap(attemptThreads_);
        }
        for (auto& t : attempts)
            if (t.joinable()) t.join();
        (void)disconnectAll();
        std::shared_ptr<boost::asio::io_context> ioc;
        std::vector<std::thread> threads;
        {
            std::scoped_lock lock(mutex_);
            ioc = std::move(ioc_);
            threads.swap(ioThreads_);
        }
        if (!ioc) return;
        // The close frames get a moment to go out, then the io threads end.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        ioc->stop();
        for (auto& t : threads)
            if (t.joinable()) t.join();
        // Closed sessions can stay cached in the session manager with sockets on this context.
        if (protocols::ws::Session::liveCount() > 0) protocols::retainForProcessLifetime(std::move(ioc));
    } catch (const std::exception& e) {
        log::Registry::runtime()->error("[PeerLinks] Shutdown failed: {}", e.what());
    }
}

std::shared_ptr<LinkService> linkService() { return runtime::Manager::instance().getPeerLinkService(); }

void LinkService::ensureIo() {
    std::scoped_lock lock(mutex_);
    if (!router_) {
        router_ = std::make_shared<protocols::ws::Router>();
        protocols::ws::Handler::registerAllHandlers(router_);
    }
    if (ioc_) return;
    ioc_ = std::make_shared<boost::asio::io_context>();
    auto guard = std::make_shared<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(
        boost::asio::make_work_guard(*ioc_));
    for (unsigned i = 0; i < kIoThreads; ++i)
        ioThreads_.emplace_back([ctx = ioc_, guard] {
            for (;;) {
                try {
                    ctx->run();
                    return;
                } catch (const std::exception& e) {
                    log::Registry::runtime()->error("[PeerLinks] Unhandled exception in a handler: {}", e.what());
                }
            }
        });
}

std::shared_ptr<boost::asio::ssl::context> LinkService::clientTls() {
    const auto identity = vh::device::currentServerIdentity();
    if (!identity) throw std::runtime_error("the device listener has no server identity yet");
    std::scoped_lock lock(mutex_);
    // A rotated identity: new connections present the new certificate; open ones keep borrowing the old context.
    if (!clientTls_ || clientTlsSpki_ != identity->spkiHex()) {
        if (clientTls_) retiredClientTls_.push_back(clientTls_);
        clientTls_ = protocols::device::makeClientContext(*identity);
        clientTlsSpki_ = identity->spkiHex();
    }
    return clientTls_;
}

void LinkService::runLoop() {
    {
        std::scoped_lock lock(attemptsMutex_);
        stopping_ = false;
    }
    transfers_.resume();
    while (!shouldStop()) {
        try {
            tick();
        } catch (const std::exception& e) {
            log::Registry::runtime()->warn("[PeerLinks] {}", e.what());
        }
        std::unique_lock lock(mutex_);
        if (wakeRequested_) {
            wakeRequested_ = false;
            continue;
        }
        lock.unlock();
        lazySleep(kTick);
    }
    shutdown();
}

void LinkService::onStop() {}

void LinkService::wake() {
    std::scoped_lock lock(mutex_);
    wakeRequested_ = true;
    lastRowLoad_ = {};
}

void LinkService::tickForTesting() { tick(); }

void LinkService::tick() {
    if (!experimental()) {
        // The switch is off: nothing dials, and no link stays up.
        bool any = false;
        {
            std::scoped_lock lock(mutex_);
            any = !connections_.empty();
        }
        if (any) (void)disconnectAll();
        return;
    }
    const auto now = SteadyClock::now();
    bool reload = false;
    {
        std::scoped_lock lock(mutex_);
        reload = now - lastRowLoad_ >= kRowReload;
    }
    if (reload) {
        auto rows = db::query::peer::Peers::listLive();
        std::scoped_lock lock(mutex_);
        rows_ = std::move(rows);
        lastRowLoad_ = now;
    }

    std::vector<Record> toDial;
    std::vector<std::shared_ptr<Connection>> toPing, stale;
    std::vector<std::shared_ptr<Rpc>> rpcs;
    {
        std::scoped_lock lock(mutex_);
        std::set<uint32_t> live;
        for (const auto& row : rows_) {
            live.insert(row.id);
            auto& st = peers_[row.id];
            const bool connecting = std::ranges::any_of(connections_, [&](const auto& c) {
                return !c->closed && c->principal && c->principal->peer_id == row.id;
            });
            if (!st.active && !st.dialing && !connecting && now >= st.next_attempt) {
                st.dialing = true;
                toDial.push_back(row);
            }
        }
        for (const auto& c : connections_) {
            if (c->closed || !c->principal) continue;
            if (!c->principal->pairing && !live.contains(c->principal->peer_id)) stale.push_back(c);
            else if (c->hello && !c->ping_in_flight && now - c->last_ping >= kPingInterval) toPing.push_back(c);
            rpcs.push_back(c->rpc);
        }
        for (auto it = peers_.begin(); it != peers_.end();)
            it = live.contains(it->first) || it->second.dialing ? std::next(it) : peers_.erase(it);
    }
    for (const auto& r : rpcs) r->sweep(now);
    for (const auto& c : stale) c->session->close();  // unlinked meanwhile (by another process or a row edit)
    for (const auto& c : toPing) ping(c);
    for (const auto& row : toDial) dialPeer(row);
    if (paths::testMode) pollTestFetch();
}

// The Tier B drill's request (tools/harness/vhh/drill_peers.py, test instances only): fetch one generation from a linked
// server with the real client, optionally broken off after `interrupt_at` bytes and resumed, into a file next to the
// request, and report what came back. Sealed bytes only: nothing is opened with a key.
void LinkService::pollTestFetch() {
    const char* dir = std::getenv("VH_TEST_FAULT_DIR");
    if (!dir) return;
    const std::filesystem::path base(dir);
    const auto request = base / "peer-object-fetch.json";
    const auto taken = base / "peer-object-fetch.taken";
    std::error_code ec;
    if (!std::filesystem::exists(request, ec)) return;
    std::filesystem::remove(taken, ec);
    std::filesystem::rename(request, taken, ec);
    if (ec) return;
    json ask;
    try {
        ask = json::parse(vh::fs::ops::readFileToString(taken));
    } catch (const std::exception& e) {
        log::Registry::runtime()->warn("[PeerLinks] Ignored a malformed test fetch request: {}", e.what());
        return;
    }
    (void)transfers_.spawn([this, ask, base] {
        constexpr uint64_t kMaxBytes = 64ull * 1024 * 1024;
        json report = {{"ok", false}};
        std::vector<uint8_t> body;
        try {
            const auto row = db::query::peer::Peers::liveByNodeId(ask.at("peer_node").get<std::string>());
            if (!row) throw std::runtime_error("no live link to that node");
            const auto vault = vl::keykit::fromBase32(ask.at("vault_uid").get<std::string>());
            const auto object = vl::keykit::fromBase32(ask.at("object_uid").get<std::string>());
            if (!vault || !object) throw std::runtime_error("malformed uid");
            const object::Address what{.vault = *vault, .object = *object,
                                       .generation = ask.at("generation").get<std::string>()};
            const auto interruptAt = ask.value("interrupt_at", uint64_t{0});
            bool stop = false;
            bool interrupting = false;
            object::FetchOptions options;
            options.tls = clientTls();
            options.deadline = SteadyClock::now() + std::chrono::minutes(2);
            options.cancelled = [&] { return stop || transfers_.stopping(); };
            const object::Sink sink = [&](const std::span<const uint8_t> bytes) {
                if (body.size() + bytes.size() > kMaxBytes) throw std::runtime_error("larger than a drill fetch takes");
                body.insert(body.end(), bytes.begin(), bytes.end());
                if (interrupting && body.size() >= interruptAt) stop = true;
            };
            json attempts = json::array();
            for (int i = 0; i < 4; ++i) {
                interrupting = interruptAt > 0 && body.size() < interruptAt;
                stop = false;
                options.offset = body.size();
                const auto r = object::fetch(*row, what, options, sink);
                attempts.push_back({{"offset", options.offset}, {"status", std::string(object::toString(r.status))},
                                    {"received", r.received}, {"total", r.total}, {"http_status", r.http_status},
                                    {"code", r.code}, {"error", r.error}});
                if (r.status == object::FetchStatus::Complete || r.status == object::FetchStatus::Refused ||
                    r.status == object::FetchStatus::Unreachable)
                    break;
                // The interruption asked for: keep exactly interrupt_at bytes, and resume from there.
                if (interrupting && body.size() > interruptAt) body.resize(interruptAt);
            }
            report = {{"ok", true}, {"attempts", attempts}, {"bytes", body.size()}};
            const auto outPath = base / "peer-object-fetch.bin";
            std::filesystem::remove(outPath);
            vh::fs::ops::writeFileExclusive(outPath, body);
        } catch (const std::exception& e) {
            report = {{"ok", false}, {"error", e.what()}};
        }
        try {
            const auto dumped = report.dump();
            const auto tmp = base / "peer-object-fetch.result.tmp";
            std::filesystem::remove(tmp);
            vh::fs::ops::writeFileExclusive(tmp, std::span(reinterpret_cast<const uint8_t*>(dumped.data()), dumped.size()));
            std::filesystem::rename(tmp, base / "peer-object-fetch.result.json");
        } catch (const std::exception& e) {
            log::Registry::runtime()->warn("[PeerLinks] Could not write the test fetch report: {}", e.what());
        }
    });
}

// ---- dialling -------------------------------------------------------------------------------------------------------

void LinkService::dialPeer(const Record& row) {
    dials_.fetch_add(1, std::memory_order_relaxed);
    if (row.endpoints.empty()) return dialFailed(row.id, "no endpoints known yet (the other server dials this one)");
    std::shared_ptr<boost::asio::ssl::context> tls;
    try {
        ensureIo();
        tls = clientTls();
    } catch (const std::exception& e) {
        return dialFailed(row.id, e.what());
    }

    // Tries each endpoint in turn (stored last good first); the first that answers with a pinned key wins.
    struct Chain : std::enable_shared_from_this<Chain> {
        LinkService* svc;
        Record row;
        std::shared_ptr<boost::asio::ssl::context> tls;
        std::size_t next = 0;
        std::string lastError;
        std::optional<dc::PublicKey> seen;

        void step() {
            if (next >= row.endpoints.size()) return svc->dialFailed(row.id, lastError);
            const auto endpoint = row.endpoints[next++];
            protocols::ws::client::DialOptions options{
                .host = endpoint.host, .port = endpoint.port, .target = "/ws", .tls = tls,
                .acceptCertificate = [self = shared_from_this()](X509* leaf) {
                    // The pin, or the key the peer announced; never the trust store.
                    auto key = pinnedKeyOf(self->row, leaf);
                    if (!key) return false;
                    self->seen = std::move(key);
                    return true;
                },
                .timeout = std::chrono::seconds(10), .userAgent = "vaulthalla-server"};
            protocols::ws::client::dial(*svc->ioc_, std::move(options),
                                        [self = shared_from_this(), endpoint](protocols::ws::client::DialResult r) {
                                            if (!r.transport) {
                                                self->lastError = toString(endpoint) + ": " + r.error;
                                                return self->step();
                                            }
                                            self->finish(std::move(r), endpoint);
                                        });
        }

        void finish(protocols::ws::client::DialResult r, const Endpoint& endpoint) {
            const auto hex = dc::toHex(seen->spkiSha256);
            if (hex != row.spki_sha256 && !db::query::peer::Peers::promoteNext(row.id, hex)) {
                lastError = toString(endpoint) + ": the announced key is no longer this link's";
                return step();
            }
            auto principal = std::make_shared<Principal>();
            principal->peer_id = row.id;
            principal->node_id = row.node_id;
            principal->name = row.name;
            principal->spki = seen->spkiSha256;
            principal->spki_hex = hex;
            principal->spki_der = seen->spkiDer;
            principal->address = toString(endpoint);
            principal->inbound = false;
            // The endpoint that worked goes first next time.
            if (next > 1) {
                auto endpoints = row.endpoints;
                std::rotate(endpoints.begin(), endpoints.begin() + static_cast<std::ptrdiff_t>(next - 1),
                            endpoints.begin() + static_cast<std::ptrdiff_t>(next));
                try {
                    db::query::peer::Peers::setEndpoints(row.id, endpoints);
                } catch (const std::exception&) {
                }
            }
            svc->onDialed(row.id, std::move(r.transport), r.address, std::move(principal));
        }
    };
    auto chain = std::make_shared<Chain>();
    chain->svc = this;
    chain->row = row;
    chain->tls = std::move(tls);
    chain->step();
}

void LinkService::dialFailed(const uint32_t peerId, const std::string& why) {
    std::scoped_lock lock(mutex_);
    auto& st = peers_[peerId];
    st.dialing = false;
    const auto delay = concurrency::jitteredBackoff(st.attempt++, kBackoffFloor, kBackoffCap);
    st.next_attempt = SteadyClock::now() + delay;
    st.next_attempt_wall = wallNow() + std::chrono::duration_cast<std::chrono::seconds>(delay).count();
    if (st.last_error != why)
        log::Registry::runtime()->info("[PeerLinks] Cannot reach linked server {}: {} (retrying with backoff)", peerId, why);
    st.last_error = why;
    st.last_error_at = wallNow();
}

void LinkService::onDialed(const uint32_t peerId, std::shared_ptr<protocols::ws::TlsTransport> transport,
                           std::string address, std::shared_ptr<const Principal> principal) {
    (void)address;
    auto rpc = std::make_shared<Rpc>();
    std::shared_ptr<protocols::ws::Router> router;
    {
        std::scoped_lock lock(mutex_);
        router = router_;
        peers_[peerId].dialing = false;
    }
    auto session = std::make_shared<protocols::ws::Session>(router);
    auto conn = track(session, principal, rpc);
    conn->dialed_by = protocols::device::endpoints::nodeId();
    std::weak_ptr<Connection> weakConn = conn;
    protocols::ws::PeerHooks hooks;
    hooks.onResponse = [rpc](const json& frame) { return rpc->onResponse(frame); };
    hooks.onClose = [this, weakConn] {
        if (const auto c = weakConn.lock()) connectionClosed(c);
    };
    hooks.onOpen = [this, weakConn, rpc] {
        const auto c = weakConn.lock();
        if (!c) return;
        rpc->call(*c->session, "peer.hello", ownHello(), kRequestTimeout, [this, weakConn](std::optional<json> answer) {
            const auto conn = weakConn.lock();
            if (!conn) return;
            if (!answeredOk(answer)) {
                const auto code = answer ? errorCode(*answer) : std::string();
                // The other end kept the connection it dialled itself (the tie-break): nothing went wrong.
                if (code != "conflict")
                    dialFailed(conn->principal->peer_id, "peer.hello refused: " + (answer ? errorText(*answer) : "no answer"));
                conn->session->close();
                return;
            }
            const auto hello = dataOf(*answer);
            if (hello.value("node_id", "") != conn->principal->node_id) {
                dialFailed(conn->principal->peer_id, "the server at this address is another node than the one linked");
                conn->session->close();
                return;
            }
            {
                std::scoped_lock lock(mutex_);
                conn->hello = true;
                conn->peer_protocol = hello.value("peer_protocol", 0u);
                conn->peer_version = hello.value("product_version", "");
            }
            try {
                db::query::peer::Peers::recordHello(conn->principal->peer_id, conn->peer_protocol, conn->peer_version);
            } catch (const std::exception& e) {
                log::Registry::runtime()->debug("[PeerLinks] Could not record a hello: {}", e.what());
            }
            if (!adopt(conn)) return;
            // Where this server can be reached, and where the other one says it can.
            conn->rpc->call(*conn->session, "peer.endpoints", json{{"endpoints", ownEndpoints()}}, kRequestTimeout,
                            [weakConn](std::optional<json> reply) {
                                const auto c = weakConn.lock();
                                if (!c || !answeredOk(reply)) return;
                                try {
                                    auto advertised = endpointsFromJson(dataOf(*reply).value("endpoints", json::array()));
                                    // The endpoint this connection used stays first (last good).
                                    if (const auto used = parseAddress(c->principal->address, 0)) {
                                        std::erase_if(advertised, [&](const Endpoint& e) {
                                            return e.host == used->host && e.port == used->port;
                                        });
                                        advertised.insert(advertised.begin(), *used);
                                    }
                                    if (advertised.size() > kMaxEndpoints) advertised.resize(kMaxEndpoints);
                                    db::query::peer::Peers::setEndpoints(c->principal->peer_id, advertised);
                                } catch (const std::exception& e) {
                                    log::Registry::runtime()->debug("[PeerLinks] Ignored an advertisement: {}", e.what());
                                }
                            });
        });
    };
    session->attachPeer(std::move(transport), std::move(principal), std::move(hooks));
}

std::shared_ptr<LinkService::Connection> LinkService::track(std::shared_ptr<protocols::ws::Session> session,
                                                            std::shared_ptr<const Principal> principal,
                                                            std::shared_ptr<Rpc> rpc) {
    auto conn = std::make_shared<Connection>();
    conn->session = std::move(session);
    conn->principal = std::move(principal);
    conn->rpc = std::move(rpc);
    std::scoped_lock lock(mutex_);
    connections_.push_back(conn);
    return conn;
}

void LinkService::acceptInbound(std::shared_ptr<protocols::ws::TlsTransport> transport, const RequestType& request,
                                std::shared_ptr<const Principal> principal,
                                std::unique_ptr<protocols::ws::ConnectionSlot> slot) {
    ensureIo();
    std::shared_ptr<protocols::ws::Router> router;
    {
        std::scoped_lock lock(mutex_);
        router = router_;
    }
    auto rpc = std::make_shared<Rpc>();
    auto session = std::make_shared<protocols::ws::Session>(router);
    session->holdConnectionSlot(std::move(slot));
    auto conn = track(session, principal, rpc);
    conn->dialed_by = principal->node_id;
    std::weak_ptr<Connection> weakConn = conn;
    protocols::ws::PeerHooks hooks;
    hooks.onResponse = [rpc](const json& frame) { return rpc->onResponse(frame); };
    hooks.onClose = [this, weakConn] {
        if (const auto c = weakConn.lock()) connectionClosed(c);
    };
    session->acceptPeer(std::move(transport), request, std::move(principal), std::move(hooks));
}

bool LinkService::adopt(const std::shared_ptr<Connection>& conn) {
    std::shared_ptr<Connection> loser;
    bool kept = true;
    bool up = false;
    {
        std::scoped_lock lock(mutex_);
        if (conn->closed) return false;
        auto& st = peers_[conn->principal->peer_id];
        if (st.active && st.active != conn && !st.active->closed) {
            const auto own = protocols::device::endpoints::nodeId();
            const auto lower = std::min(own, conn->principal->node_id);
            // Both ends apply the same rule, so both keep the same connection: the one the lower node id dialled; a
            // newer connection from the same dialler replaces the older (it reconnected).
            kept = conn->dialed_by == st.active->dialed_by || conn->dialed_by == lower;
            loser = kept ? st.active : conn;
            if (kept) st.active = conn;
        } else if (st.active != conn) {
            st.active = conn;
            up = true;
        }
        if (kept) {
            st.attempt = 0;
            st.last_error.reset();
            st.next_attempt_wall.reset();
        }
    }
    if (loser) loser->session->closeAfterReply();
    if (up) auditConnection(conn->principal->peer_id, conn->principal->node_id, true, conn->principal->address);
    return kept;
}

void LinkService::connectionClosed(const std::shared_ptr<Connection>& conn) {
    bool down = false;
    {
        std::scoped_lock lock(mutex_);
        conn->closed = true;
        std::erase(connections_, conn);
        if (conn->principal && !conn->principal->pairing)
            if (const auto it = peers_.find(conn->principal->peer_id); it != peers_.end() && it->second.active == conn) {
                it->second.active.reset();
                it->second.next_attempt = SteadyClock::now();  // dial again at once (then with backoff)
                down = true;
            }
    }
    conn->rpc->failAll();
    if (down) auditConnection(conn->principal->peer_id, conn->principal->node_id, false, conn->principal->address);
}

void LinkService::auditConnection(const uint32_t peerId, const std::string& nodeId, const bool up,
                                  const std::string& detail) {
    {
        std::scoped_lock lock(mutex_);
        auto& st = peers_[peerId];
        const auto now = SteadyClock::now();
        // peer.connection: at most one per minute per peer (a flapping link must not flood the trail).
        if (st.last_audit != SteadyClock::time_point{} && now - st.last_audit < kAuditEvery) return;
        st.last_audit = now;
    }
    audit::record({.action = "peer.connection", .outcome = audit::Outcome::Info,
                   .details = {{"peer", peerId}, {"node_id", nodeId}, {"state", up ? "up" : "down"}}},
                  fmt::format("[peer] the link to server {} is {} ({})", nodeId, up ? "up" : "down", detail));
}

void LinkService::ping(const std::shared_ptr<Connection>& conn) {
    {
        std::scoped_lock lock(mutex_);
        conn->ping_in_flight = true;
        conn->last_ping = SteadyClock::now();
    }
    const auto sent = SteadyClock::now();
    std::weak_ptr<Connection> weakConn = conn;
    conn->rpc->call(*conn->session, "peer.ping", json::object(), kPingTimeout, [this, weakConn, sent](std::optional<json> a) {
        const auto c = weakConn.lock();
        if (!c) return;
        bool dead = false, touch = false;
        {
            std::scoped_lock lock(mutex_);
            c->ping_in_flight = false;
            if (answeredOk(a)) {
                c->missed = 0;
                c->rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - sent).count();
                touch = SteadyClock::now() - c->last_touch >= kTouchEvery;
                if (touch) c->last_touch = SteadyClock::now();
            } else {
                dead = ++c->missed >= kMaxMissedPings;
            }
        }
        if (touch) {
            try {
                db::query::peer::Peers::touch(c->principal->peer_id);
            } catch (const std::exception&) {
            }
        }
        if (dead) {
            log::Registry::runtime()->info("[PeerLinks] Linked server {} missed {} pings: closing the link", c->principal->node_id,
                                           kMaxMissedPings);
            c->session->close();
        }
    });
}

// ---- the wire -------------------------------------------------------------------------------------------------------

json LinkService::ownHello() {
    return {{"node_id", protocols::device::endpoints::nodeId()},
            {"name", keys::serverName()},
            {"peer_protocol", kPeerProtocol},
            {"product_version", VH_VERSION}};
}

json LinkService::ownEndpoints() {
    std::vector<Endpoint> out;
    for (const auto& c : protocols::device::endpoints::current().candidates)
        out.push_back(Endpoint{.host = c.host, .port = c.port, .kind = std::string(protocols::device::endpoints::to_string(c.kind))});
    if (out.size() > kMaxEndpoints) out.resize(kMaxEndpoints);
    return toJson(out);
}

json LinkService::helloReceived(const std::shared_ptr<protocols::ws::Session>& session, const json& payload) {
    const auto& principal = session->peerPrincipal();
    if (!principal) throw ops::Denied("not a linked server's session");
    if (!payload.is_object() || payload.value("node_id", "") != principal->node_id)
        throw ops::Invalid("peer.hello names another node than the one linked");
    const auto protocol = payload.contains("peer_protocol") && payload.at("peer_protocol").is_number_integer() &&
                                  payload.at("peer_protocol").get<int64_t>() >= 1 &&
                                  payload.at("peer_protocol").get<int64_t>() <= 65535
                              ? static_cast<uint32_t>(payload.at("peer_protocol").get<int64_t>())
                              : 0u;
    std::string version = payload.value("product_version", "");
    if (version.size() > 64 || !std::ranges::all_of(version, [](const unsigned char c) { return c >= 0x20 && c < 0x7f; }))
        version.clear();
    if (protocol < 1 || protocol > 65535) throw ops::Invalid("peer.hello needs peer_protocol (1-65535)");
    db::query::peer::Peers::recordHello(principal->peer_id, protocol, version);

    std::shared_ptr<Connection> conn;
    {
        std::scoped_lock lock(mutex_);
        for (const auto& c : connections_)
            if (c->session == session) conn = c;
        if (conn) {
            conn->hello = true;
            conn->peer_protocol = protocol;
            conn->peer_version = version;
        }
    }
    if (!conn) throw ops::Conflict("this connection is closing");
    if (!adopt(conn)) {
        session->closeAfterReply();
        throw ops::Conflict("this link already has a connection: the one the lower node id dialled is kept");
    }
    return ownHello();
}

json LinkService::endpointsReceived(const std::shared_ptr<protocols::ws::Session>& session, const json& payload) {
    const auto& principal = session->peerPrincipal();
    if (!principal) throw ops::Denied("not a linked server's session");
    if (!payload.is_object() || !payload.contains("endpoints")) throw ops::Invalid("endpoints is required");
    auto advertised = endpointsFromJson(payload.at("endpoints"));
    db::query::peer::Peers::setEndpoints(principal->peer_id, advertised);
    return {{"endpoints", ownEndpoints()}};
}

// ---- management -----------------------------------------------------------------------------------------------------

Health LinkService::health(const uint32_t peerId) const {
    Health h;
    std::scoped_lock lock(mutex_);
    const auto it = peers_.find(peerId);
    if (it == peers_.end()) return h;
    const auto& st = it->second;
    if (st.active && !st.active->closed) {
        const auto& c = *st.active;
        h.connected = true;
        h.since = c.opened_wall;
        h.dialed_by = c.principal->inbound ? "peer" : "this_server";
        h.address = c.principal->address;
        h.rtt_ms = c.rtt_ms;
        h.peer_protocol = c.peer_protocol;
        h.peer_version = c.peer_version;
        h.protocol_compatible = c.peer_protocol == kPeerProtocol;
    } else {
        h.next_attempt_at = st.next_attempt_wall;
    }
    h.last_error = st.last_error;
    h.last_error_at = st.last_error_at;
    return h;
}

std::size_t LinkService::disconnect(const uint32_t peerId, const bool notifyUnlinked,
                                    const protocols::ws::Session* spare) {
    std::vector<std::shared_ptr<Connection>> mine;
    {
        std::scoped_lock lock(mutex_);
        for (const auto& c : connections_)
            if (!c->closed && c->principal && !c->principal->pairing && c->principal->peer_id == peerId) mine.push_back(c);
        if (const auto it = peers_.find(peerId); it != peers_.end()) it->second.active.reset();
        rows_.erase(std::remove_if(rows_.begin(), rows_.end(), [&](const Record& r) { return r.id == peerId; }),
                    rows_.end());
    }
    // The sealed lane's connections of this peer go too (link.md invariant 7).
    (void)protocols::device::peer_object::closeConnections(peerId);
    for (const auto& c : mine) {
        if (c->session.get() == spare) {
            c->session->closeAfterReply();
            continue;
        }
        if (notifyUnlinked && c->hello) {
            // A notice, not a request this end waits for: the close goes out right behind it.
            c->session->send(json{{"command", "peer.unlinked"}, {"payload", json::object()}, {"requestId", "unlinked"}});
            c->session->closeAfterReply();
        } else {
            c->session->close();
        }
    }
    return mine.size();
}

std::optional<json> LinkService::request(const uint32_t peerId, const std::string& command, json payload,
                                         const std::chrono::milliseconds timeout) {
    std::shared_ptr<Connection> conn;
    {
        std::scoped_lock lock(mutex_);
        if (const auto it = peers_.find(peerId); it != peers_.end() && it->second.active && !it->second.active->closed &&
                                                 it->second.active->hello)
            conn = it->second.active;
    }
    if (!conn) return std::nullopt;
    return callAndWait(*conn->rpc, *conn->session, command, std::move(payload), timeout);
}

std::size_t LinkService::disconnectAll() {
    std::vector<std::shared_ptr<Connection>> all;
    {
        std::scoped_lock lock(mutex_);
        all = connections_;
        for (auto& [_, st] : peers_) st.active.reset();
    }
    for (const auto& c : all) c->session->close();
    (void)protocols::device::peer_object::closeAllConnections();
    return all.size();
}

std::vector<uint32_t> LinkService::announceRotation(const vh::device::ServerIdentity& current,
                                                    const dc::Hash& nextSpki, const uint64_t counter) {
    std::vector<std::shared_ptr<Connection>> targets;
    {
        std::scoped_lock lock(mutex_);
        for (const auto& [_, st] : peers_)
            if (st.active && !st.active->closed && st.active->hello) targets.push_back(st.active);
    }
    const auto own = protocols::device::endpoints::nodeId();
    std::vector<std::pair<uint32_t, std::future<std::optional<json>>>> waits;
    for (const auto& c : targets) {
        const auto message = crypto::rotationMessage(nextSpki, c->principal->spki, own, counter);
        const auto signature = crypto::signP256(current.key(), message);
        auto promise = std::make_shared<std::promise<std::optional<json>>>();
        waits.emplace_back(c->principal->peer_id, promise->get_future());
        c->rpc->call(*c->session, "peer.identity.rotate",
                     json{{"next_spki_sha256", dc::toHex(nextSpki)}, {"counter", counter},
                          {"signature", dc::toBase64(signature)}},
                     kRequestTimeout, [promise](std::optional<json> a) { promise->set_value(std::move(a)); });
    }
    std::vector<uint32_t> stored;
    for (auto& [peerId, f] : waits) {
        if (f.wait_for(kRequestTimeout + std::chrono::seconds(1)) != std::future_status::ready) continue;
        if (answeredOk(f.get())) stored.push_back(peerId);
    }
    return stored;
}

// ---- pairing, the dialling side -------------------------------------------------------------------------------------

std::string LinkService::startLink(const uint32_t ownerId, std::vector<Endpoint> endpoints,
                                   std::optional<std::string> expectSpki, std::string comparedBy) {
    ensureIo();
    LinkAttempt a;
    a.id = dc::randomHex(8);
    a.owner_id = ownerId;
    a.expect_spki = std::move(expectSpki);
    a.compared_by = comparedBy == "desktop" ? "desktop" : "person";
    a.created_at = a.updated_at = wallNow();
    {
        std::scoped_lock lock(attemptsMutex_);
        if (stopping_) throw std::runtime_error("the link service is stopping");
        // Finished attempts are kept a while for peer.link.status, then dropped.
        std::erase_if(attempts_, [now = wallNow()](const auto& kv) {
            return kv.second.finished() && now - kv.second.updated_at > 15 * 60;
        });
        attempts_[a.id] = a;
        attemptThreads_.emplace_back([this, id = a.id, endpoints = std::move(endpoints)]() mutable {
            try {
                runAttempt(id, std::move(endpoints));
            } catch (const std::exception& e) {
                updateAttempt(id, [&](LinkAttempt& x) {
                    x.state = "failed";
                    x.error = e.what();
                });
            }
        });
    }
    return a.id;
}

std::optional<LinkAttempt> LinkService::attempt(const std::string& id) const {
    std::scoped_lock lock(attemptsMutex_);
    const auto it = attempts_.find(id);
    if (it == attempts_.end()) return std::nullopt;
    return it->second;
}

bool LinkService::cancelLink(const std::string& id) {
    {
        std::scoped_lock lock(attemptsMutex_);
        const auto it = attempts_.find(id);
        if (it == attempts_.end() || it->second.finished()) return false;
        cancelled_[id] = true;
    }
    attemptsCv_.notify_all();
    return true;
}

void LinkService::updateAttempt(const std::string& id, const std::function<void(LinkAttempt&)>& change) {
    std::scoped_lock lock(attemptsMutex_);
    if (const auto it = attempts_.find(id); it != attempts_.end()) {
        change(it->second);
        it->second.updated_at = wallNow();
    }
}

bool LinkService::attemptCancelled(const std::string& id) const {
    std::scoped_lock lock(attemptsMutex_);
    if (stopping_) return true;
    const auto it = cancelled_.find(id);
    return it != cancelled_.end() && it->second;
}

void LinkService::runAttempt(const std::string& id, std::vector<Endpoint> endpoints) {
    const auto fail = [&](const std::string& state, const std::string& why) {
        updateAttempt(id, [&](LinkAttempt& x) {
            x.state = state;
            x.error = why;
        });
    };
    const auto snapshot = attempt(id);
    if (!snapshot) return;
    const auto expect = snapshot->expect_spki;
    const auto comparedBy = snapshot->compared_by;
    const auto ownerId = snapshot->owner_id;
    const auto identity = vh::device::currentServerIdentity();
    if (!identity) return fail("failed", "the device listener has no server identity yet");
    const auto tls = clientTls();

    // 1. Dial. With expect_spki only that key completes the handshake; without it, any P-256 key but this server's
    //    own (trust on first use: the code closes the gap).
    std::shared_ptr<protocols::ws::TlsTransport> transport;
    std::optional<dc::PublicKey> serverKey;
    std::string address, lastError = "no endpoint given";
    for (const auto& endpoint : endpoints) {
        if (attemptCancelled(id)) return fail("cancelled", "");
        auto seen = std::make_shared<std::optional<dc::PublicKey>>();
        auto refusal = std::make_shared<std::string>();
        auto promise = std::make_shared<std::promise<protocols::ws::client::DialResult>>();
        auto future = promise->get_future();
        dials_.fetch_add(1, std::memory_order_relaxed);
        protocols::ws::client::dial(
            *ioc_,
            {.host = endpoint.host, .port = endpoint.port, .target = "/ws", .tls = tls,
             .acceptCertificate = [seen, refusal, expect, own = identity->spkiHex()](X509* leaf) {
                 const auto key = dc::p256KeyOf(leaf);
                 if (!key) {
                     *refusal = "the server's key is not ECDSA P-256";
                     return false;
                 }
                 const auto hex = dc::toHex(key->spkiSha256);
                 if (expect && hex != *expect) {
                     *refusal = "the server's key is " + hex.substr(0, 16) + "..., not the expected " +
                                expect->substr(0, 16) + "...";
                     return false;
                 }
                 if (hex == own) {
                     *refusal = "that address is this server";
                     return false;
                 }
                 *seen = key;
                 return true;
             },
             .timeout = std::chrono::seconds(10), .userAgent = "vaulthalla-server"},
            [promise](protocols::ws::client::DialResult r) { promise->set_value(std::move(r)); });
        auto result = future.get();
        if (result.transport && *seen) {
            transport = std::move(result.transport);
            serverKey = *seen;
            address = toString(endpoint);
            const auto used = std::ranges::find_if(endpoints, [&](const Endpoint& e) {
                return e.host == endpoint.host && e.port == endpoint.port;
            });
            std::rotate(endpoints.begin(), used, std::next(used));  // the one that answered goes first
            break;
        }
        lastError = toString(endpoint) + ": " + (refusal->empty() ? result.error : *refusal);
    }
    if (!transport) return fail("failed", lastError);
    updateAttempt(id, [&](LinkAttempt& x) {
        x.address = address;
        x.peer_spki_sha256 = dc::toHex(serverKey->spkiSha256);
    });

    // 2. A pairing connection: answers to this side's requests, nothing else.
    auto principal = std::make_shared<Principal>();
    principal->spki = serverKey->spkiSha256;
    principal->spki_hex = dc::toHex(serverKey->spkiSha256);
    principal->spki_der = serverKey->spkiDer;
    principal->address = address;
    principal->pairing = true;
    auto rpc = std::make_shared<Rpc>();
    std::shared_ptr<protocols::ws::Router> router;
    {
        std::scoped_lock lock(mutex_);
        router = router_;
    }
    auto session = std::make_shared<protocols::ws::Session>(router);
    protocols::ws::PeerHooks hooks;
    hooks.onResponse = [rpc](const json& frame) { return rpc->onResponse(frame); };
    hooks.onClose = [rpc] { rpc->failAll(); };
    session->attachPeer(std::move(transport), principal, std::move(hooks));
    struct Closer {
        std::shared_ptr<protocols::ws::Session> s;
        ~Closer() { s->close(); }
    } closer{session};

    // 3. The request (card + commitment), B's card and nonce, then the reveal.
    const auto own = keys::localCard();
    const auto nonceA = dc::randomNonce();
    const auto request = callAndWait(*rpc, *session, "peer.pair.request",
                                     {{"card", toJson(own)},
                                      {"commitment", dc::toHex(crypto::commitment(identity->spkiSha256(), nonceA))}},
                                     kRequestTimeout);
    if (!answeredOk(request))
        return fail("failed", request ? errorText(*request) : "the other server did not answer peer.pair.request");
    const auto receipt = dataOf(*request);
    Card theirs;
    try {
        theirs = cardFromJson(receipt.value("card", json::object()));
    } catch (const ops::Error& e) {
        return fail("failed", std::string("the other server's card is malformed: ") + e.what());
    }
    const auto nonceB = dc::hashFromHex(receipt.value("nonce_b", ""));
    const auto requestId = receipt.value("request_id", "");
    if (!nonceB || requestId.empty()) return fail("failed", "the other server's answer is malformed");
    if (theirs.node_id == own.node_id) return fail("failed", "that server is this one (the same node id)");
    if (db::query::peer::Peers::liveByNodeId(theirs.node_id))
        return fail("failed", "that server is already linked here (unlink it first)");
    updateAttempt(id, [&](LinkAttempt& x) { x.peer_card = theirs; });

    const auto confirmed = callAndWait(*rpc, *session, "peer.pair.confirm",
                                       {{"request_id", requestId}, {"nonce_a", dc::toHex(nonceA)}}, kRequestTimeout);
    if (!answeredOk(confirmed)) return fail("failed", confirmed ? errorText(*confirmed) : "no answer to peer.pair.confirm");

    // 4. The code this side shows; the other server's owner picks it among three.
    const auto code = crypto::sasCode(crypto::sasDigest(serverKey->spkiSha256, identity->spkiSha256(), nonceA, *nonceB,
                                                        crypto::cardHash(own), crypto::cardHash(theirs)));
    updateAttempt(id, [&](LinkAttempt& x) {
        x.state = "awaiting_approval";
        x.code = code;
    });
    audit::record({.action = "peer.link.request", .actor_id = ownerId,
                   .details = {{"node_id", theirs.node_id}, {"key", principal->spki_hex.substr(0, 16)},
                               {"address", address}, {"pinned", expect.has_value()}}},
                  fmt::format("[peer] asked server {} ('{}', key {}) at {} to link{}", theirs.node_id, theirs.name,
                              principal->spki_hex.substr(0, 16), address, expect ? " (key given)" : ""));

    // 5. Wait for the decision.
    const auto deadline = SteadyClock::now() + kAttemptLifetime;
    for (;;) {
        {
            std::unique_lock lock(attemptsMutex_);
            attemptsCv_.wait_for(lock, kStatusPoll, [&] { return stopping_ || cancelled_.contains(id); });
        }
        if (attemptCancelled(id)) return fail("cancelled", "");
        if (SteadyClock::now() > deadline) return fail("expired", "no decision in time");
        if (session->closing()) return fail("failed", "the other server closed the connection");
        const auto status = callAndWait(*rpc, *session, "peer.pair.status", {{"request_id", requestId}}, kRequestTimeout);
        if (!answeredOk(status)) {
            if (status && errorCode(*status) == "not_found") return fail("expired", "the request expired");
            return fail("failed", status ? errorText(*status) : "no answer to peer.pair.status");
        }
        const auto state = dataOf(*status).value("state", "");
        if (state == "pending") continue;
        if (state == "denied") {
            audit::record({.action = "peer.link.denied", .outcome = audit::Outcome::Denied, .actor_id = ownerId,
                           .details = {{"node_id", theirs.node_id}, {"key", principal->spki_hex.substr(0, 16)},
                                       {"side", "dialling"}}},
                          fmt::format("[peer] server {} declined the link", theirs.node_id));
            return fail("denied", "the other server declined the link (or its owner picked another code)");
        }
        if (state == "expired") return fail("expired", "the request expired");
        if (state != "approved") return fail("failed", "unexpected state '" + state + "'");
        break;
    }

    // 6. Approved over there: this side's row, pinning the key the handshake saw.
    try {
        const auto row = db::query::peer::Peers::insert({
            .node_id = theirs.node_id, .name = theirs.name, .spki_sha256 = principal->spki_hex,
            .attest_public_keys = theirs.attest_public_keys, .wrap_public_key = theirs.wrap_public_key,
            .endpoints = endpoints, .approved_by = ownerId == 0 ? std::nullopt : std::optional<uint32_t>(ownerId),
            .compared_by = comparedBy, .peer_protocol = theirs.peer_protocol,
            .product_version = theirs.product_version});
        updateAttempt(id, [&](LinkAttempt& x) {
            x.state = "linked";
            x.peer_id = row.id;
        });
        audit::record({.action = "peer.link", .actor_id = ownerId,
                       .details = {{"peer", row.id}, {"node_id", row.node_id}, {"key", row.shortId()},
                                   {"compared_by", row.compared_by}, {"pinned", expect.has_value()},
                                   {"side", "dialling"}}},
                      fmt::format("[peer] linked server {} ('{}', key {}); the code was compared by {}", row.node_id,
                                  row.name, row.shortId(), row.compared_by == "desktop" ? "Desktop" : "a person"));
    } catch (const std::exception& e) {
        return fail("failed", std::string("the other server approved, but this side could not record the link (unlink "
                                          "it there and link again): ") + e.what());
    }
    wake();
}

}
