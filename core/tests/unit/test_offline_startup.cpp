// #316: on a host without outbound internet the ws and http listeners never started. ProtocolService downloaded the
// password lists from GitHub before initProtocols(), a failed download threw, and the run loop shut the protocols
// down (every watchdog restart failed the same way). The lists now ship with the package and load from local files;
// the one remaining network check (the breach-corpus lookup when a password is set) is bounded and never decides
// the outcome when the service can't be reached.

#include "auth/registration/Validator.hpp"
#include "auth/session/Manager.hpp"
#include "config/Registry.hpp"
#include "crypto/password/Strength.hpp"
#include "crypto/util/hash.hpp"
#include "protocols/ProtocolService.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"

#include <gtest/gtest.h>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <paths.h>
#include <sstream>
#include <string>
#include <thread>

namespace vh::test_offline_startup {

using crypto::password::Strength;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

uint16_t freeLoopbackPort() {
    asio::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    return acceptor.local_endpoint().port();
}

bool canConnect(const uint16_t port) {
    asio::io_context ioc;
    tcp::socket socket(ioc);
    boost::system::error_code ec;
    socket.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
    return !ec;
}

std::filesystem::path scratchDir(const std::string& name) {
    auto dir = std::filesystem::temp_directory_path() /
               ("vh_offline_" + name + "_" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

// Serves one canned HTTP response per connection on 127.0.0.1 until destroyed.
class CannedHttpServer {
  public:
    explicit CannedHttpServer(std::string response)
        : acceptor_(ioc_, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)), response_(std::move(response)) {
        thread_ = std::thread([this] {
            while (!stop_) {
                boost::system::error_code ec;
                tcp::socket socket(ioc_);
                acceptor_.accept(socket, ec);
                if (ec || stop_) return;
                asio::streambuf request;
                asio::read_until(socket, request, "\r\n\r\n", ec);
                asio::write(socket, asio::buffer(response_), ec);
                socket.shutdown(tcp::socket::shutdown_both, ec);
            }
        });
    }
    ~CannedHttpServer() {
        stop_ = true;
        boost::system::error_code ec;
        canConnect(port());  // wake the blocking accept
        acceptor_.close(ec);
        if (thread_.joinable()) thread_.join();
    }
    [[nodiscard]] uint16_t port() const { return acceptor_.local_endpoint().port(); }
    [[nodiscard]] std::string rangeEndpoint() const { return "http://127.0.0.1:" + std::to_string(port()) + "/range/"; }

  private:
    asio::io_context ioc_;
    tcp::acceptor acceptor_;
    std::string response_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

std::string httpOk(const std::string& body) {
    return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(body.size()) +
           "\r\nConnection: close\r\n\r\n" + body;
}

// A range-response body that lists `password`'s suffix (or not).
std::string rangeBody(const std::string& password, const bool include) {
    const auto suffix = Strength::SHA1Hex(password).substr(5);
    std::string body = "0000000000000000000000000000000000A:3\r\n";
    if (include) body += suffix + ":42\r\n";
    return body;
}

class NetworkGuard {
  public:
    NetworkGuard() { Strength::setNetworkTimeoutsForTesting({.connect = 500ms, .total = 1000ms}); }
    ~NetworkGuard() { Strength::resetNetworkForTesting(); }
};

class ListsGuard {
  public:
    ~ListsGuard() {
        std::istringstream none;
        Strength::loadDictionary(none);
        std::istringstream none2;
        Strength::loadCommonWeakPasswords(none2);
    }
};

}

// The regression itself: the real ProtocolService, no password lists on disk, and a breach endpoint that would never
// answer. Both listeners come up and accept connections, and startup made no outbound request at all.
TEST(OfflineStartup, ListenersStartWithoutNetworkAndWithoutListFiles) {
    NetworkGuard network;
    Strength::setBreachEndpointForTesting("http://10.255.255.1/range/");  // unroutable: would hang if ever used

    // The probe connections below are accepted by the real ws server, which hands them to the session manager the
    // daemon always has (this test process has none until we give it one).
    const auto previousSessions = runtime::Deps::get().sessionManager;
    if (!previousSessions) runtime::Deps::get().sessionManager = std::make_shared<auth::session::Manager>();
    const auto previousConfig = config::Registry::get();
    const auto previousLists = paths::passwordListsPath;
    paths::passwordListsPath = scratchDir("missing") / "does-not-exist";

    auto cfg = previousConfig;
    cfg.websocket.enabled = true;
    cfg.websocket.host = "127.0.0.1";
    cfg.websocket.port = freeLoopbackPort();
    cfg.http_preview.enabled = true;
    cfg.http_preview.host = "127.0.0.1";
    cfg.http_preview.port = freeLoopbackPort();
    config::Registry::set(cfg);

    const auto requestsBefore = Strength::outboundRequestCount();
    const auto started = std::chrono::steady_clock::now();
    {
        protocols::ProtocolService service;
        service.start();
        auto status = service.protocolStatus();
        while (!(status.websocketReady && status.httpPreviewReady) && std::chrono::steady_clock::now() - started < 10s) {
            std::this_thread::sleep_for(20ms);
            status = service.protocolStatus();
        }
        EXPECT_TRUE(status.websocketReady) << "ws listener did not start";
        EXPECT_TRUE(status.httpPreviewReady) << "http listener did not start";
        EXPECT_LT(std::chrono::steady_clock::now() - started, 5s) << "startup waited on something";
        EXPECT_TRUE(canConnect(cfg.websocket.port));
        EXPECT_TRUE(canConnect(cfg.http_preview.port));
        // The ws probe can leave a cached session whose socket is bound to the service's io_context. Stopping the
        // service used to free that context, so destroying the session afterwards (below, with the session manager)
        // was a use-after-free: an intermittent SIGSEGV under MALLOC_PERTURB_ (meson test sets it). The service now
        // keeps the context while any ws session object is alive.
        service.stop();
    }
    EXPECT_EQ(Strength::outboundRequestCount(), requestsBefore) << "startup made an outbound request";

    config::Registry::set(previousConfig);
    paths::passwordListsPath = previousLists;
    runtime::Deps::get().sessionManager = previousSessions;
}

TEST(OfflineStartup, BundledListsLoadFromTheShippedFiles) {
    ListsGuard restore;
    const auto requestsBefore = Strength::outboundRequestCount();
    const auto report = Strength::loadBundledLists(VH_TEST_PASSWORD_LISTS_DIR);
    ASSERT_TRUE(report.complete()) << report.dictionary.problem << " / " << report.commonPasswords.problem;
    EXPECT_GT(report.dictionary.entries, 50'000u);
    EXPECT_GT(report.commonPasswords.entries, 90'000u);
    EXPECT_EQ(Strength::outboundRequestCount(), requestsBefore);

    EXPECT_TRUE(Strength::isDictionaryWord("Sunshine2024!"));
    EXPECT_TRUE(Strength::isCommonWeakPassword("Password1"));
    EXPECT_TRUE(Strength::isCommonWeakPassword("qwerty"));
    EXPECT_FALSE(Strength::isCommonWeakPassword("hT3$documentRw9!pL2@xQ7kZ"));
    // The policy still accepts long random passwords with the real lists loaded.
    for (int i = 0; i < 50; ++i) {
        const auto password = crypto::hash::generate_secure_password(32);
        EXPECT_FALSE(auth::registration::Validator::localPasswordPolicyViolation(password).has_value()) << password;
    }
}

TEST(OfflineStartup, MissingEmptyOrUnreadableListFilesAreReportedNotThrown) {
    ListsGuard restore;
    std::istringstream words("sunshine\n");
    Strength::loadDictionary(words);
    std::istringstream common("qwerty123\n");
    Strength::loadCommonWeakPasswords(common);

    const auto missing = Strength::loadBundledLists(scratchDir("absent") / "nope");
    EXPECT_FALSE(missing.dictionary.loaded);
    EXPECT_FALSE(missing.commonPasswords.loaded);
    EXPECT_EQ(missing.dictionary.problem, "missing");

    const auto dir = scratchDir("empty");
    std::ofstream(dir / Strength::kDictionaryFile).close();               // empty file
    std::filesystem::create_directory(dir / Strength::kCommonPasswordsFile);  // a directory, not a file
    const auto broken = Strength::loadBundledLists(dir);
    EXPECT_FALSE(broken.dictionary.loaded);
    EXPECT_EQ(broken.dictionary.problem, "empty");
    EXPECT_FALSE(broken.commonPasswords.loaded);

    // A failed load keeps what was loaded before.
    EXPECT_TRUE(Strength::isDictionaryWord("Sunshine1!"));
    EXPECT_TRUE(Strength::isCommonWeakPassword("QWERTY123"));
    std::filesystem::remove_all(dir);
}

TEST(OfflineStartup, BreachLookupIsUnavailableWhenTheConnectionIsRefused) {
    NetworkGuard network;
    const auto port = freeLoopbackPort();  // nothing listens there once the probe acceptor is gone
    Strength::setBreachEndpointForTesting("http://127.0.0.1:" + std::to_string(port) + "/range/");
    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(Strength::checkPwnedPassword("correct horse"), Strength::BreachCheck::Unavailable);
    EXPECT_LT(std::chrono::steady_clock::now() - started, 3s);
}

TEST(OfflineStartup, BreachLookupTimesOutWhenTheServerNeverAnswers) {
    NetworkGuard network;
    // Listens (the kernel completes the handshake) but never reads or answers: a stalled upstream or a middlebox.
    asio::io_context ioc;
    tcp::acceptor blackhole(ioc, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    Strength::setBreachEndpointForTesting("http://127.0.0.1:" + std::to_string(blackhole.local_endpoint().port()) +
                                          "/range/");
    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(Strength::checkPwnedPassword("correct horse"), Strength::BreachCheck::Unavailable);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_GE(elapsed, 900ms) << "returned before the total timeout: the stall wasn't exercised";
    EXPECT_LT(elapsed, 4s) << "the total timeout was not applied";
}

TEST(OfflineStartup, BreachLookupIsUnavailableWhenNameResolutionFails) {
    NetworkGuard network;
    Strength::setBreachEndpointForTesting("http://vaulthalla-offline-test.invalid/range/");  // RFC 6761: never resolves
    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(Strength::checkPwnedPassword("correct horse"), Strength::BreachCheck::Unavailable);
    EXPECT_LT(std::chrono::steady_clock::now() - started, 4s);
}

TEST(OfflineStartup, BreachLookupIsUnavailableOnHttpErrors) {
    NetworkGuard network;
    CannedHttpServer server("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    Strength::setBreachEndpointForTesting(server.rangeEndpoint());
    EXPECT_EQ(Strength::checkPwnedPassword("correct horse"), Strength::BreachCheck::Unavailable);
}

TEST(OfflineStartup, BreachLookupStillReportsFoundAndNotFound) {
    NetworkGuard network;
    const std::string password = "Tr0ub4dor&3-vh-test";
    {
        CannedHttpServer server(httpOk(rangeBody(password, true)));
        Strength::setBreachEndpointForTesting(server.rangeEndpoint());
        EXPECT_EQ(Strength::checkPwnedPassword(password), Strength::BreachCheck::Found);
    }
    {
        CannedHttpServer server(httpOk(rangeBody(password, false)));
        Strength::setBreachEndpointForTesting(server.rangeEndpoint());
        EXPECT_EQ(Strength::checkPwnedPassword(password), Strength::BreachCheck::NotFound);
    }
}

// Offline, a password that passes the local policy is accepted; a breached one is still refused when the service
// answers. (The policy is off in test mode, so these turn it on for the duration.)
TEST(OfflineStartup, PasswordsCanBeSetOfflineAndBreachedOnesAreStillRefused) {
    NetworkGuard network;
    struct TestModeOff {
        bool previous = paths::testMode;
        TestModeOff() { paths::testMode = false; }
        ~TestModeOff() { paths::testMode = previous; }
    } policyOn;
    const std::string password = "hT3$documentRw9!pL2@xQ7kZ";

    const auto port = freeLoopbackPort();
    Strength::setBreachEndpointForTesting("http://127.0.0.1:" + std::to_string(port) + "/range/");
    EXPECT_FALSE(auth::registration::Validator::passwordPolicyViolation(password).has_value())
        << "an unreachable breach service must not block setting a password";

    CannedHttpServer server(httpOk(rangeBody(password, true)));
    Strength::setBreachEndpointForTesting(server.rangeEndpoint());
    const auto violation = auth::registration::Validator::passwordPolicyViolation(password);
    ASSERT_TRUE(violation.has_value());
    EXPECT_NE(violation->find("breaches"), std::string::npos);
}

}
