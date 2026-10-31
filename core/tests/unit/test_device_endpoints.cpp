// Endpoint advertisement and the transfer lanes' policy, without a database (docs/reference/transfer-protocol.md
// §1, §4, §5): address classification by range and interface name, the candidate list (filtering, de-duplication,
// order, cap), the firewall probe on a fixture tree, device_server.advertise through YAML and JSON, the dual-stack
// listener, and the calibration helpers (slots, ?bytes=, the positioned random source).

#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "config/config_yaml.hpp"
#include "device/ServerIdentity.hpp"
#include "ops/Config.hpp"
#include "ops/Error.hpp"
#include "platform/Network.hpp"
#include "protocols/device/Endpoints.hpp"
#include "protocols/device/Listener.hpp"
#include "protocols/device/Transfer.hpp"
#include "protocols/ws/Router.hpp"
#include "storage/PlaintextReader.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <unistd.h>
#include <yaml-cpp/yaml.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_device_endpoints {

namespace fs = std::filesystem;
namespace ep = protocols::device::endpoints;
namespace transfer = protocols::device::transfer;
using json = nlohmann::json;
using Kind = ep::Kind;

// ---- classification -------------------------------------------------------------------------------------------

TEST(DeviceEndpoints, ClassifiesAddressesByRange) {
    struct Case {
        const char* address;
        std::optional<Kind> kind;
    };
    const std::vector<Case> cases = {
        {"127.0.0.1", Kind::Loopback},
        {"127.8.9.10", Kind::Loopback},
        {"::1", Kind::Loopback},
        {"10.0.0.11", Kind::Lan},
        {"172.16.0.1", Kind::Lan},
        {"172.31.255.255", Kind::Lan},
        {"172.32.0.1", Kind::Wan},
        {"172.15.0.1", Kind::Wan},
        {"192.168.1.20", Kind::Lan},
        {"100.64.0.1", Kind::Vpn},
        {"100.101.1.2", Kind::Vpn},
        {"100.127.255.255", Kind::Vpn},
        {"100.128.0.1", Kind::Wan},
        {"203.0.113.7", Kind::Wan},
        {"8.8.8.8", Kind::Wan},
        {"169.254.10.1", std::nullopt},
        {"0.0.0.0", std::nullopt},
        {"224.0.0.251", std::nullopt},
        {"255.255.255.255", std::nullopt},
        {"fd00::11", Kind::Lan},
        {"fc12:3456::1", Kind::Lan},
        {"fd7a:115c:a1e0::1", Kind::Lan},
        {"2001:db8::7", Kind::Wan},
        {"2606:4700::1111", Kind::Wan},
        {"fe80::1", std::nullopt},
        {"fe80::1%en0", std::nullopt},
        {"::", std::nullopt},
        {"ff02::fb", std::nullopt},
        {"::ffff:10.0.0.11", Kind::Lan},
        {"::ffff:127.0.0.1", Kind::Loopback},
        {"::ffff:203.0.113.7", Kind::Wan},
        {"not-an-address", std::nullopt},
        {"", std::nullopt},
    };
    for (const auto& c : cases) EXPECT_EQ(ep::classifyAddress(c.address), c.kind) << c.address;
}

TEST(DeviceEndpoints, InterfaceNamesMakeVpnAndExcludeGlobsDrop) {
    const std::vector<std::string> exclude = config::DeviceAdvertiseConfig{}.exclude_interfaces;
    struct Case {
        const char* address;
        const char* interface;
        std::optional<Kind> kind;
    };
    const std::vector<Case> cases = {
        {"10.0.0.11", "enp3s0", Kind::Lan},
        {"10.8.0.2", "wg0", Kind::Vpn},
        {"203.0.113.9", "wg-home", Kind::Vpn},
        {"100.101.1.2", "tailscale0", Kind::Vpn},
        {"fd7a:115c:a1e0::5", "tailscale0", Kind::Vpn},
        {"10.147.17.3", "ztabcdef12", Kind::Vpn},
        {"fd00::5", "utun4", Kind::Vpn},
        {"127.0.0.1", "wg0", Kind::Loopback},
        {"172.17.0.1", "docker0", std::nullopt},
        {"172.18.0.1", "br-1a2b3c", std::nullopt},
        {"10.88.0.1", "podman0", std::nullopt},
        {"192.168.122.1", "virbr0", std::nullopt},
        {"10.0.0.1", "veth12ab", std::nullopt},
        {"10.0.0.1", "lxcbr0", std::nullopt},
        {"192.168.1.20", "en0", Kind::Lan},
        {"fe80::1", "en0", std::nullopt},
    };
    for (const auto& c : cases)
        EXPECT_EQ(ep::classify(c.address, c.interface, exclude), c.kind) << c.address << " on " << c.interface;
    EXPECT_EQ(ep::classify("10.0.0.11", "enp3s0", {"enp*"}), std::nullopt) << "an operator's own glob";
}

TEST(DeviceEndpoints, Globs) {
    EXPECT_TRUE(ep::globMatch("docker*", "docker0"));
    EXPECT_TRUE(ep::globMatch("br-*", "br-"));
    EXPECT_FALSE(ep::globMatch("br-*", "bridge0"));
    EXPECT_TRUE(ep::globMatch("eth?", "eth1"));
    EXPECT_FALSE(ep::globMatch("eth?", "eth10"));
    EXPECT_TRUE(ep::globMatch("en[0-3]", "en2"));
    EXPECT_FALSE(ep::globMatch("en[0-3]", "en7"));
}

TEST(DeviceEndpoints, KindNamesRoundTrip) {
    for (const auto k : {Kind::Loopback, Kind::Lan, Kind::Vpn, Kind::Wan, Kind::Passthrough})
        EXPECT_EQ(ep::kindFromString(ep::to_string(k)), k);
    EXPECT_EQ(ep::kindFromString("public"), std::nullopt);
}

// ---- the candidate list ---------------------------------------------------------------------------------------

std::vector<ep::InterfaceAddress> hostInterfaces() {
    return {{"lo", "127.0.0.1"},          {"lo", "::1"},
            {"enp3s0", "10.0.0.11"},      {"enp3s0", "fd00::11"},
            {"enp3s0", "fe80::1234"},     {"enp3s0", "2001:db8::11"},
            {"tailscale0", "100.101.1.2"}, {"docker0", "172.17.0.1"},
            {"wan0", "203.0.113.7"},      {"enp3s0", "10.0.0.11"}};
}

std::vector<std::string> hosts(const std::vector<ep::Candidate>& list) {
    std::vector<std::string> out;
    for (const auto& c : list) out.push_back(c.host + ":" + std::to_string(c.port));
    return out;
}

TEST(DeviceEndpoints, RemoteListIsOrderedDeduplicatedAndFiltered) {
    config::DeviceServerConfig cfg;
    cfg.remote = true;
    cfg.advertise.hostnames = {"nas.home.arpa", "NAS.home.arpa"};
    cfg.advertise.public_ = {{.host = "device.example.com", .port = 36972, .kind = "wan"},
                             {.host = "device.example.com", .port = 443, .kind = "passthrough"},
                             {.host = "10.0.0.11", .port = 0, .kind = "lan"}};
    const auto list = ep::buildCandidates(cfg, {.port = 36972, .remote = true, .ipv6 = true,
                                                .interfaces = hostInterfaces(), .mdnsHost = "vh-storage.local"});
    EXPECT_EQ(hosts(list), (std::vector<std::string>{
                               "127.0.0.1:36972", "::1:36972", "10.0.0.11:36972", "fd00::11:36972",
                               "vh-storage.local:36972", "nas.home.arpa:36972", "100.101.1.2:36972",
                               "2001:db8::11:36972", "203.0.113.7:36972", "device.example.com:36972",
                               "device.example.com:443"}));
    EXPECT_EQ(list.at(0).kind, Kind::Loopback);
    EXPECT_EQ(list.at(0).source, "interface");
    EXPECT_EQ(list.at(0).interface, "lo");
    EXPECT_EQ(list.at(4).source, "mdns");
    EXPECT_FALSE(list.at(4).interface);
    EXPECT_EQ(list.at(5).source, "config");
    EXPECT_EQ(list.at(6).kind, Kind::Vpn);
    EXPECT_EQ(list.back().kind, Kind::Passthrough);
}

TEST(DeviceEndpoints, LoopbackOnlyListsLoopbackAndConfiguredNames) {
    config::DeviceServerConfig cfg;
    cfg.advertise.public_ = {{.host = "tunnel.example.com", .port = 8443, .kind = "wan"}};
    const auto list = ep::buildCandidates(cfg, {.port = 36972, .remote = false, .ipv6 = true,
                                                .interfaces = hostInterfaces(), .mdnsHost = "vh-storage.local"});
    EXPECT_EQ(hosts(list), (std::vector<std::string>{"127.0.0.1:36972", "::1:36972", "tunnel.example.com:8443"}));
}

TEST(DeviceEndpoints, Ipv6SwitchesAndInterfaceSwitch) {
    config::DeviceServerConfig cfg;
    cfg.advertise.include_ipv6 = false;
    auto list = ep::buildCandidates(cfg, {.port = 1, .remote = true, .ipv6 = true, .interfaces = hostInterfaces()});
    EXPECT_EQ(hosts(list), (std::vector<std::string>{"127.0.0.1:1", "10.0.0.11:1", "100.101.1.2:1", "203.0.113.7:1"}));

    cfg.advertise.include_ipv6 = true;
    list = ep::buildCandidates(cfg, {.port = 1, .remote = true, .ipv6 = false, .interfaces = hostInterfaces()});
    EXPECT_EQ(hosts(list), (std::vector<std::string>{"127.0.0.1:1", "10.0.0.11:1", "100.101.1.2:1", "203.0.113.7:1"}))
        << "no IPv6 socket bound: IPv6 addresses can't be reached";

    cfg.advertise.interfaces = false;
    cfg.advertise.hostnames = {"nas.lan"};
    list = ep::buildCandidates(cfg, {.port = 1, .remote = true, .ipv6 = true, .interfaces = hostInterfaces()});
    EXPECT_EQ(hosts(list), (std::vector<std::string>{"nas.lan:1"}));
}

TEST(DeviceEndpoints, ListIsCappedAt32) {
    config::DeviceServerConfig cfg;
    for (int i = 0; i < 40; ++i) cfg.advertise.hostnames.push_back("host" + std::to_string(i) + ".lan");
    const auto list = ep::buildCandidates(cfg, {.port = 1, .remote = true, .interfaces = hostInterfaces()});
    EXPECT_EQ(list.size(), ep::kMaxCandidates);
    EXPECT_EQ(list.front().host, "127.0.0.1");
}

TEST(DeviceEndpoints, InjectedEnumeratorAndCurrent) {
    ep::setInterfaceEnumeratorForTesting([] { return hostInterfaces(); });
    EXPECT_EQ(ep::enumerateInterfaces().size(), hostInterfaces().size());
    const auto before = config::Registry::get();
    auto cfg = before;
    cfg.device_server.remote = false;
    cfg.device_server.port = 40001;
    config::Registry::set(cfg);
    const auto adv = ep::current();
    EXPECT_FALSE(adv.listening) << "no DeviceServer runs in this process";
    EXPECT_EQ(adv.port, 40001);
    EXPECT_EQ(hosts(adv.candidates), (std::vector<std::string>{"127.0.0.1:40001", "::1:40001"}));
    EXPECT_GT(adv.generated_at, 0);
    config::Registry::set(before);
    ep::setInterfaceEnumeratorForTesting({});
}

TEST(DeviceEndpoints, RealInterfacesIncludeLoopback) {
    const auto all = ep::enumerateInterfaces();
    EXPECT_TRUE(std::ranges::any_of(all, [](const ep::InterfaceAddress& a) { return a.address == "127.0.0.1"; }));
    for (const auto& a : all) EXPECT_EQ(a.address.find('%'), std::string::npos) << a.address;
}

TEST(DeviceEndpoints, LastRemoteDeviceRecordsOnlyPublicSources) {
    ep::clearLastRemoteDeviceForTesting();
    for (const auto* a : {"127.0.0.1", "10.0.0.5", "100.100.1.1", "fd00::5", "192.168.1.9"}) ep::noteDeviceHandshake(a);
    EXPECT_FALSE(ep::lastRemoteDevice());
    ep::noteDeviceHandshake("203.0.113.7");
    ASSERT_TRUE(ep::lastRemoteDevice());
    EXPECT_EQ(ep::lastRemoteDevice()->ip, "203.0.113.7");
    EXPECT_GT(ep::lastRemoteDevice()->at, 0);
    ep::noteDeviceHandshake("10.0.0.5");
    EXPECT_EQ(ep::lastRemoteDevice()->ip, "203.0.113.7") << "a later private handshake doesn't replace it";
    ep::clearLastRemoteDeviceForTesting();
}

// ---- firewall (read-only, unknown stays unknown) --------------------------------------------------------------

#if defined(__linux__)
class FirewallFixture : public ::testing::Test {
protected:
    void SetUp() override {
        root_ = fs::temp_directory_path() / ("vh-fw-" + std::to_string(::getpid()) + "-" +
                                              ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(root_);
        fs::create_directories(root_);
    }
    void TearDown() override { fs::remove_all(root_); }
    void write(const std::string& rel, const std::string& text) {
        fs::create_directories((root_ / rel).parent_path());
        std::ofstream(root_ / rel) << text;
    }
    fs::path root_;
};

TEST_F(FirewallFixture, NothingKnownIsUnknown) {
    const auto s = platform::network::detectFirewall(36972, root_);
    EXPECT_EQ(s.detected, "unknown");
    EXPECT_FALSE(s.active);
    EXPECT_FALSE(s.hint);
}

TEST_F(FirewallFixture, UfwEnabledGivesTheRule) {
    write("etc/ufw/ufw.conf", "# comment\nENABLED=yes\nLOGLEVEL=low\n");
    const auto s = platform::network::detectFirewall(36972, root_);
    EXPECT_EQ(s.detected, "ufw");
    EXPECT_EQ(s.active, true);
    EXPECT_EQ(s.hint, "sudo ufw allow 36972/tcp");
}

TEST_F(FirewallFixture, UfwDisabledAloneIsInactive) {
    write("etc/ufw/ufw.conf", "ENABLED=no\n");
    const auto s = platform::network::detectFirewall(36972, root_);
    EXPECT_EQ(s.detected, "ufw");
    EXPECT_EQ(s.active, false);
    EXPECT_FALSE(s.hint);
}

TEST_F(FirewallFixture, FirewalldRunning) {
    write("etc/ufw/ufw.conf", "ENABLED=no\n");
    write("run/firewalld.pid", "123\n");
    const auto s = platform::network::detectFirewall(40000, root_);
    EXPECT_EQ(s.detected, "firewalld");
    EXPECT_EQ(s.active, true);
    ASSERT_TRUE(s.hint);
    EXPECT_NE(s.hint->find("--add-port=40000/tcp"), std::string::npos);
}

TEST_F(FirewallFixture, NftablesOnlyWhenTheServiceIsEnabled) {
    write("etc/nftables.conf", "flush ruleset\n");
    EXPECT_EQ(platform::network::detectFirewall(36972, root_).detected, "unknown")
        << "Debian/Ubuntu ship the file with the service disabled";
    write("etc/systemd/system/sysinit.target.wants/nftables.service", "");
    const auto s = platform::network::detectFirewall(36972, root_);
    EXPECT_EQ(s.detected, "nftables");
    EXPECT_FALSE(s.active) << "what is loaded needs root to read";
    EXPECT_TRUE(s.hint);
}

TEST_F(FirewallFixture, AvahiMakesMdnsAvailable) {
    EXPECT_FALSE(platform::network::mdnsResponderAvailable(root_));
    write("run/avahi-daemon/pid", "77\n");
    EXPECT_TRUE(platform::network::mdnsResponderAvailable(root_));
}
#endif

#if defined(__APPLE__)
TEST(DeviceFirewall, ApplicationFirewallIsReadOrUnknown) {
    const auto s = platform::network::detectFirewall(36972);
    EXPECT_TRUE(s.detected == "alf" || s.detected == "unknown") << s.detected;
    if (s.detected == "alf") {
        EXPECT_TRUE(s.active.has_value());
    }
    EXPECT_TRUE(platform::network::mdnsResponderAvailable());
    EXPECT_EQ(platform::network::detectFirewall(36972, "/nonexistent-root").detected, "unknown");
}
#endif

// ---- device_server.advertise ----------------------------------------------------------------------------------

class AdvertiseConfigTest : public ::testing::Test {
protected:
    config::Config load(const std::string& yaml) {
        path_ = fs::temp_directory_path() / ("vh-advertise-" + std::to_string(::getpid()) + ".yaml");
        std::ofstream(path_) << yaml;
        return config::loadConfig(path_.string());
    }
    void TearDown() override {
        if (!path_.empty()) fs::remove(path_);
    }
    fs::path path_;
};

TEST_F(AdvertiseConfigTest, AbsentSectionKeepsTheDefaults) {
    const auto cfg = load("device_server:\n  remote: true\n");
    const config::DeviceAdvertiseConfig defaults;
    EXPECT_TRUE(cfg.device_server.advertise.interfaces);
    EXPECT_TRUE(cfg.device_server.advertise.include_ipv6);
    EXPECT_EQ(cfg.device_server.advertise.exclude_interfaces, defaults.exclude_interfaces);
    EXPECT_TRUE(cfg.device_server.advertise.hostnames.empty());
    EXPECT_TRUE(cfg.device_server.advertise.public_.empty());
}

TEST_F(AdvertiseConfigTest, ParsesAndRoundTrips) {
    const auto cfg = load(R"(device_server:
  advertise:
    include_ipv6: false
    exclude_interfaces: ["docker*"]
    hostnames: [nas.home.arpa]
    public:
      - {host: device.example.com, port: 36972}
      - {host: device.example.com, port: 443, kind: passthrough}
      - {host: "[2001:db8::5]"}
)");
    const auto& a = cfg.device_server.advertise;
    EXPECT_FALSE(a.include_ipv6);
    EXPECT_EQ(a.exclude_interfaces, std::vector<std::string>{"docker*"});
    EXPECT_EQ(a.hostnames, std::vector<std::string>{"nas.home.arpa"});
    ASSERT_EQ(a.public_.size(), 3u);
    EXPECT_EQ(a.public_[0].kind, "wan");
    EXPECT_EQ(a.public_[1].port, 443);
    EXPECT_EQ(a.public_[1].kind, "passthrough");
    EXPECT_EQ(a.public_[2].host, "2001:db8::5") << "stored unbracketed";
    EXPECT_EQ(a.public_[2].port, 0) << "the listener's port";

    // YAML (Config::save) and JSON (settings.get / settings.update) both round-trip it.
    config::DeviceServerConfig back;
    ASSERT_TRUE(YAML::convert<config::DeviceServerConfig>::decode(
        YAML::Load(YAML::Dump(YAML::convert<config::DeviceServerConfig>::encode(cfg.device_server))), back));
    EXPECT_EQ(json(back), json(cfg.device_server));
    const json doc = cfg.device_server;
    EXPECT_EQ(doc.at("advertise").at("public").at(1).at("kind"), "passthrough");
    EXPECT_EQ(json(doc.get<config::DeviceServerConfig>()), doc);
    // A settings document from before advertise existed keeps the defaults.
    json old = doc;
    old.erase("advertise");
    EXPECT_EQ(json(old.get<config::DeviceServerConfig>().advertise), json(config::DeviceAdvertiseConfig{}));
}

TEST_F(AdvertiseConfigTest, MalformedEntriesRefuseToLoad) {
    EXPECT_THROW(load("device_server:\n  advertise:\n    public: [{host: a.example.com, kind: public}]\n"),
                 std::exception);
    EXPECT_THROW(load("device_server:\n  advertise:\n    public: [{host: \"https://a.example.com\"}]\n"),
                 std::exception);
    EXPECT_THROW(load("device_server:\n  advertise:\n    public: [{port: 443}]\n"), std::exception);
    EXPECT_THROW(load("device_server:\n  advertise:\n    hostnames: [\"nas lan\"]\n"), std::exception);
    EXPECT_THROW(load("device_server:\n  advertise:\n    exclude_interfaces: [\"\"]\n"), std::exception);
    EXPECT_THROW(load("device_server:\n  advertise:\n    public: {host: x}\n"), std::exception);
}

TEST(AdvertiseSettings, SettingsUpdateRefusesMalformedEntries) {
    json doc = config::Registry::get();
    doc["device_server"]["advertise"]["public"] = json::array({{{"host", "a.example.com"}, {"kind", "public"}}});
    EXPECT_THROW(ops::config::validateSettings(doc), ops::Invalid);
    doc["device_server"]["advertise"]["public"] = json::array({{{"host", "a.example.com"}, {"port", 443},
                                                               {"kind", "passthrough"}}});
    EXPECT_NO_THROW(ops::config::validateSettings(doc));
}

TEST(AdvertiseShippedConfig, ShipsTheDefaults) {
    const auto path = fs::path(VH_TEST_ASSETS_DIR).parent_path().parent_path() / "deploy" / "config" / "config.yaml";
    ASSERT_TRUE(fs::exists(path)) << path;
    const auto cfg = config::loadConfig(path.string());
    EXPECT_EQ(json(cfg.device_server.advertise), json(config::DeviceAdvertiseConfig{}));
}

// ---- the listener binds dual-stack ----------------------------------------------------------------------------

bool tcpConnects(const std::string& host, const uint16_t port) {
    boost::asio::io_context ioc;
    boost::asio::ip::tcp::socket socket(ioc);
    boost::system::error_code ec;
    socket.connect({boost::asio::ip::make_address(host), port}, ec);
    return !ec;
}

bool ipv6Available() {
    boost::asio::io_context ioc;
    boost::asio::ip::tcp::acceptor probe(ioc);
    boost::system::error_code ec;
    probe.open(boost::asio::ip::tcp::v6(), ec);
    if (!ec) probe.bind({boost::asio::ip::address_v6::loopback(), 0}, ec);
    return !ec;
}

TEST(DeviceListenerBinding, WildcardIpv6IsDualStackAndLoopbackAddsV6) {
    if (!ipv6Available()) GTEST_SKIP() << "no IPv6 on this host";
    const auto server = vh::device::ServerIdentity::generate();
    boost::asio::io_context ioc;
    auto guard = boost::asio::make_work_guard(ioc);
    std::thread runner([&] { ioc.run(); });
    auto listener = std::make_shared<protocols::device::Listener>(ioc, protocols::device::makeServerContext(*server),
                                                                  std::make_shared<protocols::ws::Router>(), 8);

    listener->listen({boost::asio::ip::address_v6::any(), 0});
    auto port = listener->localEndpoint().port();
    ASSERT_NE(port, 0);
    EXPECT_TRUE(tcpConnects("127.0.0.1", port)) << "[::] takes IPv4 too";
    EXPECT_TRUE(tcpConnects("::1", port));

    listener->listen({boost::asio::ip::address_v4::loopback(), 0});
    port = listener->localEndpoint().port();
    listener->listenAlso({boost::asio::ip::address_v6::loopback(), port});
    const auto bound = listener->localEndpoints();
    ASSERT_EQ(bound.size(), 2u);
    EXPECT_EQ(bound[1].port(), port) << "both loopback sockets share the port";
    EXPECT_TRUE(tcpConnects("127.0.0.1", port));
    EXPECT_TRUE(tcpConnects("::1", port));

    listener->close();
    EXPECT_TRUE(listener->localEndpoints().empty());
    EXPECT_FALSE(tcpConnects("127.0.0.1", port));
    guard.reset();
    ioc.stop();
    runner.join();
}

// ---- transfer lanes: the policy half --------------------------------------------------------------------------

TEST(DeviceTransfer, TargetsAndBytes) {
    EXPECT_TRUE(transfer::isTarget("/transfer/probe"));
    EXPECT_TRUE(transfer::isTarget("/transfer/source?bytes=1"));
    EXPECT_TRUE(transfer::isTarget("/transfer"));
    EXPECT_FALSE(transfer::isTarget("/transferx"));
    EXPECT_FALSE(transfer::isTarget("/upload/transfer"));

    EXPECT_EQ(transfer::sourceBytes("/transfer/source?bytes=0"), 0u);
    EXPECT_EQ(transfer::sourceBytes("/transfer/source?x=1&bytes=1048576"), 1048576u);
    EXPECT_EQ(transfer::sourceBytes("/transfer/source?bytes=268435456"), transfer::kMaxBytes);
    EXPECT_EQ(transfer::sourceBytes("/transfer/source?bytes=268435457"), std::nullopt);
    EXPECT_EQ(transfer::sourceBytes("/transfer/source?bytes=-1"), std::nullopt);
    EXPECT_EQ(transfer::sourceBytes("/transfer/source?bytes=1e6"), std::nullopt);
    EXPECT_EQ(transfer::sourceBytes("/transfer/source?bytes="), std::nullopt);
    EXPECT_EQ(transfer::sourceBytes("/transfer/source"), std::nullopt);
}

TEST(DeviceTransfer, AtMostTwoCalibrationsPerDevice) {
    auto a = transfer::acquire(9001);
    auto b = transfer::acquire(9001);
    ASSERT_TRUE(a && b);
    EXPECT_FALSE(transfer::acquire(9001));
    EXPECT_TRUE(transfer::acquire(9002)) << "per device";
    EXPECT_EQ(transfer::inFlightForTesting(9001), 2u);
    a.reset();
    auto c = transfer::acquire(9001);
    EXPECT_TRUE(c);
    b.reset();
    c.reset();
    EXPECT_EQ(transfer::inFlightForTesting(9001), 0u);
}

TEST(DeviceTransfer, RandomSourceIsPositionedAndExact) {
    const auto reader = transfer::randomSource(1000, 42);
    EXPECT_EQ(reader->size(), 1000u);
    std::vector<uint8_t> whole(1000);
    ASSERT_EQ(reader->read(0, whole), 1000u);
    std::vector<uint8_t> part(37);
    ASSERT_EQ(reader->read(501, part), 37u);
    EXPECT_TRUE(std::equal(part.begin(), part.end(), whole.begin() + 501)) << "any offset, same bytes";
    std::vector<uint8_t> tail(64);
    EXPECT_EQ(reader->read(990, tail), 10u);
    EXPECT_EQ(reader->read(1000, tail), 0u);
    // Not a constant fill.
    EXPECT_GT(std::ranges::count_if(whole, [&](const uint8_t b) { return b != whole[0]; }), 900);
    std::vector<uint8_t> other(1000);
    (void)transfer::randomSource(1000, 43)->read(0, other);
    EXPECT_NE(other, whole);
}

}
