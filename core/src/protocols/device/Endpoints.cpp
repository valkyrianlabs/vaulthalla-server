#include "protocols/device/Endpoints.hpp"

#include "config/Registry.hpp"
#include "db/query/device/Device.hpp"
#include "platform/Network.hpp"
#include "protocols/device/Service.hpp"
#include "runtime/Manager.hpp"

#include <boost/asio/ip/address.hpp>

#include <arpa/inet.h>
#include <fnmatch.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <mutex>
#include <set>
#include <utility>

namespace vh::protocols::device::endpoints {

namespace {

namespace ip = boost::asio::ip;

std::mutex& enumeratorMutex() {
    static std::mutex m;
    return m;
}

std::function<std::vector<InterfaceAddress>()>& enumeratorOverride() {
    static std::function<std::vector<InterfaceAddress>()> f;
    return f;
}

std::optional<Kind> classifyV4(const ip::address_v4& a) noexcept {
    const auto b = a.to_bytes();
    if (b[0] == 127) return Kind::Loopback;
    if (b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168)) return Kind::Lan;
    if (b[0] == 100 && (b[1] & 0xC0) == 64) return Kind::Vpn;  // 100.64/10 (CGNAT: Tailscale and friends)
    if (b[0] == 0 || (b[0] == 169 && b[1] == 254) || b[0] >= 224) return std::nullopt;  // this-net, link-local, multicast, reserved
    return Kind::Wan;
}

std::optional<Kind> classifyV6(const ip::address_v6& a) noexcept {
    if (a.is_v4_mapped()) return classifyV4(ip::make_address_v4(ip::v4_mapped, a));
    if (a.is_loopback()) return Kind::Loopback;
    const auto b = a.to_bytes();
    if ((b[0] & 0xFE) == 0xFC) return Kind::Lan;                     // fc00::/7 (ULA)
    if ((b[0] & 0xE0) == 0x20) return Kind::Wan;                     // 2000::/3 (global unicast)
    return std::nullopt;  // unspecified, link-local fe80::/10, multicast, everything not unicast
}

bool vpnInterface(const std::string_view name) noexcept {
    for (const auto* glob : {"tailscale*", "wg*", "zt*", "utun*"})
        if (globMatch(glob, name)) return true;
    return false;
}

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::vector<InterfaceAddress> enumerateWithGetifaddrs() {
    std::vector<InterfaceAddress> out;
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0) return out;
    for (const auto* it = list; it; it = it->ifa_next) {
        if (!it->ifa_addr || !it->ifa_name || !(it->ifa_flags & IFF_UP)) continue;
        std::array<char, INET6_ADDRSTRLEN> text{};
        if (it->ifa_addr->sa_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(it->ifa_addr);
            if (!::inet_ntop(AF_INET, &sin->sin_addr, text.data(), text.size())) continue;
        } else if (it->ifa_addr->sa_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(it->ifa_addr);
            if (!::inet_ntop(AF_INET6, &sin6->sin6_addr, text.data(), text.size())) continue;
        } else {
            continue;
        }
        out.push_back({.interface = it->ifa_name, .address = text.data()});
    }
    ::freeifaddrs(list);
    return out;
}

// An address that a socket bound to it reports with a scope ("fe80::1%en0") loses the scope here; such addresses
// are never advertised anyway.
std::string bare(std::string_view address) {
    if (const auto pct = address.find('%'); pct != std::string_view::npos) address = address.substr(0, pct);
    return std::string(address);
}

std::mutex& contactMutex() {
    static std::mutex m;
    return m;
}

std::optional<RemoteContact>& contact() {
    static std::optional<RemoteContact> c;
    return c;
}

std::mutex& nodeIdMutex() {
    static std::mutex m;
    return m;
}

std::optional<std::string>& nodeIdCache() {
    static std::optional<std::string> v;
    return v;
}

}

std::string_view to_string(const Kind kind) noexcept {
    switch (kind) {
        case Kind::Loopback: return "loopback";
        case Kind::Lan: return "lan";
        case Kind::Vpn: return "vpn";
        case Kind::Wan: return "wan";
        case Kind::Passthrough: return "passthrough";
    }
    return "lan";
}

std::optional<Kind> kindFromString(const std::string_view text) noexcept {
    for (const auto k : {Kind::Loopback, Kind::Lan, Kind::Vpn, Kind::Wan, Kind::Passthrough})
        if (to_string(k) == text) return k;
    return std::nullopt;
}

std::vector<InterfaceAddress> enumerateInterfaces() {
    {
        std::scoped_lock lock(enumeratorMutex());
        if (enumeratorOverride()) return enumeratorOverride()();
    }
    return enumerateWithGetifaddrs();
}

void setInterfaceEnumeratorForTesting(std::function<std::vector<InterfaceAddress>()> enumerator) {
    std::scoped_lock lock(enumeratorMutex());
    enumeratorOverride() = std::move(enumerator);
}

bool globMatch(const std::string_view pattern, const std::string_view name) noexcept {
    const std::string p(pattern), n(name);
    return ::fnmatch(p.c_str(), n.c_str(), 0) == 0;
}

std::optional<Kind> classifyAddress(const std::string_view address) noexcept {
    boost::system::error_code ec;
    const auto parsed = ip::make_address(bare(address), ec);
    if (ec) return std::nullopt;
    return parsed.is_v4() ? classifyV4(parsed.to_v4()) : classifyV6(parsed.to_v6());
}

std::optional<Kind> classify(const std::string_view address, const std::string_view interfaceName,
                             const std::vector<std::string>& exclude) noexcept {
    for (const auto& glob : exclude)
        if (globMatch(glob, interfaceName)) return std::nullopt;
    const auto kind = classifyAddress(address);
    if (!kind) return std::nullopt;
    if (*kind != Kind::Loopback && vpnInterface(interfaceName)) return Kind::Vpn;
    return kind;
}

std::vector<Candidate> buildCandidates(const config::DeviceServerConfig& cfg, const Inputs& in) {
    const auto& adv = cfg.advertise;
    std::vector<Candidate> all;

    if (adv.interfaces) {
        for (const auto& ifa : in.interfaces) {
            const auto host = bare(ifa.address);
            boost::system::error_code ec;
            const auto parsed = ip::make_address(host, ec);
            if (ec) continue;
            const bool v6 = parsed.is_v6() && !parsed.to_v6().is_v4_mapped();
            if (v6 && (!adv.include_ipv6 || !in.ipv6)) continue;
            const auto kind = classify(host, ifa.interface, adv.exclude_interfaces);
            if (!kind || (!in.remote && *kind != Kind::Loopback)) continue;
            // Canonical text, so "::ffff:10.0.0.1" and "10.0.0.1" de-duplicate.
            const auto text = v6 ? parsed.to_v6().to_string()
                                 : (parsed.is_v6() ? ip::make_address_v4(ip::v4_mapped, parsed.to_v6()).to_string()
                                                   : parsed.to_v4().to_string());
            all.push_back({.host = text, .port = in.port, .kind = *kind, .source = "interface",
                           .interface = ifa.interface});
        }
    }
    if (in.remote && in.mdnsHost) all.push_back({.host = *in.mdnsHost, .port = in.port, .kind = Kind::Lan, .source = "mdns"});
    for (const auto& name : adv.hostnames)
        all.push_back({.host = name, .port = in.port, .kind = Kind::Lan, .source = "config"});
    for (const auto& e : adv.public_)
        all.push_back({.host = e.host, .port = e.port ? e.port : in.port, .kind = kindFromString(e.kind).value_or(Kind::Wan),
                       .source = "config"});

    std::set<std::pair<std::string, uint16_t>> seen;
    std::vector<Candidate> out;
    for (auto& c : all)
        if (seen.emplace(lower(c.host), c.port).second) out.push_back(std::move(c));
    std::ranges::stable_sort(out, {}, [](const Candidate& c) { return static_cast<int>(c.kind); });
    if (out.size() > kMaxCandidates) out.resize(kMaxCandidates);
    return out;
}

std::optional<std::string> mdnsHostname() {
    if (!platform::network::mdnsResponderAvailable()) return std::nullopt;
    std::array<char, 256> host{};
    if (::gethostname(host.data(), host.size() - 1) != 0) return std::nullopt;
    std::string name(host.data());
    if (const auto dot = name.find('.'); dot != std::string::npos) name.resize(dot);
    if (name.empty() || name == "localhost") return std::nullopt;
    return name + ".local";
}

Advertisement current() {
    const auto cfg = config::Registry::get().device_server;
    std::optional<ListenerStatus> status;
    if (const auto service = runtime::Manager::instance().getDeviceServer(); service && service->isRunning())
        status = service->listenerStatus();

    Advertisement out;
    out.remote = cfg.remote;
    out.listening = status && status->listening;
    out.port = out.listening && status->bound_port ? status->bound_port : cfg.port;
    out.generated_at = std::time(nullptr);
    out.candidates = buildCandidates(cfg, {.port = out.port, .remote = cfg.remote,
                                           .ipv6 = !out.listening || status->ipv6,
                                           .interfaces = cfg.advertise.interfaces ? enumerateInterfaces()
                                                                                  : std::vector<InterfaceAddress>{},
                                           .mdnsHost = cfg.remote ? mdnsHostname() : std::nullopt});
    return out;
}

std::string nodeId() {
    std::scoped_lock lock(nodeIdMutex());
    if (!nodeIdCache()) nodeIdCache() = db::query::device::Devices::nodeId();
    return *nodeIdCache();
}

void clearNodeIdForTesting() {
    std::scoped_lock lock(nodeIdMutex());
    nodeIdCache().reset();
}

void noteDeviceHandshake(const std::string_view address) {
    if (classifyAddress(address) != Kind::Wan) return;
    std::scoped_lock lock(contactMutex());
    contact() = RemoteContact{.at = std::time(nullptr), .ip = bare(address)};
}

std::optional<RemoteContact> lastRemoteDevice() {
    std::scoped_lock lock(contactMutex());
    return contact();
}

void clearLastRemoteDeviceForTesting() {
    std::scoped_lock lock(contactMutex());
    contact().reset();
}

}
