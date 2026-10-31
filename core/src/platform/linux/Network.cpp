#include "platform/Network.hpp"

#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

namespace vh::platform::network {

namespace {

std::filesystem::path under(const std::filesystem::path& root, const std::string_view absolute) {
    return root / std::filesystem::path(absolute).relative_path();
}

bool pathExists(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::exists(p, ec);
}

// ENABLED=yes|no in /etc/ufw/ufw.conf (world-readable); nullopt when the file can't be read or says neither.
std::optional<bool> ufwEnabled(const std::filesystem::path& root) {
    std::ifstream in(under(root, "/etc/ufw/ufw.conf"));
    if (!in) return std::nullopt;
    std::optional<bool> out;
    for (std::string line; std::getline(in, line);) {
        const auto start = line.find_first_not_of(" \t");
        if (start == std::string::npos || line[start] == '#') continue;
        std::string_view v(line);
        v.remove_prefix(start);
        if (!v.starts_with("ENABLED=")) continue;
        v.remove_prefix(8);
        while (!v.empty() && (v.back() == ' ' || v.back() == '\t' || v.back() == '\r')) v.remove_suffix(1);
        if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'') && v.back() == v.front()) v = v.substr(1, v.size() - 2);
        if (v == "yes") out = true;
        else if (v == "no") out = false;
    }
    return out;
}

bool nonEmptyFile(const std::filesystem::path& p) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(p, ec);
    return !ec && size > 0;
}

}

FirewallState detectFirewall(const uint16_t port, const std::filesystem::path& root) {
    const auto rule = std::to_string(port) + "/tcp";
    const auto ufw = ufwEnabled(root);
    if (ufw && *ufw) return {.detected = "ufw", .active = true, .hint = "sudo ufw allow " + rule};
    // firewalld writes its pid file while it runs and keeps its runtime state under /run/firewalld.
    if (pathExists(under(root, "/run/firewalld.pid")) || pathExists(under(root, "/var/run/firewalld.pid")) ||
        pathExists(under(root, "/run/firewalld")))
        return {.detected = "firewalld", .active = true,
                .hint = "sudo firewall-cmd --permanent --add-port=" + rule + " && sudo firewall-cmd --reload"};
    // nftables.service loads /etc/nftables.conf at boot when enabled (Debian and Ubuntu ship the file with the
    // service disabled). What is loaded now, and whether it filters input, needs root to read: active unknown.
    const bool nftEnabled = pathExists(under(root, "/etc/systemd/system/sysinit.target.wants/nftables.service")) ||
                            pathExists(under(root, "/etc/systemd/system/multi-user.target.wants/nftables.service"));
    if (nftEnabled && nonEmptyFile(under(root, "/etc/nftables.conf")))
        return {.detected = "nftables", .active = std::nullopt,
                .hint = "if the nftables ruleset filters input, accept tcp dport " + std::to_string(port)};
    if (ufw) return {.detected = "ufw", .active = false, .hint = std::nullopt};
    return {};
}

bool mdnsResponderAvailable(const std::filesystem::path& root) {
    return pathExists(under(root, "/run/avahi-daemon/pid"));
}

}
