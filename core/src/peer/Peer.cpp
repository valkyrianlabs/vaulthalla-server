#include "peer/Peer.hpp"

#include "device/Device.hpp"
#include "ops/Error.hpp"

#include <nlohmann/json.hpp>

#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <cctype>
#include <set>

namespace vh::peer {

namespace {

namespace dc = vh::device::crypto;
using json = nlohmann::json;

bool printableAscii(const std::string& s) {
    return std::ranges::all_of(s, [](const unsigned char c) { return c >= 0x20 && c < 0x7f; });
}

std::string key64(const Key32& k) { return dc::toBase64(k); }

Key32 keyFrom(const json& v, const std::string& what) {
    if (!v.is_string()) throw ops::Invalid(what + " must be a base64 string");
    const auto raw = dc::fromBase64(v.get<std::string>());
    if (!raw || raw->size() != kKeyBytes) throw ops::Invalid(what + " must be 32 bytes in standard base64");
    Key32 out{};
    std::ranges::copy(*raw, out.begin());
    return out;
}

std::string requiredString(const json& j, const char* key) {
    if (!j.is_object() || !j.contains(key) || !j.at(key).is_string())
        throw ops::Invalid(std::string("card.") + key + " is required (a string)");
    return j.at(key).get<std::string>();
}

json optTime(const std::optional<std::time_t>& t) { return t ? json(static_cast<int64_t>(*t)) : json(nullptr); }

bool validKind(const std::string& k) {
    for (const auto* allowed : {"loopback", "lan", "vpn", "wan", "passthrough", "manual"})
        if (k == allowed) return true;
    return false;
}

bool validHost(const std::string& h) {
    if (h.empty() || h.size() > 253) return false;
    return std::ranges::all_of(h, [](const unsigned char c) {
        return c > 0x20 && c < 0x7f && c != '/' && c != '@' && c != '?' && c != '#';
    });
}

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

}

json toJson(const Card& card) {
    json keys = json::array();
    for (const auto& k : card.attest_public_keys) keys.push_back(key64(k));
    return {{"node_id", card.node_id},
            {"name", card.name},
            {"attest_public_keys", std::move(keys)},
            {"wrap_public_key", key64(card.wrap_public_key)},
            {"peer_protocol", card.peer_protocol},
            {"product_version", card.product_version}};
}

Card cardFromJson(const json& j) {
    if (!j.is_object()) throw ops::Invalid("card must be an object");
    Card card;
    card.node_id = requiredString(j, "node_id");
    if (card.node_id.empty() || card.node_id.size() > 64 || !printableAscii(card.node_id))
        throw ops::Invalid("card.node_id must be 1-64 printable ASCII characters");
    const auto name = vh::device::normalizeDeviceName(requiredString(j, "name"));
    if (!name) throw ops::Invalid("card.name must be 1-64 characters without control characters");
    card.name = *name;
    if (!j.contains("attest_public_keys") || !j.at("attest_public_keys").is_array())
        throw ops::Invalid("card.attest_public_keys is required (an array of base64 keys)");
    const auto& keys = j.at("attest_public_keys");
    if (keys.size() > kMaxAttestKeys) throw ops::Invalid("card.attest_public_keys holds at most 64 keys");
    std::set<Key32> seen;
    for (const auto& k : keys) {
        auto key = keyFrom(k, "card.attest_public_keys[]");
        if (!seen.insert(key).second) throw ops::Invalid("card.attest_public_keys lists a key twice");
        card.attest_public_keys.push_back(key);
    }
    if (!j.contains("wrap_public_key")) throw ops::Invalid("card.wrap_public_key is required");
    card.wrap_public_key = keyFrom(j.at("wrap_public_key"), "card.wrap_public_key");
    if (!j.contains("peer_protocol") || !j.at("peer_protocol").is_number_integer() ||
        j.at("peer_protocol").get<int64_t>() < 1 || j.at("peer_protocol").get<int64_t>() > 65535)
        throw ops::Invalid("card.peer_protocol must be an integer 1-65535");
    card.peer_protocol = j.at("peer_protocol").get<uint32_t>();
    card.product_version = requiredString(j, "product_version");
    if (card.product_version.size() > 64 || !printableAscii(card.product_version))
        throw ops::Invalid("card.product_version must be at most 64 printable ASCII characters");
    return card;
}

json toJson(const std::vector<Endpoint>& endpoints) {
    json out = json::array();
    for (const auto& e : endpoints) out.push_back({{"host", e.host}, {"port", e.port}, {"kind", e.kind}});
    return out;
}

std::vector<Endpoint> endpointsFromJson(const json& j) {
    if (!j.is_array()) throw ops::Invalid("endpoints must be an array of {host, port}");
    if (j.size() > kMaxEndpoints) throw ops::Invalid("endpoints holds at most 32 entries");
    std::vector<Endpoint> out;
    std::set<std::pair<std::string, uint16_t>> seen;
    for (const auto& item : j) {
        if (!item.is_object() || !item.contains("host") || !item.at("host").is_string() || !item.contains("port") ||
            !item.at("port").is_number_integer())
            throw ops::Invalid("each endpoint is {host, port}");
        Endpoint e{.host = item.at("host").get<std::string>(), .port = 0, .kind = "manual"};
        const auto port = item.at("port").get<int64_t>();
        if (!validHost(e.host) || port < 1 || port > 65535)
            throw ops::Invalid("an endpoint's host is 1-253 characters (no spaces) and its port 1-65535");
        e.port = static_cast<uint16_t>(port);
        if (item.contains("kind") && !item.at("kind").is_null()) {
            if (!item.at("kind").is_string() || !validKind(item.at("kind").get<std::string>()))
                throw ops::Invalid("an endpoint's kind is loopback, lan, vpn, wan, passthrough or manual");
            e.kind = item.at("kind").get<std::string>();
        }
        if (seen.emplace(lower(e.host), e.port).second) out.push_back(std::move(e));
    }
    return out;
}

std::optional<Endpoint> parseAddress(const std::string& text, const uint16_t defaultPort) {
    std::string host = text, port;
    if (text.starts_with("[")) {
        const auto close = text.find(']');
        if (close == std::string::npos) return std::nullopt;
        host = text.substr(1, close - 1);
        if (close + 1 < text.size()) {
            if (text[close + 1] != ':' || close + 2 >= text.size()) return std::nullopt;
            port = text.substr(close + 2);
        }
        boost::system::error_code ec;
        (void)boost::asio::ip::make_address_v6(host, ec);
        if (ec) return std::nullopt;
    } else if (const auto colon = text.find(':'); colon != std::string::npos) {
        if (text.find(':', colon + 1) != std::string::npos) {
            // A bare IPv6 literal: no port.
            boost::system::error_code ec;
            (void)boost::asio::ip::make_address_v6(text, ec);
            if (ec) return std::nullopt;
        } else {
            host = text.substr(0, colon);
            port = text.substr(colon + 1);
            if (port.empty()) return std::nullopt;
        }
    }
    if (!validHost(host)) return std::nullopt;
    uint32_t value = defaultPort;
    if (!port.empty()) {
        if (port.size() > 5 || !std::ranges::all_of(port, [](const unsigned char c) { return std::isdigit(c) != 0; }))
            return std::nullopt;
        value = static_cast<uint32_t>(std::stoul(port));
    }
    if (value < 1 || value > 65535) return std::nullopt;
    return Endpoint{.host = host, .port = static_cast<uint16_t>(value), .kind = "manual"};
}

std::string toString(const Endpoint& e) {
    const bool v6 = e.host.find(':') != std::string::npos;
    return (v6 ? "[" + e.host + "]" : e.host) + ":" + std::to_string(e.port);
}

void to_json(json& j, const Record& r) {
    json keys = json::array();
    for (const auto& k : r.attest_public_keys) keys.push_back(key64(k));
    j = {{"id", r.id},
         {"node_id", r.node_id},
         {"name", r.name},
         {"spki_sha256", r.spki_sha256},
         {"next_spki_sha256", r.next_spki_sha256 ? json(*r.next_spki_sha256) : json(nullptr)},
         {"attest_public_keys", std::move(keys)},
         {"wrap_public_key", key64(r.wrap_public_key)},
         {"endpoints", toJson(r.endpoints)},
         {"sharing", r.sharing},
         {"approved_by", r.approved_by ? json(*r.approved_by) : json(nullptr)},
         {"compared_by", r.compared_by},
         {"peer_protocol", r.peer_protocol},
         {"product_version", r.product_version},
         {"linked_at", static_cast<int64_t>(r.linked_at)},
         {"last_seen_at", optTime(r.last_seen_at)},
         {"revoked_at", optTime(r.revoked_at)},
         {"revoked", r.revoked()}};
}

std::optional<dc::PublicKey> pinnedKeyOf(const Record& row, const X509* leaf) {
    if (!leaf) return std::nullopt;
    auto key = dc::p256KeyOf(leaf);
    if (!key) return std::nullopt;
    const auto hex = dc::toHex(key->spkiSha256);
    if (hex != row.spki_sha256 && (!row.next_spki_sha256 || hex != *row.next_spki_sha256)) return std::nullopt;
    return key;
}

}
