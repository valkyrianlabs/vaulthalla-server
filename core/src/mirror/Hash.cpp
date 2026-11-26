#include "mirror/Hash.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <optional>
#include <stdexcept>

namespace vh::mirror {

namespace {

// state #>> '{a,b}': the value at a dotted path, or nullptr when a step is missing or not an object.
const nlohmann::json* at(const nlohmann::json& state, const std::string_view field) {
    const nlohmann::json* node = &state;
    std::size_t start = 0;
    while (true) {
        const auto dot = field.find('.', start);
        const auto key = field.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
        if (!node->is_object()) return nullptr;
        const auto it = node->find(std::string(key));
        if (it == node->end()) return nullptr;
        node = &*it;
        if (dot == std::string_view::npos) return node;
        start = dot + 1;
    }
}

// As PostgreSQL's #>> prints a scalar.
std::optional<std::string> text(const nlohmann::json& v) {
    if (v.is_null()) return std::nullopt;
    if (v.is_string()) return v.get<std::string>();
    if (v.is_boolean()) return v.get<bool>() ? "true" : "false";
    if (v.is_number_unsigned()) return std::to_string(v.get<uint64_t>());
    if (v.is_number_integer()) return std::to_string(v.get<int64_t>());
    return v.dump();
}

uint64_t word(const Hash& h, const std::size_t k) {
    uint64_t w = 0;
    for (std::size_t i = 0; i < 8; ++i) w = (w << 8) | h[8 * k + i];
    return w;
}

int nibble(const char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}

std::string canonicalEncoding(const nlohmann::json& state) {
    std::string out(kEntryHashDomain);
    out += '\n';
    for (const auto field : kEntryHashFields) {
        out += field;
        out += '=';
        const auto* v = at(state, field);
        if (const auto value = v ? text(*v) : std::nullopt) {
            out += std::to_string(value->size());
            out += ':';
            out += *value;
        } else {
            out += '-';
        }
        out += '\n';
    }
    return out;
}

Hash entryHash(const nlohmann::json& state) {
    const auto encoded = canonicalEncoding(state);
    Hash h{};
    crypto_hash_sha256(h.data(), reinterpret_cast<const unsigned char*>(encoded.data()), encoded.size());
    return h;
}

std::string toHex(const std::span<const uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

Hash hashFromHex(const std::string_view hex) {
    Hash h{};
    if (hex.size() != h.size() * 2) throw std::invalid_argument("mirror hash: expected 64 hex digits");
    for (std::size_t i = 0; i < h.size(); ++i) {
        const auto hi = nibble(hex[2 * i]);
        const auto lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) throw std::invalid_argument("mirror hash: not hex");
        h[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return h;
}

void Digest::add(const Hash& h) {
    for (std::size_t k = 0; k < lanes.size(); ++k) lanes[k] += word(h, k);
    ++entries;
}

void Digest::remove(const Hash& h) {
    for (std::size_t k = 0; k < lanes.size(); ++k) lanes[k] -= word(h, k);
    --entries;
}

Hash Digest::bytes() const {
    Hash out{};
    for (std::size_t k = 0; k < lanes.size(); ++k)
        for (std::size_t i = 0; i < 8; ++i) out[8 * k + i] = static_cast<uint8_t>(lanes[k] >> (56 - 8 * i));
    return out;
}

Digest Digest::fromBytes(const std::span<const uint8_t> bytes, const int64_t entries) {
    if (bytes.size() != 32) throw std::invalid_argument("mirror digest: expected 32 bytes");
    Hash h{};
    std::ranges::copy(bytes, h.begin());
    Digest d;
    for (std::size_t k = 0; k < d.lanes.size(); ++k) d.lanes[k] = word(h, k);
    d.entries = entries;
    return d;
}

}
