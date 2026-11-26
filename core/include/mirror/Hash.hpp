#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <nlohmann/json_fwd.hpp>

// The entry hash and the running digest of a mirrored vault (design/peers/mirror.md "Parity"; migration 160). The
// core, the mirror and later Desktop tooling compute them the same way, from the state document a replication log row
// carries (vault_replication_log.state), so the definition is fixed here and in vh_mirror_state_hash.
//
// Entry hash: SHA-256 of the canonical encoding of the state document's replicated fields,
//
//     "vh.mirror.entry/1\n"
//     then for each field of kEntryHashFields, in order:
//         "<field>=<n>:<value>\n"   the value as UTF-8 text, n its length in bytes, or
//         "<field>=-\n"             when the field is absent or null.
//
// A field is a path into the document ("created_by.node" is state["created_by"]["node"]). Values are strings
// (written as they are), integers (decimal, a leading '-' when negative) or booleans ("true" / "false"); the state
// builders never put an object, an array or a fraction at a hashed field. Times are microseconds since the epoch.
// Fields outside the list (none today) do not count, so a document may grow without changing any hash.
//
// Test vector (also checked against PostgreSQL's vh_mirror_state_hash in MirrorReplicationLogDbTest):
//
//     {"v":1,"uid":"0f8fad5b-d9cb-469f-a165-70867728950e","type":"file","parent":"7c9e6679-7425-40de-944b-e07fc1f90ae7",
//      "name":"Résumé.txt","mode":420,"hidden":false,"owner_uid":1000,"owner_gid":1000,
//      "created_at":1732540000123456,"modified_at":1732540100654321,"created_by":{"node":"node-a","id":3},
//      "modified_by":{"node":"node-b","id":7},"size":5,"content_hash":"ab12","mime":"text/plain",
//      "generation":"AAAA","key_version":2,"content_format":"vhf1"}
//     -> c3cd6e5ea36d18109bdc5878a6ce1bcc6ea5e8325b3b78e5cb186ba636cae95d
//
// Digest: the entry hashes of every entry of the vault (live entries and trashed files) read as four big-endian
// 64-bit words and summed per word modulo 2^64, written back as 32 big-endian bytes, with the number of entries
// alongside. An entry's change adds its new hash and subtracts the one it replaced, so the digest of a tree is
// maintained from the log rows alone; its order does not matter. It detects accidents and bugs, not a peer that
// lies (that is the audit exchange's job).
namespace vh::mirror {

using Hash = std::array<uint8_t, 32>;

inline constexpr std::string_view kEntryHashDomain = "vh.mirror.entry/1";

// The replicated fields, in encoding order (vh_mirror_state_hash's list).
inline constexpr std::array<std::string_view, 26> kEntryHashFields{
    "v", "uid", "type", "parent", "name", "mode", "hidden", "owner_uid", "owner_gid", "created_at", "modified_at",
    "created_by.node", "created_by.id", "modified_by.node", "modified_by.id", "size", "content_hash", "mime",
    "generation", "key_version", "content_format", "target", "trashed.path", "trashed.at", "trashed.by.node",
    "trashed.by.id"};

// The bytes the entry hash is taken over.
[[nodiscard]] std::string canonicalEncoding(const nlohmann::json& state);
[[nodiscard]] Hash entryHash(const nlohmann::json& state);

[[nodiscard]] std::string toHex(std::span<const uint8_t> bytes);
// 64 hex digits; std::invalid_argument otherwise.
[[nodiscard]] Hash hashFromHex(std::string_view hex);

struct Digest {
    std::array<uint64_t, 4> lanes{};
    // Entries counted in (signed: a stretch of the log can remove more than it adds).
    int64_t entries{};

    void add(const Hash& h);
    void remove(const Hash& h);
    [[nodiscard]] Hash bytes() const;
    [[nodiscard]] std::string hex() const { return toHex(bytes()); }
    [[nodiscard]] static Digest fromBytes(std::span<const uint8_t> bytes, int64_t entries);

    bool operator==(const Digest&) const = default;
};

}
