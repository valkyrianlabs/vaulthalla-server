#pragma once

#include "crypto/vhf1/Format.hpp"
#include "sync/manifest/Document.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The manifest's objects in the bucket (spec 03 §3.1) and their sealing: every document is one VHF1 object, kind 3
// with object uid = vault uid for the root, kind 2 with object uid = sid for a segment (and a snapshot segment). The
// header binds kind, vault and object uid, so a segment can't be read as the root, nor one vault's root as another's.
namespace vh::sync::manifest {

inline constexpr std::string_view kRootKey = ".vaulthalla/root";
inline constexpr std::string_view kSegmentPrefix = ".vaulthalla/seg/";
inline constexpr std::string_view kLayoutKey = ".vaulthalla/layout.json";
inline constexpr std::string_view kObjectPrefix = "o/";

[[nodiscard]] std::string segmentKey(std::string_view sid);
// The sid of a `.vaulthalla/seg/<sid>` key, or nullopt for any other key.
[[nodiscard]] std::optional<std::string> sidOfKey(std::string_view key);
// The uid of an `o/<uid>` key, or nullopt.
[[nodiscard]] std::optional<Uid> uidOfObjectKey(std::string_view key);

// `{"format":1,"layout":"OpaqueV1","vault_uid":"…"}`: a discovery hint, never trusted (§4.2).
[[nodiscard]] std::string layoutHint(const Uid& vaultUid);

[[nodiscard]] std::string sha256Hex(std::span<const uint8_t> bytes);

// What sealing needs: the vault key version a document is sealed under and its key.
struct SealingKey {
    uint32_t version{};
    crypto::SecretKeyPtr key;
};

// A fresh salt per sealing (spec 02 §3.3); chunked like product writers (64 KiB).
[[nodiscard]] std::vector<uint8_t> sealRoot(const RootDocument& root, const Uid& vaultUid, const SealingKey& key);
[[nodiscard]] std::vector<uint8_t> sealSegment(const SegmentDocument& doc, const Uid& vaultUid, const Uid& sid,
                                               const SealingKey& key);
[[nodiscard]] std::vector<uint8_t> sealSnapshot(const SnapshotDocument& doc, const Uid& vaultUid, const Uid& sid,
                                                const SealingKey& key);
// The low-level form: canonical JSON of `doc` sealed as `kind`.
[[nodiscard]] std::vector<uint8_t> sealDocument(const Json& doc, crypto::vhf1::Kind kind, const Uid& vaultUid,
                                                const Uid& objectUid, const SealingKey& key);

// Authenticates the object (crypto::vhf1::Error on any failure, e.g. kind_mismatch, header_auth_failed) and parses
// its plaintext as JSON (FormatError(code) when it isn't). The plaintext buffer is wiped once parsed.
[[nodiscard]] Json openDocument(std::span<const uint8_t> object, crypto::vhf1::Kind kind, const Uid& vaultUid,
                                const Uid& objectUid, const crypto::vhf1::KeyLookup& keys, const std::string& code);
[[nodiscard]] RootDocument openRoot(std::span<const uint8_t> object, const Uid& vaultUid,
                                    const crypto::vhf1::KeyLookup& keys);
[[nodiscard]] SegmentDocument openSegment(std::span<const uint8_t> object, const Uid& vaultUid, const Uid& sid,
                                          const crypto::vhf1::KeyLookup& keys);
[[nodiscard]] SnapshotDocument openSnapshot(std::span<const uint8_t> object, const Uid& vaultUid, const Uid& sid,
                                            const crypto::vhf1::KeyLookup& keys);

}
