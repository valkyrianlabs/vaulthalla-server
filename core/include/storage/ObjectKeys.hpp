#pragma once

#include "crypto/id/ObjectUid.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

// The object keys of an opaque_v1 bucket (design/encryption/01-provider-blind-storage.md §4.2, §4.3) and the one place
// that builds and parses them. A bucket holds one vault, so keys carry no vault prefix:
//
//   o/<file uid>                 a file's content, one object per file (VHF1); provider versions = content versions
//   .vaulthalla/layout.json      the cleartext layout hint (never trusted)
//   .vaulthalla/root             the manifest root
//   .vaulthalla/seg/<sid>        a manifest segment (or snapshot segment)
//   .vaulthalla/key/<kid>        a key envelope (KEV1, #370)
//   .vaulthalla/probe/<uid>      the bucket capability probe's object, deleted by version id once it has answered
//                                (storage/s3/Capability.hpp; design/encryption/06-publish-without-preconditions.md §7)
//
// Uids are lower-case Crockford base32 (crypto::id::toBase32), 26 symbols, one spelling per id. Anything else in an
// opaque_v1 bucket is a foreign object (spec 01 §4.4). Under path_v0 and transparent the key is the vault path
// without its leading slash, as before.
namespace vh::storage::object_keys {

inline constexpr std::string_view kContentPrefix = "o/";
inline constexpr std::string_view kMetadataPrefix = ".vaulthalla/";
// Where `foreign_objects = import` puts a foreign object's content: /Imported/<its key>.
inline constexpr std::string_view kImportedRoot = "/Imported";

[[nodiscard]] std::string contentKey(const crypto::id::ObjectUid& uid);
// The uid of an `o/<uid>` key (strict base32), nullopt for any other key. A leading '/' is accepted (scope keys and
// index paths carry one).
[[nodiscard]] std::optional<crypto::id::ObjectUid> uidOfContentKey(std::string_view key);

enum class KeyClass {
    Content,    // o/<uid>
    Metadata,   // .vaulthalla/layout.json, root, seg/<sid>, key/<kid>, probe/<uid>
    Foreign,    // anything else
};
[[nodiscard]] KeyClass classify(std::string_view key);
[[nodiscard]] bool isMetadataKey(std::string_view key);
// Content or Metadata: the allowlist every request of an opaque_v1 vault is held to (§4.3, §8).
[[nodiscard]] bool isAllowedKey(std::string_view key);
// The ListObjectsV2 / ListObjectVersions prefixes an opaque_v1 vault may send: "" (the whole bucket: no name in the
// query), "o/", ".vaulthalla/" and the metadata sub-prefixes, or one allowlisted key (the versions of that key).
[[nodiscard]] bool isAllowedListPrefix(std::string_view prefix);

// The vault path a foreign object is imported to (`foreign_objects = import`): /Imported/<key>.
[[nodiscard]] std::string importedPathOf(std::string_view foreignKey);

// ---- multipart part size (spec 01 §7) -------------------------------------------------------------------------------

inline constexpr uint64_t kMinPartSize = 5ull * 1024 * 1024;   // S3's minimum (every part but the last)
inline constexpr uint64_t kMaxParts = 10'000;                    // S3's maximum part count
inline constexpr uint64_t kPartAlignment = 1024ull * 1024;       // part sizes are whole MiB

// max(5 MiB, ceil(size / 10,000)) rounded up to a whole MiB: the part count never exceeds 10,000, and every object
// up to 48.8 GiB keeps today's 5 MiB parts.
[[nodiscard]] uint64_t partSizeFor(uint64_t objectSize);
// How many parts an object of objectSize takes at partSize (0 for an empty object).
[[nodiscard]] uint64_t partCountFor(uint64_t objectSize, uint64_t partSize);

}
