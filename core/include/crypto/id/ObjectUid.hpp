#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace vh::crypto::id {

// A 16-byte identifier drawn from libsodium's CSPRNG (randombytes_buf), never from PostgreSQL: a vault's uid
// (vault.uid) and a file's object uid (files.object_uid), design/encryption/01-provider-blind-storage.md §4.1. The
// bytes are raw: no UUID version or variant bits. PostgreSQL keeps them in UUID columns because that is its 16-byte
// type. The text form in object keys and documents is lower-case Crockford base32, 26 symbols.
using ObjectUid = std::array<uint8_t, 16>;

[[nodiscard]] ObjectUid newObjectUid();

// The database's form: UUID text, 8-4-4-4-12 hex digits. toUuid writes lower case; fromUuid takes PostgreSQL's output
// (either case) and throws std::invalid_argument on anything else.
[[nodiscard]] std::string toUuid(const ObjectUid& uid);
[[nodiscard]] ObjectUid fromUuid(std::string_view text);

enum class Base32Error { BadLength, BadSymbol, NonCanonical };

[[nodiscard]] std::string_view to_string(Base32Error error);

// 26 lower-case symbols of 0123456789abcdefghjkmnpqrstvwxyz, big-endian bit order, the 2 trailing padding bits zero.
[[nodiscard]] std::string toBase32(const ObjectUid& uid);

// Strict: one spelling per id. Refuses upper case, symbols outside the alphabet (i, l, o, u), any other length and
// non-zero padding bits (vectors.json object_ids).
[[nodiscard]] std::optional<ObjectUid> fromBase32(std::string_view text, Base32Error* error = nullptr);

}
