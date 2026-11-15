#pragma once

#include <vl/keykit/uid.hpp>

#include <string>
#include <string_view>

namespace vh::crypto::id {

// A 16-byte identifier drawn from libsodium's CSPRNG (randombytes_buf), never from PostgreSQL: a vault's uid
// (vault.uid) and a file's object uid (files.object_uid), design/encryption/01-provider-blind-storage.md §4.1. The
// bytes are raw: no UUID version or variant bits. The type and its text form in object keys and documents (lower-case
// Crockford base32, 26 symbols: vl::keykit::toBase32 / fromBase32) are vl-keykit's; what stays here is the server's
// generator and the database's form, UUID columns being PostgreSQL's 16-byte type.
using ObjectUid = vl::keykit::Uid;

[[nodiscard]] ObjectUid newObjectUid();

// The database's form: UUID text, 8-4-4-4-12 hex digits. toUuid writes lower case; fromUuid takes PostgreSQL's output
// (either case) and throws std::invalid_argument on anything else.
[[nodiscard]] std::string toUuid(const ObjectUid& uid);
[[nodiscard]] ObjectUid fromUuid(std::string_view text);

}
