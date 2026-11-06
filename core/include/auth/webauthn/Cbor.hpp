#pragma once

// Strict CBOR for WebAuthn (RFC 8949 on libcbor). Every CBOR input the verifier reads (the attestation object, the
// COSE credential key, authenticator extension outputs) goes through scan() before libcbor builds a tree:
//
// - one data item, definite lengths only (no indefinite strings, arrays or maps, no break codes);
// - major types 0-5 plus false/true/null; tags, floats, undefined and other simple values are refused;
// - text strings are valid UTF-8;
// - map keys are integers or text strings, never repeated in one map (compared by value, not encoding);
// - nesting, container sizes and the total item count are bounded (Limits).
//
// decode() additionally requires that the item fills its input exactly (no trailing bytes).

#include "auth/webauthn/Types.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

struct cbor_item_t;

namespace vh::auth::webauthn::cbor {

struct Limits {
    std::size_t maxDepth = 8;          // containers inside containers
    std::size_t maxContainerSize = 64; // entries in one array, pairs in one map
    std::size_t maxItems = 512;        // data items in total
};

// Length of the one strict data item at the start of `in`, or nullopt when there isn't one.
[[nodiscard]] std::optional<std::size_t> scan(ByteView in, const Limits& limits = {});

struct ItemDeleter {
    void operator()(cbor_item_t* item) const;
};
using Item = std::unique_ptr<cbor_item_t, ItemDeleter>;

// The libcbor tree of `in`, which must be exactly one strict data item. nullptr otherwise.
[[nodiscard]] Item decode(ByteView in, const Limits& limits = {});

// Read-only accessors over a decoded tree. Each returns nullopt/nullptr when the item has another type.
[[nodiscard]] std::optional<std::int64_t> asInt(const cbor_item_t* item);
[[nodiscard]] std::optional<ByteView> asBytes(const cbor_item_t* item);
[[nodiscard]] std::optional<std::string_view> asText(const cbor_item_t* item);
[[nodiscard]] bool isMap(const cbor_item_t* item);
[[nodiscard]] bool isArray(const cbor_item_t* item);
[[nodiscard]] std::size_t size(const cbor_item_t* item);  // pairs of a map, entries of an array
[[nodiscard]] const cbor_item_t* arrayAt(const cbor_item_t* array, std::size_t i);
[[nodiscard]] const cbor_item_t* mapKeyAt(const cbor_item_t* map, std::size_t i);
[[nodiscard]] const cbor_item_t* mapValueAt(const cbor_item_t* map, std::size_t i);
// The value under an integer / text key (keys are unique after scan()).
[[nodiscard]] const cbor_item_t* find(const cbor_item_t* map, std::int64_t key);
[[nodiscard]] const cbor_item_t* find(const cbor_item_t* map, std::string_view key);

}
