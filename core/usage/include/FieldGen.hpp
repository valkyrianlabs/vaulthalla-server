#pragma once

#include "ArgsGenerator.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

// How a value for a usage field is produced, as data. The usage module declares it next to the field it belongs to
// (a CLI positional or option value, a ws payload field, an operation field); `vh_usage --json` exports every member,
// so the Python engine renders values from the same declaration the C++ side does, with its own seeded RNG.
// `executable()` turns the self-contained kinds into an args::Gen for C++ callers; a Ref needs a world to draw from.
namespace vh::contract {

struct FieldGen {
    enum class Kind { Const, OneOf, IntRange, Pattern, Email, Bool, Ref, Path, Bytes };

    Kind kind = Kind::Const;
    std::vector<std::string> values{};  // Const (one value) and OneOf
    std::string pattern{};              // Pattern / Path mask: {a} lower, {A} upper, {9} digit, {*} [A-Za-z0-9_-]
    std::int64_t min = 0, max = 0;    // IntRange bounds; Bytes length bounds
    std::string entity{};               // Ref: the world entity kind ("user", "group", "vault", "role.vault", ...);
                                      // "subject" is a user or a group, whichever the option token names
    std::vector<std::string> attrs{};   // Ref: the renderings the field accepts ("name", "id"), preferred first
    std::string scope{};                // Ref: "any" (any visible one), "own" (created by this session), "member"
    bool fresh = false;               // the value names a new entity (or id): the renderer keeps it unique in the run

    [[nodiscard]] static const char* kindName(Kind k) {
        switch (k) {
            case Kind::Const: return "const";
            case Kind::OneOf: return "one_of";
            case Kind::IntRange: return "int_range";
            case Kind::Pattern: return "pattern";
            case Kind::Email: return "email";
            case Kind::Bool: return "bool";
            case Kind::Ref: return "ref";
            case Kind::Path: return "path";
            case Kind::Bytes: return "bytes";
        }
        return "const";
    }

    // nullptr for a Ref (it names world state, not a distribution).
    [[nodiscard]] args::Gen executable() const {
        switch (kind) {
            case Kind::Const: return args::ArgGenerator::Constant(values.empty() ? std::string{} : values.front());
            case Kind::OneOf: {
                std::vector<args::Value> v(values.begin(), values.end());
                return args::ArgGenerator::OneOf(std::move(v));
            }
            case Kind::IntRange: return args::ArgGenerator::RandomInt(min, max);
            case Kind::Pattern:
            case Kind::Path: return args::ArgGenerator::RegexMask(pattern);
            case Kind::Email: return args::Email();
            case Kind::Bool: return args::ArgGenerator::RandomBool();
            case Kind::Bytes:
                return args::ArgGenerator::RandomString(static_cast<size_t>(min), static_cast<size_t>(max));
            case Kind::Ref: return nullptr;
        }
        return nullptr;
    }
};

using FieldGenPtr = std::shared_ptr<const FieldGen>;

namespace gen {

inline FieldGenPtr make(FieldGen g) { return std::make_shared<const FieldGen>(std::move(g)); }

inline FieldGenPtr constant(std::string v) {
    return make({.kind = FieldGen::Kind::Const, .values = {std::move(v)}});
}

inline FieldGenPtr oneOf(std::vector<std::string> v) {
    return make({.kind = FieldGen::Kind::OneOf, .values = std::move(v)});
}

inline FieldGenPtr intRange(const std::int64_t lo, const std::int64_t hi) {
    return make({.kind = FieldGen::Kind::IntRange, .min = lo, .max = hi});
}

inline FieldGenPtr pattern(std::string mask) {
    return make({.kind = FieldGen::Kind::Pattern, .pattern = std::move(mask)});
}

// A new entity name: `prefix` plus random lower-case letters and digits (3..50 characters is what the identity
// validators accept; the renderer adds its run/session namespace and must stay inside that).
inline FieldGenPtr freshName(const std::string& prefix) {
    return make({.kind = FieldGen::Kind::Pattern, .pattern = prefix + "{a}{a}{a}{9}{9}{a}{9}", .fresh = true});
}

inline FieldGenPtr email() { return make({.kind = FieldGen::Kind::Email}); }

inline FieldGenPtr boolean() { return make({.kind = FieldGen::Kind::Bool}); }

inline FieldGenPtr ref(std::string entity, std::vector<std::string> attrs = {"id"}, std::string scope = "any") {
    return make({.kind = FieldGen::Kind::Ref, .entity = std::move(entity), .attrs = std::move(attrs),
                 .scope = std::move(scope)});
}

// A vault-relative path: always absolute ("/..."), segments from the mask.
inline FieldGenPtr path(std::string mask) {
    return make({.kind = FieldGen::Kind::Path, .pattern = std::move(mask)});
}

// Linux UIDs/GIDs for test identities: the reserved test range (VH_TEST_UID_BASE, default 2900000000), unique per
// run. Never a real account's id.
inline FieldGenPtr testLinuxId() {
    return make({.kind = FieldGen::Kind::IntRange, .min = 2900000000, .max = 2999999999, .fresh = true});
}

inline FieldGenPtr bytes(const std::int64_t lo, const std::int64_t hi) {
    return make({.kind = FieldGen::Kind::Bytes, .min = lo, .max = hi});
}

}

}
