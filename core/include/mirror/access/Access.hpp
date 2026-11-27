#pragma once

#include "ops/Error.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

// PIECE A'S FILE (wave 4). This is piece B's minimal stand-in, built to the interface fixed in the wave's COMMON.md,
// so that piece B's pending path has the gate to sit behind; piece A's merge replaces this header and its .cpp
// (core/src/mirror/access/Access.cpp) wholesale. Nothing of piece B lives here except acceptsLocalChanges() returning
// true (piece B flips it) and the test hook at the end, which piece B's suites call.
//
// The gate of a vault this server holds as another server's copy (design/peers/mirror.md "Strict mode"): Live while the
// link is up and the mirror follows its core (a write is accepted as pending: mirror::submit), ReadOnly otherwise (link
// down, the vault paused, diverged, expired or stopped, the first copy unfinished, an orphaned copy). A vault that is
// not held as a mirror or orphaned copy is NotMirrored and every write goes through as it always has.
namespace vh::mirror::access {

enum class State { NotMirrored, Live, ReadOnly };

// A write refused because the vault is read-only here. ws code read_only; `reason` says why (mirror_link_down, ...).
struct MirrorReadOnly final : vh::ops::Refused {
    std::string reason;
    explicit MirrorReadOnly(std::string reason_)
        : Refused("read_only", "This vault is read-only on this server: " + reason_), reason(std::move(reason_)) {}
};

[[nodiscard]] State state(uint32_t vaultId);
// Why the vault is ReadOnly ("" when it is not).
[[nodiscard]] std::string reason(uint32_t vaultId);
// Returns for a vault that is not held as a mirror or orphaned copy, and for a Live mirror when local changes are
// accepted; throws MirrorReadOnly otherwise.
void requireWritable(uint32_t vaultId, std::string_view operation);
// Whether a Live mirror accepts a person's changes as pending (piece B: true).
[[nodiscard]] bool acceptsLocalChanges();

// Tests (piece B's suites): treat the vault's link as up (or not) without a link service. Piece A's merge maps this to
// its own hook.
void setLinkUpForTesting(uint32_t vaultId, bool up);
void clearForTesting();

}
