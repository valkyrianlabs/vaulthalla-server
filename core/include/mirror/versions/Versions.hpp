#pragma once

#include "recovery/Model.hpp"

#include <cstdint>
#include <ctime>
#include <optional>

// Versions on the mirror, opt-in (server mirror phase 2, wave 5, piece A; migration 167 mirror_vault.keep_versions;
// design/peers/mirror.md "As built: leaving a mirror"): a long-term safeguard against an unintended deletion on the core.
// Per vault this server holds as another server's copy (role mirror), set by a super admin here, default off. When it
// is on, the applier keeps the prior generation of a file before it applies the core's replacement, delete or purge of
// it, with the local versioning mechanism (recovery::local::versions::retain, the policy's shape: keep_last,
// max_age_days, quota_bytes), as this server's own state: written past the backstop (recovery tables only), never
// logged, hashed or submitted, never part of the digest. Retention (versions::maintain) bounds them by the policy.
// Reading a kept version is the recovery commands' (rbac::mirrored decides who may read the file); restoring one is a
// change made here (a pending write, Live only). After a detach they belong to the local vault; a removed copy takes
// them with it.
namespace vh::mirror::versions {

struct Setting {
    vh::recovery::LocalVersioningPolicy policy{};   // enabled false: off
    std::optional<uint32_t> set_by{};
    std::optional<std::time_t> set_at{};
};

// The vault's setting (off for a vault with no mirror row).
[[nodiscard]] Setting get(uint32_t vaultId);
// Replaces it (a trusted primitive: ops::mirrors authorizes). On: limits left unset get the defaults (kDefaultKeepLast,
// kDefaultMaxAgeDays), a 0 means "no limit" for that one, and at least one limit stays. ops::Conflict when the vault is
// not held here as a live copy's mirror.
inline constexpr unsigned int kDefaultKeepLast = 10;
inline constexpr unsigned int kDefaultMaxAgeDays = 30;
Setting set(uint32_t vaultId, const vh::recovery::LocalVersioningPatch& patch, std::optional<uint32_t> by);

// The applier's question, per group: the policy when this vault keeps versions, nullopt otherwise. One atomic load
// while no vault here keeps any (every server but a mirror that turned it on); the rows are read once per process and
// again after each set().
[[nodiscard]] std::optional<vh::recovery::LocalVersioningPolicy> policyFor(uint32_t vaultId);
void invalidate() noexcept;

}
