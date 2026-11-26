#pragma once

#include "rbac/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>

// A linked server's vault roles on this server (migration 162): its per-link default (peer_vault_policy) and what
// rbac::resolver::PeerVault reads to decide its role on one vault. Trusted primitives: callers (ops::peer_policy,
// the resolver) authorize. Per-vault assignments are vault_role_assignments rows with subject_type 'peer', written
// through db::query::rbac::role::vault::Assignments like a user's or a group's.
namespace vh::db::query::peer {

struct LinkDefault {
    uint32_t peer_id{};
    std::shared_ptr<vh::rbac::role::Vault> role{};  // null: no default role
    std::optional<uint32_t> set_by{};
    std::optional<std::time_t> set_at{};             // nullopt: never set
};

// What decides a linked server's role on one vault, read in one snapshot.
struct PeerStanding {
    bool exists{false};
    bool live{false};                                      // linked: not revoked
    std::shared_ptr<vh::rbac::role::Vault> vault_role{};   // its assignment on the vault (with assignment info)
    std::shared_ptr<vh::rbac::role::Vault> link_default{}; // the link's default role
    bool mirrored_from_here{false};  // this server is the vault's core, mirrored with this linked server
    bool vault_live{false};          // the vault exists and is not deleted
};

class VaultPolicy {
public:
    // The link's default (never set: no role, no set_by, no set_at).
    [[nodiscard]] static LinkDefault get(uint32_t peerId);
    // Sets (roleId) or clears (nullopt) the link's default, by `setBy`.
    static void set(uint32_t peerId, std::optional<uint32_t> roleId, uint32_t setBy);
    // Links whose default is this vault role (a role in use can't be deleted).
    [[nodiscard]] static uint32_t countForRole(uint32_t roleId);

    [[nodiscard]] static PeerStanding standing(uint32_t peerId, uint32_t vaultId);
};

}
