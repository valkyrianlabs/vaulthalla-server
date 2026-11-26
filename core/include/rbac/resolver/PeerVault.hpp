#pragma once

#include "rbac/Fwd.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

// A linked server's vault role on this server, the core (design/peers/identity.md "Decided and given", Cooper
// 2026-11-25; migration 162). The role is the ceiling on everything that arrives from that server for the vault; the
// core tells the mirror which role it has by name and with its actual permissions (never by id). The questions the
// next waves ask: role() to tell the mirror, may() for each change the mirror submits. Nothing calls may() yet, and
// nothing a linked server does reaches it: a peer session runs only the peer wire set (Router::classifyCommand).
//
// The precedence, read in one snapshot:
//   1. a linked server that is unlinked (revoked), unknown, or a deleted vault: nothing, whatever rows remain;
//   2. its per-vault assignment (vault_role_assignments, subject_type 'peer') if it has one; an assignment of the
//      built-in role implicit_deny is "no access" and grants nothing whatever that role's bits say;
//   3. otherwise the link's default (peer_vault_policy);
//   4. otherwise nothing.
// A user's, a group's or an admin role's rows are never read: the subject is the `peer` row, not an account. The
// link's default applies only to vaults mirrored over that link (may() asks that this server is the vault's core,
// mirrored with that linked server); role() answers what it holds or would hold, so that an offer can name it.
// Path overrides do not apply to a linked server (migration 162 refuses them).
namespace vh::rbac::resolver {

struct PeerVaultRole {
    enum class Source : uint8_t {
        None,         // no role: not linked, no assignment and no default, or a deleted vault
        Vault,        // the per-vault assignment
        LinkDefault,  // the link's default
    };

    Source source{Source::None};
    // The role that applies, as it is defined here now (its name, its permissions; no overrides). Null when nothing
    // applies, and for "no access".
    std::shared_ptr<const role::Vault> role{};
    bool no_access{false};      // the per-vault assignment is implicit_deny (source Vault, role null)
    bool linked{false};         // the linked server is known here and not revoked
    bool mirrored{false};       // this server is the vault's core, mirrored with that linked server

    [[nodiscard]] bool grantsAnything() const noexcept { return !!role; }
};

[[nodiscard]] std::string_view to_string(PeerVaultRole::Source source) noexcept;

// The built-in vault role that carries "no access" for a linked server's per-vault override.
inline constexpr std::string_view kPeerNoAccessRole = "implicit_deny";

class PeerVault {
public:
    // The linked server `peerId`'s role on `vaultId`, by the precedence above.
    [[nodiscard]] static PeerVaultRole role(uint32_t peerId, uint32_t vaultId);

    // May the linked server perform `action` on the entry at `vaultPath` (vault-relative, "/" for the root) in
    // `vaultId`? Only on a vault this server is the core of and mirrors with that linked server, within its role's
    // base permissions (exists / isDirectory describe the target as the evaluator needs them).
    [[nodiscard]] static bool may(uint32_t peerId, uint32_t vaultId, permission::vault::FilesystemAction action,
                                  const std::filesystem::path& vaultPath, bool exists, bool isDirectory);
};

}
