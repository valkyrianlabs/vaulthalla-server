#pragma once

#include "ops/Actor.hpp"
#include "ops/Roles.hpp"
#include "peer/Peer.hpp"
#include "rbac/Fwd.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>

// A linked server's vault role on this server, the core (design/peers/identity.md; migration 162): the link's default
// (`vh peer policy get|set`, ws peer.policy.get|set) here, the per-vault role through ops::roles with the subject
// type `peer` (`vh vault role assign|remove --peer`, ws role.vault.assign|unassign). The resolver is
// rbac::resolver::PeerVault. Nothing transmits it to the mirror yet.
//
// Who may (decided 2026-11-25 from how this server governs the global vault policy and role assignment: "someone on
// the core who may manage vault policies"):
//   - a person: an authorizing, non-system account on the host socket, in the web console, or on a full-access,
//     directly connected device's session; never an agent (MCP, `vh mcp`), a scoped device or a relayed one
//     (ops::Refused "peer_forbidden"), and a linked server's own session runs no management command at all;
//   - per vault: the right to assign (or remove) vault roles on that vault, as for a user or a group
//     (vault.roles.assign / revoke from the actor's global vault policy in the vault's scope; super admins);
//   - the link's default, which reaches every vault mirrored over the link whoever owns it: that right in every scope
//     (self, admin and user) of the actor's global vault policy, to set it, and vault.roles.view in every scope to
//     read it; super admins hold both;
//   - setting either is an identity.admin step-up in the console, like every vault role assignment.
// Every change is audited, naming the linked server (its row id and node id).
namespace vh::ops::peer_policy {

struct LinkPolicy {
    vh::peer::Record peer{};
    std::shared_ptr<rbac::role::Vault> role{};  // null: no default
    std::optional<uint32_t> set_by{};
    std::string set_by_name{};
    std::optional<std::time_t> set_at{};        // nullopt: never set
};

// The gate for any write that names a linked server as a vault role subject: the switch, then a person (above).
void requirePerson(const Actor& actor, const std::string& what);

[[nodiscard]] LinkPolicy get(const Actor& actor, const std::string& peerRef);
// role: a vault role by id or name, or nullopt for none. implicit_deny is refused here: "no access" is a per-vault
// override, and the link's absence of a default already grants nothing. Audited peer.policy.set.
LinkPolicy set(const Actor& actor, const std::string& peerRef, const std::optional<roles::Ref>& role);

// {peer: {id, node_id, name, revoked}, role: VaultRole | null, set_by, set_by_name, set_at}.
[[nodiscard]] nlohmann::json toJson(const LinkPolicy& policy);

}
