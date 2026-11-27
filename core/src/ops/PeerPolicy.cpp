#include "ops/PeerPolicy.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "db/query/peer/VaultPolicy.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "device/Peer.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Peers.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/PolicyEpoch.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "rbac/permission/vault/Roles.hpp"
#include "rbac/resolver/PeerVault.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/vault/Global.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <variant>

namespace vh::ops::peer_policy {

namespace {

using RolePerm = rbac::permission::vault::RolePermissions;
using VaultPolicyQuery = db::query::peer::VaultPolicy;

// The actor's global vault policy grants `perm` in every scope (self, admin, user): it may act on any vault,
// whoever owns it. Super admins always.
bool everyScopeGrants(const Actor& actor, const RolePerm perm) {
    if (actor->isSuperAdmin()) return true;
    const auto globals = actor->vaultGlobals();
    return globals.self.rolesPerms().has(perm) && globals.admin.rolesPerms().has(perm) &&
           globals.user.rolesPerms().has(perm);
}

std::shared_ptr<rbac::role::Vault> requirePolicyRole(const roles::Ref& ref) {
    auto role = std::holds_alternative<unsigned int>(ref)
                    ? db::query::rbac::role::Vault::get(std::get<unsigned int>(ref))
                    : db::query::rbac::role::Vault::get(std::get<std::string>(ref));
    if (!role) {
        const auto text = std::holds_alternative<unsigned int>(ref) ? std::to_string(std::get<unsigned int>(ref))
                                                                    : std::get<std::string>(ref);
        throw NotFound("vault role not found: " + text);
    }
    return role;
}

LinkPolicy policyOf(const vh::peer::Record& peer) {
    const auto stored = VaultPolicyQuery::get(peer.id);
    LinkPolicy out{.peer = peer, .role = stored.role, .set_by = stored.set_by, .set_by_name = {}, .set_at = stored.set_at};
    if (stored.set_by)
        if (const auto who = vh::identities::manager().user(*stored.set_by)) out.set_by_name = who->name();
    return out;
}

}

void requirePerson(const Actor& actor, const std::string& what) {
    requireActor(actor);
    if (actor->systemOnly() || !actor->authorizing()) throw Denied("this account cannot " + what);
    const auto* scope = auth::stepup::Scope::current();
    if (!scope) return;  // the daemon's own callers and tests (ops/Actor.hpp)
    switch (scope->channel()) {
        case auth::stepup::Channel::Host:
        case auth::stepup::Channel::Web: return;
        case auth::stepup::Channel::Agent:
            throw Refused("peer_forbidden", "what a linked server may do here is decided by a person: an agent can't " +
                                                what);
        case auth::stepup::Channel::Device: {
            const auto& session = scope->session();
            const auto& device = session ? session->devicePeer() : nullptr;
            if (!device || device->scoped() || device->readOnly())
                throw Refused("peer_forbidden", "only a person, or a fully trusted device connected directly, may " + what);
            return;
        }
    }
}

LinkPolicy get(const Actor& actor, const std::string& peerRef) {
    requirePerson(actor, "see what a linked server may do");
    if (!everyScopeGrants(actor, RolePerm::View))
        throw Denied("seeing a linked server's default vault role takes vault.roles.view on every vault");
    return policyOf(peers::resolveRef(peerRef));
}

LinkPolicy set(const Actor& actor, const std::string& peerRef, const std::optional<roles::Ref>& role) {
    const struct EpochBump { ~EpochBump() { rbac::bumpPolicyEpoch(); } } bumpOnExit;
    requirePerson(actor, "decide what a linked server may do");
    if (!everyScopeGrants(actor, RolePerm::Assign))
        throw Denied("a linked server's default vault role reaches every vault mirrored with it: it takes "
                     "vault.roles.assign on every vault");
    const auto peer = peers::resolveRef(peerRef);
    if (peer.revoked()) throw Conflict("that server is unlinked: link it again first");
    const auto staged = role ? requirePolicyRole(*role) : nullptr;
    if (staged && staged->name == rbac::resolver::kPeerNoAccessRole)
        throw Invalid("a link's default is a role or none: '" + std::string(rbac::resolver::kPeerNoAccessRole) +
                      "' is for one vault's \"no access\" (vh vault role assign <vault> " +
                      std::string(rbac::resolver::kPeerNoAccessRole) + " --peer <server>)");

    const auto before = VaultPolicyQuery::get(peer.id);
    auth::stepup::require(auth::stepup::Family::IdentityAdmin);
    VaultPolicyQuery::set(peer.id, staged ? std::optional<uint32_t>(staged->id) : std::nullopt, actor->id);
    const auto out = policyOf(peer);
    audit::record({.action = "peer.policy.set", .actor_id = actor->id, .actor = actor->name(),
                   .details = {{"peer", peer.id}, {"node_id", peer.node_id},
                               {"role_id", staged ? nlohmann::json(staged->id) : nlohmann::json(nullptr)},
                               {"previous_role_id", before.role ? nlohmann::json(before.role->id) : nlohmann::json(nullptr)}}},
                  fmt::format("[peer] {} set the default vault role of linked server {} ('{}') to {} (was {})",
                              actor->name(), peer.node_id, peer.name, staged ? "'" + staged->name + "'" : "none",
                              before.role ? "'" + before.role->name + "'" : "none"));
    return out;
}

nlohmann::json toJson(const LinkPolicy& policy) {
    nlohmann::json role = nullptr;
    if (policy.role) {
        auto definition = *policy.role;
        definition.assignment.reset();
        role = definition;
    }
    return {{"peer", {{"id", policy.peer.id}, {"node_id", policy.peer.node_id}, {"name", policy.peer.name},
                      {"revoked", policy.peer.revoked()}}},
            {"role", std::move(role)},
            {"set_by", policy.set_by ? nlohmann::json(*policy.set_by) : nlohmann::json(nullptr)},
            {"set_by_name", policy.set_by ? nlohmann::json(policy.set_by_name) : nlohmann::json(nullptr)},
            {"set_at", policy.set_at ? nlohmann::json(static_cast<int64_t>(*policy.set_at)) : nlohmann::json(nullptr)}};
}

}
