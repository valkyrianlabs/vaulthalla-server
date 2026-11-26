#pragma once

#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Start.hpp"
#include "ops/Actor.hpp"
#include "peer/Peer.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Mirrored vaults, for a person (design/peers/mirror.md "Starting a mirror", "As built: starting a mirror"), shared by
// `vh mirror ...` and the ws mirror.* commands. The protocol is mirror::start; this layer authorizes and resolves.
//
// Who may:
//   - mirror.add, mirror.cancel on the core: a super admin, or a person whose roles here let them manage the vault and
//     who may decide which servers hold it: the vault's admin Edit permission and the vault-role assignment right on
//     it (vault.roles.assign), as for giving any principal access to it. The web console asks the keys step-up
//     (target mirror.add:<vault>), as every operation that sends a vault's keys somewhere else does.
//   - mirror.pending, mirror.accept, mirror.decline, mirror.cancel on the mirror, the link's "accept every vault"
//     setting: super admins of this server only.
//   - mirror.list, mirror.get: super admins (every mirrored vault and start); on the core, the vault's admin View.
// Never an agent (MCP, `vh mcp`), a scoped device, a relayed device or a linked server's session: Refused
// "peer_forbidden" (and the router and the MCP catalog refuse first). Gate: peers.experimental, else Refused
// "peers_experimental".
namespace vh::ops::mirrors {

using db::query::mirror::Offer;

struct AddRequest {
    uint32_t vault_id{};
    std::string peer{};  // as ops::peers::get names one: id, node id, key or prefix, name
};
// Starts mirroring the vault to the linked server: the preconditions (mirror::start::checkVault, each with its code),
// then the offer, which the start service sends.
[[nodiscard]] Offer add(const Actor& actor, const AddRequest& request);

// Offers this server received that wait for a super admin.
[[nodiscard]] std::vector<Offer> pending(const Actor& actor);
// `ref`: the offer's number here or its offer uid.
[[nodiscard]] Offer accept(const Actor& actor, const std::string& ref);
[[nodiscard]] Offer decline(const Actor& actor, const std::string& ref);

struct CancelRequest {
    std::optional<uint32_t> vault_id{};  // a vault on this server (either role)
    std::optional<std::string> offer{};  // or an offer (a start whose vault does not exist here yet)
};
struct Cancelled {
    std::string side{};                  // core | mirror
    std::optional<uint32_t> vault_id{};
    std::optional<Offer> offer{};
    bool removed{false};                 // mirror: the vault this server was given went
};
// From either side, at any step. On the core: the core row and the log go, and the mirror is told (it removes what it
// was given). On the mirror: a start that has not completed is removed here and the core is told; a completed one is
// refused (mirror_detach_required).
[[nodiscard]] Cancelled cancel(const Actor& actor, const CancelRequest& request);

struct Mirrored {
    uint32_t vault_id{};
    std::string vault_name{};
    std::string role{};                  // core | mirror | orphaned | starting (an offer with no mirror row yet)
    std::optional<db::query::mirror::MirrorVault> row{};
    std::optional<vh::peer::Record> peer{};
    std::optional<Offer> start{};        // the latest offer of the vault on this side
};
[[nodiscard]] std::vector<Mirrored> list(const Actor& actor);
[[nodiscard]] Mirrored get(const Actor& actor, uint32_t vaultId);
// Every offer on this server (both sides, newest first), finished ones included.
[[nodiscard]] std::vector<Offer> offers(const Actor& actor);

// The link's "accept every vault from this server" (default off).
[[nodiscard]] db::query::mirror::AcceptVaults acceptAll(const Actor& actor, const std::string& peer);
[[nodiscard]] db::query::mirror::AcceptVaults setAcceptAll(const Actor& actor, const std::string& peer, bool enabled);

[[nodiscard]] nlohmann::json toJson(const Offer& offer);
[[nodiscard]] nlohmann::json toJson(const Mirrored& m);
[[nodiscard]] nlohmann::json toJson(const Cancelled& c);
[[nodiscard]] nlohmann::json toJson(const db::query::mirror::AcceptVaults& a, const vh::peer::Record& peer);

}
