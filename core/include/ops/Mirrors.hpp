#pragma once

#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Pending.hpp"
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
    // On the core: ask the mirror to remove its copy (it removes it unless its link keeps the vaults this server
    // removes; a copy whose first copy isn't finished is removed anyway). For a mirror that has begun this needs the
    // data-destroy step-up in the console.
    bool remove_copy{false};
};
struct Cancelled {
    std::string side{};                  // core | mirror
    std::optional<uint32_t> vault_id{};
    std::optional<Offer> offer{};
    bool removed{false};                 // mirror: the vault this server was given went
    bool remove_copy{false};             // core: what was asked of the mirror's copy (the answer comes later: mirror.get)
};
// From either side, at any step. On the core: the core row and the log go at once, and the mirror is told (when the
// link is up; the request waits while it is down, and is dropped if the servers are unlinked first), with
// remove_copy. On the mirror: a start that has not completed is removed here and the core is told; a completed one is
// refused (mirror_detach_required); an orphaned copy is removed (super admins, data-destroy step-up; audited
// mirror.remove).
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
// The link's "keep the vaults this server's core removes" (default off): a removal the core asks for leaves the copy
// here, orphaned, instead. Super admins; audited mirror.keep_removed.set.
[[nodiscard]] db::query::mirror::AcceptVaults keepRemoved(const Actor& actor, const std::string& peer);
[[nodiscard]] db::query::mirror::AcceptVaults setKeepRemoved(const Actor& actor, const std::string& peer, bool enabled);

// Held changes and conflict copies (design/peers/mirror.md "As built: a change made on the mirror"): a person's change
// to a vault this server mirrors that the core refused (kind held: the entry came back to the core's state, the
// change is kept with the reason) or that became a conflict copy (kind conflict: a record of the rename). Super admins
// of this server (the people who may change a mirrored vault here). `vaultId` narrows to one vault; `all` includes
// the ones discarded or retried.
[[nodiscard]] std::vector<db::query::mirror::HeldChange> held(const Actor& actor, std::optional<uint32_t> vaultId,
                                                              bool all);
// Drops the held change (or dismisses a conflict record): nothing changes in the vault. Audited mirror.held.discard.
[[nodiscard]] db::query::mirror::HeldChange discardHeld(const Actor& actor, uint64_t id);
// Submits a held change again as it was (a new request, at the end of the vault's queue, as the person who made it):
// the core executes it or refuses it again (a refusal is held again). Not applied here first: its result comes back in
// the log. The vault must be live here (mirror_read_only otherwise); a conflict record is not retried (invalid).
// Audited mirror.held.retry.
[[nodiscard]] db::query::mirror::HeldChange retryHeld(const Actor& actor, uint64_t id);

[[nodiscard]] nlohmann::json toJson(const db::query::mirror::HeldChange& h);

// Starts a stopped copy over from its core's tree (wave 5 piece B; mirror::resync::start): the vault is held here as a
// mirror, diverged, expired or stopped. Super admins of this server; audited mirror.resync. Answers the row's new state
// and how many pending changes were kept as held.
[[nodiscard]] nlohmann::json resync(const Actor& actor, uint32_t vaultId);

// A planned switch of the core role (wave 5 piece B; mirror::switching::request), asked on either server: super admins
// of this server. Waits for the outcome (bounded: the switch's deadline and a margin) and answers it: switched,
// abandoned (nothing changed, with the reason) or running. Audited mirror.switch on both servers.
// `acceptNoAccess`: go ahead when the old core would hold no role on the vault on the new core (refused otherwise,
// mirror_switch_no_role). The answer names that role and what it allows (peer_role, peer_access).
[[nodiscard]] nlohmann::json switchRole(const Actor& actor, uint32_t vaultId, bool acceptNoAccess = false);

// "Take over as core" (design/peers/mirror.md "Who may do it"): a person (never an agent, a scoped or relayed device,
// a linked server) who is a super admin of this server. Piece A's admin permission bit (admin.mirror.takeover) joins it
// when that piece lands; until then super admins alone. Throws ops::Refused peer_forbidden or ops::Denied.
void requireTakeover(const Actor& actor, const std::string& what);

// Take over as the vault's core (wave 5 piece B; mirror::takeover::take): this server holds the vault as a mirror and
// its core is gone or does not answer. requireTakeover, the vault's name typed (`confirmName`), and the data-destroy
// step-up in the console (target mirror.takeover:<vault>). Audited mirror.takeover.
[[nodiscard]] nlohmann::json takeover(const Actor& actor, uint32_t vaultId, const std::string& confirmName);

[[nodiscard]] nlohmann::json toJson(const Offer& offer);
[[nodiscard]] nlohmann::json toJson(const Mirrored& m);
[[nodiscard]] nlohmann::json toJson(const Cancelled& c);
[[nodiscard]] nlohmann::json toJson(const db::query::mirror::AcceptVaults& a, const vh::peer::Record& peer);

}
