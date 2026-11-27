#pragma once

#include "concurrency/AsyncService.hpp"
#include "db/query/mirror/Start.hpp"
#include "mirror/start/Guard.hpp"
#include "peer/Peer.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// Starting a mirror, the control plane (server mirror phase 2, wave 3, piece A; design/peers/mirror.md "Starting a
// mirror" steps 1 to 4, the vault-creation half of step 5, the grant, cancelling; "As built: starting a mirror").
//
//   core                                             mirror
//   mirror.add: preconditions, offer row (offered)
//   peer.mirror.offer ─────────────────────────────▶ checks; offer row (pending, or accepted for a link set to
//                                                    accept every vault); a person accepts or declines
//   (accepted) ◀──────────────────────────────────── peer.mirror.answer
//   peer.mirror.keys: every version, KEV1 to the ─▶ prove each against the attestation keys pinned at pairing; one
//   mirror's wrap key, the core's attestation        unprovable version refuses the whole start and writes nothing;
//                                                    else one transaction: the vault (core's uid, root uid), the keys
//                                                    sealed here with their origin, the `mirror` row (installed)
//   (keys_acked) ◀────────────────────────────────── the answer to peer.mirror.keys
//   MirrorVaults::startCore, then peer.mirror.begin ▶ recordGrant / clearGrant (started)
//   peer.mirror.grant on every change and link-up ─▶ recordGrant / clearGrant
//   peer.mirror.cancel ◀───────────────────────────▶ peer.mirror.cancel
//
// Every step is a row state on each side (db::query::mirror::MirrorStart, migration 163): the Service tells the other
// server what it has not been told yet (`notify`), asks again after a restart or a link that was down, and never holds
// a lock while it waits for an answer. The wire handlers (protocols/ws/handler/Mirrors.cpp) only change rows and answer.
// A `core` row exists only after the mirror holds its keys and its own `mirror` row, and the mirror is told the begin
// until it answers; a crash at any point leaves a state the Service resumes or mirror.cancel removes (on both sides).
//
// On a server that has linked nothing the Service does nothing (db::query::peer::Peers::anyRecorded). Key material is never logged, audited, put in an error or stored outside vault_keys.
namespace vh::mirror::start {

using json = nlohmann::json;
using db::query::mirror::Offer;

inline constexpr std::chrono::hours kOfferLifetime{24 * 7};       // an offer nobody answered expires
inline constexpr std::chrono::hours kFinishedKept{24 * 30};       // finished rows stay for the record
inline constexpr uint64_t kSpaceMarginFloor = 256ull * 1024 * 1024;  // plus a tenth of the vault's size
inline constexpr std::size_t kMaxKeyVersions = 1024;
inline constexpr std::chrono::seconds kKeysTimeout{60};           // proving and sealing many versions takes a while

// ---- who answers on the other end (the link, or a test)

struct Transport {
    // A request to a linked server over its link, waiting for the answer frame ({status, data, error}); nullopt when
    // not connected or no answer came.
    std::function<std::optional<json>(uint32_t peerId, const std::string& command, const json& payload,
                                      std::chrono::milliseconds timeout)>
        request;
    // When the link to the server came up (connected now), nullopt while it is down.
    std::function<std::optional<std::time_t>(uint32_t peerId)> upSince;
};
// Tests: replaces the link (an empty Transport restores it).
void setTransportForTesting(Transport transport);
// The transport in use: the link service's, or the test's.
[[nodiscard]] Transport transport();

// One lock for the steps that touch both this server's rows and its vaults (startCore against a cancel, a mirror's
// vault creation against its removal). Never held while waiting for the other server.
[[nodiscard]] std::mutex& stepMutex();

// ---- the core ------------------------------------------------------------------------------------------------------

struct Prepared {
    db::query::mirror::VaultFacts facts{};
    std::vector<uint32_t> versions{};  // every key version the mirror needs: the vault's files, its trash, the current
};

// Every precondition on the vault (design "Starting a mirror" 1), each an ops::Refused with its own code and a
// sentence a person can act on: vault_not_found (NotFound), mirror_already (mirrored, or held here as another server's
// copy), mirror_start_running, vault_replicated, vault_attach_running, vault_detach_running, layout_migration_running,
// key_rotation_running, key_salvage_running, vault_pending_deletion, vault_unavailable, legacy_content,
// key_version_missing, key_version_unattested, trashed_without_uid, contents_not_held.
[[nodiscard]] Prepared checkVault(uint32_t vaultId);
// The key versions the mirror needs (the vault's files, its trash, the current one), each held and attested by this
// server: key_version_missing, key_version_unattested, vault_unavailable.
[[nodiscard]] std::vector<uint32_t> neededVersions(uint32_t vaultId);
// The linked server is live and its link is up: peer_not_linked, peer_link_down.
void checkLink(const vh::peer::Record& peer);
// mirror.add once authorized: checks, then the offer row (offered, to be told). Audited mirror.offer.
[[nodiscard]] Offer offerVault(uint32_t vaultId, const vh::peer::Record& peer, std::optional<uint32_t> actorId,
                               const std::string& actorName);

// What the core grants the server for the vault now (PeerVault::role): {role_name, files, directories, sync, roles},
// or null when it grants nothing.
[[nodiscard]] json grantFor(uint32_t peerId, uint32_t vaultId);

// The wire payloads the core sends.
[[nodiscard]] json offerPayload(const Offer& offer);
// Every version the mirror needs, each wrapped in a KEV1 envelope to the server's wrap key (peer.wrap_public_key), with
// this node's key check and attestation over the vault's id here. Holds key bytes only in memory.
[[nodiscard]] json keysPayload(const Offer& offer, const vh::peer::Record& peer);
[[nodiscard]] json beginPayload(const Offer& offer);

// Ends the vault's mirror here (mirror.cancel on the core, or the mirror's peer.mirror.cancel): drops the core row and
// the log at once, and the open or started offer becomes cancelled (the mirror to be told when `tell`, with
// `removeCopy`: the core asks the mirror to remove its copy; the mirror decides by the ending rule, mirror.md "Ending a
// mirror"). Audited mirror.cancel with what was asked. False when there was nothing to cancel.
bool cancelOnCore(uint32_t vaultId, const std::string& reason, bool tell, bool removeCopy,
                  std::optional<uint32_t> actorId, const std::string& by);

// ---- the mirror ----------------------------------------------------------------------------------------------------

// Whether this server would take the vault now: decline codes mirror_vault_exists, mirror_name_taken, mirror_no_space.
[[nodiscard]] std::optional<std::pair<std::string, std::string>> mirrorRefusal(const Offer& offer,
                                                                               std::optional<uint32_t> ownVault = std::nullopt);
// A person here accepts / declines (ops::mirrors authorizes). Audited mirror.accept / mirror.decline.
[[nodiscard]] Offer accept(const Offer& offer, std::optional<uint32_t> actorId, const std::string& actorName);
[[nodiscard]] Offer decline(const Offer& offer, std::optional<uint32_t> actorId, const std::string& actorName,
                            const std::string& reason = "declined");
// A person here cancels: a start that has not completed (its vault, keys and rows go; the core is told); a completed
// one is refused (mirror_detach_required: detach is a later wave). Audited mirror.cancel.
[[nodiscard]] Offer cancelOnMirror(const Offer& offer, std::optional<uint32_t> actorId, const std::string& actorName);
// Removes the vault this server holds as another server's copy and every row of it (keys, pending contents, mirror row).
void removeCopy(uint32_t vaultId);
// Whether this server holds the vault's first copy complete. The one place this is asked (the ending rule). Piece A
// answers from the start: true once its offer here is `started`, or when no offer of it is left (erring towards
// "finished" errs towards keeping the copy). The lead rewires it to piece B's first-copy column at the merge.
[[nodiscard]] bool firstCopyFinished(uint32_t vaultId);
// The mirror holds the vault's keys and its row, and the core's begin has not arrived yet: the core may not have its
// `core` row (startCore runs after the keys are answered, and takes as long as its baseline), so it answers a tree
// request with not_found. The follower asks nothing until the begin (piece B treats not_found as "the core is gone").
[[nodiscard]] bool awaitingBegin(uint32_t vaultId);
// A super admin here removes an orphaned copy (ops::mirrors authorizes, with the data-destroy step-up). Audited
// mirror.remove.
void removeOrphaned(uint32_t vaultId, std::optional<uint32_t> actorId, const std::string& actorName);
// Linked servers unlinked meanwhile (any path: unlink, peer.unlinked, a rotation that dropped the link): the vaults this
// server holds as their copies become orphaned (kept), the mirrors this server is the core of end (core row and log
// dropped), and the notices still queued for them are dropped (unlinking invalidated the trust; a queued removal is
// never delivered). Returns how many copies were orphaned. The Service runs it every pass.
std::size_t reconcileUnlinked();

// ---- the wire (a linked server's session; the handlers check the switch) --------------------------------------------

[[nodiscard]] json offerReceived(const vh::peer::Record& from, const json& payload);    // on the mirror
[[nodiscard]] json answerReceived(const vh::peer::Record& from, const json& payload);   // on the core
[[nodiscard]] json keysReceived(const vh::peer::Record& from, const json& payload);     // on the mirror
[[nodiscard]] json beginReceived(const vh::peer::Record& from, const json& payload);    // on the mirror
[[nodiscard]] json grantReceived(const vh::peer::Record& from, const json& payload);    // on the mirror
[[nodiscard]] json cancelReceived(const vh::peer::Record& from, const json& payload);   // on either

// ---- the service -----------------------------------------------------------------------------------------------------

// Tells, asks and retries what the offers say is left (above), expires unanswered offers, sweeps finished ones, and
// keeps every mirror's grant current: the core sends it at begin, on every link-up, and whenever PeerVault::role
// answers something else (a link default, a per-vault assignment, a role's permissions edited, the role deleted).
// Registered with runtime::Manager as "MirrorStarter", after the link service.
class Service final : public concurrency::AsyncService {
public:
    static constexpr std::chrono::seconds kInterval{1};
    // A request that got no answer is retried after this (the link being down is not counted: nothing is sent).
    static constexpr std::chrono::seconds kRetryAfter{5};

    Service();
    static const std::shared_ptr<Service>& instance();

    // One pass (the loop; tests call it directly).
    void tick();
    // Sooner than the next pass (an operation changed something).
    void wake();
    // Tests: forget which grants were sent.
    void resetForTesting();

protected:
    void runLoop() override;

    // How often the core looks for vaults to offer a linked server set to receive every vault (and sooner on wake).
    static constexpr std::chrono::seconds kEveryVaultInterval{10};
    // A vault whose preconditions refused it is looked at again after this (its refusal logged once a time).
    static constexpr std::chrono::seconds kEveryVaultRetry{60};

private:
    void step(const Offer& offer);
    void syncGrants();
    // The core's per-link setting "mirror every vault to this server" (peer.mirror_vaults): an offer for each vault
    // this server owns that is not mirrored yet, new ones included, with the link up (offerVault, as mirror.add does
    // once authorized; attributed to whoever turned the setting on). An offer that ended since is not made again.
    void offerEveryVault(bool now);

    std::chrono::steady_clock::time_point everyVaultAt_{};
    std::map<std::pair<uint32_t, uint32_t>, std::chrono::steady_clock::time_point> everyVaultRetry_;  // (peer, vault)

    std::mutex mutex_;
    bool woken_{false};
    bool everyVaultWoken_{false};
    std::map<uint32_t, std::pair<std::string, std::time_t>> sentGrants_;  // vault → (grant sent, link up since)
    std::map<uint32_t, std::chrono::steady_clock::time_point> retryAt_;   // offer → not before
};

}
