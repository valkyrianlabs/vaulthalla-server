#pragma once

#include "ops/Actor.hpp"
#include "ops/VaultKeys.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <ctime>
#include <functional>
#include <optional>
#include <string>
#include <vector>

// Managed storage (design/cloud/managed-remotes.md): a linked server keeps its vaults in buckets the account's
// service provisions, one bucket per vault. The server holds every vault key and encrypts; the service never receives
// a key or anything unwrapped, and is never in the data path (the server talks to the bucket's provider directly).
//
// Nothing here runs unless the server is linked and a super admin confirmed the account recovery key on it
// (ops::cloud_keys): until then the service contacts nobody, status says why, and every switch only records a
// person's choice. A self-hosted server never needs any of it.
//
// Two halves:
//   - Operations for people (`vh cloud storage …`, ws cloud.storage.*): status, the per-vault switch, the offer for
//     vaults that existed when storage became available, bucket key rotation, the default for new vaults and the
//     billing handoff. They read the cached rows and record intents; none calls the cloud except the billing handoff
//     (on the caller's thread, bounded) and `vh cloud storage status --refresh` on the CLI.
//   - The engine (tick(), run by cloud::StorageService on its own thread, never a FUSE, sync or ws thread): it caches
//     the account's state (GET /v1/storage, GET /v1/billing), hosts the account recovery key check, finds vaults
//     without a row, and moves each vault one step: register and seal its label, switch it on at the cloud, wait for
//     its bucket, exchange its sealed bucket key, attach the bucket through the attach-remote engine (origin cloud: the
//     account key becomes its recovery recipient first), send its retention, enroll it in the cloud's recovery, follow
//     the account's access through the remote access gate, rotate and re-request keys, and handle the switch off
//     (detach), a move (another server restored it), an ejection (the customer's own credentials in place) and the end
//     of the plan (local in place, what was lost listed).
//
// Who: status needs the admin cloud View permission (or super admin; any channel, agents included). The switch, the
// offer, rotation and the default need the cloud Storage permission, and a switch also the vault's admin Edit
// permission; billing the cloud Billing permission. No step-up: managed storage adds no decryption path (the account
// key's pin was the one confirmation) and the bucket is the account's. Agents may only read: where a vault is stored and
// what the account pays is decided by a person.
namespace vh::ops::cloud_storage {

using Channel = vault_keys::Channel;

struct VaultEntry {
    unsigned int vault_id{};
    std::string vault_name{};
    std::string vault_uid{};
    // managed (a row), own (an S3 vault on the customer's own storage), local (a local vault without a row: storage
    // isn't available yet, or the vault appeared before it was)
    std::string storage{"local"};
    std::optional<std::string> switch_state{};   // on | off | offered | declined
    std::string state{"unregistered"};         // the row's state (managed), else "own" or "local"
    std::optional<std::string> reason{};
    std::string summary{};                       // the state in words
    uint64_t local_bytes{};                    // the vault's content held here
    std::optional<std::string> access{};         // the remote access gate: full | read_only | none
    std::string key_state{"none"};
    std::optional<std::string> key_access{};
    std::optional<uint32_t> retention_days{}, retention_sent{};
    bool retention_pending{false};
    std::optional<std::string> recovery{};       // the automatic enrollment: ready | behind | none
    nlohmann::json progress{};                   // the attach's or detach's progress (vault.remote.status), or null
    nlohmann::json lost{};                       // an in-place conversion's lost files, or null
    std::optional<std::string> last_error{};
    std::optional<std::time_t> active_at{}, moved_at{}, ejected_at{}, ended_at{};
};

// The plan ended and the conversion waits (an admin's confirmation, or ended_grace_hours of continuous `ended`).
struct EndedPending {
    std::time_t since{};
    std::time_t converts_at{};
    std::optional<std::string> confirmed_by{};
};

struct Status {
    bool linked{false};
    std::string account_key{"unlinked"};       // unlinked | unconfirmed | pinned | tampered
    // Storage can be used: linked, the account key pinned, and the account entitled (an access other than none).
    bool available{false};
    std::optional<std::string> entitlement{};    // active | past_due | restricted | suspended | ended | null
    std::optional<std::string> plan{};
    std::optional<uint64_t> quota_bytes{}, used_bytes{};
    std::optional<std::string> usage_day{};
    std::optional<std::string> storage_access{}, cause{};
    uint64_t managed_local_bytes{};            // this server's own figure: the managed vaults' content held here
    bool new_vaults{true};
    bool offer_open{false};
    std::vector<VaultEntry> offered{};           // the offer: vaults waiting for a person (with their sizes)
    std::vector<VaultEntry> vaults{};
    nlohmann::json billing{};                    // the billing summary as last fetched, or null
    nlohmann::json ejection{};
    std::optional<std::time_t> fetched_at{};
    std::optional<std::string> fetch_error{};
    std::optional<EndedPending> ended{};
    std::optional<std::string> next_step{};
};
[[nodiscard]] Status status(const Actor& actor);

// The switch: on asks for a bucket (a vault without content waits for its first file); off, before a bucket exists,
// tells the cloud and stops, and with one makes the vault local again through the detach (every file fetched and
// verified, the bucket left in place). Off on a vault with a bucket needs `confirm` (the vault's name). A moved vault
// switched off is kept as a local vault without any request to its bucket. Records the intent; the service carries it
// out. Refusals: Denied, NotFound, Invalid (confirm), Conflict (an S3 vault on its own storage, a vault being
// ejected), Refused managed_storage_unavailable (switching on while storage isn't available).
VaultEntry setSwitch(const Actor& actor, unsigned int vaultId, bool on, const std::optional<std::string>& confirm,
                     Channel channel);

struct OfferResult {
    std::vector<unsigned int> vaults{};   // the vaults the answer changed
    bool offer_open{false};
};
// The offer (open question 1): vaults that existed when storage became available are listed once; a person accepts
// all or some (their switches go on) or declines the rest. `vaults` nullopt: every offered vault.
OfferResult acceptOffer(const Actor& actor, const std::optional<std::vector<unsigned int>>& vaults, Channel channel);
OfferResult declineOffer(const Actor& actor, const std::optional<std::vector<unsigned int>>& vaults, Channel channel);

// Asks for a new bucket key for an active vault (the service exchanges, probes, swaps and acknowledges it).
VaultEntry rotate(const Actor& actor, unsigned int vaultId, Channel channel);

// An admin's confirmation that the plan ended (`vh cloud storage confirm-ended`): managed vaults then become local in
// place without waiting for cloud.storage.ended_grace_hours. Conflict unless the service reports `ended` now. The cloud
// Storage permission; never an agent.
struct EndedConfirmation {
    bool confirmed{false};
    std::optional<std::time_t> since{};
    unsigned int vaults{};   // the managed vaults it converts
};
EndedConfirmation confirmEnded(const Actor& actor, Channel channel);

// Whether vaults created from now on are switched on by default (open question 10: an admin setting, on by default).
bool setNewVaultsDefault(const Actor& actor, bool on, Channel channel);

struct Handoff {
    std::string kind{};   // checkout | portal
    std::string url{};    // opens the account's billing page in a browser; never stored or logged
    std::optional<std::time_t> expires_at{};
};
// POST /v1/billing/handoffs on the caller's thread (bounded), then the service polls fast for a few minutes. The
// cloud Billing permission; never an agent.
Handoff billingHandoff(const Actor& actor, const std::string& kind, const std::optional<std::string>& plan,
                       Channel channel);

// ---- the engine ----------------------------------------------------------------------------------------------------

// One pass (cloud::StorageService calls it; tests too): nothing unless linked; the account key check when due; the
// account's state fetched when due (or `force`), then one step per vault. Never throws; returns what it did, for logs.
struct TickResult {
    bool linked{false};
    bool pinned{false};
    bool fetched{false};
    std::optional<std::string> error{};
    unsigned int steps{};
};
TickResult tick(bool force = false);

// Asks the service for a pass now (non-blocking: a vault was created or restored, a switch flipped, a refresh asked).
void wake();
// Whether a pass was asked for since the last one (the service clears it); takeWakePeek leaves it set.
[[nodiscard]] bool takeWake() noexcept;
[[nodiscard]] bool takeWakePeek() noexcept;
// Asks the service for an account recovery key check on its next pass (ws cloud.key.refresh).
void requestKeyCheck();

// Installs the attach engine's managed hooks (vault::remote::setManagedHooks): the account key's grant and the quota
// courtesy check. The service does this when it starts; tests call it.
void installHooks();

// A managed vault restored onto this server (`vh vault recover --from-cloud` without --api-key). Approving the restore
// moved the vault to this server's deployment at the cloud, so this server may ask for a bucket key of its own: the
// same sealed exchange as any managed vault's (keyForRestore), stored as a cloud key owned by `ownerId` and probed,
// never acknowledged before the restore succeeds. The restore reads the bucket with it; adoptRestored() then makes the
// restored vault managed (its row active on that key, the key acknowledged, the bucket bound), and discardRestoreKey()
// removes the key when the restore stops (unacknowledged, the cloud revokes it). Needs the cloud Storage permission
// (or super admin), a link and a confirmed account key; Refused managed_storage_unavailable, cloud_refused (with the
// cloud's reason, e.g. bucket_not_ready), cloud_unreachable or key_probe_failed.
struct RestoreKey {
    std::string vault_uid{};
    unsigned int api_key_id{};
    std::string key_id{}, access{}, bucket{}, bucket_id{}, s3_endpoint{}, region{};
};
[[nodiscard]] RestoreKey keyForRestore(const Actor& actor, const std::string& vaultUid, unsigned int ownerId,
                                       Channel channel);
void adoptRestored(const RestoreKey& key, unsigned int vaultId);
void discardRestoreKey(const RestoreKey& key) noexcept;

// Vaults whose data is in managed storage now (`vh cloud unlink` refuses while any exists): their names.
[[nodiscard]] std::vector<std::string> unlinkBlockers();
// The link is gone (`vh cloud unlink`): the cloud revokes this installation's keys, so managed vaults lose access to
// their buckets (access none; their local copies keep working, `vh cloud storage disable` keeps them local); the cached
// account state goes.
void onUnlinked() noexcept;

// What health reports: cloud_account_key_unconfirmed (managed storage is available on the link but nobody confirmed
// the key; degraded), cloud_recovery_behind (a managed vault's automatic enrollment has been failing for a day;
// degraded), cloud_account_key_no_offline_copy (managed vaults exist and the cloud records no offline copy of the
// account key; info), vault_cloud_moved (a managed vault was restored onto another server; this copy no longer syncs;
// degraded), vault_cloud_failed (degraded).
struct HealthIssue {
    std::string code{};
    std::string severity{};   // degraded | info
    std::optional<unsigned int> vault_id{};
    std::string detail{};
};
[[nodiscard]] std::vector<HealthIssue> health();

// For tests: replaces the bucket key probe (validateAPICredentials). Test mode only.
using KeyProbe = std::function<bool(unsigned int apiKeyId, std::string& error)>;
void setKeyProbeForTesting(std::optional<KeyProbe> probe);

[[nodiscard]] nlohmann::json toJson(const VaultEntry& v);
[[nodiscard]] nlohmann::json toJson(const Status& s);
[[nodiscard]] nlohmann::json toJson(const OfferResult& r);
[[nodiscard]] nlohmann::json toJson(const EndedConfirmation& e);
[[nodiscard]] nlohmann::json toJson(const Handoff& h);

}
