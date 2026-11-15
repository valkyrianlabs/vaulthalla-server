#pragma once

#include "cloud/Client.hpp"
#include "crypto/SecretBytes.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// The managed-storage calls a linked server makes (design/cloud/managed-remotes.md; the cloud's
// docs/design/managed-storage.md and account-model.md, "As built"), each signed with this installation's identity key
// (cloud::signedCall). The JSON shapes are the cloud's code's (src/storage/ManagedStorage.cpp, src/accounts/
// Deployments.cpp, src/billing/Billing.cpp): every member read here is checked for its type, and anything else is
// ignored. Nothing here sends a vault key, a vault name in the clear or anything unwrapped: vaults are named by their
// uid, the label is sealed to the pinned account key, and the bucket key arrives sealed to a one-time key that never
// leaves this process.
//
// Never called on a FUSE, sync or ws thread: CloudStorageService (and the CLI's own thread) only.
namespace vh::cloud::storage {

// This server's link, ready to sign: nullopt while unlinked (or the identity key no longer unseals).
struct Linked {
    Endpoint endpoint;
    std::string installation;
    vl::keykit::SecretBytes seed;
};
[[nodiscard]] std::optional<Linked> linked();

// A reply that wasn't 2xx: the HTTP status (0: unreachable), the cloud's error code and the optional `reason` the
// cloud adds to the 409s a client tells apart (account_key_unconfirmed, bucket_not_ready, bucket_off, ejecting,
// bucket_deleting, key_<state>, not_ejecting, managed_bucket, ...).
class CallError final : public std::runtime_error {
public:
    CallError(long status, std::string code, std::string reason, const std::string& message);
    [[nodiscard]] long status() const noexcept { return status_; }
    [[nodiscard]] const std::string& code() const noexcept { return code_; }
    [[nodiscard]] const std::string& reason() const noexcept { return reason_; }
    [[nodiscard]] bool unreachable() const noexcept { return status_ == 0 || status_ == 503; }

private:
    long status_;
    std::string code_;
    std::string reason_;
};

// The cloud's contract names that are announced to change, each in one place (contract:: in Storage.cpp):
//   - `account_key_confirmed` (the offline copy's confirmation) is renamed: offlineCopyConfirmedOf reads either name;
//   - GET /v1/storage gains the ejection portal's address: ejectionPortalOf;
//   - the envelopes route answers base64url instead of base64: decodeEnvelope takes either;
//   - a moved vault is listed with where it went: movedToOf.

// GET /v1/storage: the account's entitlement and this deployment's vaults.
struct Entitlement {
    std::optional<std::string> state;     // active | past_due | restricted | suspended | ended | null (no plan)
    std::string plan;
    uint64_t storage_quota_bytes{};
    std::string storage_access{"none"};   // full | read_delete | none
    std::string cause;
};

struct VaultStorage {
    std::string vault_uid;
    bool enabled{false};
    // none | waiting | pending | created | ready | off | emptying | deleted | ejecting | ejected | failed
    std::string state{"none"};
    std::optional<std::string> reason;    // waiting: payment_required | over_quota | account_key_unconfirmed | bucket_limit
    std::optional<std::string> bucket, bucket_id, s3_endpoint, region;
    std::optional<uint32_t> content_retention_days;
    std::optional<std::time_t> detached_at, converted_at;
    // This installation's key for the bucket: none | issued | active | superseded, with its id and access.
    std::string key_state{"none"};
    std::optional<std::string> key_id;
    std::optional<std::string> key_access;   // full | read_delete
    // A vault the account moved to another deployment (a restore elsewhere): where it went, when the cloud says so.
    std::optional<std::string> moved_to;
    // Replicated vaults (the cloud's managed-storage.md, "The join contract for the server", 7): the servers holding
    // it (oldest first) and the ones removed lately (newest first, at most 10: dropped from the manifest's writers).
    // node_id is the deployment's node id (its manifest writer name) when the cloud sends it.
    struct Replica {
        std::string deployment_id;
        std::string name;
        std::optional<std::string> node_id;
        std::optional<std::string> reason;   // former: server | owner | moved | deployment_removed
        // Active: a server reported that its manifest no longer names this node (contract 10), by that server's name.
        std::optional<std::string> unlisted_by;
    };
    std::vector<Replica> replicas, former_replicas;
    // The account holder removed the vault from this server (`removed: {reason: "owner"}`): stop syncing it.
    std::optional<std::string> removed_reason;
};

struct Overview {
    Entitlement entitlement;
    std::optional<uint64_t> stored_bytes;
    std::optional<std::string> usage_date;   // YYYY-MM-DD
    bool offline_copy_confirmed{false};      // the cloud's word: the account key's offline copy is confirmed
    std::optional<std::string> ejection_portal;   // where the account holder leaves managed storage, when given
    nlohmann::json ejection;                 // null, or the ejection's progress
    std::string provider;
    std::vector<VaultStorage> vaults;
};
[[nodiscard]] Overview overview(const Linked& link);
[[nodiscard]] Overview parseOverview(const nlohmann::json& body);   // throws std::runtime_error for a malformed body

// GET /v1/billing (kept as the cloud sent it, for status: state, state_since, next {state, at}, deletion_at, ...).
[[nodiscard]] nlohmann::json billing(const Linked& link);

// POST /v1/vaults {vault_uid, origin_vault_id}: true when this call registered it (201), false when this deployment
// already held it (200). 409: another deployment holds the vault.
bool registerVault(const Linked& link, const std::string& vaultUid, uint32_t originVaultId);

// PUT /v1/vaults/{uid}/label {label}: the vault's name sealed to the pinned account key (vl-keykit vault_label, 240
// bytes).
void putLabel(const Linked& link, const std::string& vaultUid, const std::vector<uint8_t>& sealedLabel);

// PUT /v1/storage/vaults/{uid} {enabled?, content_retention_days?} (202): the switch and the retention.
VaultStorage setVault(const Linked& link, const std::string& vaultUid, std::optional<bool> enabled,
                      std::optional<uint32_t> retentionDays);

// The sealed credential exchange (the cloud's managed-storage.md, "Credentials"): a one-time X25519 key pair made
// here, its public half sent in POST /v1/storage/vaults/{uid}/credentials (201), the sealed secret opened with
// vl-keykit credential::open under {this installation, the vault, the key id} and the one-time private key wiped. A
// lost response is never repeated: the next call makes a new key pair (the cloud revokes the unacknowledged key).
struct Credential {
    std::string key_id;
    std::string access;        // full | read_delete
    std::string bucket, bucket_id, s3_endpoint, region;
    vl::keykit::SecretBytes secret;
};
[[nodiscard]] Credential requestCredential(const Linked& link, const std::string& vaultUid);

// POST /v1/storage/credentials/{key_id}/ack (204): the key is stored and probed; the cloud revokes the older ones.
void acknowledge(const Linked& link, const std::string& keyId);
// DELETE /v1/vaults/{uid}/replica (204): this server stops holding a replicated vault (vh vault leave). False when the
// cloud says it doesn't hold it (404 no_such_vault); throws CallError otherwise.
bool leaveReplica(const Linked& link, const std::string& vaultUid);
// POST /v1/vaults/{uid}/replicas/unlisted {node_id} (204): a root this server published no longer names that node (vh
// vault replica remove; contract 10). False when no replica of the vault at the cloud has that node id (404
// not_held); throws CallError otherwise. The cloud records it and removes nobody: the account holder does.
bool reportUnlisted(const Linked& link, const std::string& vaultUid, const std::string& nodeId);

// POST /v1/storage/vaults/{uid}/detached and /ejected (204).
void reportDetached(const Linked& link, const std::string& vaultUid);
void reportEjected(const Linked& link, const std::string& vaultUid);

// POST /v1/billing/handoffs {kind, plan?} (201): {id, url, expires_at}. Never stored or logged.
struct Handoff {
    std::string url;
    std::optional<std::time_t> expires_at;
};
[[nodiscard]] Handoff billingHandoff(const Linked& link, const std::string& kind, const std::optional<std::string>& plan);

// GET /v1/keys/vaults/{uid}/envelopes: the cloud's account-key envelopes of the vault ({key_version, generation,
// envelope}), for `vh cloud recovery status --verify`.
struct CloudEnvelope {
    uint32_t key_version{};
    uint32_t generation{};
    std::vector<uint8_t> envelope;
};
[[nodiscard]] std::vector<CloudEnvelope> vaultEnvelopes(const Linked& link, const std::string& vaultUid);

}
