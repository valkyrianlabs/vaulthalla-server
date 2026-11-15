#pragma once

#include "ops/Actor.hpp"
#include "vault/RemoteAttach.hpp"
#include "vault/RemoteDetach.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

// Attaching a remote to a local vault (vault/RemoteAttach.hpp, design/storage/attach-remote.md) and detaching it again
// (vault/RemoteDetach.hpp) for operators: `vh vault remote attach | detach | status | abort`, ws vault.remote.attach |
// vault.remote.detach | vault.remote.status | vault.remote.abort.
//
// Who: attach, detach and abort need what binding a bucket to a vault needs (the admin Edit permission on the vault, the
// vault's sync config Edit permission, the API key's Consume permission) and the encryption-key Rotate permission (as
// the bucket layout migration: the operation decides where every object of the vault goes); super admins hold all of
// them (detach and abort ask for no API key permission: they use none). Status needs the admin View permission on the
// vault. Step-up (#359): attach, detach and abort are `keys`, bound to the vault ("vault.remote.attach:<id>",
// "vault.remote.detach:<id>", "vault.remote.abort:<id>"); the host CLI is exempt, and an agent can never satisfy it
// (where a vault's data goes is decided by a person). All three are in the audit trail (vault.remote.attach,
// vault.remote.detach, vault.remote.abort); the service records the cutovers, failures and the aborts' outcomes.
//
// Attach checks every precondition now, so a refusal is immediate and nothing was written beyond the capability
// probe's own object (which the probe deletes): then it records the attach and hands it to the RemoteAttachService.
// A vault's type never changes through storage.vault.update: attach is the one path from local to S3, detach the one
// path back.
namespace vh::ops::vault_remote {

struct ItemCounts {
    uint64_t files_pending{}, files_sent{}, files_failed{}, envelopes{}, metadata_objects{}, orphans{};
};

struct DetachCounts {
    uint64_t files_pending{}, files_verified{}, files_failed{}, files_fetched{}, envelopes{}, envelopes_copied{};
};

struct Status {
    unsigned int vault_id{};
    std::string vault_name;
    std::string type;                               // local | s3
    std::string remote;                             // none | attaching:<state> | attached | detaching:<state>
    std::optional<vault::remote::Row> attach;       // none until an operator starts one
    std::optional<vault::remote::detach::Row> detach;
    // The running (or failed) operation's progress: the detach's while one is unfinished, else the attach's.
    std::optional<vault::remote::Progress> progress;
    ItemCounts items;
    DetachCounts detach_items;
};

// One vault, or with nullopt every live vault that has (or had) an attach and that the caller may view.
[[nodiscard]] std::vector<Status> status(const Actor& actor, std::optional<unsigned int> vaultId = std::nullopt);
[[nodiscard]] nlohmann::json toJson(const Status& status);

// "none" | "attaching:<state>" | "attached" | "detaching:<state>", for storage.vault.get and vault lists: what the
// vault's type and its attach and detach rows (if any) say together.
[[nodiscard]] std::string remoteSummary(unsigned int vaultId, bool s3Vault);

struct AttachRequest {
    unsigned int vault_id{};
    unsigned int api_key_id{};
    std::string bucket;
    std::optional<std::string> storage_tier;
    bool accept_unpriced{false};
};
// Refusals: Denied, NotFound, Invalid, Conflict (an attach already runs, the bucket is another vault's or reserved, a
// failed attach names another bucket), and Refused with one of: key_rotation_running, key_salvage_running,
// legacy_content, key_version_missing, key_version_unattested, recovery_material_missing, bucket_listing_failed,
// bucket_not_empty, bucket_probe_failed, bucket_capability_insufficient. A failed attach started again with the same
// key and bucket resumes.
[[nodiscard]] Status attach(const Actor& actor, const AttachRequest& request);

struct DetachRequest {
    unsigned int vault_id{};
    std::string confirm;       // the vault's name, typed
};
// An S3 vault becomes a local vault in place: every file's current generation is fetched where it has no local copy
// and authenticated, recovery envelopes are copied from the bucket into the database, and then in one transaction the
// vault switches (vault/RemoteDetach.hpp). The bucket and its objects are left in place. Refusals: Denied, NotFound,
// Invalid (confirm), Conflict (not an S3 vault, a detach already runs, the vault isn't loaded), and Refused with one
// of: attach_running, layout_migration_running, key_rotation_running, key_salvage_running, legacy_content,
// key_version_missing, event_sync_active, sync_conflicts_open. A failed detach started again resumes.
[[nodiscard]] Status detach(const Actor& actor, const DetachRequest& request);

struct AbortRequest {
    unsigned int vault_id{};
    std::string confirm;       // the vault's name, typed
};
// Before the cutover only, of whichever runs: an attach's abort deletes exactly what the attach recorded and releases
// the bucket (state aborted), retrying deletes the provider refuses; a detach's abort leaves the vault an S3 vault (the
// local copies it fetched stay). Records the request; the service carries it out.
[[nodiscard]] Status abort(const Actor& actor, const AbortRequest& request);

}
