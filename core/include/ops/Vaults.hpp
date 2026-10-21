#pragma once

#include "ops/Actor.hpp"
#include "ops/Upstream.hpp"
#include "db/model/ListQueryParams.hpp"
#include "vault/Fwd.hpp"
#include "vault/model/Vault.hpp"
#include "sync/Fwd.hpp"

#include <nlohmann/json_fwd.hpp>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// Vault lifecycle and sync policy shared by `vh vault ...` and the ws storage.vault.* commands. Every change goes
// through storage::Manager so the live engine (which the RBAC resolver reads the owner from) never goes stale, and
// sync policy changes are copy-on-write, swapped under the engine lock, persisted and pushed to the controller.
namespace vh::ops::vaults {

using VaultPtr = std::shared_ptr<vault::model::Vault>;
using PolicyPtr = std::shared_ptr<sync::model::Policy>;
using DeletionPtr = std::shared_ptr<vault::model::Deletion>;

// Absent = unchanged; an empty inner optional clears the limit.
struct S3BudgetPatch {
    std::optional<std::optional<uint64_t>> list, head, get, put, copy, del, downloaded_bytes;
    [[nodiscard]] bool empty() const { return !list && !head && !get && !put && !copy && !del && !downloaded_bytes; }
};

// Sync settings as the caller spelled them; parsed and validated against the vault type by the op.
struct SyncPatch {
    std::optional<std::chrono::seconds> interval{};
    std::optional<bool> enabled{};
    std::optional<std::string> strategy{};          // S3 only: cache | sync | mirror
    std::optional<std::string> conflict_policy{};   // local: overwrite|keep_both|ask; S3: keep_local|keep_remote|keep_newest|ask
    std::optional<std::optional<std::chrono::seconds>> max_remote_index_age{};   // S3 only
    std::optional<std::string> s3_budget_preset{};  // S3 only, applied before s3_budget
    S3BudgetPatch s3_budget{};                      // S3 only
    [[nodiscard]] bool empty() const {
        return !interval && !enabled && !strategy && !conflict_policy && !max_remote_index_age && !s3_budget_preset &&
               s3_budget.empty();
    }
};

struct S3Spec {
    unsigned int api_key_id = 0;
    std::string bucket;                              // empty with provision.generate_name: pick one
    std::optional<std::string> storage_tier{};
    std::optional<bool> encrypt_upstream{};          // default: encrypt
    // Upstream bucket provisioning (#237): create a managed bucket or adopt an existing one with an admin-enabled key.
    // Absent or mode existing: the bucket is used as named, with no provider administration calls (as before).
    std::optional<upstream::Provision> provision{};
};

struct Create {
    std::string name;
    vault::model::VaultType type{vault::model::VaultType::Local};
    std::optional<unsigned int> owner_id{};          // default: the actor
    std::string description{};
    uintmax_t quota = 0;
    std::string slug{};
    std::optional<std::string> fuse_name{};
    std::optional<S3Spec> s3{};
    SyncPatch sync{};
    bool accept_waiver = false;                      // see NeedsConfirmation "encryption_waiver"
};

// Patch semantics: an absent field is unchanged.
struct Update {
    unsigned int id = 0;
    std::optional<std::string> name{};
    std::optional<std::string> description{};
    std::optional<uintmax_t> quota{};
    std::optional<unsigned int> owner_id{};          // reassignment also needs Create for the new owner
    std::optional<std::string> slug{};
    std::optional<std::optional<std::string>> fuse_name{};
    std::optional<bool> is_active{};
    std::optional<unsigned int> api_key_id{};        // needs Consume on the new key
    std::optional<std::string> bucket{};
    std::optional<std::optional<std::string>> storage_tier{};
    std::optional<bool> encrypt_upstream{};
    SyncPatch sync{};                                // needs vault sync.config.edit
    bool accept_waiver = false;
};

struct Details {
    VaultPtr vault;
    PolicyPtr sync;
    std::string owner_name;
};

enum class SyncStart { Started, RerunQueued };

// Safe deletion with retention (#162). A delete is a schedule: the vault vanishes at once and can be restored until
// vaults.retention_window ends, then the retention service purges its data. RBAC: vault Remove for delete, delete
// now, restore and listing deletions (the owner recorded at delete time decides the scope).
//
// NeedsConfirmation codes (the CLI asks, the web shows them in its delete dialog; both resend with the flag set):
//   "vault_upstream_key_loss"  an S3 vault keeps encrypted objects upstream while its key was never exported; without
//                              the key that data can never be decrypted again (accept_key_loss).
//   "vault_delete_now"         purging now skips the restore window (confirm_now).
inline constexpr const char* VAULT_UPSTREAM_KEY_LOSS = "vault_upstream_key_loss";
inline constexpr const char* VAULT_DELETE_NOW = "vault_delete_now";

struct Remove {
    unsigned int id = 0;
    bool now = false;                          // purge on the next retention pass instead of after the window
    std::optional<bool> delete_upstream{};     // S3 only: delete the bucket's objects at purge time; absent = keep
    bool confirm_now = false;
    bool accept_key_loss = false;
};

// What deleting this vault would do, for the delete dialogs. Nothing changes.
struct RemovalPlan {
    VaultPtr vault;
    std::string provider;                      // S3: the API key's provider, else empty
    std::string bucket;
    bool encrypted_upstream = false;           // S3 objects are encrypted with the vault key
    unsigned int key_version = 0;
    std::optional<std::time_t> key_exported_at{};   // when the current key version was exported, if ever
    std::chrono::seconds retention_window{}, key_retention_window{};
    std::string export_command;
    [[nodiscard]] bool keyExported() const { return key_exported_at.has_value(); }
};

// Throws NeedsConfirmation{"encryption_waiver"} when an S3 vault would be created over, or switch encryption on,
// a bucket that already holds data, unless accept_waiver is set. The accepted waiver is recorded.
[[nodiscard]] VaultPtr create(const Actor& actor, const Create& req);
[[nodiscard]] VaultPtr update(const Actor& actor, const Update& req);
// Schedules the deletion. On a vault already pending deletion, `now` purges it on the next pass (and
// delete_upstream, when given, replaces the earlier choice); anything else is a Conflict.
DeletionPtr remove(const Actor& actor, const Remove& req);
[[nodiscard]] RemovalPlan removalPlan(const Actor& actor, unsigned int vaultId);
// Deletions the actor could have made: pending, purging, and purged tombstones (newest first).
[[nodiscard]] std::vector<DeletionPtr> listDeleted(const Actor& actor);
// A pending deletion only; Conflict once the purge has started.
VaultPtr restore(const Actor& actor, unsigned int vaultId);
// A deleted vault by ID, or by name (owned by ownerId when given), that the actor may see.
[[nodiscard]] DeletionPtr findDeleted(const Actor& actor, const std::string& idOrName, std::optional<unsigned int> ownerId);

// Checks only, nothing changes: what update {owner_id} and remove would refuse. Ownership transfer is an
// administrator's act: it needs an admin account, vault Edit, and the right to create vaults for the new owner, and
// the new owner must not already have a vault with that name.
void requireTransferable(const Actor& actor, unsigned int vaultId, unsigned int newOwnerId);
void requireRemovable(const Actor& actor, unsigned int vaultId);
[[nodiscard]] Details get(const Actor& actor, unsigned int vaultId);
[[nodiscard]] std::vector<VaultPtr> list(const Actor& actor, db::model::ListQueryParams params = {},
                                         std::optional<vault::model::VaultType> type = std::nullopt);
[[nodiscard]] PolicyPtr updateSync(const Actor& actor, unsigned int vaultId, const SyncPatch& patch);
SyncStart triggerSync(const Actor& actor, unsigned int vaultId);

// ---- vaults the actor can reach (Vaulthalla Desktop's file browser) ----
//
// list() follows the actor's admin vault policy (admin.vaults.<scope>.view), so an account that only owns a vault or
// holds a vault role on it (its own or a group's) sees nothing there. listAccessible() answers "where can I go":
// every live vault the actor reaches by any path, with what the enforcing resolvers grant at the vault root.

// Why the actor reaches a vault. Several can hold at once; they are reported in this order.
enum class AccessVia : uint8_t {
    Owner,        // the actor owns the vault
    VaultRole,    // a vault role assigned to the actor on this vault
    GroupRole,    // a vault role assigned to one of the actor's groups on this vault
    AdminPolicy,  // the actor's admin role grants here: admin.vaults.<scope>.view, or its global vault filesystem policy
    SuperAdmin,   // super admin: everything
};

[[nodiscard]] const char* to_string(AccessVia via);

struct AccessibleVault {
    VaultPtr vault;
    std::string owner_name;         // "" when the owner no longer resolves
    // rbac::resolver::Vault::has<FilesystemAction>(List) at the vault root's FUSE path: what fs.dir.list {path: "/"}
    // enforces, so the file browser can open the vault.
    bool browse = false;
    // rbac::resolver::Admin::has<VaultPermissions>(View): what storage.vault.get enforces (vault settings, stats).
    bool manage = false;
    std::vector<AccessVia> via;     // never empty
};

// Every live (not deleted) vault where the actor is the owner, holds a vault role (directly or through a group), or
// where the super-admin role or the admin role's vault policies grant browse or manage. browse and manage are decided
// by the same resolvers that enforce them; via says which paths exist. A deactivated or deleted account gets an empty
// list. One read of the live vaults, then memory only (engines, the canonical identity state), sorted by id.
[[nodiscard]] std::vector<AccessibleVault> listAccessible(const Actor& actor);

// The ws/`--json` shape of one entry (the contract's AccessibleVault model): a summary of the vault (no backing or
// upstream details: those are storage.vault.get's, behind manage) plus browse, manage and via.
[[nodiscard]] nlohmann::json toJson(const AccessibleVault& entry);

}
