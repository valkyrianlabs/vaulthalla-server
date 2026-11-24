#pragma once

#include "ops/Actor.hpp"
#include "db/query/s3/Gateway.hpp"
#include "protocols/s3/GatewayService.hpp"
#include "rbac/permission/Override.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// The S3 gateway's credentials, vault grants, bucket bindings and credential budgets, shared by `vh s3-gateway ...`
// and the ws s3.gateway.* commands. Every rule lives here once:
//  - a credential is visible to and managed by its principal, or anyone with admin.s3_gateway.manage_credentials;
//    acting for another principal also needs assign_principal;
//  - granting a vault to a credential's principal (selecting it, assigning a role, adding an override) needs the
//    vault-role permission over that principal on that vault, and the principal must already reach the vault;
//    a granted role may not exceed what the principal can do, and only admins grant role administration;
//  - global credentials and their policy need manage_credentials; buckets need manage_buckets plus vault edit;
//    budgets need manage_budgets (plus vault edit for a key/vault budget);
//  - upstream profiles (what a gateway CreateBucket creates, migration 154) need manage_buckets plus what creating
//    a bucket with the profile's API key needs (admin.upstream.provision and the key's Consume); pointing a
//    credential at a profile needs management of that credential plus the same two, for the actor and for the
//    credential's principal. The principal is checked again on every CreateBucket: a credential never exceeds it.
// protocols::s3::CredentialManager and db::query::s3::Gateway underneath are trusted and never authorize.
namespace vh::ops::s3_gateway {

using Credential = db::query::s3::GatewayCredential;
using Assignment = db::query::s3::CredentialVaultRoleAssignment;
using DefaultRole = db::query::s3::CredentialDefaultVaultRole;
using SelectedVault = db::query::s3::CredentialSelectedVault;
using Bucket = db::query::s3::BucketBinding;
using UpstreamProfile = db::query::s3::UpstreamProfile;
using Override = rbac::permission::Override;
using Policy = storage::s3::pricing::PriceBudgetPolicy;

// A credential as the caller named it: by id, or by access key or name.
using Ref = std::variant<uint32_t, std::string>;

// Boolean compatibility shorthand for a vault grant. Gateway authorization uses vault roles; a shorthand is
// mapped to one. Listing and reading are on unless turned off.
struct VaultAccess {
    uint32_t vault_id{};
    bool list{true};
    bool read{true};
    bool write{false};
    bool del{false};
    bool admin{false};
};

struct CreateCredential {
    std::string name;
    std::optional<uint32_t> principal_id{};         // defaults to the actor
    std::optional<std::string> scope_mode{};        // user-access | global | vault-allowlist; default: vault-allowlist
                                                    // when vaults are given, else user-access
    std::optional<std::string> description{};
    std::optional<std::time_t> expires_at{};
    std::optional<uint32_t> default_role_id{};
    std::vector<uint32_t> selected_vault_ids{};
    std::vector<VaultAccess> vault_access{};
    bool enforce_budget_for_local_requests{false};
};

struct CreatedCredential {
    Credential credential;
    std::string secret_access_key;   // shown once
};

// Absent fields stay as they are.
struct ScopeUpdate {
    std::optional<std::string> scope_mode{};
    std::optional<uint32_t> principal_id{};
    std::optional<std::optional<std::string>> description{};
    std::optional<std::optional<std::time_t>> expires_at{};
    std::optional<bool> enforce_budget_for_local_requests{};
    std::optional<std::vector<VaultAccess>> vault_access{};
    std::optional<std::vector<uint32_t>> selected_vault_ids{};
    std::optional<uint32_t> default_role_id{};
};

struct OverrideSpec {
    std::string permission;   // id, qualified name, or a files/directories short name
    std::string effect;       // allow | deny; required
    std::string pattern;      // glob; required
    bool enabled{true};
};

struct BindBucket {
    uint32_t vault_id{};
    std::optional<std::string> bucket_name{};   // defaults to the vault's slug
    std::optional<std::string> mode{};          // local | remote_cache | remote_proxy; default by vault type
    bool api_exclusive{false};
};

struct CreateLocalBucket {
    std::optional<std::string> bucket_name{};   // absent: a new vault whose slug is the bucket
    std::optional<uint32_t> owner_id{};
    uintmax_t quota{0};
    std::optional<std::string> name{};
    std::optional<std::string> description{};
};

struct CreateRemoteCacheBucket {
    std::optional<std::string> bucket_name{};   // defaults to the new vault's slug
    std::optional<uint32_t> owner_id{};
    uint32_t api_key_id{};
    std::string upstream_bucket;
    bool encrypt_upstream{true};
    std::optional<std::string> name{};
    std::optional<std::string> description{};
    bool accept_waiver{false};
};

// An upstream profile as the caller named it: by id or by name.
using ProfileRef = std::variant<uint32_t, std::string>;

struct CreateProfile {
    std::string name;                               // region-shaped ("vl-b2"), immutable, never "local" or a real region
    std::variant<unsigned int, std::string> api_key;   // id or name; must be enabled for provider administration
    std::optional<bool> encrypt_upstream{};         // default: encrypt
    std::optional<std::string> sync_strategy{};     // cache | sync | mirror; default vaults.s3.default_remote_sync_strategy
    std::optional<std::string> conflict_policy{};   // keep_local | keep_remote | keep_newest | ask; default likewise
    std::optional<std::string> bucket_prefix{};     // the upstream bucket is <prefix><gateway bucket>
    std::optional<std::string> description{};
};

// Absent fields stay as they are. The name never changes.
struct UpdateProfile {
    std::optional<std::variant<unsigned int, std::string>> api_key{};
    std::optional<bool> encrypt_upstream{};
    std::optional<std::string> sync_strategy{};
    std::optional<std::string> conflict_policy{};
    std::optional<std::string> bucket_prefix{};
    std::optional<std::optional<std::string>> description{};
};

// A bucket created from a profile, after a change of the profile's sync settings.
struct ReappliedBucket {
    std::string bucket_name;
    uint32_t vault_id{};
    bool applied{false};
    std::string detail;     // why not, when it wasn't
};

struct UpdatedProfile {
    UpstreamProfile profile;
    std::vector<ReappliedBucket> reapplied;   // empty unless the sync strategy or conflict policy changed
};

// What a credential's CreateBucket creates. source: local | profile | server_default.
struct CredentialUpstream {
    std::string source{"local"};
    std::optional<UpstreamProfile> profile{};   // the profile a CreateBucket would use now
    std::string problem{};                      // why there is none although the source asks for one
    std::optional<bool> reapply{};              // the credential's own choice; unset = the server's setting
    bool reapply_effective{true};
    // The profiles a request made with this credential may name (LocationConstraint or signing region), besides the
    // one above. A profile outside both is refused: the key is bounded in which upstream accounts it can reach.
    std::vector<UpstreamProfile> allowed{};
};

// Absent fields stay as they are.
struct SetCredentialUpstream {
    std::optional<std::string> source{};        // local | profile | server_default
    std::optional<ProfileRef> profile{};        // implies source profile
    std::optional<std::optional<bool>> reapply{};
    std::optional<std::vector<ProfileRef>> allowed{};   // replaces the allowlist; empty: none
};

// What a gateway request said about where its bucket belongs.
struct CreateHints {
    std::string location_constraint;   // CreateBucketConfiguration.LocationConstraint
    std::string signing_region;        // the SigV4 credential scope's region
};

enum class BudgetScope { Key, KeyVault };

struct BudgetSpec {
    BudgetScope scope{BudgetScope::Key};
    uint32_t credential_id{};
    std::optional<uint32_t> vault_id{};
    std::optional<std::string> mode{};                  // default enforce
    std::optional<std::string> currency{};              // default USD
    std::optional<std::string> max_run_cost{};
    std::optional<std::string> max_daily_cost{};
    std::optional<std::string> max_monthly_cost{};
    std::optional<bool> require_verified_catalog{};     // default true
    std::optional<bool> allow_stale_catalog{};          // default false
    std::optional<int64_t> max_catalog_age_seconds{};   // default 43200
};

struct BudgetFilter {
    std::optional<uint32_t> credential_id{};
    std::optional<uint32_t> vault_id{};
    bool include_inactive{true};
};

struct BudgetStatus {
    std::vector<Policy> policies;
    std::vector<storage::s3::pricing::PriceBudgetLedgerEntry> ledger;
    std::vector<storage::s3::pricing::PriceBudgetTrendStats> trends;
};

// ------------------------------------------------------------------------------------------------- lookups

// A vault by name: under `owner` when given; otherwise the actor's own vault of that name, else the only vault
// with that name. More than one is ambiguous, never "the first".
[[nodiscard]] uint32_t vaultIdByName(const Actor& actor, const std::string& name, std::optional<uint32_t> owner = {});
[[nodiscard]] Credential getCredential(const Actor& actor, const Ref& credential);
// For budget commands: budget viewers and managers, or anyone scoping to a vault they can view, may name any
// credential (what they then see is still filtered per policy); others only the credentials they see.
[[nodiscard]] Credential getBudgetCredential(const Actor& actor, const Ref& credential,
                                             std::optional<uint32_t> scopedToVault = std::nullopt);

// ------------------------------------------------------------------------------------------------- service

[[nodiscard]] protocols::s3::GatewayService::RuntimeStatus status(const Actor& actor);

// ------------------------------------------------------------------------------------------------- credentials

[[nodiscard]] CreatedCredential createCredential(const Actor& actor, const CreateCredential& req);
// One principal's credentials, or with no principal every credential the actor may see.
[[nodiscard]] std::vector<Credential> listCredentials(const Actor& actor, std::optional<uint32_t> principal,
                                                      bool includeDisabled = true);
Credential revokeCredential(const Actor& actor, const Ref& credential);
Credential updateScope(const Actor& actor, const Ref& credential, const ScopeUpdate& req);
// Boolean shorthand: selects the vault and grants the role it maps to (CLI `creds scope allow-vault`).
Credential allowVault(const Actor& actor, const Ref& credential, const VaultAccess& access);
// Drops the vault from the credential: its selection and any per-vault role.
void removeVault(const Actor& actor, const Ref& credential, uint32_t vaultId);

[[nodiscard]] std::optional<DefaultRole> getDefaultRole(const Actor& actor, const Ref& credential);
DefaultRole setDefaultRole(const Actor& actor, const Ref& credential, uint32_t roleId, bool enabled = true);
bool clearDefaultRole(const Actor& actor, const Ref& credential);

[[nodiscard]] std::vector<SelectedVault> listSelectedVaults(const Actor& actor, const Ref& credential);
std::vector<SelectedVault> replaceSelectedVaults(const Actor& actor, const Ref& credential, const std::vector<uint32_t>& vaultIds);
SelectedVault addSelectedVault(const Actor& actor, const Ref& credential, uint32_t vaultId, bool enabled = true);

// The actor's view: a principal sees all of their credential's roles, anyone else those on vaults where they
// may view the principal's roles.
[[nodiscard]] std::vector<Assignment> listRoleAssignments(const Actor& actor, const Ref& credential);
Assignment assignRole(const Actor& actor, const Ref& credential, uint32_t vaultId, uint32_t roleId, bool enabled = true);
void revokeRole(const Actor& actor, const Ref& credential, uint32_t vaultId);

[[nodiscard]] std::vector<Override> listDefaultRoleOverrides(const Actor& actor, const Ref& credential);
Override addDefaultRoleOverride(const Actor& actor, const Ref& credential, const OverrideSpec& spec);
void removeDefaultRoleOverride(const Actor& actor, const Ref& credential, uint32_t overrideId);
[[nodiscard]] std::vector<Override> listRoleOverrides(const Actor& actor, const Ref& credential, uint32_t vaultId);
Override addRoleOverride(const Actor& actor, const Ref& credential, uint32_t vaultId, const OverrideSpec& spec);
void removeRoleOverride(const Actor& actor, const Ref& credential, uint32_t vaultId, uint32_t overrideId);

// ------------------------------------------------------------------------------------------------- buckets

[[nodiscard]] std::vector<Bucket> listBuckets(const Actor& actor);
Bucket bindBucket(const Actor& actor, const BindBucket& req);
void unbindBucket(const Actor& actor, const std::string& bucketName);
// For bucket maintenance (backfill): the binding, once the actor may manage it.
[[nodiscard]] Bucket requireManageableBucket(const Actor& actor, const std::string& bucketName);
Bucket createLocalBucket(const Actor& actor, const CreateLocalBucket& req);
// Creates the S3 vault through ops::vaults (key Consume, encryption waiver), then binds it; a failed bind removes
// the vault again.
Bucket createRemoteCacheBucket(const Actor& actor, const CreateRemoteCacheBucket& req);

// ------------------------------------------------------------------------------------------------- upstream profiles

// Visible with admin.s3_gateway view, manage_buckets or manage_credentials, or admin.upstream.provision.
[[nodiscard]] std::vector<UpstreamProfile> listUpstreamProfiles(const Actor& actor);
[[nodiscard]] UpstreamProfile getUpstreamProfile(const Actor& actor, const ProfileRef& profile);
UpstreamProfile createUpstreamProfile(const Actor& actor, const CreateProfile& req);
// A changed sync strategy or conflict policy is re-applied to the buckets created from the profile whose creating
// credential asks for it (CredentialUpstream::reapply_effective), with the actor's own sync-settings permission on
// each vault. The API key, encryption and prefix only ever apply to buckets created afterwards.
UpdatedProfile updateUpstreamProfile(const Actor& actor, const ProfileRef& profile, const UpdateProfile& req);
// Refused while a credential or the server default names it. Buckets created from it are untouched.
void deleteUpstreamProfile(const Actor& actor, const ProfileRef& profile);
// The server default (s3_gateway.default_upstream_profile), when it names an existing profile.
[[nodiscard]] std::optional<UpstreamProfile> serverDefaultProfile();

[[nodiscard]] CredentialUpstream credentialUpstream(const Actor& actor, const Ref& credential);
// Trusted: the same answer for a credential already resolved (the gateway, and the surfaces' credential JSON).
[[nodiscard]] CredentialUpstream upstreamOf(const Credential& credential);
Credential setCredentialUpstream(const Actor& actor, const Ref& credential, const SetCredentialUpstream& req);

// The profile a gateway CreateBucket uses, or none for a local vault. In order: a LocationConstraint naming a profile
// ("local" forces a local vault; anything else, a region, is ignored), a signing region naming a profile, the
// credential's profile, the server default when the credential opted in. A profile the request names must be the
// credential's own or on its allowlist, else Denied. Trusted (no actor): the gateway calls it for an authenticated
// credential. Throws Invalid when the credential asks for a profile that isn't there, so a bucket meant for an
// upstream account is never silently created as a local vault.
[[nodiscard]] std::optional<UpstreamProfile> profileForCreate(const Credential& credential, const CreateHints& hints);
// A gateway bucket over the profile: the upstream bucket <prefix><name> is created (or adopted while it is empty),
// the S3 vault gets the profile's settings, and the bucket is bound in remote_cache mode. `actor` is the
// credential's principal and needs everything creating that vault by hand would: manage_buckets, vault Create,
// admin.upstream.provision and the key's Consume. A failed bind removes the vault again.
Bucket createProfileBucket(const Actor& actor, const UpstreamProfile& profile, const std::string& bucketName,
                           std::optional<uint32_t> credentialId);

// ------------------------------------------------------------------------------------------------- budgets

Policy upsertBudget(const Actor& actor, const BudgetSpec& spec);
bool disableBudget(const Actor& actor, BudgetScope scope, uint32_t credentialId, std::optional<uint32_t> vaultId);
[[nodiscard]] std::vector<Policy> listBudgets(const Actor& actor, const BudgetFilter& filter);
[[nodiscard]] std::vector<storage::s3::pricing::PriceBudgetLedgerEntry> budgetLedger(const Actor& actor,
                                                                                     const BudgetFilter& filter,
                                                                                     uint32_t limit);
[[nodiscard]] BudgetStatus budgetStatus(const Actor& actor, const BudgetFilter& filter, uint32_t limit);

}
