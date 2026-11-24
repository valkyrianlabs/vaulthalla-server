#pragma once

#include "rbac/permission/Override.hpp"
#include "rbac/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace vh::db::query::s3 {

struct GatewayCredential {
    uint32_t id{};
    uint32_t user_id{};
    std::optional<uint32_t> created_by;
    uint32_t principal_user_id{};
    std::string name;
    std::string access_key;
    std::vector<uint8_t> encrypted_secret_access_key;
    std::vector<uint8_t> iv;
    unsigned int master_version{1};  // the S3 gateway master that wraps the secret (migration 124)
    bool enabled{true};
    bool enforce_budget_for_local_requests{false};
    std::string scope_mode{"user_access"};
    std::optional<std::string> description;
    std::time_t created_at{};
    std::optional<std::time_t> last_used_at;
    std::optional<std::time_t> expires_at;
    // What this credential's CreateBucket creates (migration 154): a vault over this upstream profile, or over the
    // server's default profile, or (neither) a local vault. upstream_reapply: unset = the server's setting.
    std::optional<uint32_t> upstream_profile_id{};
    bool upstream_server_default{false};
    std::optional<bool> upstream_reapply{};
};

// What a gateway CreateBucket creates upstream (migration 154). The API key is a reference; its secret never leaves
// api_keys.
struct UpstreamProfile {
    uint32_t id{};
    std::string name{};               // region-shaped and immutable: clients select the profile with it
    uint32_t api_key_id{};
    bool encrypt_upstream{true};
    std::string sync_strategy{"cache"};
    std::string conflict_policy{"keep_local"};
    std::string bucket_prefix{};      // the upstream bucket is <prefix><gateway bucket>
    std::optional<std::string> description{};
    std::optional<uint32_t> created_by{};
    std::time_t created_at{};
    std::time_t updated_at{};
};

struct CredentialVaultAccessShorthand {
    uint32_t credential_id{};
    uint32_t vault_id{};
    bool can_list{true};
    bool can_read{true};
    bool can_write{false};
    bool can_delete{false};
    bool can_admin{false};
};

struct CredentialVaultRoleAssignment {
    uint32_t id{};
    uint32_t credential_id{};
    uint32_t vault_id{};
    uint32_t vault_role_id{};
    bool enabled{true};
    std::optional<uint32_t> created_by;
    std::time_t created_at{};
    std::time_t updated_at{};
};

struct CredentialVaultRoleAssignmentInput {
    uint32_t credential_id{};
    uint32_t vault_id{};
    uint32_t vault_role_id{};
    bool enabled{true};
    std::optional<uint32_t> created_by;
    std::vector<::vh::rbac::permission::Override> overrides{};
};

struct CredentialDefaultVaultRole {
    uint32_t id{};
    uint32_t credential_id{};
    uint32_t vault_role_id{};
    bool enabled{true};
    std::optional<uint32_t> created_by;
    std::time_t created_at{};
    std::time_t updated_at{};
};

struct CredentialSelectedVault {
    uint32_t credential_id{};
    uint32_t vault_id{};
    bool enabled{true};
    std::optional<uint32_t> created_by;
    std::time_t created_at{};
    std::time_t updated_at{};
};

struct CredentialDefaultVaultRoleOverride {
    uint32_t id{};
    uint32_t credential_id{};
    uint32_t gateway_credential_default_role_id{};
    ::vh::rbac::permission::Override rule;
    std::time_t created_at{};
    std::time_t updated_at{};
};

struct BucketBinding {
    uint32_t vault_id{};
    std::string bucket_name;
    bool api_exclusive{};
    std::string mode{"local"};
    std::optional<uint32_t> created_by;
    std::time_t created_at{};
    std::time_t updated_at{};
    // Set by a gateway CreateBucket that went through an upstream profile (migration 154).
    std::optional<uint32_t> created_by_credential_id{};
    std::optional<uint32_t> upstream_profile_id{};
};

// A bucket created from an upstream profile, with its creating credential's re-apply choice (unset = the server's;
// also unset once that credential is gone).
struct ProfileBucket {
    BucketBinding binding{};
    std::optional<bool> credential_reapply{};
};

struct ObjectState {
    uint32_t vault_id{};
    std::string object_key;
    std::string etag;
    uint64_t size_bytes{};
    std::optional<std::string> content_type;
    std::optional<std::string> storage_class;
    std::time_t last_modified{};
    bool multipart{};
    std::optional<uint32_t> part_count;
};

// One page of a bucket's keys (Gateway::listObjectStates), in S3's order: ascending UTF-8 bytes of the key, whatever
// the database's collation is. Every comparison of the listing (the sort, the place a page starts, the roll-up into
// common prefixes) is that one byte comparison, so a page boundary can't skip or repeat a key.
struct ObjectListParams {
    std::string prefix;
    std::optional<std::string> delimiter;   // empty: none
    // The page starts strictly after this position: a key (StartAfter, the v1 Marker; it need not exist) or the
    // last item of the page before (ObjectListResult::next_after). With a delimiter, a position that is itself a
    // common prefix of this listing skips every key under it; any other position names a key, and keys after it
    // still roll up into their common prefix, even the one the position lies in.
    std::optional<std::string> after;
    uint32_t max_keys{1000};                // capped at 1000; 0 answers an empty page
};

struct ObjectListResult {
    std::vector<ObjectState> objects;           // ascending
    std::vector<std::string> common_prefixes;   // ascending; with `objects`, at most max_keys items
    // The last item of a truncated page, a key or a common prefix: the next page's ObjectListParams::after. The S3
    // layer hands it out as NextMarker (v1) or wrapped in a continuation token (v2, protocols/s3/Listing.hpp).
    std::optional<std::string> next_after;
    bool is_truncated{};
};

struct MultipartUpload {
    std::string upload_id;
    std::string parts_dir_id;
    uint32_t vault_id{};
    std::string object_key;
    uint32_t initiated_by{};
    std::time_t initiated_at{};
    std::optional<std::string> content_type;
    std::map<std::string, std::string> metadata;
    std::optional<std::string> storage_class;
    bool aborted{};
    bool completed{};
};

struct MultipartPart {
    std::string upload_id;
    uint32_t part_number{};
    std::string etag;
    uint64_t size_bytes{};
    std::vector<uint8_t> md5;
    std::filesystem::path path;
    std::time_t created_at{};
    // The sealed part's IV (base64) and vault key version (protocols/s3/PartCipher.hpp, migration 118). Unset only on
    // a part stored as plaintext before migration 118, until the daemon seals it.
    std::optional<std::string> encryption_iv;
    std::optional<uint32_t> key_version;
};

class Gateway {
public:
    static uint32_t createCredential(const GatewayCredential& credential);
    static std::vector<GatewayCredential> listCredentials(std::optional<uint32_t> userId = std::nullopt);
    static std::vector<GatewayCredential> listCredentialsForPrincipal(uint32_t userId);
    static std::vector<GatewayCredential> listCredentialsAdmin(bool includeDisabled = false);
    static std::optional<GatewayCredential> getCredentialByAccessKey(const std::string& accessKey);
    static bool deleteCredentialByAccessKey(const std::string& accessKey);
    static bool deleteCredentialByName(uint32_t userId, const std::string& name);
    static void updateCredentialLastUsed(uint32_t id);
    static void replaceCredentialScopeShorthand(uint32_t credentialId, const std::vector<CredentialVaultAccessShorthand>& scopes);
    static std::vector<CredentialVaultRoleAssignment> listCredentialVaultRoleAssignments(uint32_t credentialId);
    static uint32_t upsertCredentialVaultRoleAssignment(const CredentialVaultRoleAssignmentInput& input);
    static bool deleteCredentialVaultRoleAssignment(uint32_t credentialId, uint32_t vaultId);
    static std::vector<::vh::rbac::permission::Override> listCredentialVaultRoleOverrides(uint32_t credentialId, uint32_t vaultId);
    static uint32_t upsertCredentialVaultRoleOverride(uint32_t credentialId, uint32_t vaultId, const ::vh::rbac::permission::Override& overrideRule);
    static bool deleteCredentialVaultRoleOverride(uint32_t credentialId, uint32_t vaultId, uint32_t overrideId);
    static std::shared_ptr<::vh::rbac::role::Vault> getCredentialVaultRoleForVault(uint32_t credentialId, uint32_t vaultId);
    static std::optional<CredentialDefaultVaultRole> getCredentialDefaultVaultRole(uint32_t credentialId);
    static uint32_t upsertCredentialDefaultVaultRole(uint32_t credentialId, uint32_t vaultRoleId, bool enabled, std::optional<uint32_t> createdBy);
    static bool deleteCredentialDefaultVaultRole(uint32_t credentialId);
    static std::vector<::vh::rbac::permission::Override> listCredentialDefaultVaultRoleOverrides(uint32_t credentialId);
    static uint32_t upsertCredentialDefaultVaultRoleOverride(uint32_t credentialId, const ::vh::rbac::permission::Override& overrideRule);
    static bool deleteCredentialDefaultVaultRoleOverride(uint32_t credentialId, uint32_t overrideId);
    static std::vector<CredentialSelectedVault> listCredentialSelectedVaults(uint32_t credentialId);
    static void replaceCredentialSelectedVaults(uint32_t credentialId, const std::vector<uint32_t>& vaultIds, std::optional<uint32_t> createdBy);
    static CredentialSelectedVault upsertCredentialSelectedVault(uint32_t credentialId, uint32_t vaultId, bool enabled, std::optional<uint32_t> createdBy);
    static bool deleteCredentialSelectedVault(uint32_t credentialId, uint32_t vaultId);
    static std::shared_ptr<::vh::rbac::role::Vault> getEffectiveCredentialVaultRole(
        uint32_t credentialId,
        uint32_t vaultId,
        const std::string& scopeMode);
    static void updateCredentialScopeMode(
        uint32_t credentialId,
        const std::string& scopeMode,
        uint32_t principalUserId,
        std::optional<uint32_t> createdBy,
        std::optional<std::string> description,
        std::optional<std::time_t> expiresAt,
        std::optional<bool> enforceBudgetForLocalRequests = std::nullopt);
    static std::optional<GatewayCredential> getCredentialById(uint32_t id);
    // The credential's upstream source: a profile, the server default, or neither (the schema refuses both).
    static void setCredentialUpstream(uint32_t credentialId, std::optional<uint32_t> profileId, bool serverDefault,
                                      std::optional<bool> reapply);
    // Credentials whose own profile it is, or that may select it.
    static std::vector<GatewayCredential> listCredentialsUsingProfile(uint32_t profileId);
    // The profiles a credential may select per request, besides its own (by name).
    static std::vector<UpstreamProfile> listCredentialAllowedProfiles(uint32_t credentialId);
    static void replaceCredentialAllowedProfiles(uint32_t credentialId, const std::vector<uint32_t>& profileIds,
                                                 std::optional<uint32_t> createdBy);

    static uint32_t createUpstreamProfile(const UpstreamProfile& profile);
    // Everything but the name, which is immutable. False when the profile is gone.
    static bool updateUpstreamProfile(const UpstreamProfile& profile);
    static bool deleteUpstreamProfile(uint32_t id);
    static std::optional<UpstreamProfile> getUpstreamProfile(uint32_t id);
    static std::optional<UpstreamProfile> getUpstreamProfileByName(const std::string& name);
    static std::vector<UpstreamProfile> listUpstreamProfiles();
    static std::vector<UpstreamProfile> listUpstreamProfilesUsingKey(uint32_t apiKeyId);
    // The live buckets a gateway CreateBucket made from this profile.
    static std::vector<ProfileBucket> listBucketsOfProfile(uint32_t profileId);

    static void recordSyncOrigin(
        uint32_t vaultId,
        const std::string& objectKey,
        const std::string& operation,
        std::optional<uint32_t> gatewayCredentialId,
        const std::string& requestUuid);

    static void bindBucket(const BucketBinding& binding);
    static bool unbindBucket(const std::string& bucketName);
    static std::optional<BucketBinding> resolveBucket(const std::string& bucketName);
    static std::vector<BucketBinding> listBuckets(std::optional<uint32_t> userId = std::nullopt);

    static void upsertObject(const ObjectState& state);
    static std::optional<ObjectState> getObjectState(uint32_t vaultId, const std::string& objectKey);
    static void deleteObjectState(uint32_t vaultId, const std::string& objectKey);
    static void deleteObjectStateAndRemoteIndex(uint32_t vaultId, const std::string& objectKey);
    static ObjectListResult listObjectStates(uint32_t vaultId, const ObjectListParams& params);

    static void upsertObjectMetadata(uint32_t vaultId, const std::string& objectKey,
                                     const std::map<std::string, std::string>& metadata);
    static std::map<std::string, std::string> listObjectMetadata(uint32_t vaultId, const std::string& objectKey);
    static void deleteObjectMetadata(uint32_t vaultId, const std::string& objectKey);

    static void createMultipartUpload(const MultipartUpload& upload);
    static std::optional<MultipartUpload> getMultipartUpload(const std::string& uploadId);
    static std::vector<MultipartUpload> listMultipartUploads(uint32_t vaultId, const std::string& prefix = {});
    static std::vector<MultipartUpload> listMultipartUploadsInitiatedBefore(std::time_t cutoff);
    // Every upload that is neither completed nor aborted, in every vault.
    static std::vector<MultipartUpload> listOpenMultipartUploads();
    static void markMultipartUploadCompleted(const std::string& uploadId);
    static void abortMultipartUpload(const std::string& uploadId);

    // Inserts or replaces the part's row; returns the file the replaced row pointed at (the caller removes it when it
    // differs from the new one), read under the row's lock in the same transaction.
    static std::optional<std::filesystem::path> upsertMultipartPart(const MultipartPart& part);
    // Points a plaintext part (no encryption_iv) at its sealed copy. False when the row is no longer that plaintext
    // part (re-uploaded or gone meanwhile): the caller then drops its copy.
    static bool sealLegacyMultipartPart(const std::string& uploadId, uint32_t partNumber,
                                        const std::filesystem::path& plaintextPath, const std::filesystem::path& sealedPath,
                                        const std::string& encryptionIv, uint32_t keyVersion);
    static std::vector<MultipartPart> listMultipartParts(const std::string& uploadId);
    static std::optional<MultipartPart> getMultipartPart(const std::string& uploadId, uint32_t partNumber);
    static void deleteMultipartParts(const std::string& uploadId);

    static void backfillObjectStateFromFs(uint32_t vaultId);
    static void backfillObjectStateFromRemoteIndex(uint32_t vaultId);
};

}
