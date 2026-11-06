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
    bool enabled{true};
    bool enforce_budget_for_local_requests{false};
    std::string scope_mode{"user_access"};
    std::optional<std::string> description;
    std::time_t created_at{};
    std::optional<std::time_t> last_used_at;
    std::optional<std::time_t> expires_at;
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

struct ObjectListParams {
    std::string prefix;
    std::optional<std::string> delimiter;
    std::optional<std::string> start_after;
    std::optional<std::string> continuation_token;
    uint32_t max_keys{1000};
};

struct ObjectListResult {
    std::vector<ObjectState> objects;
    std::vector<std::string> common_prefixes;
    std::optional<std::string> next_continuation_token;
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
