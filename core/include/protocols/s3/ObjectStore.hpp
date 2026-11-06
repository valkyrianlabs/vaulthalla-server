#pragma once

#include "protocols/http/Range.hpp"
#include "protocols/s3/Auth.hpp"
#include "db/query/s3/Gateway.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/s3/policy/Request.hpp"
#include "fs/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "storage/Fwd.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace vh::protocols::s3 {

struct GatewayAccessContext {
    uint32_t credential_id{};
    std::string access_key;
    std::string scope_mode{"user_access"};
    db::query::s3::GatewayCredential credential;
    bool enforce_budget_for_local_requests{false};
    bool dev_context{false};
};

struct ResolvedBucket {
    std::string bucket_name;
    uint32_t vault_id{};
    std::string mode;
    bool api_exclusive{};
    std::shared_ptr<storage::Engine> engine;
    std::shared_ptr<identities::User> actor;
    std::optional<GatewayAccessContext> gateway_access;
};

enum class MetadataDirective {
    Copy,
    Replace
};

struct PutObjectOptions {
    std::string content_type{"application/octet-stream"};
    bool content_type_explicit{};
    std::optional<std::string> storage_class;
    std::map<std::string, std::string> metadata;
    MetadataDirective metadata_directive{MetadataDirective::Replace};
    bool multipart{};
    std::optional<uint32_t> part_count;
    std::optional<std::string> etag_override;
};

using ByteRange = protocols::http::range::Spec;

struct ObjectBody {
    db::query::s3::ObjectState state;
    std::map<std::string, std::string> metadata;
    std::vector<uint8_t> bytes;
    std::optional<std::pair<uint64_t, uint64_t>> content_range;
};

// A vault file's object body (whole, or the bytes of one resolved range).
struct FileObjectBody {
    std::vector<uint8_t> bytes;
    std::optional<std::pair<uint64_t, uint64_t>> content_range;
};

struct BucketEmptyResult {
    bool empty{true};
    uint64_t gateway_objects{};
    uint64_t fs_entries{};
    uint64_t remote_index_objects{};
    uint64_t active_tombstones{};
    std::vector<std::string> reasons;
};

class ObjectStore {
public:
    std::vector<db::query::s3::BucketBinding> listBuckets(const AuthContext& auth) const;
    std::vector<db::query::s3::BucketBinding> listBuckets(const std::shared_ptr<identities::User>& actor) const;
    ResolvedBucket resolveBucket(const std::string& bucket, const AuthContext& auth) const;
    ResolvedBucket resolveBucket(const std::string& bucket, const std::shared_ptr<identities::User>& actor) const;
    ResolvedBucket headBucket(const std::string& bucket, const AuthContext& auth) const;
    ResolvedBucket headBucket(const std::string& bucket, const std::shared_ptr<identities::User>& actor) const;
    ResolvedBucket createBucket(const std::string& bucket, const AuthContext& auth,
                                const std::string& mode = "local",
                                uintmax_t quotaBytes = 0) const;
    ResolvedBucket createBucket(const std::string& bucket, const std::shared_ptr<identities::User>& actor,
                                const std::string& mode = "local",
                                uintmax_t quotaBytes = 0) const;
    ResolvedBucket createBucket(const std::string& bucket, const std::shared_ptr<identities::User>& actor,
                                uint32_t ownerUserId,
                                const std::string& mode = "local",
                                uintmax_t quotaBytes = 0) const;
    void deleteBucket(const std::string& bucket, const AuthContext& auth) const;
    void deleteBucket(const std::string& bucket, const std::shared_ptr<identities::User>& actor) const;

    db::query::s3::ObjectListResult listObjects(const ResolvedBucket& bucket,
                                                const db::query::s3::ObjectListParams& params) const;
    db::query::s3::ObjectListResult listObjectsFromVaulthallaMetadata(
        const ResolvedBucket& bucket,
        const db::query::s3::ObjectListParams& params) const;
    BucketEmptyResult bucketIsEmpty(const ResolvedBucket& bucket) const;
    bool remoteIndexStale(const ResolvedBucket& bucket) const;
    db::query::s3::ObjectState headObject(const ResolvedBucket& bucket, const std::string& key) const;
    ObjectBody getObject(const ResolvedBucket& bucket, const std::string& key,
                         std::optional<ByteRange> range = std::nullopt) const;
    db::query::s3::ObjectState putObject(const ResolvedBucket& bucket, const std::string& key,
                                         const std::vector<uint8_t>& body,
                                         const PutObjectOptions& options = {}) const;
    // Seals `source` (a streamed request body's scratch file, or a completed multipart upload's sealed parts) into the
    // object. Without options.etag_override the ETag is the MD5 of the source, read once more.
    db::query::s3::ObjectState putObjectFromSource(const ResolvedBucket& bucket, const std::string& key,
                                                   const fs::PlaintextSource& source,
                                                   const PutObjectOptions& options = {}) const;
    db::query::s3::ObjectState copyObject(const ResolvedBucket& sourceBucket, const std::string& sourceKey,
                                          const ResolvedBucket& destBucket, const std::string& destKey,
                                          const PutObjectOptions& options = {}) const;
    void deleteObject(const ResolvedBucket& bucket, const std::string& key) const;
    std::vector<std::pair<std::string, std::optional<std::string>>> deleteObjects(
        const ResolvedBucket& bucket,
        const std::vector<std::string>& keys) const;

    static std::filesystem::path keyToVaultPath(const std::string& key);
    static std::string vaultPathToKey(const std::filesystem::path& path);
    static std::string md5Hex(const std::vector<uint8_t>& bytes);
    static std::string multipartEtag(const std::vector<std::vector<uint8_t>>& partMd5s);

    void purgeLocalObjectState(const std::shared_ptr<storage::Engine>& engine,
                               const std::filesystem::path& vaultPath,
                               uint32_t actorUserId) const;
    void requireObjectPermission(const ResolvedBucket& bucket,
                                 const std::string& key,
                                 rbac::permission::vault::FilesystemAction action) const;
    void requireS3Permission(const ResolvedBucket& bucket,
                             const AuthContext& auth,
                             rbac::s3::policy::S3Action action,
                             const std::string& key = {}) const;
    void requireBucketPermission(const ResolvedBucket& bucket,
                                 rbac::permission::vault::FilesystemAction action) const;
    void requireBucketRbacPermission(const ResolvedBucket& bucket,
                                     rbac::permission::vault::FilesystemAction action) const;
    static bool credentialAllows(const AuthContext& auth,
                                 uint32_t vaultId,
                                 rbac::permission::vault::FilesystemAction action);
    static bool credentialAllowsAdmin(const ResolvedBucket& bucket);
    static bool isRemoteBacked(const ResolvedBucket& bucket);
    // Reads a vault file's body through Engine::openPlaintextReader: its local ciphertext copy when there is one
    // (a cloud vault's local copy costs no upstream GET), a remote-only file per preview.media.remote (hydrate by
    // default). A range reads only its own bytes; the whole object is read authenticated. ContentUnavailable maps
    // to 503 ServiceUnavailable.
    static FileObjectBody readFileObject(const std::shared_ptr<storage::Engine>& engine,
                                         const std::shared_ptr<fs::model::File>& file,
                                         const std::string& key,
                                         std::optional<ByteRange> range);
    static std::shared_ptr<storage::CloudEngine> cloudEngine(const ResolvedBucket& bucket);

private:
    static void requireBucketName(const std::string& bucket);
    static void requireRbacPermission(const ResolvedBucket& bucket, const std::filesystem::path& vaultPath,
                                      rbac::permission::vault::FilesystemAction action);
    static void requirePermission(const ResolvedBucket& bucket, const std::filesystem::path& vaultPath,
                                  rbac::permission::vault::FilesystemAction action);
    static void requireS3Permission(const ResolvedBucket& bucket, const std::filesystem::path& vaultPath,
                                    rbac::s3::policy::S3Action action);
    static bool isDirectoryMarker(const std::string& key);
    static bool credentialAllows(const GatewayAccessContext& access,
                                 const std::shared_ptr<identities::User>& principal,
                                 uint32_t vaultId,
                                 rbac::permission::vault::FilesystemAction action);
    static std::map<std::string, std::string> lowerMetadata(const std::map<std::string, std::string>& metadata);
    void ensureParentDirectories(const ResolvedBucket& bucket, const std::filesystem::path& vaultPath) const;
    void backfillLocalObjectState(const ResolvedBucket& bucket) const;
    void backfillRemoteObjectState(const ResolvedBucket& bucket) const;
    std::optional<db::query::s3::ObjectState> stateFromLocalFile(const ResolvedBucket& bucket,
                                                                 const std::filesystem::path& vaultPath) const;
};

}
