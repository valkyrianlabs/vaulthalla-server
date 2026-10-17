#include "protocols/s3/ObjectStore.hpp"

#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "protocols/s3/Error.hpp"
#include "rbac/permission/admin/S3Gateway.hpp"
#include "rbac/permission/admin/Vaults.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/s3/policy/Evaluator.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Controller.hpp"
#include "sync/model/Action.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <openssl/md5.h>
#include "crypto/util/digest.hpp"
#include "db/Transactions.hpp"
#include "recovery/local/Versions.hpp"
#include <set>
#include <sstream>
#include <utility>

namespace vh::protocols::s3 {

namespace {
using Action = rbac::permission::vault::FilesystemAction;
using S3Action = rbac::s3::policy::S3Action;
using vh::fs::model::PathType;
using vh::fs::model::makeAbsolute;
using vh::fs::model::resolveParent;
using vh::fs::model::stripLeadingSlash;

std::string quoted(const std::string& value) {
    if (!value.empty() && value.front() == '"') return value;
    return "\"" + value + "\"";
}

std::string toHex(const unsigned char* bytes, const std::size_t n) {
    std::ostringstream out;
    for (std::size_t i = 0; i < n; ++i)
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    return out.str();
}

std::vector<uint8_t> md5Raw(const std::vector<uint8_t>& bytes) {
    const auto digest = crypto::util::EvpDigest::of(EVP_md5(), bytes.data(), bytes.size());
    return {digest.begin(), digest.end()};
}

std::string objectMd5FileHex(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to read object source file: " + path.string());

    crypto::util::EvpDigest md5(EVP_md5());
    std::array<char, 64 * 1024> buffer{};
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = in.gcount();
        if (count > 0) md5.update(buffer.data(), static_cast<std::size_t>(count));
    }
    const auto digest = md5.finish();
    return toHex(digest.data(), digest.size());
}

std::string metadataEtagForFile(const std::shared_ptr<fs::model::File>& file) {
    if (!file) return quoted("vh-meta-missing");
    std::ostringstream input;
    input << file->vault_id.value_or(0) << ':'
          << file->path.generic_string() << ':'
          << file->size_bytes << ':'
          << file->updated_at << ':'
          << file->content_hash.value_or("");
    const auto text = input.str();
    const std::vector<uint8_t> bytes(text.begin(), text.end());
    return quoted("vh-meta-" + toHex(md5Raw(bytes).data(), MD5_DIGEST_LENGTH));
}

void removeIfExists(const std::filesystem::path& path) {
    if (path.empty()) return;
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    if (ec)
        log::Registry::storage()->warn("[S3Gateway] Failed to remove {}: {}", path.string(), ec.message());
}

bool shouldMaterializeRemoteObject(
    const ResolvedBucket& bucket,
    const std::shared_ptr<storage::CloudEngine>& cloud) {
    if (bucket.mode == "remote_cache") return true;
    if (bucket.mode == "remote_proxy") return false;
    if (!cloud) return false;

    try {
        const auto policy = cloud->remote_policy();
        return policy && policy->strategy == sync::model::RemotePolicy::Strategy::Cache;
    } catch (const std::exception& e) {
        log::Registry::cloud()->warn(
            "[S3Gateway] Unable to inspect remote policy for vault {}: {}",
            bucket.vault_id,
            e.what());
        return false;
    }
}

std::optional<GatewayAccessContext> accessFromAuth(const AuthContext& auth) {
    return GatewayAccessContext{
        .credential_id = auth.credential_id,
        .access_key = auth.access_key,
        .scope_mode = auth.scope_mode.empty() ? std::string{"user_access"} : auth.scope_mode,
        .credential = auth.credential,
        .enforce_budget_for_local_requests = auth.enforce_budget_for_local_requests,
        .dev_context = auth.dev_context
    };
}

ResolvedBucket resolvedFromBinding(
    const db::query::s3::BucketBinding& binding,
    std::shared_ptr<storage::Engine> engine,
    std::shared_ptr<identities::User> actor,
    std::optional<GatewayAccessContext> access) {
    return {
        .bucket_name = binding.bucket_name,
        .vault_id = binding.vault_id,
        .mode = binding.mode,
        .api_exclusive = binding.api_exclusive,
        .engine = std::move(engine),
        .actor = std::move(actor),
        .gateway_access = std::move(access)
    };
}

void requireCanCreateGatewayBucketForOwner(
    const std::shared_ptr<identities::User>& actor,
    const uint32_t ownerUserId,
    const std::string& bucket) {
    if (!actor) throw accessDenied(bucket);
    using Perm = rbac::permission::admin::VaultPermissions;
    if (!rbac::resolver::Admin::has<Perm>({
            .user = actor,
            .permission = Perm::Create,
            .target_user_id = ownerUserId
        }))
        throw accessDenied(bucket);
}

bool hasGatewayBucketManagement(const std::shared_ptr<identities::User>& actor) {
    if (!actor) return false;
    if (actor->isSuperAdmin()) return true;
    using Perm = rbac::permission::admin::S3GatewayPermissions;
    return rbac::resolver::Admin::has<Perm>({
        .user = actor,
        .permission = Perm::ManageBuckets
    });
}

S3Action s3ActionForFilesystemAction(const Action action) {
    switch (action) {
    case Action::List:
        return S3Action::ListObjects;
    case Action::Read:
    case Action::Lookup:
    case Action::Preview:
        return S3Action::GetObject;
    case Action::Delete:
        return S3Action::DeleteObject;
    case Action::Write:
    case Action::Touch:
    case Action::Overwrite:
    case Action::Rename:
    case Action::Move:
    case Action::Copy:
    case Action::Link:
        return S3Action::PutObject;
    case Action::ShareInternal:
    case Action::SharePublic:
    case Action::SharePublicValidated:
        return S3Action::GetObject;
    }
    return S3Action::GetObject;
}

bool objectExistsInBucket(const ResolvedBucket& bucket, const std::filesystem::path& vaultPath) {
    if (vaultPath == std::filesystem::path{"/"}) return true;
    const auto objectKey = ObjectStore::vaultPathToKey(vaultPath);
    return db::query::s3::Gateway::getObjectState(bucket.vault_id, objectKey).has_value() ||
        db::query::fs::File::getFileByPath(bucket.vault_id, vaultPath) != nullptr;
}
}

std::vector<db::query::s3::BucketBinding> ObjectStore::listBuckets(const AuthContext& auth) const {
    if (!auth.user) throw accessDenied("/");
    const auto bindings = db::query::s3::Gateway::listBuckets(std::nullopt);

    std::vector<db::query::s3::BucketBinding> visible;
    visible.reserve(bindings.size());

    const auto storageManager = runtime::Deps::get().storageManager;
    if (!storageManager) return visible;

    for (const auto& binding : bindings) {
        auto engine = storageManager->getEngine(binding.vault_id);
        if (!engine) continue;

        auto bucket = resolvedFromBinding(binding, std::move(engine), auth.user, accessFromAuth(auth));
        try {
            requireS3Permission(bucket, "/", S3Action::ListBuckets);
            visible.push_back(binding);
        } catch (const S3Error& e) {
            if (e.code != "AccessDenied")
                log::Registry::runtime()->warn(
                    "[S3Gateway] Failed to evaluate bucket visibility for {}: {}",
                    binding.bucket_name,
                    e.what());
        } catch (const std::exception& e) {
            log::Registry::runtime()->warn(
                "[S3Gateway] Failed to evaluate bucket visibility for {}: {}",
                binding.bucket_name,
                e.what());
        }
    }

    return visible;
}

std::vector<db::query::s3::BucketBinding> ObjectStore::listBuckets(const std::shared_ptr<identities::User>& actor) const {
    if (!actor) throw accessDenied("/");
    const auto bindings = db::query::s3::Gateway::listBuckets(std::nullopt);
    if (actor->isSuperAdmin()) return bindings;

    std::vector<db::query::s3::BucketBinding> visible;
    visible.reserve(bindings.size());

    const auto storageManager = runtime::Deps::get().storageManager;
    if (!storageManager) return visible;

    for (const auto& binding : bindings) {
        auto engine = storageManager->getEngine(binding.vault_id);
        if (!engine) continue;

        auto bucket = resolvedFromBinding(binding, std::move(engine), actor, std::nullopt);

        try {
            requireS3Permission(bucket, "/", S3Action::ListBuckets);
            visible.push_back(binding);
        } catch (const S3Error& e) {
            if (e.code != "AccessDenied")
                log::Registry::runtime()->warn(
                    "[S3Gateway] Failed to evaluate bucket visibility for {}: {}",
                    binding.bucket_name,
                    e.what());
        } catch (const std::exception& e) {
            log::Registry::runtime()->warn(
                "[S3Gateway] Failed to evaluate bucket visibility for {}: {}",
                binding.bucket_name,
                e.what());
        }
    }

    return visible;
}

ResolvedBucket ObjectStore::resolveBucket(const std::string& bucket, const AuthContext& auth) const {
    auto out = resolveBucket(bucket, auth.user);
    out.gateway_access = accessFromAuth(auth);
    return out;
}

ResolvedBucket ObjectStore::resolveBucket(const std::string& bucket, const std::shared_ptr<identities::User>& actor) const {
    requireBucketName(bucket);
    if (!actor) throw accessDenied(bucket);

    const auto binding = db::query::s3::Gateway::resolveBucket(bucket);
    if (!binding) throw noSuchBucket(bucket);

    auto engine = runtime::Deps::get().storageManager->getEngine(binding->vault_id);
    if (!engine) throw noSuchBucket(bucket);

    return resolvedFromBinding(*binding, std::move(engine), actor, std::nullopt);
}

ResolvedBucket ObjectStore::headBucket(const std::string& bucket, const AuthContext& auth) const {
    auto out = resolveBucket(bucket, auth);
    requireS3Permission(out, "/", S3Action::HeadBucket);
    return out;
}

ResolvedBucket ObjectStore::headBucket(const std::string& bucket, const std::shared_ptr<identities::User>& actor) const {
    auto out = resolveBucket(bucket, actor);
    requireS3Permission(out, "/", S3Action::HeadBucket);
    return out;
}

ResolvedBucket ObjectStore::createBucket(
    const std::string& bucket,
    const AuthContext& auth,
    const std::string& mode,
    const uintmax_t quotaBytes) const {
    if (db::query::s3::Gateway::resolveBucket(bucket))
        return headBucket(bucket, auth);
    const auto access = accessFromAuth(auth);
    if (!auth.user || !auth.user->isAdmin())
        throw accessDenied(bucket);
    if (access && access->scope_mode == "vault_allowlist")
        throw accessDenied(bucket);
    if (access && access->credential_id != 0 && !hasGatewayBucketManagement(auth.user))
        throw accessDenied(bucket);
    return createBucket(bucket, auth.user, auth.user->id, mode, quotaBytes);
}

ResolvedBucket ObjectStore::createBucket(
    const std::string& bucket,
    const std::shared_ptr<identities::User>& actor,
    const std::string& mode,
    const uintmax_t quotaBytes) const {
    if (!actor) throw accessDenied(bucket);
    return createBucket(bucket, actor, actor->id, mode, quotaBytes);
}

ResolvedBucket ObjectStore::createBucket(
    const std::string& bucket,
    const std::shared_ptr<identities::User>& actor,
    const uint32_t ownerUserId,
    const std::string& mode,
    const uintmax_t quotaBytes) const {
    requireBucketName(bucket);
    if (!actor) throw accessDenied(bucket);
    if (db::query::s3::Gateway::resolveBucket(bucket))
        return headBucket(bucket, actor);

    if (mode != "local")
        throw invalidArgument("Remote-backed buckets must be created with vh s3-gateway bucket create-remote-cache", bucket);

    requireCanCreateGatewayBucketForOwner(actor, ownerUserId, bucket);

    auto vault = std::make_shared<vault::model::Vault>();
    vault->name = bucket;
    vault->description = "S3 gateway bucket " + bucket;
    vault->owner_id = ownerUserId;
    vault->type = vault::model::VaultType::Local;
    vault->quota = quotaBytes;
    vault->is_active = true;

    auto sync = std::make_shared<sync::model::LocalPolicy>();
    sync->conflict_policy = sync::model::LocalPolicy::ConflictPolicy::KeepBoth;

    vault = runtime::Deps::get().storageManager->addVault(vault, sync);
    db::query::s3::Gateway::bindBucket({
        .vault_id = vault->id,
        .bucket_name = bucket,
        .api_exclusive = config::Registry::get().s3_gateway.default_api_exclusive,
        .mode = "local",
        .created_by = actor->id
    });
    return resolveBucket(bucket, actor);
}

void ObjectStore::deleteBucket(const std::string& bucket, const AuthContext& auth) const {
    auto resolved = resolveBucket(bucket, auth);
    const auto hasGatewayAdminAccess =
        resolved.gateway_access &&
        resolved.gateway_access->credential_id != 0 &&
        credentialAllowsAdmin(resolved);
    if (!hasGatewayAdminAccess) {
        requireRbacPermission(resolved, "/", Action::Delete);
        if (!credentialAllowsAdmin(resolved)) throw accessDenied(bucket);
    }
    const auto empty = bucketIsEmpty(resolved);
    if (!empty.empty)
        throw S3Error{"BucketNotEmpty", "The bucket you tried to delete is not empty", http::status::conflict, bucket};
    db::query::s3::Gateway::unbindBucket(bucket);
    if (resolved.api_exclusive)
        runtime::Deps::get().storageManager->removeVault(resolved.vault_id);
}

void ObjectStore::deleteBucket(const std::string& bucket, const std::shared_ptr<identities::User>& actor) const {
    auto resolved = resolveBucket(bucket, actor);
    requirePermission(resolved, "/", Action::Delete);
    const auto empty = bucketIsEmpty(resolved);
    if (!empty.empty)
        throw S3Error{"BucketNotEmpty", "The bucket you tried to delete is not empty", http::status::conflict, bucket};
    db::query::s3::Gateway::unbindBucket(bucket);
    if (resolved.api_exclusive)
        runtime::Deps::get().storageManager->removeVault(resolved.vault_id);
}

db::query::s3::ObjectListResult ObjectStore::listObjects(
    const ResolvedBucket& bucket,
    const db::query::s3::ObjectListParams& params) const {
    return listObjectsFromVaulthallaMetadata(bucket, params);
}

db::query::s3::ObjectListResult ObjectStore::listObjectsFromVaulthallaMetadata(
    const ResolvedBucket& bucket,
    const db::query::s3::ObjectListParams& params) const {
    requireS3Permission(bucket, "/", S3Action::ListObjects);
    if (isRemoteBacked(bucket))
        backfillRemoteObjectState(bucket);
    else
        backfillLocalObjectState(bucket);
    return db::query::s3::Gateway::listObjectStates(bucket.vault_id, params);
}

BucketEmptyResult ObjectStore::bucketIsEmpty(const ResolvedBucket& bucket) const {
    db::query::s3::ObjectListParams params;
    params.max_keys = 1;
    if (isRemoteBacked(bucket))
        backfillRemoteObjectState(bucket);
    else
        backfillLocalObjectState(bucket);
    const auto objects = db::query::s3::Gateway::listObjectStates(bucket.vault_id, params);

    auto result = db::Transactions::exec("S3Gateway::bucketIsEmpty", [&](pqxx::work& txn) {
        const auto row = txn.exec(
            "SELECT (SELECT COUNT(*) FROM s3_gateway_object WHERE vault_id = $1), "
            "       (SELECT COUNT(*) FROM fs_entry e JOIN files f ON f.fs_entry_id = e.id "
            "         WHERE e.vault_id = $1 AND e.path <> '/'), "
            "       (SELECT COUNT(*) FROM remote_object_index WHERE vault_id = $1), "
            "       (SELECT COUNT(*) FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL)",
            pqxx::params{bucket.vault_id}).one_row();
        BucketEmptyResult out;
        out.gateway_objects = row[0].as<uint64_t>();
        out.fs_entries = row[1].as<uint64_t>();
        out.remote_index_objects = row[2].as<uint64_t>();
        out.active_tombstones = row[3].as<uint64_t>();
        return out;
    });

    result.empty = objects.objects.empty() && objects.common_prefixes.empty();
    if (!result.empty) result.reasons.push_back("live gateway-visible objects exist");
    if (result.fs_entries > 0) result.reasons.push_back("live Vaulthalla filesystem entries exist");
    if (isRemoteBacked(bucket) && result.remote_index_objects > result.active_tombstones)
        result.reasons.push_back("remote object index contains live objects");
    return result;
}

bool ObjectStore::remoteIndexStale(const ResolvedBucket& bucket) const {
    if (!isRemoteBacked(bucket)) return false;

    try {
        const auto cloud = cloudEngine(bucket);
        if (!cloud) return false;
        const auto policy = cloud->remote_policy();
        const auto summary = db::query::sync::RemoteObjectIndex::summaryForVault(bucket.vault_id);
        return summary.isStale(policy ? policy->max_remote_index_age : std::nullopt);
    } catch (const std::exception& e) {
        log::Registry::cloud()->warn(
            "[S3Gateway] Failed to evaluate remote index freshness for vault {}: {}",
            bucket.vault_id,
            e.what());
        return false;
    }
}

db::query::s3::ObjectState ObjectStore::headObject(const ResolvedBucket& bucket, const std::string& key) const {
    const auto vaultPath = keyToVaultPath(key);
    requireS3Permission(bucket, vaultPath, S3Action::HeadObject);

    if (auto state = db::query::s3::Gateway::getObjectState(bucket.vault_id, vaultPathToKey(vaultPath)))
        return *state;
    if (auto state = stateFromLocalFile(bucket, vaultPath))
        return *state;

    if (isRemoteBacked(bucket)) {
        backfillRemoteObjectState(bucket);
        if (auto state = db::query::s3::Gateway::getObjectState(bucket.vault_id, vaultPathToKey(vaultPath)))
            return *state;
    }

    throw noSuchKey(key);
}

ObjectBody ObjectStore::getObject(
    const ResolvedBucket& bucket,
    const std::string& key,
    const std::optional<ByteRange> range) const {
    const auto vaultPath = keyToVaultPath(key);
    requireS3Permission(bucket, vaultPath, S3Action::GetObject);
    auto state = headObject(bucket, key);
    auto metadata = db::query::s3::Gateway::listObjectMetadata(bucket.vault_id, vaultPathToKey(vaultPath));

    std::vector<uint8_t> bytes;
    if (isDirectoryMarker(key)) {
        bytes = {};
    } else if (const auto file = db::query::fs::File::getFileByPath(bucket.vault_id, vaultPath)) {
        auto body = readFileObject(bucket.engine, file, key, range);
        return {
            .state = std::move(state),
            .metadata = std::move(metadata),
            .bytes = std::move(body.bytes),
            .content_range = body.content_range
        };
    } else if (const auto cloud = cloudEngine(bucket)) {
        auto remotePayload = cloud->downloadToBuffer(vaultPath);
        bytes = cloud->decryptRemotePayload(vaultPath, remotePayload);
        if (shouldMaterializeRemoteObject(bucket, cloud)) {
            try {
                ensureParentDirectories(bucket, vaultPath);
                fs::Filesystem::createFile({
                    .path = vaultPath,
                    .fuse_path = bucket.engine->vaultPathToFusePath(vaultPath),
                    .buffer = bytes,
                    .engine = bucket.engine,
                    .user = bucket.actor,
                    .overwrite = true
                });
            } catch (const std::exception& e) {
                log::Registry::cloud()->warn(
                    "[S3Gateway] Remote-cache materialization failed for vault {} key {}: {}",
                    bucket.vault_id,
                    vaultPath.generic_string(),
                    e.what());
            }
        }
    } else {
        throw noSuchKey(key);
    }

    std::optional<std::pair<uint64_t, uint64_t>> actualRange;
    if (range) {
        if (bytes.empty()) throw invalidRange(key);

        const auto resolved = protocols::http::range::resolve(*range, bytes.size());
        if (!resolved) throw invalidRange(key);
        const auto first = resolved->first;
        const auto last = resolved->last;
        bytes = std::vector<uint8_t>(bytes.begin() + static_cast<std::ptrdiff_t>(first),
                                     bytes.begin() + static_cast<std::ptrdiff_t>(last + 1));
        actualRange = std::make_pair(first, last);
    }

    return {
        .state = std::move(state),
        .metadata = std::move(metadata),
        .bytes = std::move(bytes),
        .content_range = actualRange
    };
}

db::query::s3::ObjectState ObjectStore::putObject(
    const ResolvedBucket& bucket,
    const std::string& key,
    const std::vector<uint8_t>& body,
    const PutObjectOptions& options) const {
    const auto vaultPath = keyToVaultPath(key);
    requireS3Permission(bucket, vaultPath, S3Action::PutObject);

    const auto etag = options.etag_override.value_or(quoted(md5Hex(body)));
    const auto objectKey = vaultPathToKey(vaultPath);
    const auto directoryMarker = isDirectoryMarker(key);

    if (directoryMarker && !body.empty())
        throw invalidArgument("Directory marker objects must be zero-byte objects", key);

    if (!directoryMarker) {
        ensureParentDirectories(bucket, vaultPath);
        const auto file = fs::Filesystem::createFile({
            .path = vaultPath,
            .fuse_path = bucket.engine->vaultPathToFusePath(vaultPath),
            .buffer = body,
            .engine = bucket.engine,
            .user = bucket.actor,
            .overwrite = true
        });
        (void)file;
    }

    db::query::s3::ObjectState state{
        .vault_id = bucket.vault_id,
        .object_key = objectKey,
        .etag = etag,
        .size_bytes = body.size(),
        .content_type = options.content_type.empty() ? std::make_optional<std::string>("application/octet-stream") : std::make_optional(options.content_type),
        .storage_class = options.storage_class,
        .last_modified = std::time(nullptr),
        .multipart = options.multipart,
        .part_count = options.part_count
    };
    db::query::s3::Gateway::upsertObject(state);
    db::query::s3::Gateway::upsertObjectMetadata(bucket.vault_id, objectKey, lowerMetadata(options.metadata));
    return *db::query::s3::Gateway::getObjectState(bucket.vault_id, objectKey);
}

db::query::s3::ObjectState ObjectStore::putObjectFromFile(
    const ResolvedBucket& bucket,
    const std::string& key,
    const std::filesystem::path& sourcePath,
    const uint64_t sourceSize,
    const PutObjectOptions& options) const {
    const auto vaultPath = keyToVaultPath(key);
    requireS3Permission(bucket, vaultPath, S3Action::PutObject);

    if (!std::filesystem::exists(sourcePath) || !std::filesystem::is_regular_file(sourcePath))
        throw invalidArgument("Object source file is unavailable", sourcePath.string());
    const auto actualSize = std::filesystem::file_size(sourcePath);
    if (actualSize != sourceSize)
        throw std::runtime_error("S3 request body temp file size changed before commit");

    const auto directoryMarker = isDirectoryMarker(key);
    if (directoryMarker && sourceSize != 0)
        throw invalidArgument("Directory marker objects must be zero-byte objects", key);

    const auto etag = options.etag_override.value_or(quoted(objectMd5FileHex(sourcePath)));
    const auto objectKey = vaultPathToKey(vaultPath);

    if (!directoryMarker) {
        ensureParentDirectories(bucket, vaultPath);
        const auto file = fs::Filesystem::createFile({
            .path = vaultPath,
            .fuse_path = bucket.engine->vaultPathToFusePath(vaultPath),
            .buffer = {},
            .source_path = sourcePath,
            .engine = bucket.engine,
            .user = bucket.actor,
            .overwrite = true
        });
        (void)file;
    }

    db::query::s3::ObjectState state{
        .vault_id = bucket.vault_id,
        .object_key = objectKey,
        .etag = etag,
        .size_bytes = sourceSize,
        .content_type = options.content_type.empty() ? std::make_optional<std::string>("application/octet-stream") : std::make_optional(options.content_type),
        .storage_class = options.storage_class,
        .last_modified = std::time(nullptr),
        .multipart = options.multipart,
        .part_count = options.part_count
    };
    db::query::s3::Gateway::upsertObject(state);
    db::query::s3::Gateway::upsertObjectMetadata(bucket.vault_id, objectKey, lowerMetadata(options.metadata));
    return *db::query::s3::Gateway::getObjectState(bucket.vault_id, objectKey);
}

db::query::s3::ObjectState ObjectStore::copyObject(
    const ResolvedBucket& sourceBucket,
    const std::string& sourceKey,
    const ResolvedBucket& destBucket,
    const std::string& destKey,
    const PutObjectOptions& options) const {
    auto source = getObject(sourceBucket, sourceKey);
    auto putOptions = options;

    if (putOptions.metadata_directive == MetadataDirective::Copy) {
        putOptions.metadata = source.metadata;
        putOptions.content_type = source.state.content_type.value_or("application/octet-stream");
        if (!putOptions.storage_class) putOptions.storage_class = source.state.storage_class;
    } else if (!putOptions.content_type_explicit) {
        putOptions.content_type = "application/octet-stream";
    }

    return putObject(destBucket, destKey, source.bytes, putOptions);
}

void ObjectStore::deleteObject(const ResolvedBucket& bucket, const std::string& key) const {
    const auto vaultPath = keyToVaultPath(key);
    requireS3Permission(bucket, vaultPath, S3Action::DeleteObject);
    const auto objectKey = vaultPathToKey(vaultPath);

    if (isRemoteBacked(bucket)) backfillRemoteObjectState(bucket);
    const auto knownState = db::query::s3::Gateway::getObjectState(bucket.vault_id, objectKey);
    const auto file = db::query::fs::File::getFileByPath(bucket.vault_id, vaultPath);
    std::optional<ino_t> oldInode;
    uint32_t oldId = 0;
    if (file) {
        oldInode = file->inode;
        oldId = file->id;
        bucket.engine->remove(vaultPath, bucket.actor->id);
    } else if (isRemoteBacked(bucket) && knownState) {
        db::query::fs::File::markRemoteFileAsTrashed(
            bucket.actor->id,
            bucket.vault_id,
            vaultPath,
            knownState->size_bytes);
    }

    db::query::s3::Gateway::deleteObjectMetadata(bucket.vault_id, objectKey);
    db::query::s3::Gateway::deleteObjectState(bucket.vault_id, objectKey);

    if (const auto& cache = runtime::Deps::get().fsCache) {
        const auto fusePath = bucket.engine->vaultPathToFusePath(vaultPath);
        cache->evictPath(fusePath);
        if (oldInode) cache->evictIno(*oldInode);
        if (oldId) cache->evictId(oldId);
    }
}

std::vector<std::pair<std::string, std::optional<std::string>>> ObjectStore::deleteObjects(
    const ResolvedBucket& bucket,
    const std::vector<std::string>& keys) const {
    std::vector<std::pair<std::string, std::optional<std::string>>> out;
    out.reserve(keys.size());
    for (const auto& key : keys) {
        try {
            deleteObject(bucket, key);
            out.emplace_back(key, std::nullopt);
        } catch (const S3Error& e) {
            out.emplace_back(key, e.code + ": " + e.what());
        } catch (const std::exception& e) {
            out.emplace_back(key, std::string("InternalError: ") + e.what());
        }
    }
    return out;
}

std::filesystem::path ObjectStore::keyToVaultPath(const std::string& key) {
    if (key.empty()) throw invalidArgument("Object key must not be empty");
    if (key.find('\0') != std::string::npos) throw invalidArgument("Object key must not contain NUL");

    for (const auto& part : std::filesystem::path(key)) {
        if (part == "..")
            throw invalidArgument("Object key escapes the bucket");
    }

    std::filesystem::path raw = std::filesystem::path("/") / key;
    const auto normalized = raw.lexically_normal();
    const auto normalizedStr = normalized.string();
    if (normalizedStr == "/" || normalizedStr.starts_with("/../") || normalizedStr.contains("/../") ||
        normalizedStr.ends_with("/.."))
        throw invalidArgument("Object key escapes the bucket");
    return makeAbsolute(normalized);
}

std::string ObjectStore::vaultPathToKey(const std::filesystem::path& path) {
    auto out = stripLeadingSlash(path).generic_string();
    if (out == "/") return {};
    return out;
}

std::string ObjectStore::md5Hex(const std::vector<uint8_t>& bytes) {
    const auto digest = md5Raw(bytes);
    return toHex(digest.data(), digest.size());
}

std::string ObjectStore::multipartEtag(const std::vector<std::vector<uint8_t>>& partMd5s) {
    std::vector<uint8_t> concat;
    concat.reserve(partMd5s.size() * MD5_DIGEST_LENGTH);
    for (const auto& md5 : partMd5s) concat.insert(concat.end(), md5.begin(), md5.end());
    return quoted(md5Hex(concat) + "-" + std::to_string(partMd5s.size()));
}

void ObjectStore::purgeLocalObjectState(
    const std::shared_ptr<storage::Engine>& engine,
    const std::filesystem::path& vaultPath,
    const uint32_t actorUserId) const {
    if (!engine) return;
    const auto fusePath = engine->vaultPathToFusePath(vaultPath);
    const auto file = db::query::fs::File::getFileByPath(engine->vault->id, vaultPath);
    std::optional<ino_t> oldInode;
    uint32_t oldId = 0;
    std::filesystem::path oldBacking;

    if (file) {
        oldInode = file->inode;
        oldId = file->id;
        oldBacking = file->backing_path;
        // Local versioning keeps the purged object's last generation (the backing file goes after the commit), under
        // the file's content lock with the row re-read, so a concurrent seal/overwrite can't be linked under the old IV.
        std::scoped_lock contentLock(vh::fs::Filesystem::contentWriteMutex(file->id));
        const auto current = db::query::fs::File::getFileById(file->id);
        auto kept = current ? recovery::local::versions::retain(*engine, *current, recovery::local::Reason::Delete,
                                                                {.actor = actorUserId})
                            : recovery::local::versions::Pending{};
        db::Transactions::exec("ObjectStore::purgeLocalObjectState", [&](pqxx::work& txn) {
            kept.attach(txn);
            db::query::fs::File::deleteFile(txn, actorUserId, file);
        });
        kept.committed();
    }

    if (const auto& cache = runtime::Deps::get().fsCache) {
        cache->evictPath(fusePath);
        if (oldInode) cache->evictIno(*oldInode);
        if (oldId) cache->evictId(oldId);
        // The folder stays (#168); the totals listings read from the cache follow the delete.
        if (file && file->parent_id) cache->refreshDirStats(static_cast<unsigned int>(*file->parent_id));
    }

    if (file) {
        engine->purgeDerivedArtifacts(oldId);
        removeIfExists(oldBacking);
    }
}

void ObjectStore::requireObjectPermission(
    const ResolvedBucket& bucket,
    const std::string& key,
    const rbac::permission::vault::FilesystemAction action) const {
    requirePermission(bucket, keyToVaultPath(key), action);
}

void ObjectStore::requireS3Permission(
    const ResolvedBucket& bucket,
    const AuthContext&,
    const rbac::s3::policy::S3Action action,
    const std::string& key) const {
    requireS3Permission(bucket, key.empty() ? std::filesystem::path{"/"} : keyToVaultPath(key), action);
}

void ObjectStore::requireBucketPermission(
    const ResolvedBucket& bucket,
    const rbac::permission::vault::FilesystemAction action) const {
    requirePermission(bucket, "/", action);
}

void ObjectStore::requireBucketRbacPermission(
    const ResolvedBucket& bucket,
    const rbac::permission::vault::FilesystemAction action) const {
    requireRbacPermission(bucket, "/", action);
}

void ObjectStore::requireBucketName(const std::string& bucket) {
    try {
        vault::model::requireValidS3Name(bucket);
    } catch (const std::exception&) {
        throw invalidArgument("Invalid bucket name", bucket);
    }
}

void ObjectStore::requireRbacPermission(
    const ResolvedBucket& bucket,
    const std::filesystem::path& vaultPath,
    const rbac::permission::vault::FilesystemAction action) {
    if (!bucket.actor) throw accessDenied(bucket.bucket_name);
    const auto fusePath = bucket.engine->vaultPathToFusePath(makeAbsolute(vaultPath));
    if (!bucket.actor->isSuperAdmin()) {
        if (!rbac::resolver::Vault::has<rbac::permission::vault::FilesystemAction>({
                .user = bucket.actor,
                .permission = action,
                .vault_id = bucket.vault_id,
                .path = fusePath
            }))
            throw accessDenied(fusePath.string());
    }
}

void ObjectStore::requirePermission(
    const ResolvedBucket& bucket,
    const std::filesystem::path& vaultPath,
    const rbac::permission::vault::FilesystemAction action) {
    requireS3Permission(bucket, vaultPath, s3ActionForFilesystemAction(action));
}

void ObjectStore::requireS3Permission(
    const ResolvedBucket& bucket,
    const std::filesystem::path& vaultPath,
    const rbac::s3::policy::S3Action action) {
    const auto fusePath = bucket.engine->vaultPathToFusePath(makeAbsolute(vaultPath));
    const auto absoluteVaultPath = makeAbsolute(vaultPath);
    const auto objectExists = objectExistsInBucket(bucket, absoluteVaultPath);
    const auto isDirectory = absoluteVaultPath == std::filesystem::path{"/"} || isDirectoryMarker(vaultPath.generic_string());

    if (!bucket.gateway_access) {
        const auto fsAction = rbac::s3::policy::Evaluator::filesystemActionFor(action, objectExists, isDirectory);
        if (!fsAction) throw accessDenied(fusePath.string());
        requireRbacPermission(bucket, vaultPath, *fsAction);
        return;
    }

    const auto decision = rbac::s3::policy::Evaluator::evaluate({
        .principal = bucket.actor,
        .credential_id = bucket.gateway_access->dev_context ? 0u : bucket.gateway_access->credential_id,
        .scope_mode = bucket.gateway_access->scope_mode,
        .vault_id = bucket.vault_id,
        .vault_path = absoluteVaultPath,
        .fuse_path = fusePath,
        .action = action,
        .object_exists = objectExists,
        .is_directory_marker = isDirectory,
        .target_user_id = std::nullopt
    });
    if (!decision.allowed) throw accessDenied(fusePath.string());
}

bool ObjectStore::credentialAllows(
    const AuthContext& auth,
    const uint32_t vaultId,
    const rbac::permission::vault::FilesystemAction action) {
    const auto access = accessFromAuth(auth);
    return access && credentialAllows(*access, auth.user, vaultId, action);
}

bool ObjectStore::credentialAllows(
    const GatewayAccessContext& access,
    const std::shared_ptr<identities::User>& principal,
    const uint32_t vaultId,
    const rbac::permission::vault::FilesystemAction action) {
    if (access.dev_context || access.credential_id == 0) return true;
    if (!principal || vaultId == 0) return false;
    const auto decision = rbac::s3::policy::Evaluator::evaluate({
        .principal = principal,
        .credential_id = access.credential_id,
        .scope_mode = access.scope_mode,
        .vault_id = vaultId,
        .vault_path = std::filesystem::path{"/"},
        .fuse_path = std::filesystem::path{"/"},
        .action = s3ActionForFilesystemAction(action),
        .object_exists = true,
        .is_directory_marker = true,
        .target_user_id = std::nullopt
    });
    return decision.allowed;
}

bool ObjectStore::credentialAllowsAdmin(const ResolvedBucket& bucket) {
    if (!bucket.gateway_access) return true;
    const auto& access = *bucket.gateway_access;
    if (access.dev_context || access.credential_id == 0) return true;
    if (!bucket.engine) return false;
    const auto fusePath = bucket.engine->vaultPathToFusePath(std::filesystem::path{"/"});
    const auto decision = rbac::s3::policy::Evaluator::evaluate({
        .principal = bucket.actor,
        .credential_id = access.credential_id,
        .scope_mode = access.scope_mode,
        .vault_id = bucket.vault_id,
        .vault_path = std::filesystem::path{"/"},
        .fuse_path = fusePath,
        .action = S3Action::DeleteObject,
        .object_exists = true,
        .is_directory_marker = true,
        .target_user_id = std::nullopt
    });
    return decision.allowed;
}

bool ObjectStore::isRemoteBacked(const ResolvedBucket& bucket) {
    return bucket.mode == "remote_cache" || bucket.mode == "remote_proxy" ||
           (bucket.engine && bucket.engine->type() == storage::StorageType::Cloud);
}

FileObjectBody ObjectStore::readFileObject(
    const std::shared_ptr<storage::Engine>& engine,
    const std::shared_ptr<fs::model::File>& file,
    const std::string& key,
    const std::optional<ByteRange> range) {
    if (!engine || !file) throw noSuchKey(key);

    FileObjectBody body;
    const auto size = file->size_bytes;
    try {
        if (range) {
            if (size == 0) throw invalidRange(key);
            const auto resolved = protocols::http::range::resolve(*range, size);
            if (!resolved) throw invalidRange(key);

            const auto reader = engine->openPlaintextReader(file);
            const auto length = resolved->last - resolved->first + 1;
            body.bytes.resize(static_cast<std::size_t>(length));
            std::size_t done = 0;
            while (done < body.bytes.size()) {
                const auto got = reader->read(resolved->first + done,
                                              std::span<uint8_t>(body.bytes.data() + done, body.bytes.size() - done));
                if (got == 0) throw storage::IntegrityError("Object content is shorter than its metadata: " + key);
                done += got;
            }
            body.content_range = std::make_pair(resolved->first, resolved->last);
            return body;
        }

        if (size == 0) return body;
        const auto reader = engine->openPlaintextReader(file);
        body.bytes = storage::readAll(*reader, size);
        return body;
    } catch (const storage::ContentUnavailable& e) {
        throw S3Error{"ServiceUnavailable", e.what(), http::status::service_unavailable, key};
    }
}

bool ObjectStore::isDirectoryMarker(const std::string& key) {
    return !key.empty() && key.back() == '/';
}

std::shared_ptr<storage::CloudEngine> ObjectStore::cloudEngine(const ResolvedBucket& bucket) {
    return std::dynamic_pointer_cast<storage::CloudEngine>(bucket.engine);
}

std::map<std::string, std::string> ObjectStore::lowerMetadata(const std::map<std::string, std::string>& metadata) {
    std::map<std::string, std::string> out;
    for (const auto& item : metadata) {
        auto key = item.first;
        std::ranges::transform(key, key.begin(), [](const unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        out[std::move(key)] = item.second;
    }
    return out;
}

void ObjectStore::ensureParentDirectories(const ResolvedBucket& bucket, const std::filesystem::path& vaultPath) const {
    const auto parent = resolveParent(vaultPath);
    if (parent == "/" || parent.empty()) return;
    const auto err = fs::Filesystem::mkdir({
        .path = bucket.engine->vaultPathToFusePath(parent),
        .engine = bucket.engine,
        .user = bucket.actor
    });
    if (err && err != -EEXIST)
        throw std::runtime_error("Failed to create object parent directories");
}

void ObjectStore::backfillLocalObjectState(const ResolvedBucket& bucket) const {
    db::query::s3::Gateway::backfillObjectStateFromFs(bucket.vault_id);
}

void ObjectStore::backfillRemoteObjectState(const ResolvedBucket& bucket) const {
    db::query::s3::Gateway::backfillObjectStateFromRemoteIndex(bucket.vault_id);
}

std::optional<db::query::s3::ObjectState> ObjectStore::stateFromLocalFile(
    const ResolvedBucket& bucket,
    const std::filesystem::path& vaultPath) const {
    const auto file = db::query::fs::File::getFileByPath(bucket.vault_id, vaultPath);
    if (!file) return std::nullopt;
    return db::query::s3::ObjectState{
        .vault_id = bucket.vault_id,
        .object_key = vaultPathToKey(vaultPath),
        .etag = metadataEtagForFile(file),
        .size_bytes = file->size_bytes,
        .content_type = file->mime_type,
        .storage_class = file->remote_storage_class,
        .last_modified = file->updated_at,
        .multipart = false,
        .part_count = std::nullopt
    };
}

} // namespace vh::protocols::s3
