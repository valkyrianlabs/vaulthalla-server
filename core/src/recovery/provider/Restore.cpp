#include "recovery/provider/Restore.hpp"

#include "crypto/util/Gcm.hpp"
#include "crypto/util/encrypt.hpp"
#include "crypto/util/hash.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/recovery/ObjectVersion.hpp"
#include "db/query/sync/Conflict.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "fs/ops/file.hpp"
#include "fuse/WorkingCopies.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "recovery/provider/Points.hpp"
#include "recovery/provider/Versions.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/s3/pricing/PriceEstimate.hpp"
#include "sync/Controller.hpp"
#include "sync/model/Action.hpp"
#include "sync/model/Baseline.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/tasks/Baseline.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/S3Vault.hpp"

#include <fmt/format.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <ctime>
#include <fcntl.h>
#include <system_error>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

namespace vh::recovery::provider {

namespace restore_detail {

using FilePtr = std::shared_ptr<fs::model::File>;
using VersionRow = db::query::recovery::ObjectVersionRow;

constexpr uint64_t kRestoreGcmTag = 16;
constexpr uint64_t kRestoreErrorSlack = 64 * 1024;
constexpr const char* kRestoreOperation = "recovery_restore";

std::string unquoted(std::string etag) {
    if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') etag = etag.substr(1, etag.size() - 2);
    return etag;
}

bool sameEtag(const std::optional<std::string>& a, const std::optional<std::string>& b) {
    return a && b && !a->empty() && unquoted(*a) == unquoted(*b);
}

std::string isoTime(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// A sealed version without the IV / key version to open it with.
class NoEncryptionContext final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// What a version's HEAD says about its content (Vaulthalla's metadata, when present).
struct VersionMeta {
    bool encrypted{false};
    std::string iv;
    unsigned int key_version{};
    std::optional<std::string> content_hash;
    uint64_t object_size{};
    uint64_t plaintext_size{};
    std::string etag;
    std::optional<std::string> storage_class;
};

std::optional<std::string> metaValue(const storage::s3::ObjectVersionHead& head, const std::string& name) {
    if (const auto it = head.metadata.find(name); it != head.metadata.end() && !it->second.empty()) return it->second;
    return std::nullopt;
}

VersionMeta metaFromHead(const storage::s3::ObjectVersionHead& head) {
    VersionMeta m;
    m.object_size = head.content_length;
    m.etag = head.etag;
    m.storage_class = head.storage_class;
    m.content_hash = metaValue(head, "content-hash");
    const auto iv = metaValue(head, "vh-iv");
    std::optional<unsigned int> keyVersion;
    if (const auto v = metaValue(head, "vh-key-version")) {
        try {
            keyVersion = static_cast<unsigned int>(std::stoul(*v));
        } catch (const std::exception&) {
            keyVersion.reset();
        }
    }
    std::optional<bool> flag;
    if (auto v = metaValue(head, "vh-encrypted")) {
        std::ranges::transform(*v, v->begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (*v == "true" || *v == "1") flag = true;
        else if (*v == "false" || *v == "0") flag = false;
    }
    const bool hasPayload = iv && keyVersion && *keyVersion > 0;
    // Objects Vaulthalla writes always carry vh-encrypted; one without any vh metadata is plaintext.
    m.encrypted = flag ? *flag : hasPayload;
    if (m.encrypted) {
        if (!hasPayload)
            throw NoEncryptionContext("the version is sealed but carries no IV / key version");
        m.iv = *iv;
        m.key_version = *keyVersion;
        if (m.object_size < kRestoreGcmTag)
            throw storage::IntegrityError("the version is shorter than its authentication tag");
        m.plaintext_size = m.object_size - kRestoreGcmTag;
    } else {
        m.plaintext_size = m.object_size;
    }
    return m;
}

std::filesystem::path backingOf(const storage::CloudEngine& engine, const fs::model::File& f) {
    if (f.backing_path.is_absolute() || !engine.paths) return f.backing_path;
    return engine.paths->absPath(f.backing_path, fs::model::PathType::BACKING_ROOT);
}

// The destination's row as the rest of the daemon sees it (the fs cache entry when there is one).
FilePtr currentRow(const storage::CloudEngine& engine, const std::filesystem::path& vaultPath) {
    if (const auto& cache = runtime::Deps::get().fsCache) {
        try {
            if (auto entry = std::dynamic_pointer_cast<fs::model::File>(cache->getEntry(engine.vaultPathToFusePath(vaultPath))))
                return entry;
        } catch (const std::exception&) {}
    }
    return db::query::fs::File::getFileByPath(engine.vault->id, vaultPath);
}

bool isDirectoryAt(const storage::CloudEngine& engine, const std::filesystem::path& vaultPath) {
    if (const auto& cache = runtime::Deps::get().fsCache) {
        try {
            if (const auto entry = cache->getEntry(engine.vaultPathToFusePath(vaultPath))) return entry->isDirectory();
        } catch (const std::exception&) {}
    }
    return false;
}

std::optional<std::string> sourceIdOf(const FilePtr& f) {
    if (!f) return std::nullopt;
    return storage::generationOf(*f).sourceId();
}

bool sameGeneration(const fs::model::File& local, const VersionRow& v) {
    if (!v.encrypted.value_or(false) || !v.encryption_iv || !v.key_version) return false;
    return !local.encryption_iv.empty() && local.encryption_iv == *v.encryption_iv &&
           local.encrypted_with_key_version == *v.key_version;
}

std::shared_ptr<identities::User> ownerOf(const storage::CloudEngine& engine, const std::optional<uint32_t>& userId) {
    if (userId)
        if (auto user = identities::manager().user(*userId)) return user;
    auto owner = identities::manager().user(engine.vault->owner_id);
    if (!owner) throw std::runtime_error("the vault owner was not found");
    return owner;
}

bool cacheStrategy(const storage::CloudEngine& engine) {
    const auto policy = engine.remote_policy();
    return !policy || policy->strategy == sync::model::RemotePolicy::Strategy::Cache;
}

void ensureParentDirectories(const std::shared_ptr<storage::CloudEngine>& engine, const std::filesystem::path& vaultPath,
                             const std::shared_ptr<identities::User>& user) {
    const auto parent = vaultPath.parent_path();
    if (parent.empty() || parent == "/") return;
    const auto fuseParent = engine->vaultPathToFusePath(parent);
    if (runtime::Deps::get().fsCache->entryExists(fuseParent)) return;
    const auto rc = fs::Filesystem::mkdir({.path = fuseParent, .engine = engine, .user = user});
    if (rc < 0 && rc != -EEXIST)
        throw std::system_error(-rc, std::generic_category(), "could not create " + parent.string());
}

std::filesystem::path directoryBacking(const storage::CloudEngine& engine, const std::filesystem::path& vaultPath) {
    const auto parent = vaultPath.parent_path();
    const auto entry = runtime::Deps::get().fsCache->getEntry(
        engine.vaultPathToFusePath(parent.empty() ? std::filesystem::path("/") : parent));
    if (!entry || !entry->isDirectory()) throw std::runtime_error("no directory for " + vaultPath.string());
    return entry->backing_path.is_absolute() || !engine.paths
               ? entry->backing_path
               : engine.paths->absPath(entry->backing_path, fs::model::PathType::BACKING_ROOT);
}

void fsyncDirectoryQuietly(const std::filesystem::path& dir) {
    try {
        fs::ops::fsyncDirectory(dir);
    } catch (const std::exception& e) {
        log::Registry::cloud()->warn("[Recovery] Could not fsync {}: {}", dir.string(), e.what());
    }
}

// A private 0600 file next to the destination's backing path for one restore's bytes (only ever ciphertext: a
// plaintext object is sealed while it streams in). Removed unless release()d.
class RestoreTemp {
public:
    explicit RestoreTemp(const std::filesystem::path& dir, const std::string& suffix = {}) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        path_ = dir / (".vh-restore-" + fs::ops::generate_random_suffix(16) + suffix);
        fd_ = ::open(path_.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd_ < 0) throw std::system_error(errno, std::generic_category(), "create " + path_.string());
    }
    ~RestoreTemp() {
        closeFd();
        if (!released_) {
            std::error_code ec;
            std::filesystem::remove(path_, ec);
        }
    }
    RestoreTemp(const RestoreTemp&) = delete;
    RestoreTemp& operator=(const RestoreTemp&) = delete;

    [[nodiscard]] int fd() const { return fd_; }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

    void write(std::span<const uint8_t> bytes) {
        while (!bytes.empty()) {
            const auto n = ::write(fd_, bytes.data(), bytes.size());
            if (n < 0) {
                if (errno == EINTR) continue;
                throw std::system_error(errno, std::generic_category(), "write " + path_.string());
            }
            bytes = bytes.subspan(static_cast<std::size_t>(n));
        }
    }
    void sync() {
        if (fd_ >= 0 && ::fsync(fd_) < 0) throw std::system_error(errno, std::generic_category(), "fsync " + path_.string());
    }
    void closeFd() {
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
    }
    void release() { released_ = true; }

private:
    std::filesystem::path path_;
    int fd_{-1};
    bool released_{false};
};

// Makes `vaultPath` describe the remote generation `gen` index-only (no local copy; hydrated on read), as the sync
// IndexRemoteOnly path does, but only while the destination is still generation `expected` (compare-and-set under the
// file's content lock, the lock every content writer takes). A missing destination is created index-only.
FilePtr adoptIndexOnly(const std::shared_ptr<storage::CloudEngine>& engine, const std::filesystem::path& vaultPath,
                       const fs::model::File& gen, const std::optional<std::string>& expected,
                       const std::shared_ptr<identities::User>& user) {
    auto row = currentRow(*engine, vaultPath);
    if (!row) {
        if (expected) throw fs::ContentConflict("the destination was removed since the plan");
        ensureParentDirectories(engine, vaultPath, user);
        auto remote = std::make_shared<fs::model::File>(gen);
        remote->path = vaultPath;
        return engine->indexAndDeleteFile(remote);
    }
    if (!expected) throw fs::ContentConflict("a file appeared at the destination since the plan");

    std::scoped_lock contentLock(fs::Filesystem::contentWriteMutex(row->id));
    const auto now = currentRow(*engine, vaultPath);
    if (!now || now->id != row->id || sourceIdOf(now) != expected)
        throw fs::ContentConflict("the destination changed since the plan");
    if (now->inode && fuse::WorkingCopies::instance().isOpen(*now->inode))
        throw fs::ContentConflict("the destination is open through the mounted filesystem");

    const auto staged = std::make_shared<fs::model::File>(*now);
    staged->size_bytes = gen.size_bytes;
    staged->encryption_iv = gen.encryption_iv;
    staged->encrypted_with_key_version = gen.encryption_iv.empty() ? 0u : gen.encrypted_with_key_version;
    staged->content_hash = gen.content_hash;
    staged->updated_at = gen.updated_at;
    staged->last_modified_by = user->id;
    db::query::fs::File::updateFile(staged);

    now->size_bytes = staged->size_bytes;
    now->encryption_iv = staged->encryption_iv;
    now->encrypted_with_key_version = staged->encrypted_with_key_version;
    now->content_hash = staged->content_hash;
    now->updated_at = staged->updated_at;
    now->last_modified_by = staged->last_modified_by;

    // The row no longer describes the old local bytes: drop them (the provider holds every generation).
    const auto backing = backingOf(*engine, *now);
    std::error_code ec;
    if (!backing.empty() && std::filesystem::remove(backing, ec)) fsyncDirectoryQuietly(backing.parent_path());
    if (now->parent_id) runtime::Deps::get().fsCache->refreshDirStats(*now->parent_id);
    engine->purgeDerivedArtifacts(now->id);
    return now;
}

// Replaces the destination's content with an already-sealed file (sealedPath, in the backing file's directory),
// createFile's overwrite protocol: under the content lock and only while the row is still generation `expected`;
// sidecar → row → rename over the backing file, so startup recovery settles a crash like any content write.
FilePtr commitSealed(const std::shared_ptr<storage::CloudEngine>& engine, const std::filesystem::path& vaultPath,
                     RestoreTemp& sealed, const std::string& ivB64, const unsigned int keyVersion,
                     const uint64_t plaintextSize, const std::string& expected,
                     const std::shared_ptr<identities::User>& user) {
    const auto row = currentRow(*engine, vaultPath);
    if (!row) throw fs::ContentConflict("the destination was removed meanwhile");

    std::scoped_lock contentLock(fs::Filesystem::contentWriteMutex(row->id));
    const auto now = currentRow(*engine, vaultPath);
    if (!now || now->id != row->id || sourceIdOf(now) != expected)
        throw fs::ContentConflict("the destination changed since the plan");
    if (now->inode && fuse::WorkingCopies::instance().isOpen(*now->inode))
        throw fs::ContentConflict("the destination is open through the mounted filesystem");

    const auto backing = backingOf(*engine, *now);
    std::filesystem::create_directories(backing.parent_path());
    const auto sidecar = fs::ops::contentSidecarPath(backing);
    std::error_code ec;
    std::filesystem::remove(sidecar, ec);   // a leftover is settled by startup recovery; we hold the file's lock
    sealed.closeFd();
    fs::ops::fsyncFile(sealed.path());   // also covers a re-sealed file written by path
    std::filesystem::rename(sealed.path(), sidecar);
    sealed.release();
    fsyncDirectoryQuietly(backing.parent_path());

    const auto staged = std::make_shared<fs::model::File>(*now);
    try {
        staged->encryption_iv = ivB64;
        staged->encrypted_with_key_version = ivB64.empty() ? 0u : keyVersion;
        staged->size_bytes = plaintextSize;
        staged->content_hash = crypto::hash::blake2b(sidecar);
        staged->last_modified_by = user->id;
        staged->updated_at = std::time(nullptr);
        db::query::fs::File::updateFile(staged);
    } catch (...) {
        std::filesystem::remove(sidecar, ec);
        throw;
    }

    // The row describes the sidecar now; a failed rename leaves it for recovery to promote.
    std::filesystem::rename(sidecar, backing);
    fsyncDirectoryQuietly(backing.parent_path());

    now->encryption_iv = staged->encryption_iv;
    now->encrypted_with_key_version = staged->encrypted_with_key_version;
    now->size_bytes = staged->size_bytes;
    now->content_hash = staged->content_hash;
    now->last_modified_by = staged->last_modified_by;
    now->updated_at = staged->updated_at;
    if (now->parent_id) runtime::Deps::get().fsCache->refreshDirStats(*now->parent_id);
    engine->purgeDerivedArtifacts(now->id);
    return now;
}

// The remote index (and its manifest) learn the new current object; the sync baseline records that both sides agree.
void publishRestored(const std::shared_ptr<storage::CloudEngine>& engine, const FilePtr& indexRow,
                     const std::optional<sync::model::Baseline>& baseline, RestoreOutcome& out) {
    const sync::model::Action action{sync::model::ActionType::Upload, {indexRow->path.u8string()}, indexRow, nullptr};
    try {
        engine->applyRemoteIndexMutation({action});
    } catch (const std::exception& e) {
        // The index rows are written before the manifest is published: only the manifest lags (the next pass keeps
        // using the index while the manifest ETag is unchanged).
        out.notes.push_back(std::string("the remote index manifest was not republished: ") + e.what());
    }
    if (baseline) sync::tasks::recordBaseline(engine, *baseline);
}

struct PassLease {
    const RestoreHooks& hooks;
    uint32_t vault;
    ~PassLease() {
        try {
            if (hooks.releasePass) hooks.releasePass(vault);
        } catch (...) {}
    }
};

RestoreHooks defaultedHooks(RestoreHooks hooks) {
    if (!hooks.tryAcquirePass)
        hooks.tryAcquirePass = [](const uint32_t v) {
            const auto& c = runtime::Deps::get().syncController;
            return !c || c->tryAcquirePass(v);
        };
    if (!hooks.releasePass)
        hooks.releasePass = [](const uint32_t v) {
            if (const auto& c = runtime::Deps::get().syncController) c->releasePass(v);
        };
    return hooks;
}

// The key's current version per the index is already this version's bytes (a restore whose copy succeeded before a
// later step failed): reuse it instead of copying again.
std::optional<VersionRow> copiedCurrent(const uint32_t vaultId, const std::string& destKey, const VersionRow& source,
                                        const VersionMeta& meta) {
    const auto rows = db::query::recovery::ObjectVersion::listForKey(vaultId, destKey, false, 1);
    if (rows.empty()) return std::nullopt;
    const auto& latest = rows.front();
    if (!latest.is_latest || latest.is_delete_marker || latest.version_id == source.version_id) return std::nullopt;
    if (!sameEtag(latest.etag, meta.etag)) return std::nullopt;
    if (meta.encrypted && latest.encryption_iv != std::make_optional(meta.iv)) return std::nullopt;
    return latest;
}

// ---- plans ---------------------------------------------------------------------------------------------------------

struct PlanContext {
    std::shared_ptr<storage::CloudEngine> engine;
    unsigned int currentKeyVersion{};
    bool encryptUpstream{true};
    std::unordered_map<uint32_t, db::query::sync::ConflictRecord> openConflicts;
    std::unordered_map<uint32_t, sync::model::Baseline> baselines;

    explicit PlanContext(std::shared_ptr<storage::CloudEngine> e) : engine(std::move(e)) {
        if (!engine || !engine->vault) throw std::invalid_argument("a restore plan needs a cloud vault engine");
        if (engine->encryptionManager) {
            try {
                currentKeyVersion = engine->encryptionManager->get_key_version();
            } catch (const std::exception&) {}
        }
        if (const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(engine->vault)) encryptUpstream = s3->encrypt_upstream;
        openConflicts = db::query::sync::Conflict::openForVault(engine->vault->id);
        baselines = db::query::sync::Conflict::baselinesForVault(engine->vault->id);
    }
};

PlanItem itemFor(const PlanContext& ctx, const VersionRow& v, const std::filesystem::path& destination) {
    const auto& engine = ctx.engine;
    PlanItem item;
    item.source_id = RecoveryId{.type = RecoveryId::Type::ProviderVersion, .id = static_cast<uint64_t>(v.id)}.str();
    item.source_path = versions::vaultPathOf(v.object_key).string();
    item.destination_path = destination.string();
    const bool encrypted = v.encrypted.value_or(false);
    if (v.plaintext_bytes) item.size_bytes = v.plaintext_bytes;
    else if (v.size_bytes) item.size_bytes = encrypted && *v.size_bytes >= kRestoreGcmTag ? *v.size_bytes - kRestoreGcmTag
                                                                                         : *v.size_bytes;
    if (v.origin != "vaulthalla")
        item.notes.emplace_back("unverified: this version was not written by Vaulthalla (restoring it needs an "
                                "explicit acceptance)");

    const auto unavailable = [&](const std::string& why) {
        item.action = ItemAction::Unavailable;
        item.method = "none";
        item.notes.push_back(why);
        return item;
    };
    if (v.gone_at) return unavailable("the provider no longer lists this version");
    if (v.is_delete_marker) return unavailable("delete marker: the file was absent at this time");
    if (points::isArchiveClass(v.storage_class))
        return unavailable("archived storage class (" + *v.storage_class + "): the provider must restore it first");
    if (encrypted && v.key_version && engine->encryptionManager && !engine->encryptionManager->hasKeyVersion(*v.key_version))
        return unavailable("sealed under key version " + std::to_string(*v.key_version) + ", which this vault no longer holds");

    const auto destKey = versions::objectKeyOf(destination);
    const bool sameKey = destKey == v.object_key;
    const bool fitsCopy = !v.size_bytes || *v.size_bytes <= storage::s3::Controller::MAX_SINGLE_COPY_BYTES;
    const bool keyOk = !v.encrypted.has_value() ? true   // unknown metadata: decided after the HEAD
                                    : (encrypted ? (ctx.encryptUpstream && v.key_version == ctx.currentKeyVersion)
                                                 : !ctx.encryptUpstream);
    item.method = sameKey && fitsCopy && keyOk ? "provider_copy" : "provider_transfer";
    if (!v.encrypted.has_value()) item.notes.emplace_back("no Vaulthalla metadata recorded: copy or transfer is decided after a HEAD");
    if (item.method == "provider_transfer") {
        if (!sameKey) item.notes.emplace_back("another destination: GET, re-seal and PUT");
        else if (!fitsCopy) item.notes.emplace_back("larger than one CopyObject (5 GiB): GET, re-seal and PUT");
        else if (encrypted && v.key_version != ctx.currentKeyVersion)
            item.notes.emplace_back("sealed under key version " + std::to_string(v.key_version.value_or(0)) +
                                    ": re-sealed under the current key and uploaded");
        else item.notes.emplace_back("the vault's upstream encryption setting differs from this version: re-stored");
    }

    if (isDirectoryAt(*engine, destination)) {
        item.action = ItemAction::Conflict;
        item.notes.emplace_back("the destination is a directory");
        return item;
    }

    const auto dest = currentRow(*engine, destination);
    if (sameKey && v.is_latest) {
        item.action = ItemAction::Skip;
        item.method = "none";
        item.notes.emplace_back("this is already the current version");
        if (dest) item.destination_source_id = sourceIdOf(dest);
        return item;
    }
    if (sameKey) {
        // The key's current version already holds these bytes (a copy of it): nothing to do.
        const auto latest = db::query::recovery::ObjectVersion::listForKey(engine->vault->id, destKey, false, 1);
        if (!latest.empty() && latest.front().is_latest && !latest.front().is_delete_marker &&
            (sameEtag(latest.front().etag, v.etag) ||
             (encrypted && latest.front().encryption_iv && latest.front().encryption_iv == v.encryption_iv &&
              latest.front().key_version == v.key_version))) {
            item.action = ItemAction::Skip;
            item.method = "none";
            item.notes.emplace_back("the current version already holds this content");
            if (dest) item.destination_source_id = sourceIdOf(dest);
            return item;
        }
    }
    if (!dest) {
        item.action = ItemAction::Create;
        return item;
    }
    item.destination_source_id = sourceIdOf(dest);
    if (sameGeneration(*dest, v)) {
        item.action = ItemAction::Skip;
        item.method = "none";
        item.notes.emplace_back("the destination already is this generation");
        return item;
    }
    if (ctx.openConflicts.contains(dest->id)) {
        item.action = ItemAction::Conflict;
        item.notes.emplace_back("the destination has an open sync conflict: decide it first");
        return item;
    }
    if (const auto base = ctx.baselines.find(dest->id);
        base != ctx.baselines.end() && sync::model::localChangedSince(*dest, base->second)) {
        item.action = ItemAction::Conflict;
        item.notes.emplace_back("the destination has local changes not uploaded yet (they would be lost): sync first");
        return item;
    }
    item.action = ItemAction::Overwrite;
    return item;
}

void tally(Plan& plan, const storage::CloudEngine& engine) {
    plan.creates = plan.overwrites = plan.skips = plan.conflicts = plan.removals = plan.unavailable = 0;
    sync::model::S3CostEstimate est;
    auto& e = plan.estimate;
    e = {};
    for (const auto& item : plan.items) {
        switch (item.action) {
        case ItemAction::Create: ++plan.creates; break;
        case ItemAction::Overwrite: ++plan.overwrites; break;
        case ItemAction::Skip: ++plan.skips; break;
        case ItemAction::Conflict: ++plan.conflicts; break;
        case ItemAction::Remove: ++plan.removals; break;
        case ItemAction::Unavailable: ++plan.unavailable; break;
        }
        if (item.action != ItemAction::Create && item.action != ItemAction::Overwrite) continue;
        const uint64_t bytes = item.size_bytes.value_or(0);
        e.head_requests += 1;
        if (item.method == "provider_copy") {
            e.copy_requests += 1;
        } else {
            e.get_requests += 1;
            e.put_requests += 1;
            e.download_bytes += bytes + kRestoreGcmTag;
            e.upload_bytes += bytes + kRestoreGcmTag;
        }
        // The remote index manifest is republished once per restored item (conditional PUT + HEADs).
        e.put_requests += 1;
        e.head_requests += 2;
    }
    est.head_requests = e.head_requests;
    est.get_requests = e.get_requests;
    est.put_requests = e.put_requests;
    est.copy_requests = e.copy_requests;
    est.planned_body_download_bytes = e.download_bytes;
    est.planned_upload_bytes = e.upload_bytes;
    try {
        const auto report = storage::s3::pricing::estimatePlannedS3Sync(engine, est);
        if (report.available) e.cost = Money{.amount = report.estimated_cost, .currency = report.currency};
        else e.unpriced_reason = report.unavailable_reason.empty() ? "no price profile for this provider"
                                                                   : report.unavailable_reason;
    } catch (const std::exception& ex) {
        e.unpriced_reason = std::string("price estimate failed: ") + ex.what();
    }
    if (plan.unavailable) plan.warnings.push_back(fmt::format("{} item(s) cannot be restored (see their notes)", plan.unavailable));
    if (plan.conflicts) plan.warnings.push_back(fmt::format("{} item(s) are conflicts and will not be restored", plan.conflicts));
    if (std::ranges::any_of(plan.items, [](const PlanItem& i) {
            return std::ranges::any_of(i.notes, [](const std::string& n) { return n.starts_with("unverified"); });
        }))
        plan.warnings.emplace_back("some versions were not written by Vaulthalla: restoring them needs an explicit acceptance");
}

std::filesystem::path rerooted(const std::filesystem::path& sourcePath, const std::filesystem::path& root,
                               const std::optional<std::filesystem::path>& destination, const bool rootIsFile) {
    if (!destination) return sourcePath;
    if (rootIsFile) return *destination;
    const auto rel = sourcePath.lexically_relative(root.empty() ? std::filesystem::path("/") : root);
    return (*destination / rel).lexically_normal();
}

}

// ---- plans ---------------------------------------------------------------------------------------------------------

PlanItem planFor(const std::shared_ptr<storage::CloudEngine>& engine, const db::query::recovery::ObjectVersionRow& version,
                 const std::optional<std::filesystem::path>& destination) {
    const restore_detail::PlanContext ctx(engine);
    if (version.vault_id != engine->vault->id) throw std::invalid_argument("the version belongs to another vault");
    return restore_detail::itemFor(ctx, version,
                                   destination ? destination->lexically_normal() : versions::vaultPathOf(version.object_key));
}

Plan planOne(const std::shared_ptr<storage::CloudEngine>& engine, const uint64_t versionRowId,
             const std::optional<std::filesystem::path>& destination) {
    if (!engine || !engine->vault) throw std::invalid_argument("a restore plan needs a cloud vault engine");
    const auto row = db::query::recovery::ObjectVersion::get(static_cast<int64_t>(versionRowId));
    if (!row || row->vault_id != engine->vault->id || versions::isInternalKey(row->object_key))
        throw std::invalid_argument("no such provider version in this vault");
    Plan plan;
    plan.vault_id = engine->vault->id;
    plan.source_label = RecoveryId{.type = RecoveryId::Type::ProviderVersion, .id = versionRowId}.str();
    plan.destination = destination ? std::make_optional(destination->string()) : std::nullopt;
    plan.atomic = false;
    plan.consistency_note = "one object version, restored as a new current version";
    plan.items.push_back(planFor(engine, *row, destination));
    restore_detail::tally(plan, *engine);
    plan.created_at = std::time(nullptr);
    plan.state = "planned";
    return plan;
}

Plan planAt(const std::shared_ptr<storage::CloudEngine>& engine, const std::filesystem::path& path, const std::time_t at,
            const std::optional<std::filesystem::path>& destination, const bool prune, const unsigned int limit) {
    const restore_detail::PlanContext ctx(engine);
    const auto vaultId = engine->vault->id;
    const auto root = path.empty() ? std::filesystem::path("/") : path.lexically_normal();
    const auto fileKey = versions::objectKeyOf(root);

    // A file when the index knows its exact key (or the vault has a file there); otherwise a directory prefix.
    auto rows = db::query::recovery::ObjectVersion::listAsOf(vaultId, fileKey, at, limit);
    const bool rootIsFile = !fileKey.empty() &&
                            (std::ranges::any_of(rows, [&](const auto& r) { return r.object_key == fileKey; }) ||
                             db::query::fs::File::getFileByPath(vaultId, root) != nullptr);
    if (rootIsFile) std::erase_if(rows, [&](const auto& r) { return r.object_key != fileKey; });
    else rows = db::query::recovery::ObjectVersion::listAsOf(vaultId, versions::directoryPrefixOf(root), at, limit);

    Plan plan;
    plan.vault_id = vaultId;
    plan.point_in_time = true;
    plan.at = at;
    plan.atomic = false;
    plan.prune = prune;
    plan.destination = destination ? std::make_optional(destination->string()) : std::nullopt;
    plan.source_label = root.string() + " at " + restore_detail::isoTime(at);
    plan.consistency_note =
        "Reconstructed from per-object provider version timestamps: for each object, the newest version whose "
        "LastModified is at or before " + restore_detail::isoTime(at) + ". This is not a transactionally consistent "
        "snapshot: objects written around that time may reflect slightly different moments, and objects whose "
        "versions the provider no longer holds cannot be reconstructed.";

    std::unordered_set<std::string> presentAt;
    for (const auto& r : rows) {
        if (versions::isInternalKey(r.object_key)) continue;
        const auto source = versions::vaultPathOf(r.object_key);
        const auto dest = restore_detail::rerooted(source, root, destination, rootIsFile);
        if (r.is_delete_marker) continue;   // absent at `at`: handled with the files that had no version below
        presentAt.insert(dest.string());
        plan.items.push_back(restore_detail::itemFor(ctx, r, dest));
    }

    // Files that exist now but did not at `at` (a delete marker or no version at that time).
    std::vector<std::shared_ptr<fs::model::File>> current;
    const auto destRoot = destination ? destination->lexically_normal() : root;
    if (rootIsFile) {
        if (const auto f = db::query::fs::File::getFileByPath(vaultId, destRoot)) current.push_back(f);
    } else {
        current = db::query::fs::File::listFilesInDir(vaultId, destRoot, true);
    }
    uint64_t kept = 0;
    for (const auto& f : current) {
        if (!f || presentAt.contains(f->path.string()) || versions::isInternalKey(versions::objectKeyOf(f->path))) continue;
        if (!prune) {
            ++kept;
            continue;
        }
        PlanItem item;
        item.source_id = "";
        item.source_path = f->path.string();
        item.destination_path = f->path.string();
        item.action = ItemAction::Remove;
        item.method = "local_remove";
        item.size_bytes = f->size_bytes;
        item.destination_source_id = restore_detail::sourceIdOf(f);
        item.notes.emplace_back("absent at " + restore_detail::isoTime(at) + ": removed (moved to the trash; the next "
                                "sync deletes it upstream, which leaves a delete marker)");
        plan.items.push_back(std::move(item));
    }
    if (kept)
        plan.warnings.push_back(fmt::format("{} file(s) did not exist at {} and are kept (prune is off)", kept,
                                            restore_detail::isoTime(at)));
    if (rows.size() >= limit) plan.warnings.push_back(fmt::format("the plan stops at {} objects", limit));

    restore_detail::tally(plan, *engine);
    plan.created_at = std::time(nullptr);
    plan.state = "planned";
    return plan;
}

// ---- restore -------------------------------------------------------------------------------------------------------

RestoreOutcome restore(const std::shared_ptr<storage::CloudEngine>& engine, const PlanItem& item,
                       const std::optional<std::string>& expectedDestinationSourceId, const RestoreOptions& options) {
    namespace d = restore_detail;
    namespace s3 = storage::s3;
    if (!engine || !engine->vault) throw std::invalid_argument("a provider restore needs a cloud vault engine");
    const auto vaultId = engine->vault->id;
    const auto hooks = d::defaultedHooks(options.hooks);
    RestoreOutcome out;
    // Everything this restore sends, under the vault's request budget (never the engine-wide budget a pass owns).
    std::optional<storage::ScopedS3RequestUsageCapture> vaultBudget;

    const auto result = [&out, &vaultBudget](std::string outcome, std::optional<std::string> error = std::nullopt) {
        out.outcome = std::move(outcome);
        out.error = std::move(error);
        if (vaultBudget) {
            out.usage = vaultBudget->usage();
            out.usage.source = d::kRestoreOperation;
        }
        return out;
    };

    switch (item.action) {
    case ItemAction::Skip: return result("skipped", item.notes.empty() ? std::nullopt : std::make_optional(item.notes.front()));
    case ItemAction::Unavailable: return result("unavailable", item.notes.empty() ? std::nullopt : std::make_optional(item.notes.front()));
    case ItemAction::Conflict: return result("conflict", item.notes.empty() ? std::nullopt : std::make_optional(item.notes.front()));
    case ItemAction::Remove: {
        if (!hooks.tryAcquirePass(vaultId)) throw PassBusy("a sync pass is running for this vault; retry shortly");
        const d::PassLease lease{hooks, vaultId};
        const auto dest = d::currentRow(*engine, item.destination_path);
        out.method = "local_remove";
        if (!dest) return result("skipped", "already absent");
        if (d::sourceIdOf(dest) != expectedDestinationSourceId)
            return result("conflict", "the file changed since the plan; nothing was removed");
        fs::Filesystem::remove(engine->vaultPathToFusePath(item.destination_path), d::ownerOf(*engine, options.user_id)->id);
        return result("removed");
    }
    case ItemAction::Create:
    case ItemAction::Overwrite:
        break;
    }

    const auto id = RecoveryId::parse(item.source_id);
    if (id.type != RecoveryId::Type::ProviderVersion) throw std::invalid_argument("not a provider version: " + item.source_id);
    const auto row = db::query::recovery::ObjectVersion::get(static_cast<int64_t>(id.id));
    if (!row || row->vault_id != vaultId || versions::isInternalKey(row->object_key))
        throw std::invalid_argument("no such provider version in this vault: " + item.source_id);
    const auto destPath = item.destination_path.empty() ? versions::vaultPathOf(row->object_key)
                                                        : std::filesystem::path(item.destination_path).lexically_normal();
    const auto srcKey = row->object_key;
    const auto destKey = versions::objectKeyOf(destPath);

    if (row->gone_at) return result("unavailable", "the provider no longer lists this version");
    if (row->is_delete_marker) return result("unavailable", "a delete marker is not content");
    if (points::isArchiveClass(row->storage_class))
        return result("unavailable", "archived storage class: the provider must restore it first");
    if (row->origin != "vaulthalla" && !options.accept_unverified)
        throw UnverifiedVersion("version " + item.source_id + " was not written by Vaulthalla");

    if (!hooks.tryAcquirePass(vaultId)) throw PassBusy("a sync pass is running for this vault; retry shortly");
    const d::PassLease lease{hooks, vaultId};
    const auto user = d::ownerOf(*engine, options.user_id);

    // The destination must still be the generation the plan was made against (re-checked before every local commit).
    const auto dest = d::currentRow(*engine, destPath);
    if (d::sourceIdOf(dest) != expectedDestinationSourceId) {
        if (dest && d::sameGeneration(*dest, *row)) return result("skipped", "already restored");
        return result("conflict", dest ? "the destination changed since the plan; nothing was restored"
                                       : "the destination was removed since the plan; nothing was restored");
    }
    if (srcKey == destKey && row->is_latest) return result("skipped", "this is already the current version");

    // Price preflight for the worst case (HEAD + COPY, or GET + PUT, + the index manifest) before any request.
    const uint64_t objectBytes = row->size_bytes.value_or(row->plaintext_bytes.value_or(0) + d::kRestoreGcmTag);
    std::optional<metering::PriceReservation> price;
    try {
        sync::model::S3CostEstimate planned;
        planned.head_requests = 3;
        planned.get_requests = 1;
        planned.copy_requests = 1;
        planned.put_requests = 2;
        planned.planned_body_download_bytes = objectBytes;
        planned.planned_upload_bytes = objectBytes;
        planned.remote_index_objects = 1;
        price.emplace(*engine, planned, d::kRestoreOperation, destKey);
    } catch (const storage::ContentUnavailable& e) {
        out.retryable = true;
        return result("failed", e.what());
    }

    const auto policy = engine->remote_policy();
    vaultBudget.emplace(*engine, policy ? std::make_optional(policy->s3_request_budget) : std::nullopt);
    try {

        // 1. HEAD ?versionId: what the version is (metadata, size, class), without its body.
        std::optional<s3::ObjectVersionHead> head;
        {
            s3::S3RequestBudget cap;
            cap.max_head_requests = 1;
            cap.max_get_requests = 0;
            const storage::ScopedS3RequestUsageCapture headCap(*engine, cap);
            head = engine->headObjectVersion(srcKey, row->version_id);
        }
        if (!head) return result("unavailable", "the provider no longer holds this version");
        if (head->delete_marker) return result("unavailable", "a delete marker is not content");
        if (points::isArchiveClass(head->storage_class))
            return result("unavailable", "archived storage class: the provider must restore it first");
        const auto meta = d::metaFromHead(*head);
        if (meta.encrypted && !engine->encryptionManager->hasKeyVersion(meta.key_version))
            return result("unavailable", "sealed under key version " + std::to_string(meta.key_version) +
                                         ", which this vault no longer holds");

        const auto s3vault = std::static_pointer_cast<vault::model::S3Vault>(engine->vault);
        const bool encryptUpstream = s3vault->encrypt_upstream;
        const auto currentKeyVersion = engine->encryptionManager->get_key_version();
        const bool copyable = destKey == srcKey && meta.object_size <= s3::Controller::MAX_SINGLE_COPY_BYTES &&
                              ((meta.encrypted && encryptUpstream && meta.key_version == currentKeyVersion) ||
                               (!meta.encrypted && !encryptUpstream));

        if (copyable) {
            // 2a. Provider copy: CopyObject ?versionId onto the key (metadata travels with directive COPY) as our own
            //     write; the version index and the event write intent learn it.
            auto gen = std::make_shared<fs::model::File>();
            gen->vault_id = vaultId;
            gen->path = destPath;
            gen->name = destPath.filename().string();
            gen->size_bytes = meta.plaintext_size;
            gen->encryption_iv = meta.encrypted ? meta.iv : std::string{};
            gen->encrypted_with_key_version = meta.encrypted ? meta.key_version : 0u;
            gen->content_hash = meta.content_hash;
            gen->remote_encrypted = meta.encrypted;
            gen->remote_storage_class = engine->writeStorageClass();
            gen->updated_at = std::time(nullptr);

            std::string newEtag;
            std::optional<std::string> newVersionId;
            if (const auto already = d::copiedCurrent(vaultId, destKey, *row, meta)) {
                newEtag = already->etag.value_or(meta.etag);
                newVersionId = already->version_id;
                out.notes.emplace_back("the provider already holds this content as the current version (an earlier "
                                       "attempt copied it): not copied again");
            } else {
                s3::S3RequestBudget cap;
                cap.max_copy_requests = 1;
                cap.max_get_requests = 0;
                const storage::ScopedS3RequestUsageCapture copyCap(*engine, cap);
                const auto copied = engine->copyObjectVersionAsOwnWrite(srcKey, row->version_id, destKey, meta.object_size,
                                                                        meta.etag, gen);
                newEtag = copied.etag;
                newVersionId = copied.version_id;
                out.provider_changed = true;
            }
            out.method = "provider_copy";
            out.new_etag = newEtag;
            out.new_version_id = newVersionId;

            // 3a. Local state follows before the lease is released.
            auto indexRow = std::make_shared<fs::model::File>(*gen);
            indexRow->remote_etag = newEtag;
            indexRow->remote_version_id = newVersionId;
            std::shared_ptr<fs::model::File> adopted;
            try {
                adopted = d::adoptIndexOnly(engine, destPath, *gen, expectedDestinationSourceId, user);
            } catch (const fs::ContentConflict& e) {
                // The provider copy is not undone: the remote side really changed. The index says so, so the next
                // pass treats it as a two-sided change (conflict policy) instead of overwriting either side.
                d::publishRestored(engine, indexRow, std::nullopt, out);
                price->commit();
                out.notes.emplace_back("the provider copy was made (it is the current version upstream); the next "
                                       "sync settles it with the local change under the vault's conflict policy");
                return result("conflict", std::string("the local file changed during the restore: ") + e.what());
            }
            indexRow = std::make_shared<fs::model::File>(*adopted);
            indexRow->remote_etag = newEtag;
            indexRow->remote_version_id = newVersionId;
            indexRow->remote_encrypted = meta.encrypted;
            indexRow->remote_storage_class = gen->remote_storage_class;
            d::publishRestored(engine, indexRow, sync::model::Baseline::agreed(*adopted, *indexRow), out);

            if (!d::cacheStrategy(*engine)) {
                // mirror / sync keep content local: fetch the restored generation now (metered, verified).
                try {
                    (void)engine->hydrate(adopted);
                } catch (const std::exception& e) {
                    out.notes.push_back(std::string("the restored content is fetched on first read: ") + e.what());
                }
            }
            price->commit();
            log::Registry::cloud()->info("[Recovery] Vault {}: restored {} onto '{}' by provider copy (version {})",
                                         vaultId, item.source_id, destPath.string(), newVersionId.value_or("-"));
            return result("restored");
        }

        // 2b. Bounded transfer: GET ?versionId (If-Match) into a private temp, verify, re-seal under the current key,
        //     commit locally (CAS), then one PUT.
        out.method = "provider_transfer";
        const bool creating = !dest;
        if (creating) d::ensureParentDirectories(engine, destPath, user);
        const auto dir = creating ? d::directoryBacking(*engine, destPath)
                                  : d::backingOf(*engine, *dest).parent_path();
        d::RestoreTemp fetched(dir);

        std::string ivB64;
        unsigned int keyVersion = 0;
        std::optional<crypto::util::GcmStreamEncryptor> sealer;
        std::array<uint8_t, crypto::util::AES_IV_SIZE> freshIv{};
        if (!meta.encrypted) {
            // Plaintext upstream: sealed on the fly, never on disk in the clear.
            const auto current = engine->encryptionManager->currentKey();
            if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
            randombytes_buf(freshIv.data(), freshIv.size());
            ivB64 = crypto::util::b64_encode(std::vector<uint8_t>(freshIv.begin(), freshIv.end()));
            keyVersion = current.version;
            sealer.emplace(current.key->bytes(), crypto::util::GcmIv(freshIv.data(), freshIv.size()));
        }
        {
            s3::S3RequestBudget cap;
            cap.max_get_requests = 1;
            cap.max_head_requests = 0;
            cap.max_downloaded_bytes = meta.object_size + d::kRestoreErrorSlack;
            const storage::ScopedS3RequestUsageCapture getCap(*engine, cap);
            std::vector<uint8_t> buf;
            const auto got = engine->streamObjectVersion(
                srcKey, row->version_id, meta.etag.empty() ? std::nullopt : std::make_optional(meta.etag),
                meta.object_size, [&](const std::span<const uint8_t> bytes) {
                    if (sealer) {
                        buf.resize(bytes.size());
                        sealer->update(bytes, buf);
                        fetched.write(buf);
                    } else {
                        fetched.write(bytes);
                    }
                });
            if (got.body_bytes != meta.object_size)
                throw std::runtime_error(fmt::format("the provider returned {} of {} bytes", got.body_bytes, meta.object_size));
        }

        std::optional<d::RestoreTemp> resealed;
        d::RestoreTemp* sealedFile = &fetched;
        if (sealer) {
            const auto tag = sealer->finish();
            fetched.write(tag);
        } else if (meta.key_version == currentKeyVersion) {
            // Sealed under the current key: the bytes are reused as they are (same IV for the same plaintext).
            const auto key = engine->encryptionManager->keySnapshot(meta.key_version);
            const auto raw = crypto::util::b64_decode(meta.iv);
            if (raw.size() != crypto::util::AES_IV_SIZE) throw storage::IntegrityError("the version's IV is malformed");
            if (!crypto::util::gcmVerifyFd(fetched.fd(), 0, meta.plaintext_size, key->bytes(),
                                           crypto::util::GcmIv(raw.data(), raw.size())))
                throw storage::IntegrityError("the version failed authentication; nothing was restored");
            ivB64 = meta.iv;
            keyVersion = meta.key_version;
        } else {
            // Sealed under a retired key: streamed GCM decrypt (old key) → encrypt (current key, fresh IV); committed
            // only once the old tag verified.
            fetched.sync();
            resealed.emplace(dir, ".sealed");
            resealed->closeFd();
            auto stamp = std::make_shared<fs::model::File>();
            engine->encryptionManager->resealFileToCurrent(fetched.path(), meta.iv, meta.key_version, resealed->path(), stamp);
            ivB64 = stamp->encryption_iv;
            keyVersion = stamp->encrypted_with_key_version;
            sealedFile = &*resealed;
            fetched.closeFd();
        }

        // 3b. Local commit under CAS (a new destination is created empty first, then filled the same way).
        std::string expectedNow;
        if (creating) {
            const auto created = fs::Filesystem::createFile({.path = destPath,
                                                             .fuse_path = engine->vaultPathToFusePath(destPath),
                                                             .buffer = {}, .engine = engine, .user = user,
                                                             .overwrite = false});
            // A file someone created meanwhile (createFile returns it unchanged) is not ours to fill.
            if (!created || created->size_bytes != 0 || !created->encryption_iv.empty() ||
                std::time(nullptr) - created->created_at > 60)
                throw fs::ContentConflict("a file appeared at the destination meanwhile");
            expectedNow = *d::sourceIdOf(created);
        } else {
            expectedNow = *expectedDestinationSourceId;
        }
        std::shared_ptr<fs::model::File> committed;
        try {
            committed = d::commitSealed(engine, destPath, *sealedFile, ivB64, keyVersion, meta.plaintext_size,
                                        expectedNow, user);
        } catch (...) {
            if (creating) {
                try {
                    engine->removeLocally(destPath);
                } catch (const std::exception& e) {
                    log::Registry::cloud()->warn("[Recovery] Could not remove the empty restore target {}: {}",
                                                 destPath.string(), e.what());
                }
            }
            throw;
        }

        // 4b. One PUT of the committed generation (as a sync upload does), then the index and the baseline.
        try {
            engine->upload(committed);
            const auto put = s3::Controller::lastPutOutcome();
            if (!put.etag.empty()) out.new_etag = put.etag;
            out.new_version_id = put.version_id;
            out.provider_changed = true;
            auto indexRow = std::make_shared<fs::model::File>(*committed);
            if (out.new_etag) indexRow->remote_etag = out.new_etag;
            indexRow->remote_version_id = out.new_version_id;
            d::publishRestored(engine, indexRow, sync::model::Baseline::afterUpload(*committed), out);
        } catch (const std::exception& e) {
            out.notes.push_back(std::string("restored locally; the upload failed and the next sync uploads it: ") + e.what());
        }
        price->commit();
        log::Registry::cloud()->info("[Recovery] Vault {}: restored {} onto '{}' by transfer", vaultId, item.source_id,
                                     destPath.string());
        return result("restored");
    } catch (const s3::RequestBudgetExceeded& e) {
        out.retryable = true;
        return result("failed", std::string("the S3 request budget stopped the restore: ") + e.what());
    } catch (const storage::ContentUnavailable& e) {
        out.retryable = true;
        return result("failed", e.what());
    } catch (const s3::ConditionalRequestFailed& e) {
        out.retryable = true;
        return result("failed", std::string("the version changed while it was restored: ") + e.what());
    } catch (const s3::ObjectNotFound&) {
        return result("unavailable", "the provider no longer holds this version");
    } catch (const fs::ContentConflict& e) {
        return result("conflict", std::string(e.what()) + "; nothing was restored");
    } catch (const storage::IntegrityError& e) {
        return result("failed", e.what());
    } catch (const vault::KeyVersionUnavailable&) {
        return result("unavailable", "the vault does not hold the key this version is sealed with");
    } catch (const d::NoEncryptionContext& e) {
        return result("unavailable", e.what());
    } catch (const storage::upstream::BucketProtected& e) {
        return result("failed", e.what());
    } catch (const std::exception& e) {
        out.retryable = true;
        return result("failed", e.what());
    }
}

}
