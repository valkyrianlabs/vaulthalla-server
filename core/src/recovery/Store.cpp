#include "recovery/Store.hpp"

#include "db/query/recovery/Blob.hpp"
#include "fs/ops/file.hpp"
#include "log/Registry.hpp"
#include "platform/Clone.hpp"
#include "platform/FileTime.hpp"
#include "vault/Retention.hpp"
#include "vault/model/Vault.hpp"

#include <paths.h>
#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <stdexcept>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <unordered_map>

namespace vh::recovery::store {

namespace {

namespace sfs = std::filesystem;
using BlobQuery = db::query::recovery::Blob;

constexpr std::string_view kStorageAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
constexpr std::size_t kStorageNameLength = 32;
constexpr std::string_view kTempPrefix = ".tmp-";

std::string trimmedAlias(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    return value;
}

bool storeAliasName(const std::string& alias) {
    if (alias.empty() || alias.size() > 128) return false;
    return std::ranges::all_of(alias, [](const unsigned char c) { return std::isalnum(c) != 0 || c == '_' || c == '-'; });
}

// `shard` is <root>/<alias>/<aa>; every level the store owns is 0700 (the backing root itself is the daemon's).
void ensurePrivateDir(const sfs::path& shard) {
    std::error_code ec;
    sfs::create_directories(shard, ec);
    if (ec) throw std::system_error(ec, "creating recovery store directory " + shard.string());
    for (const auto& p : {root(), shard.parent_path(), shard}) {
        sfs::permissions(p, sfs::perms::owner_all, sfs::perm_options::replace, ec);
        if (ec) throw std::system_error(ec, "securing recovery store directory " + p.string());
    }
}

void unlinkQuiet(const sfs::path& p) noexcept {
    if (::unlink(p.c_str()) != 0 && errno != ENOENT)
        log::Registry::storage()->warn("[RecoveryStore] Could not remove {}: {}", p.string(), std::strerror(errno));
}

void fsyncDirQuiet(const sfs::path& dir) noexcept {
    try {
        fs::ops::fsyncDirectory(dir);
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[RecoveryStore] Directory fsync failed for {}: {}", dir.string(), e.what());
    }
}

// Inode change time: link(2) and rename(2) update it, so a freshly linked blob is young even when the sealed bytes are
// old (a hard link shares the backing file's mtime).
std::optional<std::time_t> changeTime(const sfs::path& p) {
    struct stat st{};
    if (::lstat(p.c_str(), &st) != 0) return std::nullopt;
    return platform::ctime(st).tv_sec;
}

void requireRegularFile(const sfs::path& p) {
    struct stat st{};
    if (::lstat(p.c_str(), &st) != 0)
        throw std::system_error(errno, std::generic_category(), "recovery capture source " + p.string());
    if (!S_ISREG(st.st_mode)) throw std::runtime_error("recovery capture source is not a regular file: " + p.string());
}

uint64_t storeFileSize(const sfs::path& p) {
    std::error_code ec;
    const auto size = sfs::file_size(p, ec);
    if (ec) throw std::system_error(ec, "recovery blob size " + p.string());
    return size;
}

std::mutex usageMutex;
std::unordered_map<uint32_t, std::pair<uint64_t, std::chrono::steady_clock::time_point>> usageCache;
std::unordered_map<uint32_t, std::pair<uint64_t, std::chrono::steady_clock::time_point>> chargedCache;

}

// ---- paths ---------------------------------------------------------------------------------------------------------

VaultRef vaultRef(const vault::model::Vault& v) { return {.id = v.id, .alias = trimmedAlias(v.mount_point.string())}; }

sfs::path root() { return paths::getBackingPath() / kStoreDirName; }

sfs::path vaultDir(const VaultRef& vault) {
    const auto alias = trimmedAlias(vault.alias);
    if (!storeAliasName(alias)) throw std::invalid_argument("not a vault directory name: '" + vault.alias + "'");
    return root() / alias;
}

bool validStorageName(const std::string& name) {
    return name.size() == kStorageNameLength &&
           std::ranges::all_of(name, [](const char c) { return kStorageAlphabet.find(c) != std::string_view::npos; });
}

sfs::path blobPath(const VaultRef& vault, const std::string& storageName) {
    if (!validStorageName(storageName)) throw std::invalid_argument("invalid recovery blob name");
    return vaultDir(vault) / storageName.substr(0, 2) / storageName;
}

std::string newStorageName() {
    static const bool sodiumReady = sodium_init() >= 0;
    if (!sodiumReady) throw std::runtime_error("libsodium failed to initialize");
    std::string name(kStorageNameLength, 'a');
    for (auto& c : name) c = kStorageAlphabet[randombytes_uniform(static_cast<uint32_t>(kStorageAlphabet.size()))];
    return name;
}

std::string to_string(const CaptureMethod m) {
    switch (m) {
    case CaptureMethod::Existing: return "existing";
    case CaptureMethod::Link: return "link";
    case CaptureMethod::Reflink: return "reflink";
    case CaptureMethod::Copy: return "copy";
    case CaptureMethod::Stream: return "stream";
    }
    return "existing";
}

// ---- capture -------------------------------------------------------------------------------------------------------

struct detail::Stager {
    // The blob to stage into: an existing blob of the generation (nothing to stage), or a name to stage under (a new
    // one; or the existing row's name when its file is missing, which this capture then repairs).
    static bool prepare(Capture& c, const VaultRef& vault, const GenerationMeta& meta) {
        c.vault_ = {.id = vault.id, .alias = trimmedAlias(vault.alias)};
        c.meta_ = meta;
        static_cast<void>(vaultDir(c.vault_));   // validates the alias before anything touches disk
        if (!meta.encryption_iv.empty()) {
            if (const auto existing = BlobQuery::findByGeneration(vault.id, meta.encryption_iv, meta.key_version)) {
                c.storageName_ = existing->storage_name;
                std::error_code ec;
                if (sfs::is_regular_file(blobPath(c.vault_, existing->storage_name), ec)) {
                    c.method_ = CaptureMethod::Existing;
                    c.cipherBytes_ = existing->cipher_bytes;
                    return false;
                }
                log::Registry::storage()->warn("[RecoveryStore] Blob {} of vault {} is missing; recapturing it",
                                               existing->id, vault.id);
                return true;
            }
        }
        c.storageName_ = newStorageName();
        return true;
    }

    static Capture fromPath(const VaultRef& vault, const sfs::path& source, const GenerationMeta& meta,
                            const bool allowLink, const bool unlinkOrigin) {
        requireRegularFile(source);
        Capture c;
        if (unlinkOrigin) c.unlinkOriginOnCommit_ = source;
        if (!prepare(c, vault, meta)) return c;

        const auto target = blobPath(c.vault_, c.storageName_);
        const auto dir = target.parent_path();
        ensurePrivateDir(dir);

        if (allowLink && ::link(source.c_str(), target.c_str()) == 0) {
            c.method_ = CaptureMethod::Link;
        } else {
            if (allowLink && errno == EEXIST) {
                // Repaired concurrently by another capture of the same generation.
                c.method_ = CaptureMethod::Existing;
                c.cipherBytes_ = storeFileSize(target);
                return c;
            }
            const auto temp = dir / (std::string(kTempPrefix) + c.storageName_);
            unlinkQuiet(temp);
            try {
                if (platform::clone::cloneFile(source.c_str(), temp.c_str()) == 0) {
                    c.method_ = CaptureMethod::Reflink;
                } else {
                    sfs::copy_file(source, temp, sfs::copy_options::none);
                    sfs::permissions(temp, sfs::perms::owner_read | sfs::perms::owner_write, sfs::perm_options::replace);
                    c.method_ = CaptureMethod::Copy;
                }
                fs::ops::fsyncFile(temp);
                sfs::rename(temp, target);
            } catch (...) {
                unlinkQuiet(temp);
                throw;
            }
        }
        c.ownsFile_ = true;
        try {
            if (c.method_ == CaptureMethod::Link) fs::ops::fsyncFile(target);
            fs::ops::fsyncDirectory(dir);
            c.cipherBytes_ = storeFileSize(target);
        } catch (...) {
            c.abort();
            throw;
        }
        return c;
    }

    static Capture fromStream(const VaultRef& vault, const GenerationMeta& meta, const std::function<void(int)>& write) {
        Capture c;
        if (!prepare(c, vault, meta)) return c;
        const auto target = blobPath(c.vault_, c.storageName_);
        const auto dir = target.parent_path();
        ensurePrivateDir(dir);
        const auto temp = dir / (std::string(kTempPrefix) + c.storageName_);
        unlinkQuiet(temp);

        int fd = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) throw std::system_error(errno, std::generic_category(), "staging recovery blob " + temp.string());
        try {
            write(fd);
            if (::fsync(fd) != 0) throw std::system_error(errno, std::generic_category(), "fsync " + temp.string());
            const int closed = ::close(fd);
            fd = -1;
            if (closed != 0) throw std::system_error(errno, std::generic_category(), "close " + temp.string());
        } catch (...) {
            if (fd >= 0) ::close(fd);
            unlinkQuiet(temp);
            throw;
        }
        try {
            sfs::rename(temp, target);
        } catch (...) {
            unlinkQuiet(temp);
            throw;
        }
        c.method_ = CaptureMethod::Stream;
        c.ownsFile_ = true;
        try {
            fs::ops::fsyncDirectory(dir);
            c.cipherBytes_ = storeFileSize(target);
        } catch (...) {
            c.abort();
            throw;
        }
        return c;
    }
};

Capture::Capture(Capture&& other) noexcept
    : vault_(std::move(other.vault_)), meta_(std::move(other.meta_)), method_(other.method_),
      storageName_(std::move(other.storageName_)), cipherBytes_(other.cipherBytes_),
      unlinkOriginOnCommit_(std::move(other.unlinkOriginOnCommit_)), blobId_(other.blobId_), ownsFile_(other.ownsFile_),
      redundant_(other.redundant_), done_(other.done_) {
    other.done_ = true;
    other.ownsFile_ = false;
    other.unlinkOriginOnCommit_.reset();
}

Capture::~Capture() { abort(); }

sfs::path Capture::path() const { return blobPath(vault_, storageName_); }

int64_t Capture::attach(pqxx::work& txn) {
    if (blobId_) return *blobId_;
    if (done_) throw std::logic_error("recovery capture already finished");
    if (method_ == CaptureMethod::Existing) {
        const auto row = BlobQuery::findByGeneration(txn, vault_.id, meta_.encryption_iv, meta_.key_version);
        if (!row) throw std::runtime_error("the recovery blob of this generation was removed meanwhile; retry the capture");
        blobId_ = row->id;
        return *blobId_;
    }
    const auto inserted = BlobQuery::insert(txn, {.id = 0,
                                                  .vault_id = vault_.id,
                                                  .storage_name = storageName_,
                                                  .encryption_iv = meta_.encryption_iv,
                                                  .key_version = meta_.key_version,
                                                  .cipher_bytes = cipherBytes_,
                                                  .plaintext_bytes = meta_.plaintext_bytes,
                                                  .content_hash = meta_.content_hash,
                                                  .created_at = 0});
    blobId_ = inserted.id;
    if (!inserted.inserted && inserted.storage_name != storageName_) redundant_ = true;
    return *blobId_;
}

void Capture::committed() noexcept {
    if (done_) return;
    if (!blobId_) {
        log::Registry::storage()->warn("[RecoveryStore] Capture {} committed without attach(); discarding it", storageName_);
        abort();
        return;
    }
    done_ = true;
    try {
        if (redundant_ && ownsFile_) {
            const auto p = path();
            unlinkQuiet(p);
            fsyncDirQuiet(p.parent_path());
        }
        if (unlinkOriginOnCommit_) {
            unlinkQuiet(*unlinkOriginOnCommit_);
            fsyncDirQuiet(unlinkOriginOnCommit_->parent_path());
        }
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[RecoveryStore] Capture cleanup after commit failed: {}", e.what());
    }
    invalidateUsage(vault_.id);
}

void Capture::abort() noexcept {
    if (done_) return;
    done_ = true;
    if (!ownsFile_) return;
    try {
        const auto p = path();
        unlinkQuiet(p);
        fsyncDirQuiet(p.parent_path());
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[RecoveryStore] Capture abort failed: {}", e.what());
    }
}

Capture captureLink(const VaultRef& vault, const sfs::path& backing, const GenerationMeta& meta) {
    return detail::Stager::fromPath(vault, backing, meta, true, false);
}

Capture captureMove(const VaultRef& vault, const sfs::path& backing, const GenerationMeta& meta) {
    return detail::Stager::fromPath(vault, backing, meta, true, true);
}

Capture captureCopy(const VaultRef& vault, const sfs::path& source, const GenerationMeta& meta) {
    return detail::Stager::fromPath(vault, source, meta, false, false);
}

Capture captureStream(const VaultRef& vault, const GenerationMeta& meta, const std::function<void(int fd)>& write) {
    return detail::Stager::fromStream(vault, meta, write);
}

// ---- reading and removal -------------------------------------------------------------------------------------------

std::optional<BlobHandle> open(const VaultRef& vault, const int64_t blobId) {
    auto row = BlobQuery::get(blobId);
    if (!row || row->vault_id != vault.id) return std::nullopt;
    BlobHandle h{.row = std::move(*row), .path = {}, .present = false};
    h.path = blobPath(vault, h.row.storage_name);
    std::error_code ec;
    h.present = sfs::is_regular_file(h.path, ec);
    return h;
}

bool removeBlob(const VaultRef& vault, const int64_t blobId) {
    const auto row = BlobQuery::get(blobId);
    if (!row || row->vault_id != vault.id) return false;
    const auto removed = BlobQuery::deleteIfUnreferenced(blobId);
    if (!removed) return false;
    const auto p = blobPath(vault, removed->storage_name);
    unlinkQuiet(p);
    fsyncDirQuiet(p.parent_path());
    invalidateUsage(vault.id);
    return true;
}

uint64_t removeBlobs(const VaultRef& vault, const std::vector<int64_t>& blobIds) noexcept {
    uint64_t removed = 0;
    for (const auto id : blobIds) {
        try {
            if (removeBlob(vault, id)) ++removed;
        } catch (const std::exception& e) {
            log::Registry::storage()->warn("[RecoveryStore] Could not remove blob {} of vault {}: {}", id, vault.id,
                                           e.what());
        }
    }
    return removed;
}

// ---- accounting ----------------------------------------------------------------------------------------------------

uint64_t physicalBytes(const uint32_t vaultId, const std::chrono::milliseconds maxAge) {
    const auto now = std::chrono::steady_clock::now();
    {
        std::scoped_lock lock(usageMutex);
        if (const auto it = usageCache.find(vaultId); it != usageCache.end() && now - it->second.second < maxAge)
            return it->second.first;
    }
    const auto bytes = BlobQuery::physicalBytes(vaultId);
    std::scoped_lock lock(usageMutex);
    usageCache[vaultId] = {bytes, now};
    return bytes;
}

uint64_t chargedBytes(const uint32_t vaultId, const std::chrono::milliseconds maxAge) {
    const auto now = std::chrono::steady_clock::now();
    {
        std::scoped_lock lock(usageMutex);
        if (const auto it = chargedCache.find(vaultId); it != chargedCache.end() && now - it->second.second < maxAge)
            return it->second.first;
    }
    const auto bytes = BlobQuery::chargedBytes(vaultId);
    std::scoped_lock lock(usageMutex);
    chargedCache[vaultId] = {bytes, now};
    return bytes;
}

void invalidateUsage(const uint32_t vaultId) noexcept {
    std::scoped_lock lock(usageMutex);
    usageCache.erase(vaultId);
    chargedCache.erase(vaultId);
}

// ---- maintenance ---------------------------------------------------------------------------------------------------

SweepReport sweep(const VaultRef& vault, const std::chrono::seconds minAge) {
    SweepReport report;
    const auto dir = vaultDir(vault);
    const auto now = std::time(nullptr);
    const auto oldEnough = [&](const sfs::path& p) {
        const auto t = changeTime(p);
        return t && now - *t >= minAge.count();
    };

    // 1. Files: staging leftovers, and blob files without a row.
    std::error_code ec;
    if (sfs::is_directory(dir, ec)) {
        struct Candidate {
            sfs::path path;
            std::string name;
        };
        std::vector<Candidate> candidates;
        for (sfs::directory_iterator shard(dir, ec), end; !ec && shard != end; shard.increment(ec)) {
            std::error_code entryEc;
            if (!shard->is_directory(entryEc) || shard->is_symlink(entryEc)) continue;
            for (sfs::directory_iterator it(shard->path(), entryEc), stop; !entryEc && it != stop; it.increment(entryEc)) {
                const auto name = it->path().filename().string();
                if (!it->is_regular_file(entryEc) || it->is_symlink(entryEc)) continue;
                if (name.starts_with(kTempPrefix)) {
                    if (oldEnough(it->path())) {
                        unlinkQuiet(it->path());
                        ++report.temp_removed;
                    }
                } else if (validStorageName(name) && shard->path().filename() == name.substr(0, 2) &&
                           oldEnough(it->path())) {
                    candidates.push_back({it->path(), name});
                }
            }
            if (entryEc) report.errors.push_back("listing " + shard->path().string() + ": " + entryEc.message());
        }
        if (ec) report.errors.push_back("listing " + dir.string() + ": " + ec.message());

        constexpr std::size_t kBatch = 500;
        for (std::size_t i = 0; i < candidates.size(); i += kBatch) {
            std::vector<std::string> names;
            const auto last = std::min(candidates.size(), i + kBatch);
            for (auto k = i; k < last; ++k) names.push_back(candidates[k].name);
            const auto existing = BlobQuery::existingStorageNames(vault.id, names);
            for (auto k = i; k < last; ++k) {
                if (std::ranges::find(existing, candidates[k].name) != existing.end()) continue;
                std::error_code sizeEc;
                const auto size = sfs::file_size(candidates[k].path, sizeEc);
                unlinkQuiet(candidates[k].path);
                ++report.orphans_removed;
                if (!sizeEc) report.orphan_bytes += size;
            }
        }
    }

    // 2. Rows nothing references (a crash between a snapshot/version removal and the store's cleanup).
    for (const auto& row : BlobQuery::listUnreferenced(vault.id, minAge.count(), 1000)) {
        try {
            if (removeBlob(vault, row.id)) ++report.unreferenced_removed;
        } catch (const std::exception& e) {
            report.errors.push_back("blob " + std::to_string(row.id) + ": " + e.what());
        }
    }

    // 3. Rows whose file is missing: reported, never deleted.
    int64_t after = 0;
    for (;;) {
        const auto page = BlobQuery::listByVault(vault.id, after, 1000);
        if (page.empty()) break;
        for (const auto& row : page) {
            std::error_code existsEc;
            if (!sfs::is_regular_file(blobPath(vault, row.storage_name), existsEc)) report.missing.push_back(row.id);
        }
        after = page.back().id;
    }

    if (report.temp_removed || report.orphans_removed || report.unreferenced_removed) invalidateUsage(vault.id);
    if (!report.missing.empty())
        log::Registry::storage()->warn("[RecoveryStore] Vault {}: {} recovery blob(s) missing on disk", vault.id,
                                       report.missing.size());
    return report;
}

bool removeVaultStore(const std::string& alias) { return vault::retention::removeVaultDirectory(root(), alias); }

}
