#include "recovery/local/Snapshots.hpp"

#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/recovery/Blob.hpp"
#include "db/query/recovery/Generation.hpp"
#include "db/query/recovery/Policy.hpp"
#include "db/query/recovery/Snapshot.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "recovery/Model.hpp"
#include "recovery/Store.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>

#include <sys/stat.h>

#include <algorithm>
#include <filesystem>
#include <iterator>
#include <optional>
#include <mutex>
#include <ranges>
#include <set>
#include <unordered_set>

namespace vh::recovery::local {

namespace {

namespace rq = db::query::recovery;

// The store directory of a vault by id: the live engine's vault, else its row (a vault being purged has neither, and
// its whole store goes with it).
std::optional<store::VaultRef> vaultRefFor(const uint32_t vaultId) {
    if (const auto& manager = runtime::Deps::get().storageManager)
        if (const auto engine = manager->getEngine(vaultId); engine && engine->vault) return store::vaultRef(*engine->vault);
    try {
        if (const auto v = db::query::vault::Vault::getVault(vaultId)) return store::vaultRef(*v);
    } catch (const std::exception& e) {
        log::Registry::storage()->debug("[recovery::local] vault {} not found for blob removal: {}", vaultId, e.what());
    }
    return std::nullopt;
}

}

void removeVersion(const int64_t generationId) {
    const auto row = rq::Generation::get(generationId);
    const auto id = RecoveryId{.type = RecoveryId::Type::LocalGeneration, .id = static_cast<uint64_t>(generationId)}.str();
    if (!row) throw ops::NotFound("no local version " + id);
    if (row->origin == rq::Origin::Snapshot)
        throw SnapshotMemberNotDeletable(
            id + " belongs to snapshot " +
            RecoveryId{.type = RecoveryId::Type::Snapshot, .id = static_cast<uint64_t>(row->snapshot_id.value_or(0))}.str() +
            ": delete the snapshot instead");
    if (row->upstream_state == rq::UpstreamState::Pending)
        throw VersionPendingUpstream(id + " has not reached the provider yet (upstream backlog): it can't be deleted "
                                          "until it is sent or skipped");
    const auto blob = rq::Generation::remove(generationId);
    if (blob && row->vault_id)
        if (const auto ref = vaultRefFor(*row->vault_id)) store::removeBlob(*ref, *blob);
}

}

namespace vh::recovery::local::snapshots {

namespace {

namespace rq = db::query::recovery;
namespace sfs = std::filesystem;
using EntryPtr = std::shared_ptr<fs::model::Entry>;

constexpr std::size_t kMemberBatch = 64;
constexpr unsigned int kReleasePage = 500;

bool isHttpUploadStaging(const std::string& name) {
    return name.starts_with(".upload-http-") && name.ends_with(".part");
}

std::size_t depthOfPath(const sfs::path& p) {
    return static_cast<std::size_t>(std::ranges::distance(p.begin(), p.end()));
}

// path is root or lies under it (vault paths).
bool atOrUnder(const sfs::path& path, const sfs::path& root) {
    if (root == "/" || path == root) return true;
    const auto rel = path.lexically_normal().lexically_relative(root.lexically_normal());
    return !rel.empty() && rel.native() != ".." && !rel.native().starts_with("../") && rel.native() != ".";
}

sfs::path normalizedVaultPath(const std::string& p) {
    if (p.empty() || p.front() != '/') throw ops::Invalid("a vault path starts with '/': '" + p + "'");
    // An absolute path normalizes without a leading "..": "/../x" is "/x".
    auto s = sfs::path(p).lexically_normal().string();
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

// Releases a snapshot's members (rows, then the blobs nothing references any more). The snapshot row stays.
void releaseMembers(const std::optional<store::VaultRef>& ref, const int64_t snapshotId) {
    std::vector<int64_t> blobs;
    for (;;) {
        const auto page = rq::Generation::listSnapshotMembers(snapshotId, "", kReleasePage);
        if (page.empty()) break;
        db::Transactions::exec("recovery::snapshots::release", [&](pqxx::work& txn) {
            for (const auto& member : page)
                if (const auto blob = rq::Generation::remove(txn, member.id)) blobs.push_back(*blob);
        });
    }
    if (ref) store::removeBlobs(*ref, blobs);
}

struct PendingMember {
    store::Capture capture;
    rq::NewGeneration generation;
};

}

Created create(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<identities::User>& actor,
               const std::string& vaultPath, const std::optional<std::string>& name, const Authorizer& authorize) {
    if (!engine || !engine->vault) throw std::invalid_argument("a snapshot needs the vault's storage engine");
    const auto vaultId = engine->vault->id;

    const auto policy = rq::Policy::get(vaultId);
    if (policy.mode != Mode::LocalSnapshots)
        throw ops::Invalid("snapshots need the vault's recovery mode to be local_snapshots (it is " +
                           to_string(policy.mode) + ")");
    if (name && (name->empty() || name->size() > 200)) throw ops::Invalid("a snapshot name has 1 to 200 characters");

    const auto rootPath = normalizedVaultPath(vaultPath);
    const auto& cache = runtime::Deps::get().fsCache;
    const auto root = cache->getEntry(engine->vaultPathToFusePath(rootPath));
    if (!root || (root->vault_id && static_cast<uint32_t>(*root->vault_id) != vaultId))
        throw ops::NotFound("no such path in the vault: " + rootPath.string());
    if (root->isSymlink()) throw ops::Invalid("a symlink can't be snapshotted (its target is a path, not content)");
    if (!root->isDirectory() && isHttpUploadStaging(root->name))
        throw ops::Invalid("an upload in progress can't be snapshotted: " + rootPath.string());
    const bool rootIsFile = !root->isDirectory();

    // 1. Plan from the database (the authority on what is under the root; the cache can lag).
    std::vector<EntryPtr> entries{root};
    std::vector<SkippedEntry> skipped;
    if (root->isDirectory()) {
        auto descendants = db::query::fs::Entry::listSubtree(root->id);
        std::erase_if(descendants, [&](const EntryPtr& e) {
            if (!e) return true;
            if (!e->isDirectory() && !e->isSymlink() && isHttpUploadStaging(e->name)) {
                skipped.push_back({.path = e->path.string(), .reason = "upload_staging"});
                return true;
            }
            return false;
        });
        std::ranges::stable_sort(descendants, {}, [](const EntryPtr& e) { return depthOfPath(e->path); });
        entries.insert(entries.end(), descendants.begin(), descendants.end());
    }

    // 2. Authorize every entry before anything is written.
    if (authorize)
        for (const auto& e : entries) authorize(*e);

    // 3. Quota: the physical bytes this snapshot adds (a generation already retained is free), plus the local copy a
    //    cloud file without one needs first.
    const auto cloud = engine->type() == storage::StorageType::Cloud
                           ? std::static_pointer_cast<storage::CloudEngine>(engine) : nullptr;
    //    The vault quota is charged only what the capture newly allocates: a link to a live backing file shares its
    //    inode (getVaultSize counts it once; it is charged when the file is replaced), so only a copy (the store on
    //    another filesystem) or a hydrate costs space now. The snapshot quota counts the snapshot's blob bytes.
    const auto storeDevice = [&]() -> std::optional<dev_t> {
        std::error_code ec;
        for (auto p = store::root(); !p.empty(); p = p.parent_path()) {
            struct stat st{};
            if (sfs::exists(p, ec) && ::stat(p.c_str(), &st) == 0) return st.st_dev;
            if (p == p.parent_path()) break;
        }
        return std::nullopt;
    }();
    uint64_t newBlobBytes = 0, hydrateBytes = 0, copyBytes = 0;
    for (const auto& e : entries) {
        if (e->isDirectory() || e->isSymlink()) continue;
        const auto f = db::query::fs::File::getFileById(e->id);
        if (!f) continue;
        if (!f->encryption_iv.empty() &&
            rq::Blob::findByGeneration(vaultId, f->encryption_iv, f->encrypted_with_key_version))
            continue;
        struct stat st{};
        if (::stat(f->backing_path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            newBlobBytes += static_cast<uint64_t>(st.st_size);
            if (!storeDevice || st.st_dev != *storeDevice) copyBytes += static_cast<uint64_t>(st.st_size);
        } else if (f->size_bytes > 0 && cloud) {
            newBlobBytes += f->size_bytes + crypto::util::AES_TAG_SIZE;
            hydrateBytes += f->size_bytes + crypto::util::AES_TAG_SIZE;   // the hydrated copy is linked, not copied
        }
    }
    if (policy.snapshot_quota_bytes) {
        const auto used = rq::Generation::usage(vaultId).snapshots.stored_bytes;
        const auto quota = *policy.snapshot_quota_bytes;
        if (used + newBlobBytes > quota)
            throw ops::Conflict("the snapshot needs " + std::to_string(newBlobBytes) +
                                " new bytes but the vault's snapshot quota (" + std::to_string(quota) + " bytes) has " +
                                std::to_string(quota > used ? quota - used : 0) + " left");
    }
    if (const auto required = copyBytes + hydrateBytes; required > 0) {
        if (const auto free = engine->freeSpace(); required > free)
            throw ops::Conflict("the snapshot needs " + std::to_string(required) + " bytes but the vault has " +
                                std::to_string(free) + " left in its quota");
    }

    // 4. The snapshot row; from here a failure marks it failed and releases what it captured.
    const auto snapshotId = rq::Snapshot::create({
        .vault_id = vaultId,
        .name = name,
        .root_path = rootPath.string(),
        .root_type = rootIsFile ? PointKind::File : PointKind::Directory,
        .root_entry_id = root->id,
        .created_by = actor ? std::optional<uint32_t>(actor->id) : std::nullopt,
        .created_by_name = actor ? std::optional<std::string>(actor->name()) : std::nullopt,
    });
    const auto ref = store::vaultRef(*engine->vault);

    Created out;
    out.snapshot_id = snapshotId;
    try {
        std::vector<PendingMember> pending;
        std::set<std::string> captured;   // vault paths of captured files
        const auto flush = [&] {
            if (pending.empty()) return;
            db::Transactions::exec("recovery::snapshots::members", [&](pqxx::work& txn) {
                for (auto& p : pending) {
                    p.generation.blob_id = p.capture.attach(txn);
                    static_cast<void>(rq::Generation::insertSnapshotMember(txn, p.generation));
                }
            });
            for (auto& p : pending) {
                if (!p.capture.reused()) out.new_bytes += p.capture.cipherBytes();
                p.capture.committed();
                ++out.file_count;
                out.plaintext_bytes += p.generation.size_bytes;
                captured.insert(p.generation.path);
            }
            pending.clear();
        };

        for (const auto& e : entries) {
            if (e->isDirectory()) continue;
            if (e->isSymlink()) {
                skipped.push_back({.path = e->path.string(), .reason = "symlink"});
                continue;
            }

            // A cloud file without a local copy is fetched first, through the metered, price-gated hydrate (outside
            // the content lock, as copy does); a refusal skips it.
            if (const auto f = db::query::fs::File::getFileById(e->id); f && f->size_bytes > 0) {
                std::error_code ec;
                if (!sfs::is_regular_file(f->backing_path, ec)) {
                    std::optional<SkippedEntry> refused;
                    if (!cloud) refused = SkippedEntry{.path = f->path.string(), .reason = "content_unavailable",
                                                       .detail = "no local copy"};
                    else {
                        try {
                            static_cast<void>(cloud->hydrate(f));
                        } catch (const storage::ContentUnavailable& ex) {
                            refused = SkippedEntry{.path = f->path.string(), .reason = "content_unavailable",
                                                   .detail = ex.what()};
                        } catch (const storage::IntegrityError& ex) {
                            refused = SkippedEntry{.path = f->path.string(), .reason = "integrity_error",
                                                   .detail = ex.what()};
                        } catch (const std::exception& ex) {
                            refused = SkippedEntry{.path = f->path.string(), .reason = "content_unavailable",
                                                   .detail = ex.what()};
                        }
                    }
                    if (refused) {
                        skipped.push_back(std::move(*refused));
                        continue;
                    }
                }
            }

            std::optional<PendingMember> member;
            {
                // The row and the bytes it describes, together: an overwrite, FUSE seal or rotation of this file
                // can't hand us the bytes of one generation and the IV of another.
                std::scoped_lock contentLock(fs::Filesystem::contentWriteMutex(e->id));
                const auto current = db::query::fs::File::getFileById(e->id);
                if (!current) {
                    skipped.push_back({.path = e->path.string(), .reason = "vanished"});
                    continue;
                }
                if (!rootIsFile && !atOrUnder(current->path, rootPath)) {
                    skipped.push_back({.path = e->path.string(), .reason = "moved", .detail = current->path.string()});
                    continue;
                }
                const store::GenerationMeta meta{.encryption_iv = current->encryption_iv,
                                                 .key_version = current->encrypted_with_key_version,
                                                 .plaintext_bytes = current->size_bytes,
                                                 .content_hash = current->content_hash};
                std::error_code ec;
                const bool local = sfs::is_regular_file(current->backing_path, ec);
                if (current->size_bytes > 0 && current->encryption_iv.empty()) {
                    skipped.push_back({.path = current->path.string(), .reason = "unsealed"});
                    continue;
                }
                if (!local && current->size_bytes > 0) {
                    skipped.push_back({.path = current->path.string(), .reason = "content_unavailable",
                                       .detail = "no local copy"});
                    continue;
                }
                auto capture = local ? store::captureLink(ref, current->backing_path, meta)
                                     : store::captureStream(ref, meta, [](int) {});
                const auto rel = rootIsFile ? current->path.filename()
                                            : current->path.lexically_relative(rootPath);
                member.emplace(PendingMember{
                    .capture = std::move(capture),
                    .generation = rq::NewGeneration{
                        .vault_id = vaultId,
                        .file_id = current->id,
                        .blob_id = std::nullopt,
                        .content_hash = current->content_hash,
                        .size_bytes = current->size_bytes,
                        .mime_type = current->mime_type,
                        .path = current->path.string(),
                        .mode = current->mode ? std::optional<uint32_t>(static_cast<uint32_t>(*current->mode))
                                              : std::nullopt,
                        .source_updated_at = current->updated_at,
                        .created_by = actor ? std::optional<uint32_t>(actor->id) : std::nullopt,
                        .snapshot_id = snapshotId,
                        .rel_path = rel.string(),
                        .reason = std::nullopt,
                        .upstream_state = rq::UpstreamState::None,
                        .upstream_key = std::nullopt,
                    }});
            }
            pending.push_back(std::move(*member));
            if (pending.size() >= kMemberBatch) flush();
        }
        flush();

        // Directories with no captured file under them: a restore recreates them.
        std::unordered_set<std::string> holding;
        for (const auto& path : captured)
            for (auto p = sfs::path(path).parent_path(); ; p = p.parent_path()) {
                if (!holding.insert(p.string()).second) break;
                if (p == p.parent_path()) break;
            }
        rq::SnapshotTotals totals;
        for (const auto& e : entries) {
            if (!e->isDirectory()) continue;
            ++totals.directory_count;
            if (!holding.contains(e->path.string())) totals.empty_directories.push_back(e->path.string());
        }
        totals.file_count = out.file_count;
        totals.plaintext_bytes = out.plaintext_bytes;
        auto skippedJson = nlohmann::json::array();
        for (const auto& s : skipped) {
            nlohmann::json item{{"path", s.path}, {"reason", s.reason}};
            if (s.detail) item["detail"] = *s.detail;
            skippedJson.push_back(std::move(item));
        }
        totals.skipped_json = skippedJson.dump();
        if (!rq::Snapshot::finish(snapshotId, totals))
            throw std::runtime_error("the snapshot was deleted while it was being taken");
        out.directory_count = totals.directory_count;
    } catch (const std::exception& ex) {
        log::Registry::storage()->error("[recovery::snapshots] snapshot {} of {} in vault {} failed: {}", snapshotId,
                                        rootPath.string(), vaultId, ex.what());
        try {
            static_cast<void>(rq::Snapshot::fail(snapshotId, ex.what()));
            releaseMembers(ref, snapshotId);
        } catch (const std::exception& undo) {
            log::Registry::storage()->error("[recovery::snapshots] could not release failed snapshot {}: {}", snapshotId,
                                            undo.what());
        }
        throw;
    }

    out.skipped = std::move(skipped);
    log::Registry::audit()->info("[recovery] {} took snapshot snap-{} of {} in vault {} ({} files, {} new bytes, {} skipped)",
                                 actor ? actor->name() : std::string("system"), snapshotId, rootPath.string(), vaultId,
                                 out.file_count, out.new_bytes, out.skipped.size());
    return out;
}

uint64_t cleanupInterrupted(const std::chrono::seconds minAge) noexcept {
    std::vector<rq::SnapshotRow> stale;
    try {
        stale = rq::Snapshot::listStaleCreating(minAge.count());
    } catch (const std::exception& e) {
        log::Registry::storage()->error("[recovery::snapshots] listing interrupted snapshots failed: {}", e.what());
        return 0;
    }
    uint64_t cleaned = 0;
    for (const auto& row : stale) {
        try {
            static_cast<void>(rq::Snapshot::fail(row.id, "interrupted: the daemon stopped while the snapshot was being taken"));
            releaseMembers(vaultRefFor(row.vault_id), row.id);
            ++cleaned;
            log::Registry::storage()->warn("[recovery::snapshots] snapshot snap-{} of {} (vault {}) was interrupted; "
                                           "marked failed and released", row.id, row.root_path, row.vault_id);
        } catch (const std::exception& e) {
            log::Registry::storage()->error("[recovery::snapshots] could not clean up interrupted snapshot {}: {}", row.id,
                                            e.what());
        }
    }
    return cleaned;
}

void remove(const int64_t snapshotId) {
    const auto row = rq::Snapshot::get(snapshotId);
    const auto id = RecoveryId{.type = RecoveryId::Type::Snapshot, .id = static_cast<uint64_t>(snapshotId)}.str();
    if (!row) throw ops::NotFound("no snapshot " + id);
    if (row->state == "creating") throw ops::Conflict(id + " is still being taken");
    static_cast<void>(rq::Snapshot::markDeleting(snapshotId));
    const auto blobs = rq::Snapshot::remove(snapshotId);
    if (const auto ref = vaultRefFor(row->vault_id)) store::removeBlobs(*ref, blobs);
}

}
