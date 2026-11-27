#include "mirror/copy/Copy.hpp"

#include "audit/Trail.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/mirror/Detach.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/PlaintextSource.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Symlink.hpp"
#include "fuse/resolver/Resolved.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "mirror/access/Access.hpp"
#include "ops/Error.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "vault/Content.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <paths.h>

#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <map>
#include <set>
#include <span>
#include <system_error>
#include <utility>

namespace vh::mirror::copy {

namespace mirror_copy_detail {

namespace mq = vh::db::query::mirror;

constexpr uint64_t kSpaceMarginFloor = 64ull * 1024 * 1024;
constexpr auto kProgressEvery = std::chrono::milliseconds(500);
constexpr int kReadAttempts = 3;

// The copy was cancelled, or the daemon is stopping (it stays running then, and starts over).
struct Cancelled {};
struct Stopped {};

std::mutex cancelMutex;
std::set<uint64_t> cancelled;   // cancels asked for in this process (the row says so too)

bool cancelAsked(const uint64_t id) {
    std::scoped_lock lock(cancelMutex);
    return cancelled.contains(id);
}

void forgetCancel(const uint64_t id) {
    std::scoped_lock lock(cancelMutex);
    cancelled.erase(id);
}

std::string defaultName(const std::string& source, const uint32_t ownerId) {
    for (unsigned n = 1; n <= 99; ++n) {
        auto name = n == 1 ? source + " copy" : fmt::format("{} copy {}", source, n);
        if (name.size() > 255) name = name.substr(name.size() - 255);
        if (!vh::db::query::vault::Vault::vaultExists(name, ownerId) && !mq::MirrorCopies::nameReserved(name, ownerId))
            return name;
    }
    throw ops::Conflict("choose a name for the copy (--name): every default name is taken");
}

void requireHeld(const uint32_t vaultId) {
    const auto row = mq::MirrorVaults::get(vaultId);
    if (!row || (row->role != "mirror" && row->role != "orphaned"))
        throw ops::Refused("mirror_not_held", "vault " + std::to_string(vaultId) +
                                                  " is not held here as another server's copy: there is nothing to "
                                                  "copy from (a vault of this server's own is copied with vh fs copy)");
}

// A partial vault goes, with everything in it, and the gate on it.
void removeTarget(const uint32_t vaultId) {
    try {
        if (const auto& manager = runtime::Deps::get().storageManager) manager->removeVault(vaultId);
    } catch (const std::exception& e) {
        log::Registry::storage()->error("[mirror::copy] The partial copy (vault {}) could not be removed: {}", vaultId,
                                        e.what());
    }
    vh::mirror::access::endCopyTarget(vaultId);
}

struct Progress {
    uint64_t id{};
    uint64_t entries{}, bytes{}, fileBytes{};
    std::vector<mq::CopySkipped> skipped;
    std::chrono::steady_clock::time_point last{};
    const std::function<bool()>* stop{};

    void check() const {
        if (cancelAsked(id)) throw Cancelled{};
        if (*stop && (*stop)()) throw Stopped{};
    }
    void flush(const bool force = false) {
        const auto now = std::chrono::steady_clock::now();
        if (!force && now - last < kProgressEvery) return;
        last = now;
        mq::MirrorCopies::progress(id, entries, bytes + fileBytes, skipped);
    }
};

// What became of one file.
enum class FileOutcome { Copied, ContentsMissing, Removed, Unreadable };

struct Written {
    FileOutcome outcome{FileOutcome::Copied};
    std::optional<uint32_t> newId{};
};

bool missingBytes(const std::exception& e) {
    if (dynamic_cast<const storage::ContentUnavailable*>(&e)) return true;
    if (const auto* se = dynamic_cast<const std::system_error*>(&e))
        return se->code() == std::errc::no_such_file_or_directory;
    if (const auto* fe = dynamic_cast<const std::filesystem::filesystem_error*>(&e))
        return fe->code() == std::errc::no_such_file_or_directory;
    return false;
}

// One file: decrypted from the held vault as it is read and written through the new vault's ordinary write path.
Written copyFile(const std::shared_ptr<storage::Engine>& from, const std::shared_ptr<storage::Engine>& to,
                 const std::shared_ptr<identities::User>& owner, const mq::CopyEntry& e, Progress& progress) {
    for (int attempt = 1;; ++attempt) {
        const auto file = vh::db::query::fs::File::getFileById(e.id);
        if (!file || !file->vault_id || static_cast<uint32_t>(*file->vault_id) != from->vault->id)
            return {.outcome = FileOutcome::Removed};
        std::shared_ptr<storage::PlaintextReader> reader;
        try {
            reader = from->openPlaintextReader(file, {.integrity = storage::IntegrityPolicy::Optimistic,
                                                      .remote = storage::RemoteFetchPolicy::Off});
        } catch (const storage::IntegrityError&) {
            if (attempt < kReadAttempts) continue;
            return {.outcome = FileOutcome::Unreadable};
        } catch (const std::exception& ex) {
            if (missingBytes(ex)) return {.outcome = FileOutcome::ContentsMissing};
            throw;
        }
        const uint64_t size = reader->size();
        bool integrity = false, missing = false;
        fs::PlaintextSource source{
            .size = size,
            .read = [&](const uint64_t offset, const std::span<uint8_t> out) -> std::size_t {
                progress.check();
                std::size_t n = 0;
                try {
                    n = reader->read(offset, out);
                    if (offset + n >= size) reader->requireAuthenticated();
                } catch (const storage::IntegrityError&) {
                    integrity = true;
                    throw;
                } catch (const std::exception& ex) {
                    missing = missingBytes(ex);
                    throw;
                }
                progress.fileBytes = std::max<uint64_t>(progress.fileBytes, offset + n);
                progress.flush();
                return n;
            }};
        try {
            const auto made = fs::Filesystem::createFile({.path = e.path, .fuse_path = to->vaultPathToFusePath(e.path),
                                                          .source = source, .engine = to, .user = owner,
                                                          .mode = static_cast<mode_t>(e.mode & 07777u)});
            progress.check();
            if (!made) throw std::runtime_error("the new vault did not take " + e.path);
            return {.outcome = FileOutcome::Copied, .newId = made->id};
        } catch (const Cancelled&) {
            throw;
        } catch (const Stopped&) {
            throw;
        } catch (const std::exception&) {
            progress.check();
            progress.fileBytes = 0;
            if (missing) return {.outcome = FileOutcome::ContentsMissing};
            if (!integrity) throw;
            // The held vault's applier may have replaced the file under the read (a new generation): read it again.
            if (attempt < kReadAttempts) continue;
            return {.outcome = FileOutcome::Unreadable};
        }
    }
}

uint32_t entryIdAt(const std::shared_ptr<storage::Engine>& to, const std::string& path) {
    const auto entry = runtime::Deps::get().fsCache->getEntry(to->vaultPathToFusePath(path));
    if (!entry) throw std::runtime_error("the new vault has no entry at " + path + " after writing it");
    return entry->id;
}

uint32_t makeSymlink(const std::shared_ptr<storage::Engine>& to, const std::shared_ptr<identities::User>& owner,
                     const mq::CopyEntry& e) {
    const auto fusePath = to->vaultPathToFusePath(e.path);
    fuse::resolver::Resolved r;
    r.user = owner;
    r.engine = to;
    r.path = fusePath;
    r.parentEntry = runtime::Deps::get().fsCache->getEntry(fusePath.parent_path());
    const auto [err, link] = fs::Filesystem::createSymlink({.resolved = r, .target = e.target.value_or("")});
    if (err || !link) throw std::runtime_error(fmt::format("the symlink {} could not be made ({})", e.path, -err));
    return link->id;
}

void auditEnd(const Job& job, const std::string& state, const std::optional<uint32_t> newVault) {
    const auto action = "mirror.detach.copy." + state;
    audit::record({.action = action, .outcome = state == "finished" ? audit::Outcome::Success : audit::Outcome::Failure,
                   .actor_id = job.requested_by, .vault_id = newVault ? newVault : job.source_vault_id,
                   .details = {{"copy", job.id},
                               {"source", job.source_vault_id ? json(*job.source_vault_id) : json(nullptr)},
                               {"vault", newVault ? json(*newVault) : json(nullptr)},
                               {"owner", job.owner_id},
                               {"entries", job.entries_done},
                               {"bytes", job.bytes_done},
                               {"skipped", job.skipped.size()},
                               {"attempts", job.attempts}}},
                  fmt::format("[mirror] The copy {} of held vault {} {}{}", job.id,
                              job.source_vault_id ? std::to_string(*job.source_vault_id) : std::string("(removed)"),
                              state == "finished" ? "finished: vault " + std::to_string(newVault.value_or(0))
                                                  : state == "cancelled" ? std::string("was cancelled; its partial vault "
                                                                                       "was removed")
                                                                         : std::string("failed; its partial vault was "
                                                                                       "removed"),
                              job.error && state == "failed" ? ": " + *job.error : std::string()),
                  state == "finished" ? spdlog::level::info : spdlog::level::warn);
}

Job ended(const uint64_t id, const std::string& state, const std::optional<std::string>& error) {
    (void)mq::MirrorCopies::finish(id, state, error);
    forgetCancel(id);
    auto job = mq::MirrorCopies::get(id).value_or(Job{});
    auditEnd(job, state, state == "finished" ? job.vault_id : std::nullopt);
    return job;
}

}

Plan plan(const uint32_t sourceVaultId) {
    using namespace mirror_copy_detail;
    requireHeld(sourceVaultId);
    const auto vault = vh::db::query::vault::Vault::getVault(sourceVaultId);
    if (!vault) throw ops::NotFound("no vault with ID " + std::to_string(sourceVaultId));
    Plan p;
    p.source_vault_id = sourceVaultId;
    p.source_name = vault->name;
    p.quota = vault->quota;
    std::map<uint32_t, mq::MissingFile> missing;
    for (auto& m : mq::MirrorDetach::missing(sourceVaultId)) missing.emplace(m.file_id, std::move(m));
    for (auto& e : mq::MirrorCopies::entries(sourceVaultId)) {
        // An upload's staging file is this server's scratch, never content (fs::isUploadStagingName).
        if (fs::isUploadStagingName(std::filesystem::path(e.path).filename().string())) continue;
        if (e.kind == "file") {
            if (const auto m = missing.find(e.id); m != missing.end()) {
                p.skipped.push_back({.path = e.path, .size_bytes = e.size_bytes, .reason = "contents_missing"});
                continue;
            }
            ++p.files;
            p.bytes += e.size_bytes;
            p.sealed_bytes += e.size_bytes ? vault::content::newSealedSize(e.size_bytes) : 0;
        }
        p.entries.push_back(std::move(e));
    }
    return p;
}

Job start(const Request& request, const std::optional<uint32_t> actorId, const std::string& actorName) {
    using namespace mirror_copy_detail;
    auto p = plan(request.source_vault_id);
    if (request.name && (request.name->empty() || request.name->size() > 255))
        throw ops::Invalid("the copy's name must be 1 to 255 characters");
    const auto name = request.name ? *request.name : defaultName(p.source_name, request.owner_id);
    if (vh::db::query::vault::Vault::vaultExists(name, request.owner_id))
        throw ops::Conflict("a vault named '" + name + "' already exists for this owner: choose another name (--name)");

    // A second copy needs room for itself: the volume's free space with a margin, and the quota it takes.
    std::error_code ec;
    const auto space = std::filesystem::space(vh::paths::getBackingPath(), ec);
    const auto need = p.sealed_bytes + std::max<uint64_t>(kSpaceMarginFloor, p.sealed_bytes / 10);
    if (!ec && space.available < need)
        throw ops::Refused("mirror_copy_no_space",
                           fmt::format("the copy needs about {} bytes (its {} sealed bytes and a margin) and the volume "
                                       "this server keeps vaults on has {} free", need, p.sealed_bytes, space.available));
    if (p.quota > 0 && p.sealed_bytes + storage::Engine::MIN_FREE_SPACE > p.quota)
        throw ops::Refused("mirror_copy_no_space",
                           fmt::format("the copy takes the held vault's quota ({} bytes), which can't hold its {} "
                                       "sealed bytes and the reserve", p.quota, p.sealed_bytes));

    const uint64_t entries = p.entries.empty() ? 0 : p.entries.size() - 1;   // the root is the new vault's own
    auto job = mq::MirrorCopies::insert({.source_vault_id = request.source_vault_id, .name = name,
                                         .owner_id = request.owner_id, .requested_by = actorId,
                                         .entries_total = entries, .bytes_total = p.bytes, .skipped = p.skipped});
    audit::record({.action = "mirror.detach.copy", .actor_id = actorId, .actor = actorName,
                   .vault_id = request.source_vault_id,
                   .details = {{"copy", job.id}, {"owner", request.owner_id}, {"entries", entries},
                               {"bytes", p.bytes}, {"skipped", p.skipped.size()}}},
                  fmt::format("[mirror] {} started a copy of held vault {} as a new vault for account {} ({} entries, "
                              "{} bytes; {} file(s) left out)",
                              actorName.empty() ? std::string("this server") : actorName, request.source_vault_id,
                              request.owner_id, entries, p.bytes, p.skipped.size()));
    Service::instance()->wake();
    return job;
}

std::optional<Job> latest(const uint32_t sourceVaultId) { return mirror_copy_detail::mq::MirrorCopies::latestFor(sourceVaultId); }

Job cancel(const uint32_t sourceVaultId, const std::optional<uint32_t> actorId, const std::string& actorName) {
    using namespace mirror_copy_detail;
    const auto job = mq::MirrorCopies::latestFor(sourceVaultId);
    if (!job || job->state != "running" || !mq::MirrorCopies::requestCancel(job->id, actorId))
        throw ops::Refused("mirror_copy_not_running",
                           "no copy of vault " + std::to_string(sourceVaultId) + " is being written");
    {
        std::scoped_lock lock(cancelMutex);
        cancelled.insert(job->id);
    }
    audit::record({.action = "mirror.detach.copy.cancel", .actor_id = actorId, .actor = actorName,
                   .vault_id = sourceVaultId, .details = {{"copy", job->id}}},
                  fmt::format("[mirror] {} cancelled the copy {} of held vault {}",
                              actorName.empty() ? std::string("this server") : actorName, job->id, sourceVaultId));
    Service::instance()->wake();
    return mq::MirrorCopies::get(job->id).value_or(*job);
}

Job run(const uint64_t jobId, const std::function<bool()>& stop) {
    using namespace mirror_copy_detail;
    auto job = mq::MirrorCopies::get(jobId);
    if (!job) throw ops::NotFound("no copy " + std::to_string(jobId));
    if (job->state != "running") return *job;
    // An earlier attempt's partial vault (a daemon restart, a stop): removed, and the copy starts over.
    if (job->vault_id) removeTarget(*job->vault_id);
    if (job->cancel_requested || cancelAsked(jobId)) return ended(jobId, "cancelled", std::nullopt);
    if (!job->source_vault_id) return ended(jobId, "failed", "the vault being copied was removed");

    const auto& manager = runtime::Deps::get().storageManager;
    std::optional<uint32_t> target;
    try {
        const auto p = plan(*job->source_vault_id);
        const uint64_t entries = p.entries.empty() ? 0 : p.entries.size() - 1;
        if (!mq::MirrorCopies::begin(jobId, entries, p.bytes, p.skipped)) return *mq::MirrorCopies::get(jobId);
        const auto from = manager ? manager->getEngine(*job->source_vault_id) : nullptr;
        if (!from) throw std::runtime_error("the vault being copied is not loaded here");
        const auto owner = vh::identities::manager().user(job->owner_id);
        if (!owner) throw std::runtime_error("the new owner's account is gone");
        const auto source = vh::db::query::vault::Vault::getVault(*job->source_vault_id);
        if (!source) throw std::runtime_error("the vault being copied was removed");

        // The normal vault creation: a new uid and its own new key; the owner's ordinary access.
        auto fresh = std::make_shared<vault::model::Vault>();
        fresh->type = vault::model::VaultType::Local;
        fresh->name = job->name;
        fresh->owner_id = job->owner_id;
        fresh->description = source->description;
        fresh->quota = source->quota;
        const auto made = manager->addVault(fresh, std::make_shared<sync::model::LocalPolicy>());
        target = made->id;
        vh::mirror::access::beginCopyTarget(*target);
        (void)mq::MirrorCopies::setTarget(jobId, *target);
        const auto to = manager->getEngine(*target);
        if (!to) throw std::runtime_error("the new vault's engine did not start");

        const vh::mirror::access::CopyWriter writer(*target);
        Progress progress{.id = jobId, .skipped = p.skipped, .stop = &stop};
        std::vector<std::pair<uint32_t, uint32_t>> attributes;
        if (const auto root = vh::db::query::fs::Entry::getFSEntryByPath(*target, "/"); root && !p.entries.empty() &&
                                                                                     p.entries.front().path == "/")
            attributes.emplace_back(p.entries.front().id, root->id);

        // Folders first (a folder precedes what it holds), then files and symlinks.
        for (const auto& e : p.entries) {
            if (e.kind != "directory" || e.path == "/") continue;
            progress.check();
            if (const auto rc = fs::Filesystem::mkdir({.path = to->vaultPathToFusePath(e.path),
                                                       .mode = static_cast<mode_t>(e.mode & 07777u), .engine = to,
                                                       .user = owner});
                rc != 0)
                throw std::runtime_error(fmt::format("the folder {} could not be made ({})", e.path, -rc));
            attributes.emplace_back(e.id, entryIdAt(to, e.path));
            ++progress.entries;
            progress.flush();
        }
        for (const auto& e : p.entries) {
            if (e.kind == "directory") continue;
            progress.check();
            if (e.kind == "symlink") {
                attributes.emplace_back(e.id, makeSymlink(to, owner, e));
            } else {
                const auto w = copyFile(from, to, owner, e, progress);
                if (w.outcome == FileOutcome::Copied) {
                    attributes.emplace_back(e.id, *w.newId);
                    progress.bytes += e.size_bytes;
                } else {
                    progress.skipped.push_back(
                        {.path = e.path, .size_bytes = e.size_bytes,
                         .reason = w.outcome == FileOutcome::Removed       ? "removed"
                                   : w.outcome == FileOutcome::Unreadable ? "unreadable"
                                                                          : "contents_missing"});
                }
                progress.fileBytes = 0;
            }
            ++progress.entries;
            progress.flush();
        }

        // Names and places are written; now every entry's mode and modification time, exactly as the held vault has
        // them (folders last touched by what was written into them).
        progress.check();
        mq::MirrorCopies::copyAttributes(attributes, job->requested_by);
        const auto& cache = runtime::Deps::get().fsCache;
        for (const auto& [_, newId] : attributes)
            if (const auto fresher = vh::db::query::fs::Entry::getFSEntryById(newId)) cache->cacheEntry(fresher);
        progress.flush(true);
        auto done = ended(jobId, "finished", std::nullopt);
        vh::mirror::access::endCopyTarget(*target);
        (void)vh::mirror::access::reconcile();
        return done;
    } catch (const Stopped&) {
        // The daemon is stopping: the job stays running, its partial vault gated; the next start begins again.
        log::Registry::storage()->info("[mirror::copy] The copy {} stops with the daemon; it starts over when it is back",
                                       jobId);
        return mq::MirrorCopies::get(jobId).value_or(*job);
    } catch (const Cancelled&) {
        if (target) removeTarget(*target);
        return ended(jobId, "cancelled", std::nullopt);
    } catch (const std::exception& e) {
        if (target) removeTarget(*target);
        return ended(jobId, "failed", std::string(e.what()));
    }
}

json toJson(const Job& j) {
    const auto opt = [](const auto& v) { return v ? json(*v) : json(nullptr); };
    return {{"id", j.id},
            {"source_vault_id", opt(j.source_vault_id)},
            {"vault_id", opt(j.vault_id)},
            {"name", j.name},
            {"owner_id", j.owner_id},
            {"state", j.state},
            {"entries_total", j.entries_total},
            {"entries_done", j.entries_done},
            {"bytes_total", j.bytes_total},
            {"bytes_done", j.bytes_done},
            {"skipped_count", j.skipped.size()},
            {"skipped", vh::db::query::mirror::toJson(j.skipped)},
            {"error", opt(j.error)},
            {"requested_by", opt(j.requested_by)},
            {"cancel_requested", j.cancel_requested},
            {"attempts", j.attempts},
            {"created_at", static_cast<int64_t>(j.created_at)},
            {"updated_at", static_cast<int64_t>(j.updated_at)},
            {"finished_at", j.finished_at ? json(static_cast<int64_t>(*j.finished_at)) : json(nullptr)}};
}

// ---- the service

Service::Service() : AsyncService("MirrorCopies") {}

const std::shared_ptr<Service>& Service::instance() {
    static const auto service = std::make_shared<Service>();
    return service;
}

void Service::wake() {
    {
        std::scoped_lock lock(wakeMutex_);
        woken_ = true;
    }
    wakeCv_.notify_all();
}

void Service::onStop() { wake(); }

std::size_t Service::tick() {
    if (!vh::db::query::peer::Peers::anyRecorded()) return 0;  // nothing ever linked: no copy is held here
    std::size_t ran = 0;
    for (const auto& job : mirror_copy_detail::mq::MirrorCopies::running()) {
        if (shouldStop() && isRunning()) break;
        try {
            (void)run(job.id, [this] { return isRunning() && shouldStop(); });
        } catch (const std::exception& e) {
            log::Registry::storage()->error("[mirror::copy] The copy {} could not run: {}", job.id, e.what());
        }
        ++ran;
    }
    return ran;
}

void Service::runLoop() {
    while (!shouldStop()) {
        try {
            (void)tick();
        } catch (const std::exception& e) {
            log::Registry::storage()->warn("[mirror::copy] A pass failed: {}", e.what());
        }
        std::unique_lock lock(wakeMutex_);
        wakeCv_.wait_for(lock, kInterval, [this] { return woken_ || shouldStop(); });
        woken_ = false;
    }
}

void resetForTesting() {
    std::scoped_lock lock(mirror_copy_detail::cancelMutex);
    mirror_copy_detail::cancelled.clear();
}

}
