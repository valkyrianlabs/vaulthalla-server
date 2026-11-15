// Detaching a remote from a vault: see vault/RemoteDetach.hpp for the protocol (design/storage/attach-remote.md,
// "The reverse").

#include "vault/RemoteDetach.hpp"

#include <vl/keykit/kev1.hpp>
#include "audit/Trail.hpp"
#include "config/Registry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/RecoveryGrants.hpp"
#include "db/query/vault/RemoteAttach.hpp"
#include "db/query/vault/RemoteDetach.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/RemoteAccess.hpp"
#include "storage/s3/ManifestStore.hpp"
#include "sync/Controller.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <map>
#include <set>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>

namespace vh::vault::remote::detach {

// ---- names ------------------------------------------------------------------------------------------------------------

std::string_view to_string(const State state) {
    switch (state) {
    case State::Preparing: return "preparing";
    case State::Hydrating: return "hydrating";
    case State::Verifying: return "verifying";
    case State::Cutover: return "cutover";
    case State::Done: return "done";
    case State::Failed: return "failed";
    case State::Aborted: return "aborted";
    }
    return "failed";
}

State stateFromString(const std::string_view text) {
    for (const auto s : {State::Preparing, State::Hydrating, State::Verifying, State::Cutover, State::Done,
                         State::Failed, State::Aborted})
        if (to_string(s) == text) return s;
    throw std::invalid_argument("unknown remote detach state: " + std::string(text));
}

bool beforeCutover(const State state) {
    return state == State::Preparing || state == State::Hydrating || state == State::Verifying ||
           state == State::Failed;
}

bool running(const State state) {
    return state == State::Preparing || state == State::Hydrating || state == State::Verifying ||
           state == State::Cutover;
}

std::string_view to_string(const ItemKind kind) { return kind == ItemKind::Envelope ? "envelope" : "content"; }

ItemKind itemKindFromString(const std::string_view text) {
    if (text == "content") return ItemKind::Content;
    if (text == "envelope") return ItemKind::Envelope;
    throw std::invalid_argument("unknown remote detach item kind: " + std::string(text));
}

std::string_view to_string(const ItemState state) {
    switch (state) {
    case ItemState::Pending: return "pending";
    case ItemState::Verified: return "verified";
    case ItemState::Failed: return "failed";
    case ItemState::Lost: return "lost";
    }
    return "pending";
}

std::string_view to_string(const Mode mode) { return mode == Mode::InPlace ? "in_place" : "hydrate"; }

Mode modeFromString(const std::string_view text) {
    if (text == "hydrate") return Mode::Hydrate;
    if (text == "in_place") return Mode::InPlace;
    throw std::invalid_argument("unknown remote detach mode: " + std::string(text));
}

ItemState itemStateFromString(const std::string_view text) {
    for (const auto s : {ItemState::Pending, ItemState::Verified, ItemState::Failed, ItemState::Lost})
        if (to_string(s) == text) return s;
    throw std::invalid_argument("unknown remote detach item state: " + std::string(text));
}

nlohmann::json toJson(const Estimate& e) {
    return {{"files", e.files},
            {"bytes", e.bytes},
            {"files_remote_only", e.files_remote_only},
            {"bytes_remote_only", e.bytes_remote_only},
            {"envelopes", e.envelopes},
            {"envelopes_to_copy", e.envelopes_to_copy},
            {"history_in_bucket_only", e.history_in_bucket_only},
            {"trash_without_local_copy", e.trash_without_local_copy}};
}

Estimate estimateFromJson(const nlohmann::json& j) {
    Estimate e;
    const auto u = [&](const char* name) { return j.contains(name) ? j.at(name).get<uint64_t>() : uint64_t{0}; };
    e.files = u("files");
    e.bytes = u("bytes");
    e.files_remote_only = u("files_remote_only");
    e.bytes_remote_only = u("bytes_remote_only");
    e.envelopes = u("envelopes");
    e.envelopes_to_copy = u("envelopes_to_copy");
    e.history_in_bucket_only = u("history_in_bucket_only");
    e.trash_without_local_copy = u("trash_without_local_copy");
    return e;
}

namespace remote_detach_detail {

using Q = db::query::vault::RemoteDetach;
using AttachQ = db::query::vault::RemoteAttach;
namespace content = vault::content;
namespace kev1 = vl::keykit::kev1;

// A failure of the run before the cutover: the row goes to failed with this text, the vault stays an S3 vault.
struct DetachFailed : std::runtime_error {
    using std::runtime_error::runtime_error;
};
// The service is stopping, or an abort was requested: the run ends where it is and is picked up again.
struct DetachInterrupted : std::runtime_error {
    explicit DetachInterrupted(const bool abort) : std::runtime_error(abort ? "abort requested" : "stopped") {}
};

class DetachFd {
public:
    explicit DetachFd(const int fd) : fd_(fd) {}
    ~DetachFd() {
        if (fd_ >= 0) ::close(fd_);
    }
    DetachFd(const DetachFd&) = delete;
    DetachFd& operator=(const DetachFd&) = delete;
    [[nodiscard]] int get() const { return fd_; }

private:
    int fd_{-1};
};

struct Ctx {
    uint32_t vaultId{};
    Row row;
    std::shared_ptr<storage::CloudEngine> cloud;    // the vault's live engine until the cutover
    std::shared_ptr<EncryptionManager> em;
    const RunDeps* deps{};
    std::chrono::steady_clock::time_point lastAbortCheck{};

    void step(const std::string_view name) const {
        if (deps && deps->afterStep) deps->afterStep(name);
    }

    void checkpoint() {
        if (deps && deps->stop && deps->stop()) throw DetachInterrupted(false);
        const auto now = std::chrono::steady_clock::now();
        if (now - lastAbortCheck < std::chrono::seconds(2)) return;
        lastAbortCheck = now;
        if (const auto current = Q::get(vaultId); !current || current->abort_requested_at) throw DetachInterrupted(true);
    }

    [[nodiscard]] crypto::SecretKeyPtr keyOf(const unsigned int version) const {
        try {
            if (auto k = em->historicalKeySnapshot(version)) return k;
        } catch (const std::exception&) {
        }
        throw DetachFailed(fmt::format("key version {} is not held", version));
    }
};

bool hasContent(const fs::model::File& f) { return !f.encryption_iv.empty(); }

std::filesystem::path backingOf(const storage::Engine& engine, const fs::model::File& file) {
    if (file.backing_path.is_absolute() || !engine.paths) return file.backing_path;
    return engine.paths->absPath(file.backing_path, fs::model::PathType::BACKING_ROOT);
}

bool localCopyExists(const storage::Engine& engine, const fs::model::File& file) {
    std::error_code ec;
    return std::filesystem::exists(backingOf(engine, file), ec);
}

// Brings the content items in line with the vault's live files: an item per file with content; an item whose file's
// generation moved (or whose local copy went) is pending again; an item whose file is gone or emptied goes. Returns how
// many items need work.
uint64_t planItems(Ctx& ctx) {
    std::map<uint32_t, Item> current;
    for (auto& it : Q::items(ctx.vaultId))
        if (it.kind == ItemKind::Content && it.file_id) current.emplace(*it.file_id, std::move(it));

    uint64_t pending = 0;
    std::set<uint32_t> live;
    for (const auto& f : AttachQ::liveFiles(ctx.vaultId)) {
        if (!hasContent(*f)) continue;   // an empty file has no backing bytes
        if (!f->object_uid) throw DetachFailed(fmt::format("file {} has no object uid", f->id));
        live.insert(f->id);
        const auto it = current.find(f->id);
        if (it == current.end()) {
            Item fresh;
            fresh.vault_id = ctx.vaultId;
            fresh.kind = ItemKind::Content;
            fresh.file_id = f->id;
            fresh.size = content::sealedSizeOf(f->size_bytes, f->encryption_iv);
            (void)Q::insertItem(fresh);
            ++pending;
            continue;
        }
        auto& item = it->second;
        if (item.state == ItemState::Verified && item.generation == std::optional<std::string>(f->encryption_iv) &&
            localCopyExists(*ctx.cloud, *f))
            continue;   // held here at its current generation
        if (item.state != ItemState::Pending) {
            item.state = ItemState::Pending;
            item.error.reset();
            Q::updateItem(item);
        }
        ++pending;
    }
    for (const auto& [fileId, item] : current)
        if (!live.contains(fileId)) Q::deleteItem(item.id);
    return pending;
}

// One file held here: fetched from the bucket when it has no local copy, then its local copy authenticated end to end
// against the generation the catalog records. False when the file moved under the check (a newer generation, or gone):
// the next pass takes it as it is then.
bool holdLocally(Ctx& ctx, Item& it) {
    auto file = db::query::fs::File::getFileById(*it.file_id);
    if (!file || !hasContent(*file)) return false;
    if (!localCopyExists(*ctx.cloud, *file) && ctx.row.mode == Mode::InPlace) {
        // In place: the bucket is out of reach, so a file held only there is lost. It is listed first, then moved to
        // the trash (it has no local bytes, so nothing local goes); the trash keeps its name.
        Q::addLost(ctx.vaultId, {{"file_id", file->id}, {"path", file->path.string()}, {"size_bytes", file->size_bytes}});
        it.state = ItemState::Lost;
        it.generation = file->encryption_iv;
        Q::updateItem(it);
        fs::Filesystem::remove(ctx.cloud->vaultPathToFusePath(file->path), ctx.cloud->vault->owner_id);
        return false;
    }
    if (!localCopyExists(*ctx.cloud, *file)) {
        file = ctx.cloud->hydrate(file);   // price-preflighted, metered, authenticated before it becomes visible
        if (!file) return false;
        it.hydrated = true;
    }
    const auto path = backingOf(*ctx.cloud, *file);
    const DetachFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd.get() < 0) {
        if (errno == ENOENT) return false;   // replaced or released at this instant
        throw std::system_error(errno, std::generic_category(), "open " + path.string());
    }
    struct stat st {};
    if (::fstat(fd.get(), &st) != 0) throw std::system_error(errno, std::generic_category(), "stat " + path.string());
    const bool authentic = content::verifyFd(
        fd.get(), file->size_bytes,
        {.vaultUid = ctx.em->vaultUid(), .generation = file->encryption_iv,
         .keyVersion = file->encrypted_with_key_version, .objectUid = file->object_uid},
        *ctx.keyOf(file->encrypted_with_key_version));
    // The row as it is now: a write since the check is a newer generation, checked by the next pass.
    const auto now = db::query::fs::File::getFileById(*it.file_id);
    if (!now || now->encryption_iv != file->encryption_iv) return false;
    if (!authentic)
        throw storage::IntegrityError(fmt::format("file {}: its local copy does not authenticate as the generation the "
                                                  "catalog records", *it.file_id));
    it.generation = file->encryption_iv;
    it.key_version = file->encrypted_with_key_version;
    it.size = static_cast<uint64_t>(st.st_size);
    it.state = ItemState::Verified;
    it.error.reset();
    return true;
}

void hydratePending(Ctx& ctx) {
    for (auto& it : Q::items(ctx.vaultId)) {
        if (it.kind != ItemKind::Content || it.state != ItemState::Pending) continue;
        ctx.checkpoint();
        try {
            (void)holdLocally(ctx, it);
        } catch (const DetachFailed&) {
            throw;
        } catch (const DetachInterrupted&) {
            throw;
        } catch (const std::exception& e) {
            it.state = ItemState::Failed;
            it.error = e.what();
            Q::updateItem(it);
            throw DetachFailed(fmt::format("file {} could not be held locally: {}", it.file_id.value_or(0), e.what()));
        }
        Q::updateItem(it);
        ctx.step("item:" + std::to_string(it.id));
    }
}

// Every recovery envelope of the vault held in the database, where a local vault keeps them: the bytes the database
// lacks are read from the bucket and checked (the name is the envelope's hash; it opens to this vault, its key version
// and its grant's recipient) before they are stored. Returns how many it copied.
unsigned copyEnvelopes(Ctx& ctx) {
    std::map<std::string, std::string> recipientOfGrant;
    for (const auto& g : db::query::vault::RecoveryGrants::list(ctx.vaultId)) recipientOfGrant[g.grant_id] = g.recipient_id;
    std::map<std::string, Item> byKid;
    for (auto& it : Q::items(ctx.vaultId))
        if (it.kind == ItemKind::Envelope && it.kid) byKid.emplace(*it.kid, std::move(it));

    std::optional<storage::s3::ManifestStore> store;
    unsigned copied = 0;
    std::set<std::string> held;
    for (const auto& e : AttachQ::envelopes(ctx.vaultId)) {
        held.insert(e.kid);
        auto bytes = e.bytes;
        bool fromBucket = false;
        if (bytes.empty() && ctx.row.mode == Mode::InPlace) continue;   // the bucket's own: rewrapped below
        if (bytes.empty()) {
            ctx.checkpoint();
            if (!store) store.emplace(ctx.cloud->s3Controller());
            std::optional<sync::manifest::StoredObject> object;
            try {
                object = store->get(kev1::objectKey(e.kid), std::nullopt);
            } catch (const std::exception& ex) {
                throw DetachFailed(fmt::format("the recovery envelope {} of key version {} could not be read from the "
                                               "bucket: {}", e.kid, e.key_version, ex.what()));
            }
            if (!object)
                throw DetachFailed(fmt::format("the recovery envelope {} of key version {} is not in the bucket, so it "
                                               "can't be kept: the vault stays an S3 vault", e.kid, e.key_version));
            bytes = std::move(object->bytes);
            fromBucket = true;
        }
        try {
            const auto h = kev1::inspect(bytes);
            std::string recipient;
            for (const auto b : h.recipient_id) recipient += fmt::format("{:02x}", b);
            const auto grant = recipientOfGrant.find(e.grant_id);
            if (kev1::kid(bytes) != e.kid || h.vault_uid != ctx.em->vaultUid() || h.key_version != e.key_version ||
                grant == recipientOfGrant.end() || grant->second != recipient)
                throw DetachFailed(fmt::format("the recovery envelope {} is not the one for its grant and key version {}",
                                               e.kid, e.key_version));
        } catch (const kev1::Error& err) {
            throw DetachFailed(fmt::format("the recovery envelope {} is not a KEV1 envelope ({})", e.kid,
                                           kev1::errorCodeName(err.code())));
        }
        if (fromBucket) {
            AttachQ::storeEnvelopeBytes(ctx.vaultId, e.kid, bytes);
            ++copied;
        }
        auto it = byKid.find(e.kid);
        if (it == byKid.end()) {
            Item item;
            item.vault_id = ctx.vaultId;
            item.kind = ItemKind::Envelope;
            item.kid = e.kid;
            item.key_version = e.key_version;
            item.size = bytes.size();
            item.hydrated = fromBucket;
            item.state = ItemState::Verified;
            (void)Q::insertItem(item);
        } else {
            it->second.hydrated = it->second.hydrated || fromBucket;
            it->second.size = bytes.size();
            it->second.state = ItemState::Verified;
            it->second.error.reset();
            Q::updateItem(it->second);
        }
        if (fromBucket) ctx.step("envelope:" + e.kid);
    }
    for (const auto& [kid, item] : byKid)
        if (!held.contains(kid)) Q::deleteItem(item.id);
    if (ctx.row.mode == Mode::InPlace) {
        // Every usable grant gets a database-held envelope of every version it covers in the bucket only: wrapped
        // again here (the vault holds every key version), so the local vault is never less recoverable.
        std::set<uint32_t> versions;
        for (const auto& e : AttachQ::envelopes(ctx.vaultId))
            if (e.bytes.empty()) versions.insert(e.key_version);
        for (const auto v : versions) copied += envelopes::wrapIntoDatabase(ctx.vaultId, v, *ctx.keyOf(v));
    }
    return copied;
}

Estimate estimateOf(const Ctx& ctx) {
    Estimate e;
    for (const auto& f : AttachQ::liveFiles(ctx.vaultId)) {
        if (!hasContent(*f)) continue;
        const auto sealed = content::sealedSizeOf(f->size_bytes, f->encryption_iv);
        ++e.files;
        e.bytes += sealed;
        if (!localCopyExists(*ctx.cloud, *f)) {
            ++e.files_remote_only;
            e.bytes_remote_only += sealed;
        }
    }
    for (const auto& env : AttachQ::envelopes(ctx.vaultId)) {
        ++e.envelopes;
        if (env.bytes.empty()) ++e.envelopes_to_copy;
    }
    e.history_in_bucket_only = Q::historyInBucketOnly(ctx.vaultId);
    for (const auto& path : Q::trashedBackingPaths(ctx.vaultId)) {
        std::error_code ec;
        std::filesystem::path p(path);
        if (!p.is_absolute() && ctx.cloud->paths) p = ctx.cloud->paths->absPath(p, fs::model::PathType::BACKING_ROOT);
        if (!std::filesystem::exists(p, ec)) ++e.trash_without_local_copy;
    }
    return e;
}

// Under the pass lease, right before the cutover: every verified item still names its file's current generation and
// the backing file is there with that generation's sealed size. False when anything moved (it goes back to hydrating).
bool localCopiesIntact(Ctx& ctx) {
    std::map<uint32_t, Item> verified;
    for (auto& it : Q::items(ctx.vaultId))
        if (it.kind == ItemKind::Content && it.file_id && it.state == ItemState::Verified)
            verified.emplace(*it.file_id, std::move(it));
    bool intact = true;
    for (const auto& f : AttachQ::liveFiles(ctx.vaultId)) {
        if (!hasContent(*f)) continue;
        const auto it = verified.find(f->id);
        std::error_code ec;
        const auto size = std::filesystem::file_size(backingOf(*ctx.cloud, *f), ec);
        if (it != verified.end() && it->second.generation == std::optional<std::string>(f->encryption_iv) && !ec &&
            size == content::sealedSizeOf(f->size_bytes, f->encryption_iv))
            continue;
        intact = false;
        if (it != verified.end()) {
            it->second.state = ItemState::Pending;
            Q::updateItem(it->second);
        }
    }
    return intact;
}

Ctx makeCtx(const Row& row, const RunDeps& deps) {
    Ctx ctx;
    ctx.vaultId = row.vault_id;
    ctx.row = row;
    ctx.deps = &deps;
    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(row.vault_id) : nullptr;
    if (!engine || !engine->vault) throw DetachFailed("the vault is not loaded on this host");
    ctx.cloud = std::dynamic_pointer_cast<storage::CloudEngine>(engine);
    if (!ctx.cloud) throw Refusal("not_s3", "the vault is not an S3 vault: only an S3 vault detaches its remote");
    ctx.em = ctx.cloud->encryptionManager;
    if (!ctx.em) throw DetachFailed("the vault's encryption key is not loaded");
    return ctx;
}

struct DetachLease {
    const RunDeps& deps;
    uint32_t vaultId;
    bool held{false};
    DetachLease(const RunDeps& d, const uint32_t id) : deps(d), vaultId(id) {
        held = !deps.tryAcquirePass || deps.tryAcquirePass(vaultId);
    }
    ~DetachLease() {
        if (held && deps.releasePass) deps.releasePass(vaultId);
    }
    DetachLease(const DetachLease&) = delete;
    DetachLease& operator=(const DetachLease&) = delete;
};

bool rotationOrSalvageRunning(const Ctx& ctx) {
    using KeyQ = db::query::vault::Key;
    return ctx.em->rotation_in_progress() || KeyQ::keyRotationInProgress(ctx.vaultId) ||
           KeyQ::runningSalvage(ctx.vaultId).has_value();
}

// After the cutover committed (also after a restart found the row in cutover): the engine swap, then done.
void finishCutover(const uint32_t vaultId, const RunDeps& deps, RunResult& result) {
    result.state = State::Cutover;
    try {
        const DetachLease lease(deps, vaultId);
        if (!lease.held) {
            result.busy = true;
            return;
        }
        storage::remote_access::forget(vaultId);
        if (deps.swapEngine) deps.swapEngine(vaultId);
        if (deps.afterStep) deps.afterStep("swapped");
        Q::markDone(vaultId);
        result.state = State::Done;
        log::Registry::cloud()->info("[RemoteDetach] Vault {}: detached; it is a local vault from here on, and its "
                                     "bucket was left in place", vaultId);
    } catch (const std::exception& e) {
        // The vault is a local vault already: the swap is retried, never rolled back.
        try {
            Q::setError(vaultId, std::string("after the cutover: ") + e.what());
        } catch (const std::exception&) {
        }
        result.error = e.what();
    }
}

void recordFailure(const uint32_t vaultId, const std::string& what, RunResult& result) {
    Q::setState(vaultId, State::Failed, what);
    result.state = State::Failed;
    result.error = what;
    vh::audit::record({.action = "vault.remote.detach.failed", .outcome = vh::audit::Outcome::Failure,
                       .actor_id = std::nullopt, .actor = "RemoteAttachService", .vault_id = vaultId,
                       .entry_id = std::nullopt, .details = nlohmann::json::object()},
                      fmt::format("[RemoteDetach] Vault {}: detaching the remote failed before the cutover; the vault "
                                  "is still an S3 vault and syncs as before (vh vault remote status {} names the reason)",
                                  vaultId, vaultId));
}

}

// ---- preconditions ------------------------------------------------------------------------------------------------------

void requireVaultReady(const storage::Engine& engine) {
    namespace d = remote_detach_detail;
    using KeyQ = db::query::vault::Key;
    const auto& vault = engine.vault;
    if (!vault) throw Refusal("vault_unavailable", "the vault is not loaded on this host");
    if (vault->type != model::VaultType::S3 || !dynamic_cast<const storage::CloudEngine*>(&engine))
        throw Refusal("not_s3", "vault '" + vault->name + "' is not an S3 vault: only an S3 vault detaches its remote");
    const auto em = engine.encryptionManager;
    if (!em) throw Refusal("vault_unavailable", "the vault's encryption key is not loaded");
    if (const auto attach = d::AttachQ::get(vault->id); attach && remote::running(attach->state))
        throw Refusal("attach_running", "a remote attach of the vault is still finishing; detach once it is done");
    if (d::Q::layoutMigrationRunning(vault->id))
        throw Refusal("layout_migration_running", "a bucket layout migration of the vault has not completed (vh vault "
                                                  "migrate-layout status); detach once it has");
    if (em->rotation_in_progress() || KeyQ::keyRotationInProgress(vault->id))
        throw Refusal("key_rotation_running", "a key rotation of the vault is in progress; detach once it has finished");
    if (KeyQ::runningSalvage(vault->id))
        throw Refusal("key_salvage_running", "a key salvage of the vault is running; detach once it has finished");

    const auto legacy = d::AttachQ::legacyContent(vault->id);
    if (legacy.gcm0_files || legacy.plain_files)
        throw Refusal("legacy_content",
                      fmt::format("the vault still holds content in a legacy format ({} file(s) in gcm0, {} plaintext "
                                  "file(s)); the format conversion finishes first (vh vault format status {})",
                                  legacy.gcm0_files, legacy.plain_files, vault->id));

    std::vector<unsigned int> notHeld;
    for (const auto v : KeyQ::liveFileKeyVersions(vault->id))
        if (v != 0 && !em->hasKeyVersion(v)) notHeld.push_back(v);
    if (!notHeld.empty()) {
        std::string list;
        for (const auto v : notHeld) list += (list.empty() ? "" : ", ") + std::to_string(v);
        throw Refusal("key_version_missing", "the vault's files are sealed under key version(s) " + list +
                                                 ", which this host doesn't hold; import them (vh vault keys import) "
                                                 "first");
    }
    if (d::Q::eventSubscriptionActive(vault->id))
        throw Refusal("event_sync_active", "the vault has event-driven sync on its bucket; turn it off first (vault "
                                           "settings, or vh upstream events)");
    if (const auto open = d::Q::openConflicts(vault->id))
        throw Refusal("sync_conflicts_open",
                      fmt::format("the vault has {} open sync conflict(s); resolve them first, so no version in the "
                                  "bucket is left undecided", open));
}

// ---- progress -----------------------------------------------------------------------------------------------------------

Progress progressOf(const Row& row, const std::vector<Item>& items) {
    Progress p;
    p.phase = std::string(to_string(row.state));
    p.passes = row.passes;
    p.updated_at = row.updated_at;
    for (const auto& it : items) {
        if (it.kind != ItemKind::Content) continue;
        ++p.files_total;
        p.bytes_total += it.size.value_or(0);
        if (it.state == ItemState::Verified) {
            ++p.files_done;
            p.bytes_done += it.size.value_or(0);
        }
    }
    return p;
}

// ---- the run -----------------------------------------------------------------------------------------------------------

RunResult run(const uint32_t vaultId, const RunDeps& deps) {
    namespace d = remote_detach_detail;
    RunResult result;
    auto row = d::Q::get(vaultId);
    if (!row) throw std::invalid_argument("the vault has no remote detach");
    result.state = row->state;
    if (row->state == State::Done || row->state == State::Failed || row->state == State::Aborted) return result;
    if (row->state == State::Cutover) {
        d::finishCutover(vaultId, deps, result);
        return result;
    }
    if (row->abort_requested_at) return result;   // the service aborts it

    std::optional<d::Ctx> ctx;
    try {
        ctx.emplace(d::makeCtx(*row, deps));
        bool verified = row->state == State::Verifying && row->verified_at.has_value();
        for (int round = 0;; ++round) {
            if (round == 4) throw d::DetachFailed("the vault kept changing under the detach (files changed or lost "
                                                  "their local copy between the checks)");
            if (!verified) {
                requireVaultReady(*ctx->cloud);
                (void)d::planItems(*ctx);
                (void)d::copyEnvelopes(*ctx);
                if (ctx->row.state == State::Preparing) d::Q::setEstimate(vaultId, toJson(d::estimateOf(*ctx)));
                ctx->step("prepared");

                d::Q::setState(vaultId, State::Hydrating);
                ctx->row.state = State::Hydrating;
                for (unsigned int pass = 1; pass <= std::max(1u, deps.maxPasses); ++pass) {
                    const auto pending = d::planItems(*ctx);
                    d::Q::setPasses(vaultId, pass);
                    if (!pending) break;
                    d::hydratePending(*ctx);
                    ctx->step("pass:" + std::to_string(pass));
                }
                (void)d::copyEnvelopes(*ctx);   // versions wrapped meanwhile
                ctx->step("hydrated");
                d::Q::setState(vaultId, State::Verifying);
                d::Q::markVerified(vaultId);
                verified = true;
            }

            // The final check, the cutover and the engine swap: one hold of the vault's pass lease, so no sync pass
            // can evict, index or fetch anything in between.
            const d::DetachLease lease(deps, vaultId);
            if (!lease.held || d::rotationOrSalvageRunning(*ctx)) {
                result.state = State::Verifying;
                result.busy = true;
                return result;
            }
            ctx->checkpoint();
            requireVaultReady(*ctx->cloud);
            const auto moved = d::planItems(*ctx);
            if (moved > 0 || !d::localCopiesIntact(*ctx)) {
                d::Q::clearVerified(vaultId);
                d::Q::setState(vaultId, State::Hydrating);
                ctx->row.state = State::Hydrating;
                verified = false;
                continue;
            }
            (void)d::copyEnvelopes(*ctx);
            ctx->step("checked");
            const auto outcome = d::Q::cutover(vaultId);
            if (!outcome.done) throw d::DetachFailed("cutover refused: " + outcome.refused);
            vh::audit::record({.action = "vault.remote.detach.cutover", .outcome = vh::audit::Outcome::Success,
                               .actor_id = std::nullopt, .actor = "RemoteAttachService", .vault_id = vaultId,
                               .entry_id = std::nullopt,
                               .details = {{"bucket", ctx->row.bucket},
                                           {"gateway_local", outcome.gateway_flipped},
                                           {"bucket_unbound", outcome.bucket_unbound},
                                           {"backlog_skipped", static_cast<int64_t>(outcome.backlog_skipped)}}},
                              fmt::format("[RemoteDetach] Vault {} cut over to local storage: every file is held here; "
                                          "bucket '{}' was left in place", vaultId, ctx->row.bucket));
            storage::remote_access::forget(vaultId);   // its row went with the S3 binding
            ctx->step("cutover");
            result.state = State::Cutover;
            try {
                if (deps.swapEngine) deps.swapEngine(vaultId);
                ctx->step("swapped");
                d::Q::markDone(vaultId);
                result.state = State::Done;
            } catch (const std::exception& e) {
                d::Q::setError(vaultId, std::string("after the cutover: ") + e.what());
                result.error = e.what();
            }
            return result;
        }
    } catch (const d::DetachInterrupted&) {
        result.stopped = true;
        result.state = d::Q::get(vaultId).value_or(*row).state;
        return result;
    } catch (const Refusal& e) {
        d::recordFailure(vaultId, e.code() + ": " + e.what(), result);
        return result;
    } catch (const std::exception& e) {
        if (const auto now = d::Q::get(vaultId); now && !beforeCutover(now->state)) {
            result.state = now->state;   // the cutover committed: a crash seam after it, retried by finishCutover
            result.error = e.what();
            return result;
        }
        d::recordFailure(vaultId, e.what(), result);
        return result;
    }
}

RunDeps runtimeRunDeps() {
    RunDeps deps;
    deps.tryAcquirePass = [](const uint32_t vaultId) {
        const auto& controller = runtime::Deps::get().syncController;
        return !controller || controller->tryAcquirePass(vaultId);
    };
    deps.releasePass = [](const uint32_t vaultId) {
        if (const auto& controller = runtime::Deps::get().syncController) controller->releasePass(vaultId);
    };
    deps.swapEngine = [](const uint32_t vaultId) {
        const auto& manager = runtime::Deps::get().storageManager;
        if (!manager) throw std::runtime_error("the storage manager is not available");
        manager->reloadEngine(vaultId);
        if (const auto& controller = runtime::Deps::get().syncController) controller->refreshEngines();
    };
    deps.maxPasses = config::Registry::get().vaults.remote_attach.max_passes;
    return deps;
}

// ---- abort -------------------------------------------------------------------------------------------------------------

AbortResult runAbort(const uint32_t vaultId) {
    namespace d = remote_detach_detail;
    AbortResult out;
    const auto row = d::Q::get(vaultId);
    if (!row) throw std::invalid_argument("the vault has no remote detach");
    if (!beforeCutover(row->state)) throw std::runtime_error("the detach has cut over (or was aborted): nothing to abort");
    d::Q::setState(vaultId, State::Failed, "abort in progress");

    // Envelope bytes this detach copied into the database: cleared again where the bucket's copy reads back equal.
    std::shared_ptr<storage::CloudEngine> cloud;
    if (const auto& manager = runtime::Deps::get().storageManager)
        cloud = std::dynamic_pointer_cast<storage::CloudEngine>(manager->getEngine(vaultId));
    std::optional<storage::s3::ManifestStore> store;
    for (const auto& it : d::Q::items(vaultId)) {
        if (it.kind != ItemKind::Envelope || !it.hydrated || !it.kid) continue;
        bool cleared = false;
        try {
            const auto held = d::AttachQ::envelopeBytes(vaultId, *it.kid);
            if (held && cloud) {
                if (!store) store.emplace(cloud->s3Controller());
                const auto object = store->get(d::kev1::objectKey(*it.kid), std::nullopt);
                if (object && object->bytes == *held) {
                    d::AttachQ::clearEnvelopeBytes(vaultId, *it.kid);
                    cleared = true;
                }
            }
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[RemoteDetach] Vault {}: envelope {} kept in the database: {}", vaultId,
                                         *it.kid, e.what());
        }
        cleared ? ++out.envelopes_cleared : ++out.envelopes_kept;
    }
    d::Q::finishAbort(vaultId);
    out.state = State::Aborted;
    vh::audit::record({.action = "vault.remote.detach.aborted", .outcome = vh::audit::Outcome::Success,
                       .actor_id = row->abort_requested_by, .actor = "RemoteAttachService", .vault_id = vaultId,
                       .entry_id = std::nullopt,
                       .details = {{"envelopes_cleared", static_cast<int64_t>(out.envelopes_cleared)},
                                   {"envelopes_kept", static_cast<int64_t>(out.envelopes_kept)}}},
                      fmt::format("[RemoteDetach] Vault {}: detach aborted; the vault is still an S3 vault, the local "
                                  "copies it fetched stay", vaultId));
    return out;
}

bool inProgress(const uint32_t vaultId) {
    const auto row = remote_detach_detail::Q::get(vaultId);
    return row && running(row->state);
}

}
