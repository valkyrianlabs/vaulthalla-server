// Attaching a remote to a local vault: see vault/RemoteAttach.hpp for the protocol (design/storage/attach-remote.md).

#include "vault/RemoteAttach.hpp"

#include <vl/keykit/kev1.hpp>
#include "audit/Trail.hpp"
#include "config/Registry.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "crypto/util/encrypt.hpp"
#include <vl/vaultfmt/vhf1/Format.hpp>
#include "db/query/device/Device.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/Event.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/RecoveryGrants.hpp"
#include "db/query/vault/RemoteAttach.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "log/Registry.hpp"
#include "platform/Durable.hpp"
#include "recovery/Hooks.hpp"
#include "recovery/Store.hpp"
#include "recovery/provider/OwnWrites.hpp"
#include "recovery/provider/Versions.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include <vl/vaultfmt/ObjectKeys.hpp>
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/s3/ManifestStore.hpp"
#include "storage/s3/pricing/PriceEstimate.hpp"
#include "storage/s3/provider/Registry.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/Controller.hpp"
#include <vl/vaultfmt/manifest/Content.hpp>
#include <vl/vaultfmt/manifest/Document.hpp>
#include <vl/vaultfmt/manifest/Publisher.hpp>
#include <vl/vaultfmt/manifest/Reader.hpp>
#include <vl/vaultfmt/manifest/Store.hpp>
#include "sync/model/Action.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/LayoutMigration.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <paths.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <deque>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <set>
#include <system_error>
#include <unistd.h>

namespace vh::vault::remote {

// ---- names ------------------------------------------------------------------------------------------------------------

std::string_view to_string(const State state) {
    switch (state) {
    case State::Preparing: return "preparing";
    case State::Uploading: return "uploading";
    case State::CatchingUp: return "catching_up";
    case State::Verifying: return "verifying";
    case State::Cutover: return "cutover";
    case State::Done: return "done";
    case State::Failed: return "failed";
    case State::Aborted: return "aborted";
    }
    return "failed";
}

State stateFromString(const std::string_view text) {
    for (const auto s : {State::Preparing, State::Uploading, State::CatchingUp, State::Verifying, State::Cutover,
                         State::Done, State::Failed, State::Aborted})
        if (to_string(s) == text) return s;
    throw std::invalid_argument("unknown remote attach state: " + std::string(text));
}

bool beforeCutover(const State state) {
    return state == State::Preparing || state == State::Uploading || state == State::CatchingUp ||
           state == State::Verifying || state == State::Failed;
}

bool running(const State state) {
    return state == State::Preparing || state == State::Uploading || state == State::CatchingUp ||
           state == State::Verifying || state == State::Cutover;
}

std::string_view to_string(const ItemKind kind) {
    switch (kind) {
    case ItemKind::Content: return "content";
    case ItemKind::Envelope: return "envelope";
    case ItemKind::Metadata: return "metadata";
    case ItemKind::Orphan: return "orphan";
    }
    return "content";
}

ItemKind itemKindFromString(const std::string_view text) {
    for (const auto k : {ItemKind::Content, ItemKind::Envelope, ItemKind::Metadata, ItemKind::Orphan})
        if (to_string(k) == text) return k;
    throw std::invalid_argument("unknown remote attach item kind: " + std::string(text));
}

std::string_view to_string(const ItemState state) {
    switch (state) {
    case ItemState::Pending: return "pending";
    case ItemState::Sent: return "sent";
    case ItemState::Verified: return "verified";
    case ItemState::Stale: return "stale";
    case ItemState::Deleted: return "deleted";
    case ItemState::Failed: return "failed";
    }
    return "pending";
}

ItemState itemStateFromString(const std::string_view text) {
    for (const auto s : {ItemState::Pending, ItemState::Sent, ItemState::Verified, ItemState::Stale, ItemState::Deleted,
                         ItemState::Failed})
        if (to_string(s) == text) return s;
    throw std::invalid_argument("unknown remote attach item state: " + std::string(text));
}

nlohmann::json toJson(const Estimate& e) {
    return {{"list_requests", e.list_requests},
            {"head_requests", e.head_requests},
            {"get_requests", e.get_requests},
            {"put_requests", e.put_requests},
            {"delete_requests", e.delete_requests},
            {"download_bytes", e.download_bytes},
            {"upload_bytes", e.upload_bytes},
            {"readback_worst_case_gets", e.readback_worst_case_gets},
            {"readback_worst_case_bytes", e.readback_worst_case_bytes},
            {"metadata_puts", e.metadata_puts},
            {"files", e.files},
            {"envelopes", e.envelopes},
            {"sample", e.sample},
            {"priced", e.priced},
            {"estimated_cost", e.estimated_cost ? nlohmann::json(*e.estimated_cost) : nlohmann::json(nullptr)}};
}

Estimate estimateFromJson(const nlohmann::json& j) {
    Estimate e;
    const auto u = [&](const char* name) { return j.contains(name) ? j.at(name).get<uint64_t>() : uint64_t{0}; };
    e.list_requests = u("list_requests");
    e.head_requests = u("head_requests");
    e.get_requests = u("get_requests");
    e.put_requests = u("put_requests");
    e.delete_requests = u("delete_requests");
    e.download_bytes = u("download_bytes");
    e.upload_bytes = u("upload_bytes");
    e.readback_worst_case_gets = u("readback_worst_case_gets");
    e.readback_worst_case_bytes = u("readback_worst_case_bytes");
    e.metadata_puts = u("metadata_puts");
    e.files = u("files");
    e.envelopes = u("envelopes");
    e.sample = u("sample");
    e.priced = j.value("priced", false);
    if (j.contains("estimated_cost") && j.at("estimated_cost").is_string())
        e.estimated_cost = j.at("estimated_cost").get<std::string>();
    return e;
}

nlohmann::json toJson(const Progress& p) {
    return {{"phase", p.phase},
            {"files_total", p.files_total},
            {"files_done", p.files_done},
            {"bytes_total", p.bytes_total},
            {"bytes_done", p.bytes_done},
            {"bytes_per_second", p.bytes_per_second ? nlohmann::json(*p.bytes_per_second) : nlohmann::json(nullptr)},
            {"eta_seconds", p.eta_seconds ? nlohmann::json(*p.eta_seconds) : nlohmann::json(nullptr)},
            {"passes", p.passes},
            {"updated_at", p.updated_at}};
}

namespace remote_detail {

using Q = db::query::vault::RemoteAttach;
namespace keys = vl::vaultfmt::keys;
namespace content = vault::content;
namespace mf = vl::vaultfmt::manifest;
namespace kev1 = vl::keykit::kev1;

// A failure of the run before the cutover: the row goes to failed with this text, the vault stays local.
struct RunFailed : std::runtime_error {
    using std::runtime_error::runtime_error;
};
// The service is stopping, or an abort was requested: the run ends where it is and is picked up again.
struct Interrupted : std::runtime_error {
    explicit Interrupted(const bool abort) : std::runtime_error(abort ? "abort requested" : "stopped"), abort(abort) {}
    bool abort{false};
};

std::mutex factoryMutex;
ControllerFactory factory;

std::string unquoted(std::string etag) {
    if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') etag = etag.substr(1, etag.size() - 2);
    return etag;
}

bool sameEtag(const std::optional<std::string>& a, const std::string& b) { return a && unquoted(*a) == unquoted(b); }

std::string hexOfGeneration(const std::string& generation) {
    std::string hex;
    for (const auto b : crypto::util::b64_decode(generation)) hex += fmt::format("{:02x}", b);
    return hex;
}

bool isR2(const storage::s3::provider::ProfilePtr& profile) { return profile && profile->id() == "cloudflare-r2"; }

// ---- throughput (status's bytes_per_second): in memory, per vault, the last minute ------------------------------------

struct Throughput {
    std::mutex mutex;
    std::map<uint32_t, std::deque<std::pair<std::chrono::steady_clock::time_point, uint64_t>>> samples;

    void note(const uint32_t vaultId, const uint64_t bytesDone) {
        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock(mutex);
        auto& q = samples[vaultId];
        q.emplace_back(now, bytesDone);
        while (q.size() > 2 && now - q.front().first > std::chrono::seconds(60)) q.pop_front();
    }
    void forget(const uint32_t vaultId) {
        std::scoped_lock lock(mutex);
        samples.erase(vaultId);
    }
    std::optional<uint64_t> rate(const uint32_t vaultId) {
        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock(mutex);
        const auto it = samples.find(vaultId);
        if (it == samples.end() || it->second.size() < 2) return std::nullopt;
        const auto& q = it->second;
        if (now - q.back().first > std::chrono::seconds(60)) return std::nullopt;   // nothing moved for a minute
        const auto seconds = std::chrono::duration_cast<std::chrono::milliseconds>(q.back().first - q.front().first).count();
        if (seconds <= 0 || q.back().second < q.front().second) return std::nullopt;
        return (q.back().second - q.front().second) * 1000 / static_cast<uint64_t>(seconds);
    }
};

Throughput& throughput() {
    static Throughput t;
    return t;
}

// ---- temp files (sealed bytes only: hard links of backing files and objects as read back; never plaintext) ------------

std::filesystem::path tmpDirFor(const uint32_t vaultId) {
    return recovery::store::root().parent_path() / ".vh-attach" / std::to_string(vaultId);
}

class TempPath {
public:
    explicit TempPath(const std::filesystem::path& dir) {
        std::filesystem::create_directories(dir);
        std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
        unsigned char rnd[12];
        randombytes_buf(rnd, sizeof rnd);
        std::string name = "a-";
        for (const auto b : rnd) name += fmt::format("{:02x}", b);
        path_ = dir / name;
    }
    ~TempPath() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    TempPath(const TempPath&) = delete;
    TempPath& operator=(const TempPath&) = delete;
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

class FdGuard {
public:
    explicit FdGuard(const int fd) : fd_(fd) {}
    ~FdGuard() {
        if (fd_ >= 0) ::close(fd_);
    }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
    [[nodiscard]] int get() const { return fd_; }

private:
    int fd_{-1};
};

void writeAll(const int fd, const std::span<const uint8_t> bytes) {
    std::size_t off = 0;
    while (off < bytes.size()) {
        const auto n = ::write(fd, bytes.data() + off, bytes.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "write");
        }
        off += static_cast<std::size_t>(n);
    }
}

// The first kHeaderSize bytes of the file at path (fewer when it is shorter).
std::vector<uint8_t> readHeader(const std::filesystem::path& path) {
    const FdGuard fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd.get() < 0) throw std::system_error(errno, std::generic_category(), "open " + path.string());
    std::vector<uint8_t> out(vl::vaultfmt::vhf1::kHeaderSize);
    std::size_t got = 0;
    while (got < out.size()) {
        const auto n = ::read(fd.get(), out.data() + got, out.size() - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "read " + path.string());
        }
        if (n == 0) break;
        got += static_cast<std::size_t>(n);
    }
    out.resize(got);
    return out;
}

uint64_t putRequestsFor(const uint64_t size) {
    if (size < storage::s3::Controller::MIN_PART_SIZE) return 1;
    return keys::partCountFor(size, keys::partSizeFor(size)) + 2;   // initiate + parts + complete
}

uint64_t sampleSize(const uint64_t puts, const unsigned int minimum) {
    return std::min<uint64_t>(puts, std::max<uint64_t>(minimum, (puts + 99) / 100));
}

// ---- the run's context --------------------------------------------------------------------------------------------------

struct Ctx {
    uint32_t vaultId{};
    Row row;
    std::shared_ptr<storage::Engine> engine;        // the vault's live (local) engine
    std::shared_ptr<EncryptionManager> em;
    std::shared_ptr<model::APIKey> key;
    std::shared_ptr<storage::s3::Controller> ctl;
    storage::s3::provider::ProfilePtr profile;
    std::optional<storage::s3::provider::StorageTier> tier;
    std::optional<std::string> storageClass;
    storage::s3::ProbeResult probe;
    mf::WriteCapability mode{mf::WriteCapability::Unknown};
    bool versioned{true};
    std::filesystem::path tmpDir;
    const RunDeps* deps{};
    uint64_t listPages{};
    nlohmann::json usageBase = nlohmann::json::object();
    std::chrono::steady_clock::time_point lastAbortCheck{};

    void step(const std::string_view name) const {
        if (deps && deps->afterStep) deps->afterStep(name);
    }

    // Between objects: the service stopping or an abort asked for ends the run here.
    void checkpoint() {
        if (deps && deps->stop && deps->stop()) throw Interrupted(false);
        const auto now = std::chrono::steady_clock::now();
        if (now - lastAbortCheck < std::chrono::seconds(2)) return;
        lastAbortCheck = now;
        if (const auto current = Q::get(vaultId); !current || current->abort_requested_at) throw Interrupted(true);
    }

    [[nodiscard]] crypto::SecretKeyPtr keyOf(const unsigned int version) const {
        try {
            if (auto k = em->historicalKeySnapshot(version)) return k;
        } catch (const std::exception&) {
        }
        throw RunFailed(fmt::format("key version {} is not held", version));
    }

    [[nodiscard]] vl::vaultfmt::vhf1::KeyLookup keyLookup() const {
        return [em = em](const uint32_t version) -> crypto::SecretKeyPtr {
            try {
                return em->historicalKeySnapshot(version);
            } catch (const std::exception&) {
                return nullptr;
            }
        };
    }

    [[nodiscard]] storage::s3::RequestOptions putOptions(const uint64_t size) const {
        storage::s3::RequestOptions options;
        if (!profile) return options;
        const auto op = size < storage::s3::Controller::MIN_PART_SIZE
            ? storage::s3::provider::RequestOperation::PutObject
            : storage::s3::provider::RequestOperation::CreateMultipartUpload;
        options.system_headers = profile->requestMutation(op, tier).system_headers;
        return options;
    }
};

std::filesystem::path backingOf(const storage::Engine& engine, const fs::model::File& file) {
    if (file.backing_path.is_absolute() || !engine.paths) return file.backing_path;
    return engine.paths->absPath(file.backing_path, fs::model::PathType::BACKING_ROOT);
}

std::shared_ptr<model::APIKey> apiKeyOf(const uint32_t apiKeyId) {
    const auto& manager = runtime::Deps::get().apiKeyManager;
    return manager ? manager->getAPIKey(apiKeyId) : nullptr;
}

// A complete listing of the bucket: every page or an exception. R2 has no ListObjectVersions: ListObjectsV2.
std::vector<storage::s3::ObjectVersionInfo> listAll(const storage::s3::Controller& ctl, const bool versioned,
                                                    uint64_t& pages) {
    std::vector<storage::s3::ObjectVersionInfo> out;
    if (!versioned) {
        std::string token;
        do {
            const auto page = ctl.listObjectKeysPage(token, 1000);
            ++pages;
            for (auto info : page.objects) {
                info.version_id.clear();
                out.push_back(std::move(info));
            }
            token = page.next_continuation_token;
        } while (!token.empty());
        return out;
    }
    std::string keyMarker, versionMarker;
    for (;;) {
        const auto page = ctl.listObjectVersionsPage("", keyMarker, versionMarker, 1000);
        ++pages;
        out.insert(out.end(), page.versions.begin(), page.versions.end());
        if (!page.truncated) break;
        keyMarker = page.next_key_marker;
        versionMarker = page.next_version_id_marker;
    }
    return out;
}

bool isProbeKey(const std::string& key) { return key.starts_with(storage::s3::kProbePrefix); }

bool isManifestKey(const std::string& key) {
    return key == mf::kLayoutKey || key == mf::kRootKey || key.starts_with(std::string(keys::kMetadataPrefix) + "seg/");
}

// An item that names an object the bucket should hold now.
bool holdsObject(const Item& it) {
    return (it.state == ItemState::Sent || it.state == ItemState::Verified) && it.etag.has_value();
}

bool matches(const Item& it, const storage::s3::ObjectVersionInfo& v, const bool versioned) {
    if (it.object_key != v.key) return false;
    if (versioned) return it.version_id.value_or("null") == (v.version_id.empty() ? std::string("null") : v.version_id);
    return sameEtag(it.etag, v.etag);
}

// What a complete listing means for the items: every listed version is one the attach recorded, or sits at a key the
// attach recorded before writing there (a stray of an interrupted PUT, or the manifest's objects of an interrupted
// publish): those are recorded now (stale strays, metadata) so they can be deleted or accounted for. Anything else is
// foreign and refuses. Items whose object the listing doesn't show are sent again. Returns how many items changed.
struct Reconciled {
    uint64_t strays{}, missing{}, adopted{};
    [[nodiscard]] bool any() const { return strays || missing || adopted; }
};

Reconciled reconcile(const uint32_t vaultId, const std::vector<storage::s3::ObjectVersionInfo>& listed,
                     const bool versioned) {
    Reconciled out;
    auto items = Q::items(vaultId);
    // Only what the attach still records can explain an object: a deleted item's key is no longer the attach's (an
    // aborted attach's rows are all deleted, and the bucket may be someone else's by now).
    std::map<std::string, std::vector<Item*>> byKey;
    for (auto& it : items)
        if (it.state != ItemState::Deleted) byKey[it.object_key].push_back(&it);
    const bool wroteBefore = !byKey.empty();

    std::set<int64_t> seen;
    for (const auto& v : listed) {
        if (isProbeKey(v.key)) continue;   // a probe's leftover on a bucket that refused its delete: inert
        const auto known = byKey.find(v.key);
        Item* match = nullptr;
        if (known != byKey.end())
            for (auto* it : known->second)
                if (it->state != ItemState::Pending && matches(*it, v, versioned)) match = it;
        if (match) {
            seen.insert(match->id);
            continue;
        }
        if (v.delete_marker)
            throw Refusal("bucket_not_empty", fmt::format("the bucket holds a delete marker this attach did not write "
                                                          "({} object key(s) listed)", listed.size()));
        if (wroteBefore && isManifestKey(v.key)) {
            // The manifest's objects (layout hint, segments, root versions): written by the publish, recorded here.
            if (!versioned && known != byKey.end()) {
                auto* item = known->second.front();   // the key's only object, replaced by a newer publish
                item->etag = v.etag;
                item->size = v.size;
                item->state = ItemState::Verified;
                Q::updateItem(*item);
                seen.insert(item->id);
                ++out.adopted;
                continue;
            }
            Item meta;
            meta.vault_id = vaultId;
            meta.kind = ItemKind::Metadata;
            meta.object_key = v.key;
            meta.size = v.size;
            meta.etag = v.etag;
            if (versioned) meta.version_id = v.version_id.empty() ? std::string("null") : v.version_id;
            meta.state = ItemState::Verified;
            (void)Q::insertItem(meta);
            ++out.adopted;
            continue;
        }
        if (known != byKey.end()) {
            // A version at a key the attach recorded before it wrote there: an interrupted PUT's.
            const auto* first = known->second.front();
            if (!versioned) {
                // The key's only object is not the one recorded: sent again (the PUT replaces it).
                for (auto* it : known->second)
                    if (holdsObject(*it)) {
                        it->state = ItemState::Pending;
                        it->etag.reset();
                        it->version_id.reset();
                        Q::updateItem(*it);
                        seen.insert(it->id);
                        ++out.missing;
                    }
                continue;
            }
            Item stray;
            stray.vault_id = vaultId;
            stray.kind = first->kind == ItemKind::Orphan ? ItemKind::Content : first->kind;
            stray.file_id = first->file_id;
            stray.object_key = v.key;
            stray.size = v.size;
            stray.etag = v.etag;
            stray.version_id = v.version_id.empty() ? std::string("null") : v.version_id;
            stray.state = ItemState::Stale;
            (void)Q::insertItem(stray);
            ++out.strays;
            continue;
        }
        throw Refusal("bucket_not_empty",
                      "the bucket is not empty: it holds objects this attach did not write. Attach needs an empty "
                      "bucket (every object version and delete marker counts)");
    }
    for (auto& it : items) {
        if (!holdsObject(it) || seen.contains(it.id)) continue;
        if (it.kind == ItemKind::Metadata) {
            // A superseded root or a collected segment: no longer in the bucket, nothing to delete later.
            it.state = ItemState::Deleted;
            Q::updateItem(it);
            continue;
        }
        it.state = ItemState::Pending;
        it.etag.reset();
        it.version_id.reset();
        Q::updateItem(it);
        ++out.missing;
    }
    return out;
}

// One recorded object removed from the bucket: by its version id where the bucket keeps versions, else its key once a
// HEAD shows the recorded ETag (another object there is not ours to delete). True when it is gone.
bool removeObject(const storage::s3::Controller& ctl, const Item& it, const bool versioned) {
    if (!it.etag && !it.version_id) return true;   // never written
    if (versioned) {
        ctl.deleteObjectVersion(it.object_key, it.version_id.value_or("null"));
        return true;
    }
    const auto head = ctl.getHeadObject(it.object_key);
    if (!head) return true;   // already gone
    std::string etag;
    for (const auto& [name, value] : *head) {
        std::string lower = name;
        std::ranges::transform(lower, lower.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower == "etag") etag = value;
    }
    if (!sameEtag(it.etag, etag)) return true;   // replaced since by a newer object the attach recorded separately
    ctl.deleteObject(it.object_key);
    return true;
}

// Stale items (an earlier generation of a file sent again, a deleted file's object, a stray): deleted from the bucket.
void deleteStale(Ctx& ctx) {
    for (auto& it : Q::items(ctx.vaultId)) {
        if (it.state != ItemState::Stale) continue;
        ctx.checkpoint();
        try {
            (void)removeObject(*ctx.ctl, it, ctx.versioned);
        } catch (const std::exception& e) {
            it.error = e.what();
            Q::updateItem(it);
            throw RunFailed(fmt::format("a superseded object could not be deleted ({}): {}", it.object_key, e.what()));
        }
        it.state = ItemState::Deleted;
        it.error.reset();
        Q::updateItem(it);
    }
}

// ---- recovery envelopes -------------------------------------------------------------------------------------------------

// Every KEV1 envelope of the vault's recovery recipients in the bucket: the ones the database holds copied byte for
// byte, the missing ones wrapped first (into the database: the vault is still local). Returns how many were written.
unsigned stageEnvelopes(Ctx& ctx) {
    if (db::query::vault::RecoveryGrants::list(ctx.vaultId).empty()) return 0;
    std::vector<uint32_t> versions;
    for (const auto v : ctx.em->retainedKeyVersions()) versions.push_back(v);
    (void)envelopes::ensure(ctx.vaultId, versions, [&](const uint32_t v) -> crypto::SecretKeyPtr {
        try {
            return ctx.em->historicalKeySnapshot(v);
        } catch (const std::exception&) {
            return nullptr;
        }
    });

    auto items = Q::items(ctx.vaultId);
    storage::s3::ManifestStore store(ctx.ctl, ctx.mode);
    unsigned written = 0;
    for (const auto& e : Q::envelopes(ctx.vaultId)) {
        const auto objectKey = kev1::objectKey(e.kid);
        const auto held = std::ranges::find_if(items, [&](const Item& it) {
            return it.kind == ItemKind::Envelope && it.object_key == objectKey && holdsObject(it);
        });
        if (held != items.end()) continue;
        if (e.bytes.empty())
            throw RunFailed(fmt::format("the recovery envelope {} of key version {} has no stored bytes", e.kid,
                                        e.key_version));
        if (kev1::kid(e.bytes) != e.kid)
            throw RunFailed(fmt::format("the stored recovery envelope {} does not hash to its name", e.kid));
        ctx.checkpoint();
        auto pending = std::ranges::find_if(items, [&](const Item& it) {
            return it.kind == ItemKind::Envelope && it.object_key == objectKey && it.state == ItemState::Pending;
        });
        Item item;
        if (pending != items.end()) {
            item = *pending;
        } else {
            item.vault_id = ctx.vaultId;
            item.kind = ItemKind::Envelope;
            item.object_key = objectKey;
            item.key_version = e.key_version;
            item.size = e.bytes.size();
            item = Q::insertItem(item);   // recorded before the PUT: whatever lands at this key is the attach's
        }
        try {
            const auto etag = store.putOnce(objectKey, e.bytes);
            const auto outcome = storage::s3::Controller::lastPutOutcome();
            item.etag = etag.empty() ? outcome.etag : etag;
            item.version_id = outcome.version_id;
        } catch (const mf::PreconditionFailed&) {
            // The name is the envelope's hash: an object there (an interrupted attempt's) must be these bytes.
            const auto existing = store.get(objectKey, std::nullopt);
            if (!existing || existing->bytes != e.bytes)
                throw RunFailed(fmt::format("the bucket holds another object at the recovery envelope's name {}", e.kid));
            item.etag = existing->etag;
            item.version_id = existing->version_id;
        } catch (const mf::ConditionsUnsupported& ex) {
            throw RunFailed(std::string("the bucket refused a conditional write its probe found support for: ") + ex.what());
        }
        if (ctx.versioned && !item.version_id) item.version_id = "null";
        if (!ctx.versioned) item.version_id.reset();
        item.state = ItemState::Sent;
        Q::updateItem(item);
        ++written;
    }
    return written;
}

// Every envelope item holds, in the bucket, a well-formed KEV1 envelope for this vault, its key version and a grant.
void verifyEnvelopes(Ctx& ctx) {
    const auto grants = db::query::vault::RecoveryGrants::list(ctx.vaultId);
    std::map<std::string, std::string> recipientOfGrant;
    for (const auto& g : grants) recipientOfGrant[g.grant_id] = g.recipient_id;
    std::map<std::string, Q::StoredEnvelope> byKey;
    for (auto& e : Q::envelopes(ctx.vaultId)) byKey[kev1::objectKey(e.kid)] = std::move(e);

    storage::s3::ManifestStore store(ctx.ctl, ctx.mode);
    auto items = Q::items(ctx.vaultId);
    for (const auto& [objectKey, e] : byKey) {
        auto it = std::ranges::find_if(items, [&](const Item& i) {
            return i.kind == ItemKind::Envelope && i.object_key == objectKey && holdsObject(i);
        });
        if (it == items.end())
            throw RunFailed(fmt::format("the recovery envelope {} of key version {} is not in the bucket", e.kid,
                                        e.key_version));
        const auto object = store.get(objectKey, std::nullopt);
        if (!object) throw RunFailed(fmt::format("the recovery envelope {} is missing from the bucket", e.kid));
        try {
            const auto h = kev1::inspect(object->bytes);
            std::string recipient;
            for (const auto b : h.recipient_id) recipient += fmt::format("{:02x}", b);
            const auto grant = recipientOfGrant.find(e.grant_id);
            if (kev1::kid(object->bytes) != e.kid || h.vault_uid != ctx.em->vaultUid() || h.key_version != e.key_version ||
                grant == recipientOfGrant.end() || grant->second != recipient)
                throw RunFailed(fmt::format("the bucket's recovery envelope {} is not the one for its grant and key "
                                            "version {}", e.kid, e.key_version));
        } catch (const kev1::Error& err) {
            throw RunFailed(fmt::format("the bucket's recovery envelope {} is not a KEV1 envelope ({})", e.kid,
                                        kev1::errorCodeName(err.code())));
        }
        it->state = ItemState::Verified;
        Q::updateItem(*it);
    }
}

// ---- items ---------------------------------------------------------------------------------------------------------------

bool hasContent(const fs::model::File& f) { return !f.encryption_iv.empty(); }

// Brings the content items in line with the vault's live files: an item per file with content; a file whose generation
// changed since it was sent gets a new item (its earlier version becomes stale); a file that is gone leaves its object
// stale. Returns how many items need sending.
uint64_t planItems(Ctx& ctx) {
    auto items = Q::items(ctx.vaultId);
    std::map<uint32_t, Item*> current;
    for (auto& it : items)
        if (it.kind == ItemKind::Content && it.file_id &&
            (it.state == ItemState::Pending || it.state == ItemState::Sent || it.state == ItemState::Verified ||
             it.state == ItemState::Failed))
            current[*it.file_id] = &it;

    uint64_t pending = 0;
    std::set<uint32_t> live;
    for (const auto& f : Q::liveFiles(ctx.vaultId)) {
        if (!hasContent(*f)) continue;   // an empty file has no backing bytes: its object goes up with the first pass
        if (!f->object_uid) throw RunFailed(fmt::format("file {} has no object uid", f->id));
        if (!content::isVhf1(f->encryption_iv))
            throw Refusal("legacy_content", fmt::format("file {} is not in the VHF1 format; finish the format conversion "
                                                        "first (vh vault format status)", f->id));
        live.insert(f->id);
        const auto objectKey = keys::contentKey(*f->object_uid);
        const auto sealed = content::sealedSizeOf(f->size_bytes, f->encryption_iv);
        if (const auto it = current.find(f->id); it != current.end()) {
            auto& item = *it->second;
            if (item.state == ItemState::Pending || item.state == ItemState::Failed) {
                item.state = ItemState::Pending;
                item.size = sealed;
                item.error.reset();
                Q::updateItem(item);
                ++pending;
                continue;
            }
            if (item.generation == std::optional<std::string>(f->encryption_iv)) continue;   // the bucket holds it
            item.state = ItemState::Stale;   // an earlier generation: deleted once the new one is recorded
            Q::updateItem(item);
        }
        Item fresh;
        fresh.vault_id = ctx.vaultId;
        fresh.kind = ItemKind::Content;
        fresh.file_id = f->id;
        fresh.object_key = objectKey;
        fresh.size = sealed;
        (void)Q::insertItem(fresh);
        ++pending;
    }
    for (auto& [fileId, item] : current) {
        if (live.contains(fileId)) continue;
        item->state = ItemState::Stale;   // the file was deleted (or emptied) since: its object goes
        Q::updateItem(*item);
    }
    return pending;
}

Estimate estimateOf(const Ctx& ctx, const std::vector<Item>& items, const unsigned int sampleMin) {
    Estimate e;
    e.list_requests = std::max<uint64_t>(ctx.listPages, 1) * 2;
    std::vector<uint64_t> sizes;
    uint64_t total = 0;
    for (const auto& it : items) {
        if (it.kind == ItemKind::Envelope && it.state != ItemState::Deleted) ++e.envelopes;
        if (it.kind != ItemKind::Content) continue;
        if (it.state != ItemState::Pending && !holdsObject(it)) continue;
        ++total;
        sizes.push_back(it.size.value_or(0));
        if (it.state != ItemState::Pending) continue;
        ++e.files;
        e.put_requests += putRequestsFor(it.size.value_or(0));
        e.upload_bytes += it.size.value_or(0);
    }
    e.sample = sampleSize(total, sampleMin);
    std::ranges::sort(sizes, std::greater<>());
    for (uint64_t i = 0; i < e.sample && i < sizes.size(); ++i) e.download_bytes += sizes[i];
    e.get_requests = e.sample + e.envelopes + 4;   // the sample, each envelope's inspection, the manifest's load
    e.readback_worst_case_gets = total;
    for (const auto s : sizes) e.readback_worst_case_bytes += s;
    e.metadata_puts = e.envelopes + 3 + total / 8192;   // envelopes, layout hint, root, segments
    return e;
}

uint64_t bytesDone(const std::vector<Item>& items) {
    uint64_t done = 0;
    for (const auto& it : items)
        if (it.kind == ItemKind::Content && holdsObject(it)) done += it.size.value_or(0);
    return done;
}

// ---- uploading -----------------------------------------------------------------------------------------------------------

// Reads o/<uid> back (the version the PUT made, where the bucket keeps versions) and authenticates it end to end.
void readBack(Ctx& ctx, const Item& it) {
    const auto uid = keys::uidOfContentKey(it.object_key);
    if (!uid || !it.generation || !it.key_version) throw std::logic_error("nothing to read back");
    TempPath tmp(ctx.tmpDir);
    {
        const FdGuard fd(::open(tmp.path().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
        if (fd.get() < 0) throw std::system_error(errno, std::generic_category(), "create " + tmp.path().string());
        storage::s3::GetObjectOptions options;
        if (ctx.versioned && it.version_id && *it.version_id != "null") options.version_id = it.version_id;
        else options.if_match = it.etag;
        options.max_body_bytes = it.size;
        (void)ctx.ctl->streamObject(it.object_key, options, [&](const std::span<const uint8_t> b) { writeAll(fd.get(), b); });
    }
    if (!content::verifyFile(tmp.path(), it.plaintext_bytes.value_or(0),
                             {.vaultUid = ctx.em->vaultUid(), .generation = *it.generation,
                              .keyVersion = *it.key_version, .objectUid = uid},
                             *ctx.keyOf(*it.key_version)))
        throw storage::IntegrityError("the stored object does not authenticate");
}

// One file's content: a hard link of its backing file (backing files are only ever replaced by rename, so the link is
// one whole generation), the generation read from those bytes and authenticated as this vault's and this file's, the
// PUT, and the proof the provider holds exactly those bytes (ETag = their MD5, else a read-back).
void sendContent(Ctx& ctx, Item& it) {
    auto file = db::query::fs::File::getFileById(*it.file_id);
    if (!file || !hasContent(*file)) {
        it.state = ItemState::Stale;   // deleted or emptied meanwhile: nothing was sent for this item
        return;
    }
    const auto uid = keys::uidOfContentKey(it.object_key);
    if (!uid || !file->object_uid || *file->object_uid != *uid)
        throw RunFailed(fmt::format("file {} no longer has the object uid its item names", *it.file_id));

    TempPath linked(ctx.tmpDir);
    const auto backing = backingOf(*ctx.engine, *file);
    if (::link(backing.c_str(), linked.path().c_str()) != 0) {
        if (errno == ENOENT) {
            // Replaced or removed at this instant: the next pass takes the file as it is then.
            if (!db::query::fs::File::getFileById(*it.file_id)) it.state = ItemState::Stale;
            return;
        }
        if (errno != EXDEV && errno != EPERM) throw std::system_error(errno, std::generic_category(), "link " + backing.string());
        std::filesystem::copy_file(backing, linked.path());
    }
    const auto size = std::filesystem::file_size(linked.path());
    const auto header = readHeader(linked.path());
    std::string generation;
    unsigned int keyVersion{};
    try {
        const auto opened = vl::vaultfmt::vhf1::openHeader(
            header, {.kind = vl::vaultfmt::vhf1::Kind::FileContent, .vaultUid = ctx.em->vaultUid(), .objectUid = *uid,
                     .generation = std::nullopt},
            ctx.keyLookup());
        generation = content::generationOf(opened.params().salt);
        keyVersion = opened.params().keyVersion;
    } catch (const vl::vaultfmt::vhf1::Error& e) {
        throw storage::IntegrityError(fmt::format("file {}: its local copy is not this vault's sealed content ({})",
                                                  *it.file_id, e.what()));
    }
    const auto plain = content::plaintextSizeOf(size, content::Format::Vhf1);
    if (!plain) throw storage::IntegrityError(fmt::format("file {}: its local copy has no valid sealed size", *it.file_id));

    // The row that describes exactly these bytes, when it still does (a racing write is a newer generation: the item
    // records what was sent, and the next pass sends the newer one).
    std::optional<std::string> hash;
    if (const auto row = db::query::fs::File::getFileById(*it.file_id); row && row->encryption_iv == generation) {
        if (row->size_bytes != *plain)
            throw storage::IntegrityError(fmt::format("file {}: its local copy holds {} bytes, the catalog says {}",
                                                      *it.file_id, *plain, row->size_bytes));
        hash = row->content_hash;
    }
    it.generation = generation;
    it.key_version = keyVersion;
    it.plaintext_bytes = *plain;
    it.content_hash = hash;
    it.size = size;
    it.etag.reset();
    it.version_id.reset();
    it.state = ItemState::Pending;
    it.error.reset();
    Q::updateItem(it);   // the intent, before the PUT

    const auto options = ctx.putOptions(size);
    if (size < storage::s3::Controller::MIN_PART_SIZE) ctx.ctl->uploadObjectWithMetadata(it.object_key, linked.path(), options);
    else ctx.ctl->uploadLargeObject(it.object_key, linked.path(), keys::partSizeFor(size), options);
    const auto put = storage::s3::Controller::lastPutOutcome();
    it.etag = put.etag;
    it.version_id = ctx.versioned ? std::make_optional(put.version_id.value_or("null")) : std::nullopt;
    it.state = ItemState::Sent;
    Q::updateItem(it);

    if (unquoted(put.etag) == layout::s3EtagOf(linked.path(), size)) {
        it.state = ItemState::Verified;
    } else {
        readBack(ctx, it);   // the provider's ETag is not an MD5 (SSE-KMS, some S3-compatible stores)
        it.state = ItemState::Verified;
    }
}

void uploadPending(Ctx& ctx) {
    auto items = Q::items(ctx.vaultId);
    for (auto& it : items) {
        if (it.kind != ItemKind::Content || it.state != ItemState::Pending) continue;
        ctx.checkpoint();
        try {
            sendContent(ctx, it);
        } catch (const RunFailed&) {
            throw;
        } catch (const Interrupted&) {
            throw;
        } catch (const storage::IntegrityError& e) {
            it.state = ItemState::Failed;
            it.error = e.what();
            Q::updateItem(it);
            throw RunFailed(fmt::format("item {} did not authenticate: {}", it.id, e.what()));
        } catch (const std::exception& e) {
            it.error = e.what();
            Q::updateItem(it);
            throw RunFailed(fmt::format("item {} ({}): {}", it.id, it.object_key, e.what()));
        }
        Q::updateItem(it);
        throughput().note(ctx.vaultId, bytesDone(items));
        ctx.step("item:" + std::to_string(it.id));
    }
    deleteStale(ctx);
}

// ---- verification --------------------------------------------------------------------------------------------------------

void verifySample(Ctx& ctx, const unsigned int minimum) {
    std::vector<Item> proven, unproven;
    for (auto& it : Q::items(ctx.vaultId)) {
        if (it.kind != ItemKind::Content || !holdsObject(it)) continue;
        (it.state == ItemState::Verified ? proven : unproven).push_back(it);
    }
    const auto check = [&](Item& it) {
        ctx.checkpoint();
        try {
            readBack(ctx, it);
        } catch (const Interrupted&) {
            throw;
        } catch (const std::exception& e) {
            it.state = ItemState::Failed;
            it.error = std::string("read-back: ") + e.what();
            Q::updateItem(it);
            throw RunFailed(fmt::format("item {} failed its read-back: {}", it.id, e.what()));
        }
        if (it.state != ItemState::Verified) {
            it.state = ItemState::Verified;
            Q::updateItem(it);
        }
    };
    for (auto& it : unproven) check(it);   // sent, never proven (an interrupted run)
    // Without MD5 ETags no PUT was proven by its ETag: every object was read back when it was sent. The sample is
    // read on top of that, always.
    const auto n = sampleSize(proven.size(), minimum);
    std::vector<std::size_t> order(proven.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
    for (std::size_t i = order.size(); i > 1; --i)   // Fisher-Yates with libsodium's uniform draw
        std::swap(order[i - 1], order[randombytes_uniform(static_cast<uint32_t>(i))]);
    for (uint64_t i = 0; i < n; ++i) check(proven[order[i]]);
}

// The second complete listing: exactly the items, nothing foreign, nothing missing. False when the bucket moved under
// the attach (a stray, a missing object): the caller goes around again.
bool verifyListing(Ctx& ctx) {
    const auto listed = listAll(*ctx.ctl, ctx.versioned, ctx.listPages);
    const auto r = reconcile(ctx.vaultId, listed, ctx.versioned);
    if (r.strays || r.missing) {
        log::Registry::cloud()->info("[RemoteAttach] Vault {}: the bucket differs from the items ({} stray version(s), {} "
                                     "missing object(s)); sending again", ctx.vaultId, r.strays, r.missing);
        return false;
    }
    // Sizes and ETags as recorded.
    std::map<std::pair<std::string, std::string>, const storage::s3::ObjectVersionInfo*> byVersion;
    for (const auto& v : listed)
        byVersion[{v.key, ctx.versioned ? (v.version_id.empty() ? std::string("null") : v.version_id) : std::string{}}] = &v;
    for (const auto& it : Q::items(ctx.vaultId)) {
        if (!holdsObject(it) || it.kind == ItemKind::Metadata) continue;
        const auto v = byVersion.find({it.object_key, ctx.versioned ? it.version_id.value_or("null") : std::string{}});
        if (v == byVersion.end()) throw RunFailed(fmt::format("the listing does not show {}", it.object_key));
        if (!sameEtag(it.etag, v->second->etag) || (it.size && *it.size != v->second->size))
            throw RunFailed(fmt::format("the bucket's {} is not the object that was sent (ETag or size differs)",
                                        it.object_key));
    }
    return true;
}

nlohmann::json manifestJson(const mf::PublishReport& report) {
    return {{"epoch", report.published.known.epoch},
            {"root_sha256", report.published.known.root_sha256},
            {"etag", report.published.etag ? nlohmann::json(*report.published.etag) : nlohmann::json(nullptr)},
            {"sids", report.published.sids()},
            {"version_id", report.settled.version_id ? nlohmann::json(*report.settled.version_id) : nlohmann::json(nullptr)},
            {"base_version_id",
             report.settled.base_version_id ? nlohmann::json(*report.settled.base_version_id) : nlohmann::json(nullptr)},
            {"settle_window", report.settled.window}};
}

mf::RootRecord rootRecordOf(const nlohmann::json& j) {
    const auto text = [&](const char* name) -> std::optional<std::string> {
        return j.contains(name) && j.at(name).is_string() ? std::make_optional(j.at(name).get<std::string>())
                                                           : std::nullopt;
    };
    mf::RootRecord rec;
    rec.epoch = j.at("epoch").get<uint64_t>();
    rec.root_sha256 = j.at("root_sha256").get<std::string>();
    rec.etag = text("etag");
    rec.sids = j.value("sids", std::vector<std::string>{});
    rec.version_id = text("version_id");
    rec.base_version_id = text("base_version_id");
    rec.settle_window = j.value("settle_window", std::vector<std::string>{});
    rec.own = true;
    return rec;
}

std::optional<std::string> providerVersion(const Item& it) {
    if (!it.version_id || *it.version_id == "null") return std::nullopt;
    return it.version_id;
}

// The verified content items whose file still exists, as the manifest's and the index's objects.
std::vector<Q::CutoverFile> cutoverFiles(const Ctx& ctx) {
    std::vector<Q::CutoverFile> out;
    for (const auto& it : Q::items(ctx.vaultId)) {
        if (it.kind != ItemKind::Content || it.state != ItemState::Verified || !it.file_id || !it.generation) continue;
        Q::CutoverFile f;
        f.file_id = *it.file_id;
        f.item_id = it.id;
        f.object_key = it.object_key;
        f.generation = *it.generation;
        f.key_version = it.key_version.value_or(0);
        f.plaintext_bytes = it.plaintext_bytes.value_or(0);
        f.content_hash = it.content_hash;
        f.etag = it.etag;
        f.version_id = providerVersion(it);
        f.storage_class = ctx.storageClass;
        out.push_back(std::move(f));
    }
    return out;
}

std::string remoteStrategy() { return config::Registry::get().vaults.s3.default_remote_sync_strategy; }

// The manifest v2: published in the probed mode on top of whatever root an interrupted attempt left, then loaded back
// from the bucket with only the key material and compared with what was sent.
void publishAndVerifyManifest(Ctx& ctx) {
    const auto files = cutoverFiles(ctx);
    db::query::sync::Manifest::CollectOptions collect;
    collect.sync_strategy = remoteStrategy();
    for (const auto& f : files)
        collect.staged.push_back({.object_key = f.object_key, .plaintext_bytes = f.plaintext_bytes,
                                  .generation = f.generation, .etag = f.etag, .version_id = f.version_id,
                                  .storage_class = f.storage_class});
    const auto produced = db::query::sync::Manifest::collect(ctx.vaultId, collect);

    storage::s3::ManifestStore store(ctx.ctl, ctx.mode);
    std::optional<mf::Known> known;
    mf::PublishOptions options;
    options.now = mf::isoTime(std::time(nullptr));
    options.self_node = produced.producer.node_id;
    if (const auto row = Q::get(ctx.vaultId); row && row->manifest) {
        const auto rec = rootRecordOf(*row->manifest);
        known = mf::Known{rec.epoch, rec.root_sha256, rec.version_id};
        options.own_epoch = rec.epoch;
        if (rec.version_id && rec.base_version_id)
            options.settled = mf::SettledWindow{*rec.base_version_id, *rec.version_id, rec.settle_window};
    }
    const auto current = ctx.em->currentKey();
    mf::PublisherCache cache;
    nlohmann::json published;
    mf::Known publishedKnown;
    try {
        const auto report = mf::publish(store, ctx.em->vaultUid(), ctx.keyLookup(), {current.version, current.key},
                                        produced, known, cache, options);
        published = manifestJson(report);
        publishedKnown = report.published.known;
    } catch (const mf::PublishUnsupported& e) {
        throw Refusal("bucket_capability_insufficient", e.what());
    } catch (const mf::ConditionsUnsupported& e) {
        throw RunFailed(std::string("the bucket refused a conditional write its probe found support for; probe it again "
                                    "by starting the attach again: ") + e.what());
    } catch (const std::exception& e) {
        throw RunFailed(std::string("the manifest could not be published: ") + e.what());
    }
    Q::setManifest(ctx.vaultId, published);
    ctx.step("published");

    std::optional<mf::Loaded> fromBucket;
    try {
        mf::LoadOptions load;
        load.use_provider_versions = false;
        fromBucket.emplace(mf::load(store, ctx.em->vaultUid(), ctx.keyLookup(), load));
    } catch (const std::exception& e) {
        throw RunFailed(std::string("the manifest does not load back from the bucket: ") + e.what());
    }
    const auto& loaded = *fromBucket;
    if (!(loaded.known() == publishedKnown))
        throw RunFailed("the bucket's manifest root is not the one that was just published");
    if (!loaded.issues.empty() || !loaded.blind_ranges.empty())
        throw RunFailed("the bucket's manifest does not load completely (a segment is missing or unreadable)");
    std::map<std::string, const mf::Entry*> byUid;
    for (const auto& e : loaded.content.entries) byUid[e.uid] = &e;
    for (const auto& f : files) {
        const auto uid = keys::uidOfContentKey(f.object_key);
        const auto it = uid ? byUid.find(vl::keykit::toBase32(*uid)) : byUid.end();
        if (it == byUid.end()) {
            if (!db::query::fs::File::getFileById(f.file_id)) continue;   // deleted since it was sent: an orphan
            throw RunFailed(fmt::format("the bucket's manifest does not name file {}", f.file_id));
        }
        const auto& entry = *it->second;
        if (entry.generation != std::optional<std::string>(hexOfGeneration(f.generation)) || !entry.object ||
            entry.object->etag != f.etag)
            throw RunFailed(fmt::format("the bucket's manifest names another object for file {}", f.file_id));
    }
    for (const auto& f : Q::liveFiles(ctx.vaultId))
        if (f->object_uid && !byUid.contains(vl::keykit::toBase32(*f->object_uid)) &&
            db::query::fs::File::getFileById(f->id))
            throw RunFailed(fmt::format("the bucket's manifest does not name file {} (created while it was published); "
                                        "start the attach again", f->id));

    // What the publish wrote (layout hint, segments, root) becomes items: an abort deletes exactly these.
    const auto listed = listAll(*ctx.ctl, ctx.versioned, ctx.listPages);
    (void)reconcile(ctx.vaultId, listed, ctx.versioned);
}

// ---- preconditions and the bucket ---------------------------------------------------------------------------------------

std::string versionList(const std::vector<unsigned int>& versions) {
    std::string out;
    for (const auto v : versions) out += (out.empty() ? "" : ", ") + std::to_string(v);
    return out;
}

std::optional<storage::s3::ProbeResult> storedProbeOf(const Row& row) {
    if (!row.bucket_probe) return std::nullopt;
    try {
        return storage::s3::probeResultFromJson(*row.bucket_probe);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void requireUnprotected(const model::APIKey& key, const std::string& bucket) {
    if (storage::upstream::guard::isProtected(storage::upstream::identityFor(key, bucket)))
        throw Refusal("bucket_protected", "bucket '" + bucket + "' has a protection lock; unprotect it to attach it");
}

Ctx makeCtx(const Row& row, const RunDeps& deps) {
    Ctx ctx;
    ctx.vaultId = row.vault_id;
    ctx.row = row;
    ctx.deps = &deps;
    ctx.tmpDir = tmpDirFor(row.vault_id);
    if (row.usage) ctx.usageBase = *row.usage;
    const auto& manager = runtime::Deps::get().storageManager;
    ctx.engine = manager ? manager->getEngine(row.vault_id) : nullptr;
    if (!ctx.engine || !ctx.engine->vault) throw RunFailed("the vault is not loaded on this host");
    ctx.em = ctx.engine->encryptionManager;
    if (!ctx.em) throw RunFailed("the vault's encryption key is not loaded");
    if (!row.api_key_id) throw RunFailed("the API key of the attach no longer exists");
    ctx.key = apiKeyOf(*row.api_key_id);
    if (!ctx.key) throw RunFailed("the API key of the attach no longer exists");
    ctx.profile = storage::s3::provider::resolve(ctx.key->provider);
    const auto resolution = ctx.profile->normalizeStorageTier(row.storage_tier_id);
    if (!resolution.ok) throw RunFailed(resolution.error);
    ctx.tier = resolution.resolved;
    if (ctx.tier && ctx.tier->wire_class) ctx.storageClass = ctx.tier->wire_class;
    ctx.ctl = controllerFor(row.vault_id, *row.api_key_id, row.bucket);
    ctx.versioned = row.versioned.value_or(!isR2(ctx.profile));
    if (const auto probe = storedProbeOf(row)) {
        ctx.probe = *probe;
        ctx.mode = probe->capability;
    }
    return ctx;
}

void saveUsage(const Ctx& ctx) {
    if (!ctx.ctl) return;
    try {
        const auto m = ctx.ctl->requestMetrics();
        const auto base = [&](const char* name) { return ctx.usageBase.value(name, uint64_t{0}); };
        Q::setUsage(ctx.vaultId, {{"list_requests", base("list_requests") + m.list_requests},
                                  {"head_requests", base("head_requests") + m.head_requests},
                                  {"get_requests", base("get_requests") + m.get_requests},
                                  {"put_requests", base("put_requests") + m.put_requests},
                                  {"delete_requests", base("delete_requests") + m.delete_requests},
                                  {"downloaded_bytes", base("downloaded_bytes") + m.downloaded_bytes},
                                  {"uploaded_bytes", base("uploaded_bytes") + m.uploaded_bytes}});
    } catch (const std::exception& e) {
        log::Registry::cloud()->warn("[RemoteAttach] Vault {}: usage not recorded: {}", ctx.vaultId, e.what());
    }
}

// preparing: the vault and the bucket as they are now, the recipients' envelopes, the items, and on a fresh start the
// estimate and the price preflight (managed storage: the account key's grant first, and the quota instead of a price).
void prepare(Ctx& ctx) {
    const bool managed = ctx.row.origin == "cloud";
    if (managed) requireManagedReady(ctx.vaultId, std::nullopt);
    requireVaultReady(*ctx.engine);
    const auto check = requireBucketUsable(ctx.vaultId, *ctx.row.api_key_id, ctx.row.bucket, *ctx.ctl,
                                           storedProbeOf(ctx.row));
    ctx.probe = check.probe;
    ctx.mode = check.probe.capability;
    ctx.versioned = check.versioned;
    ctx.listPages = check.list_pages;
    const auto publish = check.probe.capability == mf::WriteCapability::Conditional ? "conditional" : "version_log";
    Q::setProbe(ctx.vaultId, std::string(publish), storage::s3::toJson(check.probe), check.versioned);

    (void)stageEnvelopes(ctx);
    (void)planItems(ctx);
    deleteStale(ctx);

    if (ctx.row.state == State::Preparing) {
        auto estimate = estimateOf(ctx, Q::items(ctx.vaultId), ctx.deps->sampleMinimum);
        if (managed)
            requireManagedReady(ctx.vaultId, estimate);
        else if (ctx.deps->pricePreflight)
            ctx.deps->pricePreflight({.vault_id = ctx.vaultId, .api_key_id = *ctx.row.api_key_id,
                                      .storage_tier_id = ctx.row.storage_tier_id,
                                      .accept_unpriced = ctx.row.accept_unpriced},
                                     estimate);
        Q::setEstimate(ctx.vaultId, toJson(estimate));
    }
    ctx.step("prepared");
}

// The cutover transaction's input beside the files.
Q::CutoverInput cutoverInput(const Ctx& ctx) {
    Q::CutoverInput in;
    const sync::model::RemotePolicy defaults;
    const auto& s3 = config::Registry::get().vaults.s3;
    in.remote_strategy = s3.default_remote_sync_strategy;
    in.remote_conflict_policy = s3.default_remote_conflict_policy;
    in.budget = {.max_list_requests = defaults.s3_request_budget.max_list_requests,
                 .max_head_requests = defaults.s3_request_budget.max_head_requests,
                 .max_get_requests = defaults.s3_request_budget.max_get_requests,
                 .max_put_requests = defaults.s3_request_budget.max_put_requests,
                 .max_copy_requests = defaults.s3_request_budget.max_copy_requests,
                 .max_delete_requests = defaults.s3_request_budget.max_delete_requests,
                 .max_downloaded_bytes = defaults.s3_request_budget.max_downloaded_bytes};
    if (defaults.max_remote_index_age) in.max_remote_index_age_seconds = defaults.max_remote_index_age->count();
    in.files = cutoverFiles(ctx);
    const auto row = Q::get(ctx.vaultId);
    if (!row || !row->manifest) throw RunFailed("the attach has no published manifest root");
    in.root = rootRecordOf(*row->manifest);
    // A bucket the upstream control plane already knows and nothing holds is bound with the ownership it records.
    const auto identity = storage::upstream::identityFor(*ctx.key, ctx.row.bucket);
    if (identity.account_ref)
        if (const auto known = db::query::upstream::Bucket::getByIdentity(identity.provider, *identity.account_ref,
                                                                          identity.bucket);
            known && !known->vault_id)
            in.upstream_bucket_id = known->id;
    return in;
}

struct PassLease {
    const RunDeps& deps;
    uint32_t vaultId;
    bool held{false};
    PassLease(const RunDeps& d, const uint32_t id) : deps(d), vaultId(id) {
        held = !deps.tryAcquirePass || deps.tryAcquirePass(vaultId);
    }
    ~PassLease() {
        if (held && deps.releasePass) deps.releasePass(vaultId);
    }
    PassLease(const PassLease&) = delete;
    PassLease& operator=(const PassLease&) = delete;
};

// After the cutover committed (also after a restart found the row in cutover): the engine swap, the orphans, the first
// pass. Every step is idempotent; the row is done once a first pass ended.
void finishCutover(const uint32_t vaultId, const RunDeps& deps, RunResult& result, const bool justCommitted) {
    const auto row = Q::get(vaultId);
    if (!row || row->state != State::Cutover) return;
    result.state = State::Cutover;
    try {
        {
            const PassLease lease(deps, vaultId);
            if (!lease.held) {
                result.busy = true;
                return;
            }
            if (deps.swapEngine) deps.swapEngine(vaultId);
            if (deps.afterStep) deps.afterStep("swapped");

            const auto items = Q::items(vaultId);
            if (justCommitted) {
                // The provider versions this attach wrote, for file recovery's version index (as every own upload).
                for (const auto& it : items) {
                    if (it.kind != ItemKind::Content || it.state != ItemState::Verified || !providerVersion(it)) continue;
                    auto generation = std::make_shared<fs::model::File>();
                    generation->vault_id = vaultId;
                    generation->object_uid = keys::uidOfContentKey(it.object_key);
                    generation->encryption_iv = it.generation.value_or("");
                    generation->encrypted_with_key_version = it.key_version.value_or(0);
                    generation->content_hash = it.content_hash;
                    generation->size_bytes = it.plaintext_bytes.value_or(0);
                    generation->remote_encrypted = true;
                    recovery::provider::noteOwnWrite({.vault_id = vaultId, .key = it.object_key, .is_delete = false,
                                                      .object_size = it.size, .etag = it.etag,
                                                      .version_id = it.version_id, .file = generation});
                }
            }

            // An envelope that committed inside the cutover's own window still has its bytes in the database and
            // no copy in the bucket: copied there now, read back, and only then cleared.
            if (const auto held = Q::envelopes(vaultId);
                std::ranges::any_of(held, [](const Q::StoredEnvelope& e) { return !e.bytes.empty(); })) {
                if (!row->api_key_id) throw std::runtime_error("the API key no longer exists");
                const auto mode = row->manifest_publish == std::optional<std::string>("version_log")
                    ? mf::WriteCapability::VersionLog : mf::WriteCapability::Conditional;
                storage::s3::ManifestStore store(controllerFor(vaultId, *row->api_key_id, row->bucket), mode);
                for (const auto& e : held) {
                    if (e.bytes.empty()) continue;
                    const auto objectKey = kev1::objectKey(e.kid);
                    try {
                        (void)store.putOnce(objectKey, e.bytes);
                    } catch (const mf::PreconditionFailed&) {
                        // The name is the envelope's hash: what is there is compared below.
                    }
                    const auto stored = store.get(objectKey, std::nullopt);
                    if (!stored || stored->bytes != e.bytes)
                        throw std::runtime_error("the recovery envelope " + e.kid + " did not reach the bucket");
                    Q::clearEnvelopeBytes(vaultId, e.kid);
                }
            }

            // Orphans: objects of files deleted between their upload and the cutover. Before any sync pass can list them.
            uint64_t failed = 0;
            std::string firstError;
            std::shared_ptr<storage::s3::Controller> ctl;
            for (auto it : items) {
                if (it.kind != ItemKind::Orphan || it.state == ItemState::Deleted) continue;
                try {
                    if (!ctl) {
                        if (!row->api_key_id) throw std::runtime_error("the API key no longer exists");
                        ctl = controllerFor(vaultId, *row->api_key_id, row->bucket);
                    }
                    (void)removeObject(*ctl, it, row->versioned.value_or(true));
                    it.state = ItemState::Deleted;
                    it.error.reset();
                } catch (const std::exception& e) {
                    it.error = e.what();
                    if (!failed++) firstError = e.what();
                }
                Q::updateItem(it);
            }
            if (failed) {
                Q::setError(vaultId, fmt::format("orphan cleanup: {} object(s) of deleted files could not be deleted yet: {}",
                                                 failed, firstError));
                result.error = firstError;
                return;   // retried; no pass is started while a deleted file's object could be listed
            }
        }
        const auto pass = deps.firstPass ? deps.firstPass(vaultId, row->cutover_at.value_or(0))
                                         : std::make_optional(nlohmann::json{{"status", "not_run"}});
        if (!pass) return;   // still running: the next poll looks again
        Q::markDone(vaultId, *pass);
        throughput().forget(vaultId);
        std::error_code ec;
        std::filesystem::remove_all(tmpDirFor(vaultId), ec);
        result.state = State::Done;
        log::Registry::cloud()->info("[RemoteAttach] Vault {}: attached; first pass {}", vaultId,
                                     pass->value("status", std::string("?")));
    } catch (const std::exception& e) {
        // The vault is an S3 vault already: what is left is retried, never rolled back.
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
    vh::audit::record({.action = "vault.remote.failed", .outcome = vh::audit::Outcome::Failure, .actor_id = std::nullopt,
                       .actor = "RemoteAttachService", .vault_id = vaultId, .entry_id = std::nullopt,
                       .details = nlohmann::json::object()},
                      fmt::format("[RemoteAttach] Vault {}: attaching the remote failed before the cutover; the vault is "
                                  "still local and untouched (vh vault remote status {} names the reason)",
                                  vaultId, vaultId));
}

}

// ---- the bucket ---------------------------------------------------------------------------------------------------------

void setControllerFactoryForTesting(ControllerFactory f) {
    if (!vh::paths::testMode) throw std::logic_error("setControllerFactoryForTesting outside test mode");
    std::scoped_lock lock(remote_detail::factoryMutex);
    remote_detail::factory = std::move(f);
}

std::shared_ptr<storage::s3::Controller> controllerFor(const uint32_t vaultId, const uint32_t apiKeyId,
                                                       const std::string& bucket) {
    std::shared_ptr<storage::s3::Controller> controller;
    {
        std::scoped_lock lock(remote_detail::factoryMutex);
        if (remote_detail::factory) controller = remote_detail::factory(apiKeyId, bucket);
    }
    if (!controller) {
        const auto key = remote_detail::apiKeyOf(apiKeyId);
        if (!key) throw std::runtime_error("the API key no longer exists");
        controller = std::make_shared<storage::s3::Controller>(key, bucket);
    }
    controller->setUsageVault(vaultId);
    // opaque_v1 from the first request (spec 01 §4.3): no name, no metadata, only o/<uid> and .vaulthalla/ keys.
    controller->setOpaqueLayout(true);
    return controller;
}

// ---- managed storage ----------------------------------------------------------------------------------------------------

namespace remote_managed_detail {
std::mutex hooksMutex;
ManagedHooks hooks;
}

void setManagedHooks(ManagedHooks h) {
    std::scoped_lock lock(remote_managed_detail::hooksMutex);
    remote_managed_detail::hooks = std::move(h);
}

void requireManagedReady(const uint32_t vaultId, const std::optional<Estimate>& estimate) {
    ManagedHooks h;
    {
        std::scoped_lock lock(remote_managed_detail::hooksMutex);
        h = remote_managed_detail::hooks;
    }
    if (!h.accountKeyGrant)
        throw Refusal("account_key_unconfirmed", "managed storage needs the account recovery key confirmed on this server");
    if (!estimate) h.accountKeyGrant(vaultId);
    else if (h.quotaPreflight) h.quotaPreflight(vaultId, *estimate);
}

// ---- preconditions --------------------------------------------------------------------------------------------------

void requireVaultReady(const storage::Engine& engine) {
    namespace d = remote_detail;
    using KeyQ = db::query::vault::Key;
    const auto& vault = engine.vault;
    if (!vault) throw Refusal("vault_unavailable", "the vault is not loaded on this host");
    if (vault->type != model::VaultType::Local)
        throw Refusal("not_local", "vault '" + vault->name + "' is not a local vault: only a local vault attaches a remote");
    const auto em = engine.encryptionManager;
    if (!em) throw Refusal("vault_unavailable", "the vault's encryption key is not loaded");
    if (em->rotation_in_progress() || KeyQ::keyRotationInProgress(vault->id))
        throw Refusal("key_rotation_running", "a key rotation of the vault is in progress; attach once it has finished");
    if (KeyQ::runningSalvage(vault->id))
        throw Refusal("key_salvage_running", "a key salvage of the vault is running; attach once it has finished");

    const auto legacy = d::Q::legacyContent(vault->id);
    if (legacy.any())
        throw Refusal("legacy_content",
                      fmt::format("the vault still holds content in a legacy format ({} file(s) and {} recovery blob(s) "
                                  "in gcm0, {} plaintext file(s)); the format conversion finishes first (vh vault format "
                                  "status {})", legacy.gcm0_files, legacy.gcm0_blobs, legacy.plain_files, vault->id));

    std::set<unsigned int> needed;
    for (const auto v : KeyQ::liveFileKeyVersions(vault->id)) needed.insert(v);
    for (const auto v : KeyQ::recoveryReferencedKeyVersions(vault->id)) needed.insert(v);
    needed.insert(em->get_key_version());
    needed.erase(0);
    std::vector<unsigned int> notHeld, notAttested;
    const auto unattested = d::Q::unattestedKeyVersions(vault->id);
    for (const auto v : needed) {
        if (!em->hasKeyVersion(v)) notHeld.push_back(v);
        else if (std::ranges::find(unattested, v) != unattested.end()) notAttested.push_back(v);
    }
    if (!notHeld.empty())
        throw Refusal("key_version_missing",
                      "the vault's content is sealed under key version(s) " + d::versionList(notHeld) +
                          ", which this host doesn't hold; import them (vh vault keys import) first");
    if (!notAttested.empty())
        throw Refusal("key_version_unattested",
                      "key version(s) " + d::versionList(notAttested) + " have no attestation recorded yet (vh vault keys "
                      "status " + std::to_string(vault->id) + "); the daemon records it shortly after start");

    // Precondition 6 (BYOS): once its content is in a bucket, the vault needs recovery material independent of this
    // host. A recovery recipient covering every needed version, or a verified export of the current key version.
    const auto m = envelopes::material(vault->id);
    if (m.state != envelopes::kMaterialRecipient && m.state != envelopes::kMaterialExport)
        throw Refusal("recovery_material_missing",
                      "the vault has no recovery material independent of this host: enroll a recovery recipient (vh "
                      "vault keys recipient add) or export the key (vh vault keys export) first" +
                          (m.recipients > 0 && !m.uncovered.empty()
                               ? std::string("; its recipient's envelopes are missing for some key versions")
                               : std::string{}));
}

// Whether the bucket holds this vault's own earlier copy (attach-remote question 6): its manifest root loads and
// authenticates with this vault's uid and its own keys. Read-only. Anything else (no root, another vault's, a root
// that doesn't open) is false.
bool holdsThisVault(const uint32_t vaultId, const storage::s3::Controller& controller) {
    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(vaultId) : nullptr;
    if (!engine || !engine->vault || !engine->vault->uid || !engine->encryptionManager) return false;
    const auto em = engine->encryptionManager;
    const vl::vaultfmt::vhf1::KeyLookup keys = [em](const uint32_t v) -> vl::vaultfmt::vhf1::KeyPtr {
        try {
            return em->historicalKeySnapshot(v);
        } catch (const std::exception&) {
            return nullptr;
        }
    };
    // Not owned: the store reads through the caller's controller for the length of this call.
    const std::shared_ptr<storage::s3::Controller> view(std::shared_ptr<void>{},
                                                        const_cast<storage::s3::Controller*>(&controller));
    for (const auto mode : {vl::vaultfmt::manifest::WriteCapability::Conditional, vl::vaultfmt::manifest::WriteCapability::VersionLog}) {
        try {
            storage::s3::ManifestStore store(view, mode);
            (void)vl::vaultfmt::manifest::load(store, *engine->vault->uid, keys);
            return true;
        } catch (const std::exception&) {
        }
    }
    return false;
}

BucketCheck requireBucketUsable(const uint32_t vaultId, const uint32_t apiKeyId, const std::string& bucket,
                                const storage::s3::Controller& controller,
                                const std::optional<storage::s3::ProbeResult>& storedProbe) {
    namespace d = remote_detail;
    const auto key = d::apiKeyOf(apiKeyId);
    if (!key) throw Refusal("api_key_missing", "the API key no longer exists");
    d::requireUnprotected(*key, bucket);
    if (const auto holder = d::Q::bucketHolder(apiKeyId, bucket, vaultId))
        throw Refusal("bucket_in_use", fmt::format("bucket '{}' is already the storage of vault {} (or reserved by its "
                                                   "attach) with this API key", bucket, *holder));

    BucketCheck out;
    out.versioned = !d::isR2(storage::s3::provider::resolve(key->provider));
    std::vector<storage::s3::ObjectVersionInfo> listed;
    try {
        listed = d::listAll(controller, out.versioned, out.list_pages);
    } catch (const storage::upstream::BucketProtected& e) {
        throw Refusal("bucket_protected", e.what());
    } catch (const std::exception& e) {
        throw Refusal("bucket_listing_failed",
                      std::string("the bucket could not be listed completely, so it can't be shown to be empty: ") + e.what());
    }
    try {
        (void)d::reconcile(vaultId, listed, out.versioned);
    } catch (const Refusal& e) {
        // The vault's own earlier bucket (switched off, then on again): recognised, never attached over. Rejoining it
        // means reconciling what only the bucket holds, which is a restore; nothing in it is deleted to make room.
        if (e.code() == "bucket_not_empty" && holdsThisVault(vaultId, controller))
            throw Refusal("bucket_holds_this_vault",
                          "the bucket holds this vault's own earlier copy (its manifest opens with this vault's keys), "
                          "which an attach never writes over: restore the vault from it (`vh vault recover`), or empty "
                          "the bucket first (for managed storage: the account holder deletes it in the portal, and the "
                          "next switch on gets a new one)");
        throw;
    }

    if (storedProbe && storedProbe->capability != vl::vaultfmt::manifest::WriteCapability::Unknown) {
        out.probe = *storedProbe;
    } else {
        try {
            out.probe = storage::s3::probeBucket(controller);
        } catch (const storage::s3::ProbeFailed& e) {
            throw Refusal("bucket_probe_failed", std::string("the bucket's write capability could not be probed: ") + e.what());
        }
    }
    if (out.probe.capability != vl::vaultfmt::manifest::WriteCapability::Conditional &&
        out.probe.capability != vl::vaultfmt::manifest::WriteCapability::VersionLog)
        throw Refusal("bucket_capability_insufficient",
                      "the bucket neither honours conditional writes nor keeps object versions (or not If-Match on "
                      "GET), so the vault's encrypted manifest can't be published on it: " + out.probe.reason);
    return out;
}

// ---- progress -----------------------------------------------------------------------------------------------------------

Progress progressOf(const Row& row, const std::vector<Item>& items) {
    Progress p;
    p.phase = std::string(to_string(row.state));
    p.passes = row.passes;
    p.updated_at = row.updated_at;
    for (const auto& it : items) {
        if (it.kind != ItemKind::Content) continue;
        if (it.state == ItemState::Stale || it.state == ItemState::Deleted) continue;
        ++p.files_total;
        p.bytes_total += it.size.value_or(0);
        if (remote_detail::holdsObject(it)) {
            ++p.files_done;
            p.bytes_done += it.size.value_or(0);
        }
    }
    if (row.state == State::Uploading || row.state == State::CatchingUp) {
        p.bytes_per_second = remote_detail::throughput().rate(row.vault_id);
        if (p.bytes_per_second && *p.bytes_per_second > 0)
            p.eta_seconds = (p.bytes_total - std::min(p.bytes_total, p.bytes_done)) / *p.bytes_per_second;
    }
    return p;
}

// ---- the run -----------------------------------------------------------------------------------------------------------

RunResult run(const uint32_t vaultId, const RunDeps& deps) {
    namespace d = remote_detail;
    RunResult result;
    auto row = d::Q::get(vaultId);
    if (!row) throw std::invalid_argument("the vault has no remote attach");
    result.state = row->state;
    if (row->state == State::Done || row->state == State::Failed || row->state == State::Aborted) return result;
    if (row->state == State::Cutover) {
        d::finishCutover(vaultId, deps, result, false);
        return result;
    }
    if (row->abort_requested_at) return result;   // the service aborts it

    std::optional<d::Ctx> ctx;
    try {
        ctx.emplace(d::makeCtx(*row, deps));
        // Verified already and only the cutover left (the lease was busy, or a restart): straight to it.
        const bool verified = row->state == State::Verifying && row->verified_at.has_value();
        for (int round = 0; !verified && round < 4; ++round) {
            if (round == 3) throw d::RunFailed("the bucket kept changing under the attach (stray or missing objects)");
            d::prepare(*ctx);
            d::Q::setState(vaultId, State::Uploading);
            ctx->row.state = State::Uploading;
            d::uploadPending(*ctx);
            ctx->step("uploaded");

            d::Q::setState(vaultId, State::CatchingUp);
            for (unsigned int pass = 1; pass <= std::max(1u, deps.maxPasses); ++pass) {
                const auto pending = d::planItems(*ctx);
                d::Q::setPasses(vaultId, pass);
                if (!pending) {
                    d::deleteStale(*ctx);
                    break;
                }
                d::uploadPending(*ctx);
                ctx->step("pass:" + std::to_string(pass));
            }

            d::Q::setState(vaultId, State::Verifying);
            d::Q::clearVerified(vaultId);
            d::deleteStale(*ctx);
            if (!d::verifyListing(*ctx)) continue;
            ctx->step("listed");
            d::verifySample(*ctx, deps.sampleMinimum);
            ctx->step("sampled");
            d::verifyEnvelopes(*ctx);
            d::publishAndVerifyManifest(*ctx);
            d::Q::markVerified(vaultId);
            d::saveUsage(*ctx);
            ctx->step("verified");
            break;
        }

        // The cutover: one transaction under the vault's pass lease, the preconditions checked again.
        const d::PassLease lease(deps, vaultId);
        if (!lease.held) {
            result.state = State::Verifying;
            result.busy = true;
            return result;
        }
        ctx->checkpoint();
        requireVaultReady(*ctx->engine);
        if (d::stageEnvelopes(*ctx) > 0) {
            // A key version appeared since the verification (its envelopes just went up): verified again next run.
            d::Q::clearVerified(vaultId);
            d::Q::setState(vaultId, State::Preparing);
            result.state = State::Preparing;
            return result;
        }
        ctx->step("staged");
        const auto in = d::cutoverInput(*ctx);
        const auto outcome = d::Q::cutover(vaultId, in);
        if (!outcome.done && outcome.envelopes_unstaged) {
            // A recipient was enrolled (or a key version wrapped) after the envelopes were staged: nothing changed,
            // and the next run stages and verifies it before cutting over.
            d::Q::clearVerified(vaultId);
            d::Q::setState(vaultId, State::Preparing);
            result.state = State::Preparing;
            return result;
        }
        if (!outcome.done) throw d::RunFailed("cutover refused: " + outcome.refused);
        vh::audit::record({.action = "vault.remote.cutover", .outcome = vh::audit::Outcome::Success,
                           .actor_id = std::nullopt, .actor = "RemoteAttachService", .vault_id = vaultId,
                           .entry_id = std::nullopt,
                           .details = {{"files", static_cast<int64_t>(outcome.indexed)},
                                       {"orphans", static_cast<int64_t>(outcome.orphans)},
                                       {"publish", ctx->row.manifest_publish.value_or(std::string(
                                                       vl::vaultfmt::manifest::to_string(ctx->mode)))},
                                       {"gateway_remote_cache", outcome.gateway_flipped}}},
                          fmt::format("[RemoteAttach] Vault {} cut over to its bucket: {} file(s) indexed, {} orphan(s); "
                                      "the vault is an encrypted S3 vault from here on", vaultId, outcome.indexed,
                                      outcome.orphans));
        ctx->step("cutover");
        result.state = State::Cutover;
    } catch (const d::Interrupted&) {
        if (ctx) d::saveUsage(*ctx);
        result.stopped = true;
        result.state = d::Q::get(vaultId).value_or(*row).state;
        return result;   // picked up again by the service (resumed, or aborted)
    } catch (const Refusal& e) {
        if (ctx) d::saveUsage(*ctx);
        d::recordFailure(vaultId, e.code() + ": " + e.what(), result);
        return result;
    } catch (const std::exception& e) {
        if (ctx) d::saveUsage(*ctx);
        d::recordFailure(vaultId, e.what(), result);
        return result;
    }
    // The lease is released here; finishCutover takes it again for the swap and the orphans.
    d::finishCutover(vaultId, deps, result, true);
    return result;
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
    deps.pricePreflight = [](const PricePreflight& request, Estimate& estimate) {
        namespace d = remote_detail;
        namespace pricing = storage::s3::pricing;
        const auto key = d::apiKeyOf(request.api_key_id);
        if (!key) throw std::runtime_error("the API key no longer exists");
        pricing::PriceSubject subject;
        subject.key = key;
        subject.profile = storage::s3::provider::resolve(key->provider);
        const auto resolution = subject.profile->normalizeStorageTier(request.storage_tier_id);
        if (!resolution.ok) throw std::runtime_error(resolution.error);
        subject.tier = resolution.resolved;

        sync::model::S3CostEstimate planned;
        planned.list_requests = estimate.list_requests;
        planned.head_requests = estimate.head_requests;
        planned.get_requests = estimate.get_requests + estimate.readback_worst_case_gets;
        planned.put_requests = estimate.put_requests + estimate.metadata_puts;
        planned.delete_requests = estimate.delete_requests;
        planned.planned_body_download_bytes = estimate.download_bytes + estimate.readback_worst_case_bytes;
        planned.planned_upload_bytes = estimate.upload_bytes;
        planned.remote_index_objects = estimate.files;
        const auto report = pricing::estimatePlannedS3Sync(subject, planned,
                                                           {.mode = pricing::PriceEstimateMode::BudgetConservative});
        estimate.priced = report.available;
        if (report.available) estimate.estimated_cost = report.estimated_cost;
        if (!report.available && !request.accept_unpriced)
            throw Refusal("unpriced", "the attach's cost can't be priced (" + report.unavailable_reason +
                                          "); start it again with --accept-unpriced to accept that");
        recovery::provider::metering::PriceReservation reservation(request.vault_id, subject, planned, "remote_attach",
                                                                   "vault:" + std::to_string(request.vault_id));
        reservation.commit();
    };
    deps.swapEngine = [](const uint32_t vaultId) {
        const auto& manager = runtime::Deps::get().storageManager;
        if (!manager) throw std::runtime_error("the storage manager is not available");
        manager->reloadEngine(vaultId);
        if (const auto& controller = runtime::Deps::get().syncController) controller->refreshEngines();
    };
    deps.firstPass = [](const uint32_t vaultId, const std::time_t cutoverAt) -> std::optional<nlohmann::json> {
        using Event = sync::model::Event;
        if (const auto ev = db::query::sync::Event::getLatest(vaultId); ev && ev->timestamp_begin >= cutoverAt) {
            if (!ev->hasEnded()) return std::nullopt;
            return nlohmann::json{{"status", std::string(Event::toString(ev->status))},
                                  {"started_at", ev->timestamp_begin},
                                  {"finished_at", ev->timestamp_end},
                                  {"error", ev->error_message.empty() ? nlohmann::json(nullptr)
                                                                      : nlohmann::json(ev->error_message)}};
        }
        const auto& controller = runtime::Deps::get().syncController;
        if (!controller || controller->runNow(vaultId) == sync::Controller::RunNowResult::NoTask)
            return nlohmann::json{{"status", "not_run"}, {"started_at", nullptr}, {"finished_at", nullptr},
                                  {"error", "the vault has no sync task (sync disabled?)"}};
        return std::nullopt;
    };
    deps.maxPasses = config::Registry::get().vaults.remote_attach.max_passes;
    return deps;
}

// ---- abort -------------------------------------------------------------------------------------------------------------

AbortResult runAbort(const uint32_t vaultId, const std::function<bool()>& stop) {
    namespace d = remote_detail;
    AbortResult out;
    const auto row = d::Q::get(vaultId);
    if (!row) throw std::invalid_argument("the vault has no remote attach");
    if (!beforeCutover(row->state)) throw std::runtime_error("the attach has cut over (or was aborted): nothing to abort");
    d::Q::setState(vaultId, State::Failed, "abort in progress");

    std::shared_ptr<storage::s3::Controller> ctl;
    bool versioned = row->versioned.value_or(true);
    std::string blocked;
    try {
        if (!row->api_key_id) throw std::runtime_error("the API key of the attach no longer exists");
        const auto key = d::apiKeyOf(*row->api_key_id);
        if (!key) throw std::runtime_error("the API key of the attach no longer exists");
        if (!row->versioned) versioned = !d::isR2(storage::s3::provider::resolve(key->provider));
        ctl = controllerFor(vaultId, *row->api_key_id, row->bucket);
        // Strays of interrupted PUTs and the objects of an interrupted publish sit at keys the attach recorded: they
        // become items first, so that everything deleted below is something the attach recorded.
        uint64_t pages = 0;
        (void)d::reconcile(vaultId, d::listAll(*ctl, versioned, pages), versioned);
    } catch (const std::exception& e) {
        blocked = e.what();
    }

    for (auto it : d::Q::items(vaultId)) {
        if (it.state == ItemState::Deleted) continue;
        if (stop && stop()) {
            ++out.remaining;
            continue;
        }
        const auto name = it.object_key + (it.version_id ? "@" + *it.version_id : std::string{});
        try {
            if (it.etag || it.version_id) {
                if (!ctl) throw std::runtime_error(blocked.empty() ? "the bucket is not reachable" : blocked);
                (void)d::removeObject(*ctl, it, versioned);
            }
            it.state = ItemState::Deleted;
            it.error.reset();
            ++out.deleted;
        } catch (const std::exception& e) {
            it.error = e.what();
            ++out.remaining;
            if (out.refused.size() < 20) out.refused.push_back(name + ": " + e.what());
        }
        d::Q::updateItem(it);
    }

    if (out.remaining == 0) {
        d::Q::finishAbort(vaultId);
        d::throughput().forget(vaultId);
        std::error_code ec;
        std::filesystem::remove_all(d::tmpDirFor(vaultId), ec);
        out.state = State::Aborted;
    } else {
        d::Q::setError(vaultId, fmt::format("abort: {} object(s) could not be deleted yet and stay listed (retried){}",
                                            out.remaining, out.refused.empty() ? std::string{} : ": " + out.refused.front()));
        out.state = State::Failed;
    }
    vh::audit::record({.action = "vault.remote.aborted",
                       .outcome = out.remaining ? vh::audit::Outcome::Failure : vh::audit::Outcome::Success,
                       .actor_id = row->abort_requested_by, .actor = "RemoteAttachService", .vault_id = vaultId,
                       .entry_id = std::nullopt,
                       .details = {{"deleted", static_cast<int64_t>(out.deleted)},
                                   {"remaining", static_cast<int64_t>(out.remaining)}}},
                      fmt::format("[RemoteAttach] Vault {}: abort deleted {} recorded object(s); {} remain; the vault "
                                  "was never changed", vaultId, out.deleted, out.remaining));
    return out;
}

// ---- key rotation waits ------------------------------------------------------------------------------------------------

bool attachInProgress(const uint32_t vaultId) {
    const auto row = remote_detail::Q::get(vaultId);
    return row && running(row->state);
}

bool queueRotation(const uint32_t vaultId) { return remote_detail::Q::queueRotation(vaultId); }

}
