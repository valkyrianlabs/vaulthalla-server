// The bucket layout migration path_v0 -> opaque_v1 (#373): see vault/LayoutMigration.hpp for the protocol.

#include "vault/LayoutMigration.hpp"

#include "audit/Trail.hpp"
#include "crypto/vhf1/Format.hpp"
#include "db/query/recovery/Generation.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/ObjectIdentity.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/LayoutMigration.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "log/Registry.hpp"
#include "platform/Durable.hpp"
#include "recovery/Store.hpp"
#include "recovery/provider/Versions.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/ObjectKeys.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/s3/pricing/PriceEstimate.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/Controller.hpp"
#include "sync/manifest/Content.hpp"
#include "sync/manifest/Document.hpp"
#include "sync/model/Action.hpp"
#include "sync/model/Baseline.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/FormatConversion.hpp"
#include "vault/FormatConversionService.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <fmt/format.h>
#include <openssl/evp.h>
#include <sodium.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <set>
#include <tuple>
#include <stdexcept>
#include <system_error>
#include <unistd.h>

namespace vh::vault::layout {

// ---- names ------------------------------------------------------------------------------------------------------------

std::string_view to_string(const State state) {
    switch (state) {
    case State::Copying: return "copying";
    case State::Verifying: return "verifying";
    case State::Failed: return "failed";
    case State::CutOver: return "cut_over";
    case State::Cleanup: return "cleanup";
    case State::CleanupBlocked: return "cleanup_blocked";
    case State::Complete: return "complete";
    }
    return "failed";
}

State stateFromString(const std::string_view text) {
    for (const auto s : {State::Copying, State::Verifying, State::Failed, State::CutOver, State::Cleanup,
                         State::CleanupBlocked, State::Complete})
        if (to_string(s) == text) return s;
    throw std::invalid_argument("unknown layout migration state: " + std::string(text));
}

bool beforeCutover(const State state) {
    return state == State::Copying || state == State::Verifying || state == State::Failed;
}

std::string_view to_string(const ItemKind kind) {
    switch (kind) {
    case ItemKind::Version: return "version";
    case ItemKind::Marker: return "marker";
    case ItemKind::Index: return "index";
    case ItemKind::Current: return "current";
    case ItemKind::Backlog: return "backlog";
    }
    return "version";
}

ItemKind itemKindFromString(const std::string_view text) {
    for (const auto k : {ItemKind::Version, ItemKind::Marker, ItemKind::Index, ItemKind::Current, ItemKind::Backlog})
        if (to_string(k) == text) return k;
    throw std::invalid_argument("unknown layout migration item kind: " + std::string(text));
}

std::string_view to_string(const ItemState state) {
    switch (state) {
    case ItemState::Pending: return "pending";
    case ItemState::Verified: return "verified";
    case ItemState::Superseded: return "superseded";
    case ItemState::Skipped: return "skipped";
    case ItemState::Failed: return "failed";
    }
    return "pending";
}

ItemState itemStateFromString(const std::string_view text) {
    for (const auto s : {ItemState::Pending, ItemState::Verified, ItemState::Superseded, ItemState::Skipped,
                         ItemState::Failed})
        if (to_string(s) == text) return s;
    throw std::invalid_argument("unknown layout migration item state: " + std::string(text));
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
            {"objects", e.objects},
            {"versions", e.versions},
            {"delete_markers", e.delete_markers},
            {"backlog", e.backlog},
            {"current_files", e.current_files},
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
    e.objects = u("objects");
    e.versions = u("versions");
    e.delete_markers = u("delete_markers");
    e.backlog = u("backlog");
    e.current_files = u("current_files");
    e.sample = u("sample");
    e.priced = j.value("priced", false);
    if (j.contains("estimated_cost") && j.at("estimated_cost").is_string())
        e.estimated_cost = j.at("estimated_cost").get<std::string>();
    return e;
}

nlohmann::json toJson(const CleanupEntry& entry) {
    return {{"key", entry.key},
            {"version_id", entry.version_id ? nlohmann::json(*entry.version_id) : nlohmann::json(nullptr)},
            {"delete_marker", entry.delete_marker},
            {"size", entry.size},
            {"last_modified", entry.last_modified ? nlohmann::json(*entry.last_modified) : nlohmann::json(nullptr)},
            {"reason", entry.reason},
            {"retain_until", entry.retain_until ? nlohmann::json(*entry.retain_until) : nlohmann::json(nullptr)}};
}

namespace layout_detail {

using Q = db::query::vault::LayoutMigration;
using FileSP = std::shared_ptr<fs::model::File>;
namespace keys = storage::object_keys;
namespace content = vault::content;

// A failure of the run that leaves the vault on path_v0 (the row goes to failed with this text).
struct RunFailed : std::runtime_error {
    using std::runtime_error::runtime_error;
};

std::string unquoted(std::string etag) {
    if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') etag = etag.substr(1, etag.size() - 2);
    return etag;
}

std::string lowered(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool archived(const std::optional<std::string>& storageClass) {
    if (!storageClass) return false;
    const auto upper = lowered(*storageClass);
    return upper == "glacier" || upper == "deep_archive";
}

bool isR2(const storage::CloudEngine& engine) {
    const auto profile = engine.s3ProviderProfile();
    return profile && profile->id() == "cloudflare-r2";
}

// What a listed key is to the migration.
enum class KeyRole { Target, Index, Content };

KeyRole roleOf(const std::string& key) {
    switch (keys::classify(key)) {
    case keys::KeyClass::Content:
    case keys::KeyClass::Metadata:
        return KeyRole::Target;   // opaque_v1's own objects (an earlier attempt's, envelopes)
    case keys::KeyClass::Foreign:
        break;
    }
    if (key.starts_with(keys::kMetadataPrefix)) return KeyRole::Index;   // index-v1.json and other old metadata
    return KeyRole::Content;
}

std::filesystem::path backingOf(const storage::Engine& engine, const fs::model::File& file) {
    if (file.backing_path.is_absolute() || !engine.paths) return file.backing_path;
    return engine.paths->absPath(file.backing_path, fs::model::PathType::BACKING_ROOT);
}

// ---- temp files (sealed bytes only: legacy objects as read, VHF1 as written; never plaintext) -------------------------

std::filesystem::path tmpDirFor(const uint32_t vaultId) {
    return recovery::store::root().parent_path() / ".vh-layout" / std::to_string(vaultId);
}

class TempFile {
public:
    explicit TempFile(const std::filesystem::path& dir) {
        std::filesystem::create_directories(dir);
        std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
        unsigned char rnd[12];
        randombytes_buf(rnd, sizeof rnd);
        std::string name = "o-";
        for (const auto b : rnd) name += fmt::format("{:02x}", b);
        path_ = dir / name;
    }
    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

// A new file at path (O_EXCL, 0600) filled by the sink calls.
class ExclusiveWriter {
public:
    explicit ExclusiveWriter(const std::filesystem::path& path)
        : fd_(::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)) {
        if (fd_ < 0) throw std::system_error(errno, std::generic_category(), "create " + path.string());
    }
    ~ExclusiveWriter() {
        if (fd_ >= 0) ::close(fd_);
    }
    ExclusiveWriter(const ExclusiveWriter&) = delete;
    ExclusiveWriter& operator=(const ExclusiveWriter&) = delete;
    void write(const std::span<const uint8_t> bytes) {
        std::size_t off = 0;
        while (off < bytes.size()) {
            const auto n = ::write(fd_, bytes.data() + off, bytes.size() - off);
            if (n < 0) {
                if (errno == EINTR) continue;
                throw std::system_error(errno, std::generic_category(), "write");
            }
            off += static_cast<std::size_t>(n);
        }
    }
    void close() {
        if (fd_ >= 0 && platform::durable::sync(fd_) != 0) throw std::system_error(errno, std::generic_category(), "fsync");
        if (fd_ >= 0 && ::close(fd_) != 0) {
            fd_ = -1;
            throw std::system_error(errno, std::generic_category(), "close");
        }
        fd_ = -1;
    }

private:
    int fd_{-1};
};

// ---- MD5 of what was PUT (S3's ETag of a single PUT, or of a multipart upload at partSize) -------------------------

class Md5 {
public:
    Md5() : ctx_(EVP_MD_CTX_new()) {
        if (!ctx_ || EVP_DigestInit_ex(ctx_, EVP_md5(), nullptr) != 1) throw std::runtime_error("MD5 init failed");
    }
    ~Md5() { EVP_MD_CTX_free(ctx_); }
    Md5(const Md5&) = delete;
    Md5& operator=(const Md5&) = delete;
    void update(const uint8_t* p, const std::size_t n) {
        if (n && EVP_DigestUpdate(ctx_, p, n) != 1) throw std::runtime_error("MD5 update failed");
    }
    std::array<uint8_t, 16> finish() {
        std::array<uint8_t, 16> out{};
        unsigned int n = 0;
        if (EVP_DigestFinal_ex(ctx_, out.data(), &n) != 1 || n != out.size()) throw std::runtime_error("MD5 failed");
        return out;
    }

private:
    EVP_MD_CTX* ctx_;
};

std::string hexOf(const std::array<uint8_t, 16>& d) {
    std::string out;
    for (const auto b : d) out += fmt::format("{:02x}", b);
    return out;
}

// The ETag S3 computes for these bytes uploaded the way putMigratedObject uploads them.
std::string expectedEtag(const std::filesystem::path& path, const uint64_t size) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw std::system_error(errno, std::generic_category(), "open " + path.string());
    std::vector<uint8_t> buf(1 << 20);
    const bool single = size < storage::s3::Controller::MIN_PART_SIZE;
    const uint64_t partSize = single ? size : keys::partSizeFor(size);
    Md5 whole;
    std::vector<uint8_t> partDigests;
    std::optional<Md5> part;
    uint64_t inPart = 0, parts = 0;
    try {
        for (;;) {
            const auto n = ::read(fd, buf.data(), buf.size());
            if (n < 0) {
                if (errno == EINTR) continue;
                throw std::system_error(errno, std::generic_category(), "read");
            }
            if (n == 0) break;
            std::size_t off = 0;
            while (off < static_cast<std::size_t>(n)) {
                if (single) {
                    whole.update(buf.data(), static_cast<std::size_t>(n));
                    off = static_cast<std::size_t>(n);
                    break;
                }
                if (!part) part.emplace();
                const auto take = std::min<uint64_t>(partSize - inPart, static_cast<uint64_t>(n) - off);
                part->update(buf.data() + off, take);
                off += take;
                inPart += take;
                if (inPart == partSize) {
                    const auto d = part->finish();
                    partDigests.insert(partDigests.end(), d.begin(), d.end());
                    part.reset();
                    inPart = 0;
                    ++parts;
                }
            }
        }
    } catch (...) {
        ::close(fd);
        throw;
    }
    ::close(fd);
    if (single) return hexOf(whole.finish());
    if (part) {
        const auto d = part->finish();
        partDigests.insert(partDigests.end(), d.begin(), d.end());
        ++parts;
    }
    Md5 over;
    over.update(partDigests.data(), partDigests.size());
    return hexOf(over.finish()) + "-" + std::to_string(parts);
}

uint64_t putRequestsFor(const uint64_t size) {
    if (size < storage::s3::Controller::MIN_PART_SIZE) return 1;
    return keys::partCountFor(size, keys::partSizeFor(size)) + 2;   // initiate + parts + complete
}

// ---- the run's context ----------------------------------------------------------------------------------------------

struct Ctx {
    std::shared_ptr<storage::CloudEngine> engine;
    std::shared_ptr<storage::s3::Controller> ctl;
    std::shared_ptr<EncryptionManager> em;
    uint32_t vaultId{};
    bool versioned{true};
    std::filesystem::path tmpDir;
    const RunDeps* deps{};
    uint64_t listPages{};

    void step(const std::string_view name) const {
        if (deps && deps->afterStep) deps->afterStep(name);
    }
    [[nodiscard]] bool stopping() const { return deps && deps->stop && deps->stop(); }

    [[nodiscard]] crypto::SecretKeyPtr key(const unsigned int version) const {
        auto k = em->historicalKeySnapshot(version);
        if (!k) throw RunFailed(fmt::format("key version {} is not held", version));
        return k;
    }
};

// A complete listing of the bucket: every page or an exception. R2 has no ListObjectVersions: ListObjectsV2.
std::vector<storage::s3::ObjectVersionInfo> listAll(Ctx& ctx) {
    std::vector<storage::s3::ObjectVersionInfo> out;
    if (!ctx.versioned) {
        std::string token;
        do {
            const auto page = ctx.ctl->listObjectKeysPage(token, 1000);
            ++ctx.listPages;
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
        const auto page = ctx.ctl->listObjectVersionsPage("", keyMarker, versionMarker, 1000);
        ++ctx.listPages;
        out.insert(out.end(), page.versions.begin(), page.versions.end());
        if (!page.truncated) break;
        keyMarker = page.next_key_marker;
        versionMarker = page.next_version_id_marker;
    }
    return out;
}

std::optional<std::string> versionIdOf(const storage::s3::ObjectVersionInfo& v) {
    if (v.version_id.empty()) return std::nullopt;
    return v.version_id;
}

// ---- inventory --------------------------------------------------------------------------------------------------------

using ItemsByKey = std::map<std::pair<std::string, std::string>, Item>;   // (key, version id or "")

ItemsByKey indexLegacy(const std::vector<Item>& items) {
    ItemsByKey out;
    for (const auto& it : items)
        if (it.legacy()) out[{*it.legacy_key, it.legacy_version_id.value_or("")}] = it;
    return out;
}

// Records every listed legacy entry; returns how many were new. A pending unversioned item whose object was replaced
// (another ETag) is read again.
uint64_t recordInventory(Ctx& ctx, const std::vector<storage::s3::ObjectVersionInfo>& listed) {
    auto known = indexLegacy(Q::items(ctx.vaultId));
    std::map<std::string, std::optional<crypto::id::ObjectUid>> uidOfKey;
    for (const auto& [k, it] : known)
        if (it.object_uid) uidOfKey[k.first] = it.object_uid;

    // Versions of a key arrive newest first: seq counts from the oldest (1).
    std::map<std::string, std::vector<const storage::s3::ObjectVersionInfo*>> byKey;
    for (const auto& v : listed)
        if (roleOf(v.key) != KeyRole::Target) byKey[v.key].push_back(&v);

    uint64_t added = 0;
    for (const auto& [key, versions] : byKey) {
        const auto role = roleOf(key);
        std::optional<crypto::id::ObjectUid> uid;
        if (role == KeyRole::Content) {
            if (const auto it = uidOfKey.find(key); it != uidOfKey.end() && it->second) uid = it->second;
            else if (auto atPath = db::query::sync::ObjectIdentity::uidAtPath(ctx.vaultId, fs::model::makeAbsolute(key)))
                uid = atPath;
            else uid = crypto::id::newObjectUid();   // history of a file no row names any more
        }
        const int n = static_cast<int>(versions.size());
        for (int i = 0; i < n; ++i) {
            const auto& v = *versions[static_cast<std::size_t>(i)];
            Item it;
            it.vault_id = ctx.vaultId;
            it.kind = role == KeyRole::Index ? ItemKind::Index : v.delete_marker ? ItemKind::Marker : ItemKind::Version;
            it.legacy_key = key;
            it.legacy_version_id = versionIdOf(v);
            it.legacy_etag = v.delete_marker ? std::nullopt : std::make_optional(v.etag);
            it.legacy_size = v.size;
            it.legacy_last_modified = v.last_modified;
            it.legacy_storage_class = v.storage_class;
            it.legacy_latest = v.is_latest;
            it.seq = n - i;
            it.object_uid = uid;
            if (role == KeyRole::Index) {
                it.state = ItemState::Superseded;
                it.reason = "replaced by the encrypted manifest";
            }
            const auto prior = known.find({key, it.legacy_version_id.value_or("")});
            if (prior == known.end()) {
                (void)Q::upsertLegacy(it);
                ++added;
                continue;
            }
            auto stored = Q::upsertLegacy(it);
            // An unversioned key overwritten since: a different object, read again.
            if (!ctx.versioned && stored.kind == ItemKind::Version && prior->second.legacy_etag != it.legacy_etag) {
                stored.state = ItemState::Pending;
                stored.source_generation.reset();
                stored.key_version.reset();
                stored.target_etag.reset();
                stored.target_generation.reset();
                stored.target_version_id.reset();
                stored.reason.reset();
                stored.error.reset();
                Q::updateItem(stored);
                ++added;
            }
        }
    }

    // Inventoried, not listed any more and never copied: nothing to migrate or delete.
    std::set<std::pair<std::string, std::string>> seen;
    for (const auto& v : listed) seen.insert({v.key, v.version_id});
    for (auto& [k, it] : known)
        if (!seen.contains(k) && it.state == ItemState::Pending && it.legacy()) {
            it.state = ItemState::Superseded;
            it.reason = "gone from the bucket since the inventory";
            Q::updateItem(it);
        }
    return added;
}

// What a HEAD says about a legacy content version.
struct LegacyHead {
    bool exists{false};
    bool deleteMarker{false};
    std::string etag;
    uint64_t size{};
    std::optional<std::string> storageClass;
    std::optional<std::string> iv;
    std::optional<unsigned int> keyVersion;
    std::optional<bool> encrypted;
    std::optional<std::string> contentHash;
    std::optional<std::string> lockMode;
    std::optional<std::time_t> retainUntil;
    bool legalHold{false};
};

LegacyHead headLegacy(const Ctx& ctx, const std::string& key, const std::optional<std::string>& versionId) {
    LegacyHead out;
    if (versionId) {
        const auto head = ctx.ctl->headObjectVersion(key, *versionId);
        if (!head) return out;
        out.exists = true;
        out.deleteMarker = head->delete_marker;
        out.etag = head->etag;
        out.size = head->content_length;
        out.storageClass = head->storage_class;
        const auto meta = [&](const char* name) -> std::optional<std::string> {
            const auto it = head->metadata.find(name);
            return it == head->metadata.end() ? std::nullopt : std::make_optional(it->second);
        };
        out.iv = meta("vh-iv");
        if (const auto v = meta("vh-key-version")) {
            try {
                out.keyVersion = static_cast<unsigned int>(std::stoul(*v));
            } catch (const std::exception&) {
            }
        }
        if (const auto e = meta("vh-encrypted")) out.encrypted = lowered(*e) == "true" || *e == "1";
        out.contentHash = meta("content-hash");
        out.lockMode = head->object_lock_mode;
        out.retainUntil = head->retain_until;
        out.legalHold = head->legal_hold;
        return out;
    }
    const auto head = ctx.engine->headObjectKeyStrict(key);
    if (!head) return out;
    out.exists = true;
    out.etag = head->etag;
    out.size = head->content_length.value_or(0);
    if (!head->iv_b64.empty()) out.iv = head->iv_b64;
    if (head->key_version) out.keyVersion = head->key_version;
    out.encrypted = head->encrypted;
    out.contentHash = head->content_hash;
    return out;
}

// One HEAD per pending legacy content version without its generation: what it is sealed as, or why it stays.
uint64_t headPending(Ctx& ctx, std::vector<Item>& items) {
    uint64_t heads = 0;
    for (auto& it : items) {
        if (it.kind != ItemKind::Version || it.state != ItemState::Pending || it.source_generation) continue;
        if (ctx.stopping()) throw RunFailed("stopped");
        const auto head = headLegacy(ctx, *it.legacy_key, it.legacy_version_id);
        ++heads;
        if (!head.exists || head.deleteMarker) {
            it.state = ItemState::Superseded;
            it.reason = "gone from the bucket since the inventory";
        } else if (archived(head.storageClass ? head.storageClass : it.legacy_storage_class)) {
            it.state = ItemState::Skipped;
            it.reason = kArchived;
        } else if (!head.iv || !head.keyVersion || head.encrypted == std::optional<bool>(false)) {
            it.state = ItemState::Skipped;
            it.reason = kUnattributed;
        } else if (!ctx.em->hasKeyVersion(*head.keyVersion)) {
            it.state = ItemState::Skipped;
            it.reason = kKeyUnavailable;
            it.key_version = head.keyVersion;
        } else {
            try {
                const auto plain = content::plaintextSizeOfGeneration(head.size, *head.iv);
                if (!plain) throw std::invalid_argument("size");
                it.source_generation = head.iv;
                it.key_version = head.keyVersion;
                it.plaintext_bytes = plain;
                it.content_hash = head.contentHash;
                it.legacy_etag = head.etag;
            } catch (const std::exception&) {
                it.state = ItemState::Skipped;
                it.reason = kUnattributed;
            }
        }
        Q::updateItem(it);
    }
    return heads;
}

// ---- what each file's content comes from -----------------------------------------------------------------------------

bool hasLocalCopy(const storage::Engine& engine, const fs::model::File& f) {
    std::error_code ec;
    const auto p = backingOf(engine, f);
    return !p.empty() && std::filesystem::is_regular_file(p, ec);
}

constexpr int kBacklogSeqBase = 1'000'000;
constexpr int kCurrentSeq = INT_MAX;

// Assigns every live file its current content: a current item (uploaded from its local copy), or the legacy version
// it is indexed from. Marks the latest legacy version a local copy supersedes, and refuses a bucket that changed
// since the last sync.
void planFiles(Ctx& ctx) {
    auto items = Q::items(ctx.vaultId);
    std::map<crypto::id::ObjectUid, Item*> latest;   // newest legacy content version of each uid
    std::map<uint32_t, Item*> currentOf;
    for (auto& it : items) {
        if (it.kind == ItemKind::Version && it.legacy_latest && it.object_uid) latest[*it.object_uid] = &it;
        if (it.kind == ItemKind::Current && it.file_id) currentOf[*it.file_id] = &it;
    }

    for (const auto& f : Q::liveFiles(ctx.vaultId)) {
        if (!f->object_uid) throw RunFailed(fmt::format("file {} has no object uid", f->id));
        const auto uid = *f->object_uid;
        Item* source = nullptr;
        if (const auto it = latest.find(uid); it != latest.end()) source = it->second;
        const bool local = hasLocalCopy(*ctx.engine, *f) || f->size_bytes == 0;

        if (local) {
            if (!currentOf.contains(f->id)) {
                Item cur;
                cur.vault_id = ctx.vaultId;
                cur.kind = ItemKind::Current;
                cur.file_id = f->id;
                cur.object_uid = uid;
                cur.seq = kCurrentSeq;
                (void)Q::upsertCurrent(cur);
            }
            if (!source || source->state != ItemState::Pending) continue;
            if (source->source_generation == f->encryption_iv && source->key_version == f->encrypted_with_key_version) {
                source->state = ItemState::Superseded;
                source->reason = "the same generation as the local copy, which is uploaded instead";
                Q::updateItem(*source);
                continue;
            }
            // The bucket's object is not the local copy. Unchanged since the last sync: the local copy is newer and
            // the object is its history (kept on a versioned bucket, replaced on an unversioned one, as the next sync
            // would have). Changed since: a remote change this vault hasn't seen yet.
            const auto base = Q::baselineOf(f->id);
            fs::model::File remote;
            remote.content_hash = source->content_hash;
            remote.remote_etag = source->legacy_etag;
            remote.size_bytes = source->plaintext_bytes.value_or(0);
            sync::model::Baseline b;
            if (base) {
                b.remote_content_hash = base->remote_content_hash;
                b.remote_etag = base->remote_etag;
                b.remote_size_bytes = base->remote_size_bytes;
            }
            if (!base || sync::model::remoteChangedSince(remote, b)) {
                source->state = ItemState::Failed;
                source->reason = kDiverged;
                Q::updateItem(*source);
            } else if (!ctx.versioned) {
                source->state = ItemState::Superseded;
                source->reason = "replaced by the file's newer local content";
                Q::updateItem(*source);
            }
            continue;
        }

        // No local copy: the row is indexed from the bucket, and its legacy object is the content.
        if (!source) {
            Item missing;
            missing.vault_id = ctx.vaultId;
            missing.kind = ItemKind::Current;
            missing.file_id = f->id;
            missing.object_uid = uid;
            missing.seq = kCurrentSeq;
            missing = Q::upsertCurrent(missing);
            missing.state = ItemState::Failed;
            missing.reason = kMissing;
            Q::updateItem(missing);
            continue;
        }
        if (source->state == ItemState::Skipped) {
            Item blocked = *source;
            blocked.state = ItemState::Failed;
            blocked.error = "the file's only copy is this object, which can't be re-sealed now (" +
                            blocked.reason.value_or("?") + ")";
            Q::updateItem(blocked);
            continue;
        }
        if (source->source_generation != f->encryption_iv || source->key_version != f->encrypted_with_key_version) {
            if (source->state == ItemState::Pending) {
                source->state = ItemState::Failed;
                source->reason = kDiverged;
                Q::updateItem(*source);
            }
            continue;
        }
        if (source->file_id != f->id) {
            source->file_id = f->id;
            Q::updateItem(*source);
        }
    }
}

// Pending backlog generations become items between their object's history and its current content.
void planBacklog(Ctx& ctx) {
    std::map<std::string, crypto::id::ObjectUid> uidOfKey;
    std::set<std::tuple<crypto::id::ObjectUid, std::string, unsigned int>> inHistory;   // (uid, generation, key version)
    for (const auto& it : Q::items(ctx.vaultId)) {
        if (it.legacy_key && it.object_uid) uidOfKey[*it.legacy_key] = *it.object_uid;
        if (it.kind == ItemKind::Version && it.object_uid && it.source_generation && it.key_version)
            inHistory.insert({*it.object_uid, *it.source_generation, *it.key_version});
    }
    for (const auto& g : db::query::recovery::Generation::listPending(ctx.vaultId, 1'000'000)) {
        std::optional<crypto::id::ObjectUid> uid;
        if (g.file_id)
            if (const auto f = db::query::fs::File::getFileById(*g.file_id); f && f->object_uid) uid = f->object_uid;
        if (!uid && g.upstream_key)
            if (const auto it = uidOfKey.find(*g.upstream_key); it != uidOfKey.end()) uid = it->second;
        if (!uid) uid = db::query::sync::ObjectIdentity::uidAtPath(ctx.vaultId, g.path);
        if (!uid) continue;   // no object to put it in: the backlog keeps it (local version)
        Item it;
        it.vault_id = ctx.vaultId;
        it.kind = ItemKind::Backlog;
        it.generation_id = g.id;
        it.object_uid = uid;
        it.seq = kBacklogSeqBase + g.version_number;
        it.source_generation = g.encryption_iv;
        it.key_version = g.key_version;
        it.plaintext_bytes = g.size_bytes;
        it.content_hash = g.content_hash;
        auto stored = Q::upsertBacklog(it);
        // Already upstream as a version of the key (as the replay would find): carried over with that version, sent
        // once it has its o/<uid> version (markBacklogSent).
        if (stored.state == ItemState::Pending && g.encryption_iv && g.key_version &&
            inHistory.contains({*uid, *g.encryption_iv, *g.key_version})) {
            stored.state = ItemState::Superseded;
            stored.reason = "already a version of the object";
            Q::updateItem(stored);
        }
    }
}

// Backlog generations that were already a legacy version: sent, with that version's re-sealed o/<uid> version.
void markBacklogSent(const Ctx& ctx) {
    const auto items = Q::items(ctx.vaultId);
    for (const auto& b : items) {
        if (b.kind != ItemKind::Backlog || b.state != ItemState::Superseded || !b.generation_id) continue;
        for (const auto& v : items)
            if (v.kind == ItemKind::Version && v.state == ItemState::Verified && v.object_uid == b.object_uid &&
                v.source_generation == b.source_generation && v.key_version == b.key_version && v.target_version_id) {
                (void)db::query::recovery::Generation::markSent(*b.generation_id, *v.target_version_id);
                break;
            }
    }
}

// ---- the estimate (LayoutMigrationCost) ------------------------------------------------------------------------------

uint64_t sampleSize(const uint64_t puts, const unsigned int minimum) {
    return std::min<uint64_t>(puts, std::max<uint64_t>(minimum, (puts + 99) / 100));
}

Estimate estimateOf(const Ctx& ctx, const std::vector<Item>& items, const uint64_t heads, const unsigned int sampleMin) {
    Estimate e;
    e.list_requests = ctx.listPages * 2;   // the inventory (sent) and the verification's listing
    e.head_requests = heads;
    std::set<crypto::id::ObjectUid> objects;
    uint64_t puts = 0, sampleBytes = 0;
    std::vector<uint64_t> putSizes;
    for (const auto& it : items) {
        if (it.state != ItemState::Pending) continue;
        switch (it.kind) {
        case ItemKind::Version: {
            ++e.versions;
            ++e.get_requests;
            e.download_bytes += it.legacy_size.value_or(0);
            const auto sealed = content::newSealedSize(it.plaintext_bytes.value_or(0));
            e.put_requests += putRequestsFor(sealed);
            e.upload_bytes += sealed;
            putSizes.push_back(sealed);
            ++puts;
            break;
        }
        case ItemKind::Marker:
            if (ctx.versioned) {
                ++e.delete_markers;
                ++e.delete_requests;
            }
            break;
        case ItemKind::Backlog:
        case ItemKind::Current: {
            if (it.kind == ItemKind::Backlog) ++e.backlog;
            else ++e.current_files;
            uint64_t plain = it.plaintext_bytes.value_or(0);
            if (it.kind == ItemKind::Current && it.file_id)
                if (const auto f = db::query::fs::File::getFileById(*it.file_id)) plain = f->size_bytes;
            const auto sealed = content::newSealedSize(plain);
            e.put_requests += putRequestsFor(sealed);
            e.upload_bytes += sealed;
            putSizes.push_back(sealed);
            ++puts;
            break;
        }
        case ItemKind::Index:
            break;
        }
        if (it.object_uid) objects.insert(*it.object_uid);
    }
    e.objects = objects.size();
    e.sample = sampleSize(puts, sampleMin);
    // The sample read-back: the largest objects bound the bytes.
    std::ranges::sort(putSizes, std::greater<>());
    for (uint64_t i = 0; i < e.sample && i < putSizes.size(); ++i) sampleBytes += putSizes[i];
    e.get_requests += e.sample;
    e.download_bytes += sampleBytes;
    e.readback_worst_case_gets = puts;
    for (const auto s : putSizes) e.readback_worst_case_bytes += s;
    e.metadata_puts = 2 + objects.size() / 8192;
    return e;
}

// ---- re-sealing ---------------------------------------------------------------------------------------------------------

struct Sealed {
    std::string generation;
    uint64_t plaintextBytes{};
    uint64_t sealedBytes{};
};

// The sealed bytes at src (bound by `from`) as a new VHF1 file at dst under the same key version, bound to the vault and
// uid, verified by a full chunk walk (gcm0: with matching plaintext digests).
Sealed reseal(const Ctx& ctx, const std::filesystem::path& src, const content::Binding& from,
              const std::filesystem::path& dst, const crypto::id::ObjectUid& uid, const uint64_t expectedPlain) {
    const auto key = ctx.key(from.keyVersion);
    Sealed out;
    if (content::formatOf(from.generation) == content::Format::Gcm0) {
        const auto converted = conversion::convertFile(src, from, *key, dst, 0600, uid);
        out.generation = converted.generation;
        out.plaintextBytes = converted.plaintextBytes;
        out.sealedBytes = converted.sealedBytes;
    } else {
        out.generation = content::resealFile(src, from, *key, dst, *key, from.keyVersion, uid);
        out.sealedBytes = std::filesystem::file_size(dst);
        const auto plain = content::plaintextSizeOf(out.sealedBytes, content::Format::Vhf1);
        if (!plain) throw storage::IntegrityError("the re-sealed object has no plaintext size");
        out.plaintextBytes = *plain;
        if (!content::verifyFile(dst, out.plaintextBytes,
                                 {.vaultUid = ctx.em->vaultUid(), .generation = out.generation,
                                  .keyVersion = from.keyVersion, .objectUid = uid},
                                 *key))
            throw storage::IntegrityError("the re-sealed object does not authenticate");
    }
    if (out.plaintextBytes != expectedPlain)
        throw storage::IntegrityError(fmt::format("the content holds {} bytes, the catalog says {}", out.plaintextBytes,
                                                  expectedPlain));
    return out;
}

// GET of a legacy version (If-Match its inventoried ETag) into dst.
void fetchLegacy(const Ctx& ctx, const Item& it, const std::filesystem::path& dst) {
    ExclusiveWriter out(dst);
    storage::s3::GetObjectOptions options;
    options.if_match = it.legacy_etag;
    options.version_id = it.legacy_version_id;
    options.max_body_bytes = it.legacy_size;
    (void)ctx.ctl->streamObject(*it.legacy_key, options, [&](const std::span<const uint8_t> b) { out.write(b); });
    out.close();
}

// Reads o/<uid> back (the version the PUT made, when the bucket keeps versions) and authenticates it end to end.
void readBack(const Ctx& ctx, const Item& it) {
    if (!it.object_uid || !it.target_generation || !it.key_version) throw std::logic_error("nothing to read back");
    TempFile tmp(ctx.tmpDir);
    {
        ExclusiveWriter out(tmp.path());
        storage::s3::GetObjectOptions options;
        if (it.target_version_id && *it.target_version_id != "null") options.version_id = it.target_version_id;
        else options.if_match = it.target_etag;
        (void)ctx.ctl->streamObject(keys::contentKey(*it.object_uid), options,
                                    [&](const std::span<const uint8_t> b) { out.write(b); });
        out.close();
    }
    if (!content::verifyFile(tmp.path(), it.plaintext_bytes.value_or(0),
                             {.vaultUid = ctx.em->vaultUid(), .generation = *it.target_generation,
                              .keyVersion = *it.key_version, .objectUid = it.object_uid},
                             *ctx.key(*it.key_version)))
        throw storage::IntegrityError("the stored object does not authenticate");
}

// PUT of the sealed file and the proof the provider holds those bytes: an ETag equal to their (multipart) MD5, else a
// read-back.
void putAndProve(const Ctx& ctx, Item& it, const std::filesystem::path& sealed, const uint64_t size) {
    auto generation = std::make_shared<fs::model::File>();
    generation->vault_id = ctx.vaultId;
    generation->object_uid = it.object_uid;
    generation->encryption_iv = it.target_generation.value_or("");
    generation->encrypted_with_key_version = it.key_version.value_or(0);
    generation->content_hash = it.content_hash;
    generation->size_bytes = it.plaintext_bytes.value_or(0);
    generation->remote_encrypted = true;
    const auto put = ctx.engine->putMigratedObject(keys::contentKey(*it.object_uid), sealed, size, generation);
    it.target_etag = put.etag;
    it.target_version_id = put.version_id && *put.version_id != "null" ? put.version_id : std::nullopt;
    it.target_size = size;
    if (unquoted(put.etag) != expectedEtag(sealed, size)) readBack(ctx, it);
    it.state = ItemState::Verified;
    it.error.reset();
}

void copyVersion(const Ctx& ctx, Item& it) {
    TempFile src(ctx.tmpDir), dst(ctx.tmpDir);
    fetchLegacy(ctx, it, src.path());
    const auto sealed = reseal(ctx, src.path(),
                               {.vaultUid = ctx.em->vaultUid(), .generation = *it.source_generation,
                                .keyVersion = *it.key_version, .objectUid = std::nullopt},
                               dst.path(), *it.object_uid, it.plaintext_bytes.value_or(0));
    it.target_generation = sealed.generation;
    putAndProve(ctx, it, dst.path(), sealed.sealedBytes);
}

void copyBacklog(const Ctx& ctx, Item& it) {
    const auto g = db::query::recovery::Generation::get(*it.generation_id);
    if (!g || g->upstream_state != db::query::recovery::UpstreamState::Pending) {
        it.state = ItemState::Superseded;
        it.reason = "no longer pending";
        return;
    }
    if (!g->storage_name || !g->encryption_iv || !g->key_version) {
        it.state = ItemState::Superseded;
        it.reason = "its body was released";
        return;
    }
    const auto blob = recovery::store::blobPath(recovery::store::vaultRef(*ctx.engine->vault), *g->storage_name);
    it.source_generation = g->encryption_iv;
    it.key_version = g->key_version;
    it.plaintext_bytes = g->size_bytes;
    it.content_hash = g->content_hash;
    TempFile dst(ctx.tmpDir);
    if (g->size_bytes == 0 && g->encryption_iv->empty()) {
        it.state = ItemState::Superseded;
        it.reason = "an empty generation";
        return;
    }
    const auto sealed = reseal(ctx, blob,
                               {.vaultUid = ctx.em->vaultUid(), .generation = *g->encryption_iv,
                                .keyVersion = *g->key_version, .objectUid = std::nullopt},
                               dst.path(), *it.object_uid, g->size_bytes);
    it.target_generation = sealed.generation;
    putAndProve(ctx, it, dst.path(), sealed.sealedBytes);
    if (it.target_version_id) (void)db::query::recovery::Generation::markSent(*it.generation_id, *it.target_version_id);
}

// The file's local copy as it is now: a legacy one converted first (the #372 protocol: same key version, verified,
// compare-and-set), then a hard link of the backing file taken under the content lock (backing files are only ever
// replaced by rename), verified, and PUT as it is: the row keeps its generation.
void copyCurrent(const Ctx& ctx, Item& it, const conversion::Deps& conv) {
    auto file = db::query::fs::File::getFileById(*it.file_id);
    if (!file) {
        it.state = ItemState::Superseded;
        it.reason = "the file was deleted meanwhile";
        return;
    }
    if (content::isVhf1(file->encryption_iv) == false && !file->encryption_iv.empty()) {
        conversion::ItemStats stats;
        const auto outcome = conversion::convertLiveFile(file, conv, stats);
        if (outcome == conversion::Outcome::Deferred) return;   // open for writing: the next round (or the cutover)
        file = db::query::fs::File::getFileById(*it.file_id);
        if (!file || (!file->encryption_iv.empty() && !content::isVhf1(file->encryption_iv)))
            throw RunFailed(fmt::format("file {} could not be converted ({})", *it.file_id, conversion::to_string(outcome)));
    }

    TempFile linked(ctx.tmpDir), sealedTmp(ctx.tmpDir);
    std::string generation;
    unsigned int keyVersion{};
    uint64_t plain{};
    std::optional<std::string> hash;
    {
        auto lock = conv.rotation.catalog.lock ? conv.rotation.catalog.lock(file) : std::unique_lock<std::mutex>{};
        file = db::query::fs::File::getFileById(*it.file_id);
        if (!file) {
            it.state = ItemState::Superseded;
            it.reason = "the file was deleted meanwhile";
            return;
        }
        if (file->size_bytes > 0 && !hasLocalCopy(*ctx.engine, *file)) {
            // Evicted meanwhile: its object in the bucket is its content (planFiles takes that version).
            it.state = ItemState::Superseded;
            it.reason = "no local copy any more; its object is re-sealed instead";
            return;
        }
        generation = file->encryption_iv;
        keyVersion = file->encrypted_with_key_version;
        plain = file->size_bytes;
        hash = file->content_hash;
        if (plain > 0 || !generation.empty()) {
            const auto backing = backingOf(*ctx.engine, *file);
            if (::link(backing.c_str(), linked.path().c_str()) != 0) {
                if (errno != EXDEV && errno != EPERM) throw std::system_error(errno, std::generic_category(), "link");
                std::filesystem::copy_file(backing, linked.path());
            }
        }
    }
    it.source_generation = generation;
    it.key_version = keyVersion;
    it.plaintext_bytes = plain;
    it.content_hash = hash;

    if (generation.empty()) {
        // An empty file is stored as nothing locally and as one 136-byte VHF1 object upstream.
        const auto kv = ctx.em->get_key_version();
        const auto key = ctx.key(kv);
        const auto sealed = content::sealBuffer({}, *key, kv, ctx.em->vaultUid(), *it.object_uid);
        {
            ExclusiveWriter out(sealedTmp.path());
            out.write(sealed.bytes);
            out.close();
        }
        it.key_version = kv;
        it.target_generation = sealed.generation;
        putAndProve(ctx, it, sealedTmp.path(), sealed.bytes.size());
        return;
    }
    if (!content::verifyFile(linked.path(), plain,
                             {.vaultUid = ctx.em->vaultUid(), .generation = generation, .keyVersion = keyVersion,
                              .objectUid = it.object_uid},
                             *ctx.key(keyVersion)))
        throw storage::IntegrityError(fmt::format("file {}: its local copy does not authenticate", *it.file_id));
    it.target_generation = generation;
    putAndProve(ctx, it, linked.path(), std::filesystem::file_size(linked.path()));
}

// ---- copying ----------------------------------------------------------------------------------------------------------

// Every pending item, object by object, in history order (oldest legacy version first, backlog, current content).
void copyAll(Ctx& ctx) {
    const auto conv = conversion::runtimePassDeps(ctx.engine, {}).item;
    auto items = Q::items(ctx.vaultId);
    std::map<crypto::id::ObjectUid, std::vector<Item*>> byUid;
    for (auto& it : items)
        if (it.object_uid) byUid[*it.object_uid].push_back(&it);

    for (auto& [uid, group] : byUid) {
        std::ranges::stable_sort(group, [](const Item* a, const Item* b) { return a->seq < b->seq; });
        bool content = false;      // an earlier item of this object put content
        bool hiddenByMarker = false;
        for (auto* it : group) {
            if (ctx.stopping()) throw RunFailed("stopped");
            if (it->state == ItemState::Verified) {
                content = it->kind != ItemKind::Marker;
                hiddenByMarker = it->kind == ItemKind::Marker;
                continue;
            }
            if (it->state != ItemState::Pending) continue;
            try {
                switch (it->kind) {
                case ItemKind::Version:
                    copyVersion(ctx, *it);
                    break;
                case ItemKind::Marker:
                    if (!ctx.versioned || !content || hiddenByMarker) {
                        it->state = ItemState::Superseded;
                        it->reason = "no version of the object before it to hide";
                    } else {
                        ctx.engine->deleteMigratedObject(keys::contentKey(uid));
                        it->state = ItemState::Verified;
                    }
                    break;
                case ItemKind::Backlog:
                    copyBacklog(ctx, *it);
                    break;
                case ItemKind::Current:
                    copyCurrent(ctx, *it, conv);
                    break;
                case ItemKind::Index:
                    break;
                }
            } catch (const RunFailed&) {
                throw;
            } catch (const storage::IntegrityError& e) {
                it->state = ItemState::Failed;
                it->reason = kIntegrity;
                it->error = e.what();
                Q::updateItem(*it);
                throw RunFailed(fmt::format("item {} did not authenticate: {}", it->id, e.what()));
            } catch (const std::exception& e) {
                it->error = e.what();
                Q::updateItem(*it);
                throw RunFailed(fmt::format("item {}: {}", it->id, e.what()));
            }
            Q::updateItem(*it);
            if (it->state == ItemState::Verified) {
                content = it->kind != ItemKind::Marker;
                hiddenByMarker = it->kind == ItemKind::Marker;
            }
            ctx.step("item:" + std::to_string(it->id));
        }
    }
}

// Files changed or created while the copy ran: their current content again (a few rounds; what is left after the
// cutover uploads with the next sync pass, as any local change does).
bool catchUp(Ctx& ctx) {
    bool again = false;
    auto items = Q::items(ctx.vaultId);
    std::map<uint32_t, Item*> currentOf, sourceOf;
    for (auto& it : items) {
        if (!it.file_id) continue;
        if (it.kind == ItemKind::Current) currentOf[*it.file_id] = &it;
        else if (it.kind == ItemKind::Version) sourceOf[*it.file_id] = &it;
    }
    for (const auto& f : Q::liveFiles(ctx.vaultId)) {
        if (const auto it = currentOf.find(f->id); it != currentOf.end()) {
            auto& cur = *it->second;
            if (cur.state != ItemState::Verified) continue;
            const bool same = f->encryption_iv.empty() ? cur.source_generation == std::optional<std::string>("")
                                                       : cur.target_generation == f->encryption_iv &&
                                                             cur.key_version == f->encrypted_with_key_version;
            if (same) continue;
            cur.state = ItemState::Pending;
            Q::updateItem(cur);
            again = true;
            continue;
        }
        if (const auto it = sourceOf.find(f->id); it != sourceOf.end() && !hasLocalCopy(*ctx.engine, *f) &&
                                                   it->second->source_generation == f->encryption_iv)
            continue;   // still the indexed object
        Item cur;
        cur.vault_id = ctx.vaultId;
        cur.kind = ItemKind::Current;
        cur.file_id = f->id;
        cur.object_uid = f->object_uid;
        cur.seq = kCurrentSeq;
        auto stored = Q::upsertCurrent(cur);
        if (stored.state != ItemState::Pending) {
            stored.state = ItemState::Pending;
            Q::updateItem(stored);
        }
        again = true;
    }
    return again;
}

// ---- verification ----------------------------------------------------------------------------------------------------

void verifySample(const Ctx& ctx, const unsigned int minimum) {
    std::vector<Item> put;
    std::map<crypto::id::ObjectUid, std::size_t> newest;   // unversioned: only an object's last PUT is still there
    for (auto& it : Q::items(ctx.vaultId)) {
        if (it.state != ItemState::Verified || !it.target_generation || it.kind == ItemKind::Marker || !it.object_uid)
            continue;
        if (!ctx.versioned) {
            if (const auto n = newest.find(*it.object_uid); n != newest.end()) {
                if (put[n->second].seq <= it.seq) put[n->second] = it;
                continue;
            }
            newest[*it.object_uid] = put.size();
        }
        put.push_back(it);
    }
    const auto n = sampleSize(put.size(), minimum);
    std::vector<std::size_t> order(put.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
    for (std::size_t i = order.size(); i > 1; --i)   // Fisher-Yates with libsodium's uniform draw
        std::swap(order[i - 1], order[randombytes_uniform(static_cast<uint32_t>(i))]);
    for (uint64_t i = 0; i < n; ++i) {
        auto& it = put[order[i]];
        try {
            readBack(ctx, it);
        } catch (const std::exception& e) {
            it.state = ItemState::Failed;
            it.reason = kIntegrity;
            it.error = std::string("read-back: ") + e.what();
            Q::updateItem(it);
            throw RunFailed(fmt::format("item {} failed its read-back: {}", it.id, e.what()));
        }
    }
}

// Every item that blocks the cutover: failed ones (with their reason) and pending ones.
std::optional<std::string> blockers(const std::vector<Item>& items) {
    std::vector<std::string> out;
    uint64_t failed = 0, pending = 0;
    for (const auto& it : items) {
        if (it.state == ItemState::Failed) {
            ++failed;
            if (out.size() < 5)
                out.push_back(fmt::format("{} {}{}: {}", to_string(it.kind),
                                          it.legacy_key.value_or(it.file_id ? "file " + std::to_string(*it.file_id) : "?"),
                                          it.legacy_version_id ? "@" + *it.legacy_version_id : std::string{},
                                          it.reason.value_or(it.error.value_or("failed"))));
        } else if (it.state == ItemState::Pending && it.kind != ItemKind::Index) {
            ++pending;
        }
    }
    if (!failed && !pending) return std::nullopt;
    std::string text = fmt::format("{} item(s) failed, {} not copied", failed, pending);
    for (const auto& line : out) text += "; " + line;
    bool diverged = false;
    for (const auto& it : items) diverged = diverged || (it.state == ItemState::Failed && it.reason == std::optional<std::string>(kDiverged));
    if (diverged) text += ". The bucket changed since the vault's last sync: run a sync pass, then start the migration again";
    return text;
}

// ---- cutover ----------------------------------------------------------------------------------------------------------

Q::CutoverInput cutoverInput(const Ctx& ctx, const unsigned int waitDays) {
    Q::CutoverInput in;
    in.wait_days = waitDays;
    const auto items = Q::items(ctx.vaultId);
    std::map<uint32_t, const Item*> target;
    for (const auto& it : items) {
        if (!it.file_id || it.state != ItemState::Verified) continue;
        if (it.kind == ItemKind::Current) target[*it.file_id] = &it;
        else if (it.kind == ItemKind::Version && !target.contains(*it.file_id)) target[*it.file_id] = &it;
    }
    const auto storageClass = ctx.engine->writeStorageClass();
    for (const auto& [fileId, it] : target) {
        Q::CutoverFile f;
        f.file_id = fileId;
        if (const auto file = db::query::fs::File::getFileById(fileId)) f.path = file->path.string();
        else continue;   // deleted meanwhile: nothing to cut over for it
        f.object_key = keys::contentKey(*it->object_uid);
        f.key_version = it->key_version.value_or(0);
        f.plaintext_bytes = it->plaintext_bytes.value_or(0);
        f.content_hash = it->content_hash;
        f.etag = it->target_etag;
        f.version_id = it->target_version_id;
        f.storage_class = storageClass;
        f.empty_object = it->kind == ItemKind::Current && it->source_generation == std::optional<std::string>("");
        f.from_generation = it->kind == ItemKind::Current ? it->target_generation.value_or("")
                                                          : it->source_generation.value_or("");
        f.to_generation = it->target_generation.value_or("");
        if (f.empty_object) f.from_generation = f.to_generation = "";
        in.files.push_back(std::move(f));
    }

    // Legacy versions in key order, to know each one's successor's time.
    std::map<std::string, std::vector<const Item*>> byKey;
    for (const auto& it : items)
        if (it.legacy() && (it.kind == ItemKind::Version || it.kind == ItemKind::Marker)) byKey[*it.legacy_key].push_back(&it);
    for (auto& [key, group] : byKey) {
        std::ranges::sort(group, [](const Item* a, const Item* b) { return a->seq < b->seq; });
        if (group.front()->object_uid) in.keyOf[key] = keys::contentKey(*group.front()->object_uid);
        for (std::size_t i = 0; i < group.size(); ++i) {
            const auto* it = group[i];
            if (it->kind != ItemKind::Version || it->state != ItemState::Verified || !it->target_version_id ||
                !it->legacy_version_id)
                continue;
            Q::VersionMove v;
            v.legacy_key = key;
            v.legacy_version_id = *it->legacy_version_id;
            v.object_key = keys::contentKey(*it->object_uid);
            v.version_id = *it->target_version_id;
            v.last_modified = it->legacy_last_modified;
            if (i + 1 < group.size()) v.superseded_at = group[i + 1]->legacy_last_modified;
            in.versions.push_back(std::move(v));
        }
    }
    return in;
}

// After the cutover committed: in-memory rows (fs cache) follow the index-only rows that moved.
void refreshCache(const Ctx& ctx, const Q::CutoverInput& in) {
    const auto conv = conversion::runtimePassDeps(ctx.engine, {}).item;
    if (!conv.rotation.catalog.committed) return;
    for (const auto& f : in.files) {
        if (f.from_generation == f.to_generation) continue;
        if (auto file = db::query::fs::File::getFileById(f.file_id)) conv.rotation.catalog.committed(file);
    }
}

// The manifest v2 now: published, then loaded back from the bucket alone and compared with the database.
void publishAndVerifyManifest(const std::shared_ptr<storage::CloudEngine>& engine) {
    engine->publishRemoteIndexManifest();
    verifyManifestAgainstDatabase(*engine);
    Q::markManifestVerified(engine->vault->id);
}

void requireCutoverReady(const std::vector<Item>& items) {
    if (const auto b = blockers(items)) throw RunFailed(*b);
}

}

std::string s3EtagOf(const std::filesystem::path& sealed, const uint64_t size) {
    return layout_detail::expectedEtag(sealed, size);
}

// ---- preconditions --------------------------------------------------------------------------------------------------

void requirePreconditions(const storage::CloudEngine& engine) {
    const auto s3 = std::dynamic_pointer_cast<model::S3Vault>(engine.vault);
    if (!s3) throw std::runtime_error("only an S3 or R2 vault has a bucket layout");
    if (!s3->encrypt_upstream)
        throw std::runtime_error("the vault stores plaintext upstream (transparent layout); there is nothing to migrate");
    if (s3->storage_layout != model::StorageLayout::PathV0)
        throw std::runtime_error(fmt::format("the vault's layout is {}, not path_v0", model::to_string(s3->storage_layout)));
    const auto em = engine.encryptionManager;
    if (!em) throw std::runtime_error("the vault's encryption key is not loaded");
    if (em->rotation_in_progress()) throw std::runtime_error("a key rotation of the vault is in progress");
    if (db::query::vault::Key::runningSalvage(s3->id)) throw std::runtime_error("a key salvage of the vault is running");
    if (const auto key = engine.s3ApiKey())
        if (storage::upstream::guard::isProtected(storage::upstream::identityFor(*key, s3->bucket)))
            throw std::runtime_error("the bucket has a protection lock; unprotect it to migrate");
    std::set<unsigned int> versions;
    for (const auto& f : layout_detail::Q::liveFiles(s3->id))
        if (f->encrypted_with_key_version) versions.insert(f->encrypted_with_key_version);
    for (const auto v : versions)
        if (!em->hasKeyVersion(v))
            throw std::runtime_error(fmt::format("files are sealed under key version {}, which this host doesn't hold; "
                                                 "import it (vh vault keys import) first", v));
    if (const auto m = envelopes::material(s3->id); m.state == envelopes::kMaterialMissing)
        throw std::runtime_error("the vault has no recovery material independent of this host (" + m.detail +
                                 "); add a recovery recipient or export the key first");
    // Spec 01 §6.1 step 5: the migration publishes the encrypted manifest (spec 03 §3.4), which needs conditional
    // writes until the publish of spec 06 §5 exists. A bucket never probed is probed here (storage/BucketCapability).
    if (const auto capability = engine.writeCapability(); !storage::s3::sendsPreconditions(capability))
        throw std::runtime_error(fmt::format("the bucket does not support conditional writes (capability {}), and this "
                                             "server version can't publish the opaque_v1 manifest on such a bucket yet",
                                             storage::s3::to_string(capability)));
}

// ---- the run -----------------------------------------------------------------------------------------------------------

RunResult run(const std::shared_ptr<storage::CloudEngine>& engine, const RunDeps& deps) {
    namespace d = layout_detail;
    RunResult result;
    if (!engine || !engine->vault) throw std::invalid_argument("layout migration needs a cloud engine");
    const auto vaultId = engine->vault->id;
    auto row = d::Q::get(vaultId);
    if (!row) throw std::invalid_argument("the vault has no layout migration");
    result.state = row->state;

    // After the cutover only the manifest's publish and bucket-only check can be left (retried until they pass).
    if (!beforeCutover(row->state)) {
        if (row->state == State::CutOver && !row->manifest_verified_at) {
            try {
                d::publishAndVerifyManifest(engine);
            } catch (const std::exception& e) {
                d::Q::setError(vaultId, std::string("manifest: ") + e.what());
                result.error = e.what();
            }
        }
        return result;
    }
    if (row->state == State::Failed) return result;

    if (!deps.tryAcquirePass || !deps.tryAcquirePass(vaultId)) {
        result.busy = true;
        return result;
    }
    struct Release {
        const RunDeps& deps;
        uint32_t id;
        ~Release() {
            if (deps.releasePass) deps.releasePass(id);
        }
    } release{deps, vaultId};

    d::Ctx ctx;
    ctx.engine = engine;
    ctx.ctl = engine->s3Controller();
    ctx.em = engine->encryptionManager;
    ctx.vaultId = vaultId;
    ctx.deps = &deps;
    ctx.tmpDir = d::tmpDirFor(vaultId);
    ctx.versioned = row->versioned.value_or(!d::isR2(*engine));

    std::optional<storage::ScopedS3RequestUsageCapture> capture;
    try {
        requirePreconditions(*engine);
        d::Q::setVersioned(vaultId, ctx.versioned);

        // Every request of the run is captured (the inventory and its HEADs precede the estimate and are counted in
        // it): the usage recorded next to the estimate.
        for (int round = 0; round < 4; ++round) {
            if (row->state == State::Copying || round > 0) {
                d::Q::setState(vaultId, State::Copying);
                d::Q::resetFailed(vaultId);
                if (!capture) capture.emplace(*engine);
                const auto listed = d::listAll(ctx);
                (void)d::recordInventory(ctx, listed);
                ctx.step("inventory");
                auto items = d::Q::items(vaultId);
                const auto heads = d::headPending(ctx, items);
                d::planFiles(ctx);
                d::planBacklog(ctx);
                ctx.step("heads");
                auto estimate = d::estimateOf(ctx, d::Q::items(vaultId), heads, deps.sampleMinimum);
                if (deps.pricePreflight) deps.pricePreflight(*engine, estimate, row->accept_unpriced);
                d::Q::setEstimate(vaultId, toJson(estimate));
                d::requireCutoverReady([&] {
                    auto all = d::Q::items(vaultId);
                    std::erase_if(all, [](const Item& it) { return it.state == ItemState::Pending; });
                    return all;
                }());
                d::copyAll(ctx);
                for (int n = 0; n < 3 && d::catchUp(ctx); ++n) d::copyAll(ctx);
                d::markBacklogSent(ctx);
                // Recovery generations the #372 converter left legacy (pending backlog blobs among them).
                (void)conversion::convertVault(engine, {}, deps.stop, nullptr);
                ctx.step("copied");
                d::Q::setState(vaultId, State::Verifying);
            }

            d::verifySample(ctx, deps.sampleMinimum);
            const auto again = d::listAll(ctx);
            if (d::recordInventory(ctx, again) > 0) {
                row = d::Q::get(vaultId);
                continue;   // the bucket changed since the inventory: copy what is new
            }
            d::requireCutoverReady(d::Q::items(vaultId));
            d::Q::markVerified(vaultId);
            ctx.step("verified");

            if (capture) d::Q::setUsage(vaultId, nlohmann::json{{"list_requests", capture->usage().list_requests},
                                                                {"head_requests", capture->usage().head_requests},
                                                                {"get_requests", capture->usage().get_requests},
                                                                {"put_requests", capture->usage().put_requests},
                                                                {"delete_requests", capture->usage().delete_requests},
                                                                {"downloaded_bytes", capture->usage().downloaded_bytes},
                                                                {"uploaded_bytes", capture->usage().uploaded_bytes}});
            const auto in = d::cutoverInput(ctx, row->wait_days);
            const auto outcome = d::Q::cutover(vaultId, in);
            if (!outcome.done) {
                if (round == 3) throw d::RunFailed("cutover refused: " + outcome.refused);
                log::Registry::cloud()->info("[LayoutMigration] Vault {}: cutover refused ({}): {} legacy row(s), {} "
                                             "legacy backlog generation(s); catching up",
                                             vaultId, outcome.refused, outcome.legacy_rows, outcome.legacy_backlog);
                row = d::Q::get(vaultId);
                row->state = State::Copying;
                continue;
            }
            engine->adoptStorageLayout(model::StorageLayout::OpaqueV1);
            d::refreshCache(ctx, in);
            vh::audit::record({.action = "vault.layout.cutover", .outcome = vh::audit::Outcome::Success,
                               .actor_id = std::nullopt, .actor = "LayoutMigrationService", .vault_id = vaultId,
                               .entry_id = std::nullopt,
                               .details = {{"files", static_cast<int64_t>(in.files.size())},
                                           {"versions", static_cast<int64_t>(in.versions.size())},
                                           {"wait_days", static_cast<int64_t>(row->wait_days)}}},
                              fmt::format("[LayoutMigration] Vault {} cut over to opaque_v1: {} file(s), {} re-sealed "
                                          "provider version(s); the legacy objects stay until the cleanup",
                                          vaultId, in.files.size(), in.versions.size()));
            ctx.step("cutover");
            log::Registry::cloud()->info("[LayoutMigration] Vault {}: cut over to opaque_v1; the legacy objects stay "
                                         "until cleanup (after {} day(s))", vaultId, row->wait_days);
            result.state = State::CutOver;
            break;
        }
    } catch (const std::exception& e) {
        if (dynamic_cast<const d::RunFailed*>(&e) && std::string_view(e.what()) == "stopped") {
            result.stopped = true;
            return result;   // resumed on the next start
        }
        d::Q::setState(vaultId, State::Failed, e.what());
        result.state = State::Failed;
        result.error = e.what();
        vh::audit::record({.action = "vault.layout.failed", .outcome = vh::audit::Outcome::Failure,
                           .actor_id = std::nullopt, .actor = "LayoutMigrationService", .vault_id = vaultId,
                           .entry_id = std::nullopt, .details = nlohmann::json::object()},
                          fmt::format("[LayoutMigration] Vault {}: the bucket layout migration failed before the cutover; "
                                      "the vault stays path_v0 and nothing was deleted (vh vault migrate-layout {} "
                                      "--status names the reason)", vaultId, vaultId));
        return result;
    }
    if (result.state != State::CutOver) return result;

    try {
        d::publishAndVerifyManifest(engine);
    } catch (const std::exception& e) {
        // Cut over already: retried by the service until it passes; cleanup waits for it.
        d::Q::setError(vaultId, std::string("manifest: ") + e.what());
        result.error = e.what();
    }
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
    deps.pricePreflight = [](const storage::CloudEngine& engine, Estimate& estimate, const bool acceptUnpriced) {
        sync::model::S3CostEstimate planned;
        planned.list_requests = estimate.list_requests;
        planned.head_requests = estimate.head_requests;
        planned.get_requests = estimate.get_requests + estimate.readback_worst_case_gets;
        planned.put_requests = estimate.put_requests + estimate.metadata_puts;
        planned.delete_requests = estimate.delete_requests;
        planned.planned_body_download_bytes = estimate.download_bytes + estimate.readback_worst_case_bytes;
        planned.planned_upload_bytes = estimate.upload_bytes;
        planned.remote_index_objects = estimate.objects;
        namespace pricing = storage::s3::pricing;
        const auto report = pricing::estimatePlannedS3Sync(engine, planned,
                                                           {.mode = pricing::PriceEstimateMode::BudgetConservative});
        estimate.priced = report.available;
        if (report.available) estimate.estimated_cost = report.estimated_cost;
        if (!report.available && !acceptUnpriced)
            throw std::runtime_error("the migration's cost can't be priced (" + report.unavailable_reason +
                                     "); start it again with --accept-unpriced to accept that");
        recovery::provider::metering::PriceReservation reservation(engine, planned, "layout_migration",
                                                                   "vault:" + std::to_string(engine.vault->id));
        reservation.commit();
    };
    return deps;
}

// ---- manifest check ----------------------------------------------------------------------------------------------------

void verifyManifestAgainstDatabase(const storage::CloudEngine& engine) {
    const auto loaded = engine.loadManifestFromBucket();
    std::map<std::string, const sync::manifest::Entry*> byUid;
    for (const auto& e : loaded.entries) byUid[e.uid] = &e;
    for (const auto& f : layout_detail::Q::liveFiles(engine.vault->id)) {
        if (!f->object_uid) continue;
        const auto it = byUid.find(crypto::id::toBase32(*f->object_uid));
        if (it == byUid.end())
            throw std::runtime_error(fmt::format("the bucket's manifest does not name file {}", f->id));
        // The object the bucket holds for it (the remote index's row of o/<uid>, Vaulthalla's own upload).
        const auto indexed = db::query::sync::RemoteObjectIndex::getFile(engine.vault->id,
                                                                         storage::object_keys::contentKey(*f->object_uid));
        if (!indexed || indexed->encryption_iv.empty()) continue;
        const auto& entry = *it->second;
        std::string hex;
        for (const auto b : crypto::util::b64_decode(indexed->encryption_iv)) hex += fmt::format("{:02x}", b);
        if (entry.generation != std::optional<std::string>(hex) || !entry.object)
            throw std::runtime_error(fmt::format("the bucket's manifest names another object for file {}", f->id));
    }
}

// ---- cleanup ----------------------------------------------------------------------------------------------------------

CleanupPlan planCleanup(const storage::CloudEngine& engine, const Row& row) {
    namespace d = layout_detail;
    CleanupPlan plan;
    d::Ctx ctx;
    ctx.ctl = engine.s3Controller();
    ctx.vaultId = engine.vault->id;
    ctx.versioned = row.versioned.value_or(true);
    const storage::s3::ScopedLegacyLayoutCleanup scope;
    const auto listed = d::listAll(ctx);
    plan.complete_listing = true;
    const auto known = d::indexLegacy(d::Q::items(ctx.vaultId));
    std::set<std::pair<std::string, std::string>> seen;
    for (const auto& v : listed) {
        if (d::roleOf(v.key) == d::KeyRole::Target) continue;
        seen.insert({v.key, v.version_id});
        CleanupEntry e{.key = v.key, .version_id = d::versionIdOf(v), .delete_marker = v.delete_marker, .size = v.size,
                       .last_modified = v.last_modified, .reason = {}, .retain_until = std::nullopt};
        const auto it = known.find({v.key, v.version_id});
        if (it == known.end()) {
            e.reason = kNotInventoried;
        } else {
            const auto& item = it->second;
            const bool unchanged = ctx.versioned || item.legacy_etag == std::optional<std::string>(v.etag);
            if (!unchanged) e.reason = kNotInventoried;
            else if (item.state == ItemState::Verified || item.state == ItemState::Superseded) e.reason.clear();
            else e.reason = item.reason.value_or(std::string(to_string(item.state)));
            if (item.cleanup_state == std::optional<std::string>("blocked") && e.reason.empty()) {
                e.reason = item.cleanup_reason.value_or("blocked");
                e.retain_until = item.retain_until;
                // A block whose date passed (or a failed delete) is tried again.
                if (!item.retain_until || *item.retain_until <= std::time(nullptr)) e.reason.clear();
            }
        }
        if (e.reason.empty()) {
            ++plan.deletable;
            plan.deletable_bytes += e.size;
            if (e.delete_marker) ++plan.deletable_markers;
            if (e.last_modified) {
                plan.oldest = plan.oldest ? std::min(*plan.oldest, *e.last_modified) : *e.last_modified;
                plan.newest = plan.newest ? std::max(*plan.newest, *e.last_modified) : *e.last_modified;
            }
            plan.deletable_entries.push_back(std::move(e));
        } else {
            plan.kept.push_back(std::move(e));
        }
    }
    for (const auto& [k, item] : known)
        if (!seen.contains({k.first, k.second}) && item.cleanup_state != std::optional<std::string>("deleted"))
            ++plan.already_gone;
    return plan;
}

CleanupResult runCleanup(const storage::CloudEngine& engine, const CleanupDeps& deps) {
    namespace d = layout_detail;
    const auto row = d::Q::get(engine.vault->id);
    if (!row || !row->cutover_at) throw std::runtime_error("the vault has not cut over");
    if (!row->manifest_verified_at) throw std::runtime_error("the bucket's manifest has not been verified yet");
    verifyManifestAgainstDatabase(engine);

    CleanupResult result;
    const auto plan = planCleanup(engine, *row);
    const auto ctl = engine.s3Controller();
    auto items = d::indexLegacy(d::Q::items(engine.vault->id));
    const bool versioned = row->versioned.value_or(true);
    const storage::s3::ScopedLegacyLayoutCleanup scope;

    for (const auto& e : plan.deletable_entries) {
        if (deps.stop && deps.stop()) break;
        auto& item = items.at({e.key, e.version_id.value_or("")});
        ++item.cleanup_attempts;
        try {
            if (versioned && e.version_id) {
                if (!e.delete_marker) {
                    const auto head = ctl->headObjectVersion(e.key, *e.version_id);
                    if (head && (head->legal_hold || (head->retain_until && *head->retain_until > std::time(nullptr)))) {
                        item.cleanup_state = "blocked";
                        item.cleanup_reason = head->legal_hold ? "legal_hold" : "object_lock_retention";
                        item.retain_until = head->legal_hold ? std::nullopt : head->retain_until;
                        d::Q::updateItem(item);
                        ++result.blocked;
                        continue;
                    }
                }
                ctl->deleteObjectVersion(e.key, *e.version_id);
            } else {
                const auto head = engine.headObjectKeyStrict(e.key);
                if (head && d::unquoted(head->etag) != d::unquoted(item.legacy_etag.value_or(""))) {
                    item.cleanup_state = "blocked";
                    item.cleanup_reason = kNotInventoried;
                    d::Q::updateItem(item);
                    ++result.blocked;
                    continue;
                }
                if (head) ctl->deleteObject(e.key);
            }
            item.cleanup_state = "deleted";
            item.cleanup_reason.reset();
            item.retain_until.reset();
            d::Q::updateItem(item);
            d::Q::markLegacyVersionGone(engine.vault->id, e.key, e.version_id);
            ++result.deleted;
        } catch (const storage::s3::DeleteRefused& ex) {
            item.cleanup_state = "blocked";
            item.cleanup_reason = "refused: " + ex.code();
            d::Q::updateItem(item);
            ++result.blocked;
        } catch (const storage::s3::ObjectNotFound&) {
            item.cleanup_state = "deleted";
            d::Q::updateItem(item);
            ++result.deleted;
        } catch (const std::exception& ex) {
            item.cleanup_state = "blocked";
            item.cleanup_reason = std::string("failed: ") + ex.what();
            d::Q::updateItem(item);
            ++result.failed;
        }
    }

    // Complete only when a complete listing shows nothing legacy.
    const auto after = planCleanup(engine, *row);
    for (const auto& e : after.kept) result.remaining.push_back(e);
    for (auto e : after.deletable_entries) {
        const auto it = items.find({e.key, e.version_id.value_or("")});
        e.reason = it != items.end() && it->second.cleanup_reason ? *it->second.cleanup_reason : "not deleted yet";
        if (it != items.end()) e.retain_until = it->second.retain_until;
        result.remaining.push_back(std::move(e));
    }
    result.state = result.remaining.empty() ? State::Complete : State::CleanupBlocked;
    d::Q::finishCleanupRun(engine.vault->id, result.state);
    vh::audit::record({.action = "vault.layout.cleanup.run", .outcome = vh::audit::Outcome::Success,
                       .actor_id = std::nullopt, .actor = "LayoutMigrationService", .vault_id = engine.vault->id,
                       .entry_id = std::nullopt,
                       .details = {{"deleted", static_cast<int64_t>(result.deleted)},
                                   {"blocked", static_cast<int64_t>(result.blocked)},
                                   {"failed", static_cast<int64_t>(result.failed)},
                                   {"remaining", static_cast<int64_t>(result.remaining.size())},
                                   {"state", std::string(to_string(result.state))}}},
                      fmt::format("[LayoutMigration] Vault {}: cleanup deleted {} legacy version(s) by version id; {} "
                                  "remain ({})", engine.vault->id, result.deleted, result.remaining.size(),
                                  to_string(result.state)));
    return result;
}

}
