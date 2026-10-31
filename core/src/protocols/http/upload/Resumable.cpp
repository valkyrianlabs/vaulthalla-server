#include "protocols/http/upload/Resumable.hpp"

#include "config/Registry.hpp"
#include "crypto/SecretKey.hpp"
#include "crypto/util/Gcm.hpp"
#include "crypto/util/digest.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/query/upload/Resumable.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/metadata/Magic.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fuse/WorkingCopies.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "platform/Durable.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/AccessHooks.hpp"
#include "protocols/http/upload/CreateClaim.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "runtime/Deps.hpp"
#include "share/Manager.hpp"
#include "share/Principal.hpp"
#include "share/Scope.hpp"
#include "share/TargetResolver.hpp"
#include "storage/Engine.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Controller.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <set>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace vh::protocols::http::upload::resumable {

namespace {

using json = nlohmann::json;
using Response = model::preview::Response;
using FsAction = rbac::permission::vault::FilesystemAction;
namespace q = vh::db::query::upload;

// AES-GCM's single-message limit, (2^32 - 2) blocks: the largest file the vault format can hold.
constexpr uint64_t kFormatMaxBytes = (uint64_t{1} << 36) - 32;
constexpr std::size_t kIoChunk = 1u << 20;
// The sealed prefix is flushed and recorded at least this often while a cursor runs (and at the end of every pass).
constexpr uint64_t kSealCheckpointBytes = 256ull << 20;
// Part bodies being received at once, all sessions together; beyond it the server answers 503 busy.
constexpr unsigned kMaxActiveParts = 64;
constexpr std::size_t kSniffBytes = 64u * 1024u;

// ---- typed refusals --------------------------------------------------------------------------------------------

struct HttpError final : std::runtime_error {
    HttpError(const status s, std::string c, const std::string& message, json e = json::object())
        : std::runtime_error(message), st(s), code(std::move(c)), extra(std::move(e)) {}
    status st;
    std::string code;
    json extra;
    std::optional<std::string> etag;
    std::optional<std::string> retryAfter;
};

[[nodiscard]] HttpError withEtag(HttpError e, std::optional<std::string> etag) {
    if (etag) {
        e.extra["error_etag"] = *etag;
        e.etag = std::move(etag);
    }
    return e;
}

[[nodiscard]] Response jsonResponse(const request& req, const status st, const json& body) {
    string_response res{st, req.version()};
    res.set(field::content_type, "application/json");
    res.set(field::cache_control, "no-store");
    res.body() = body.dump();
    res.prepare_payload();
    res.keep_alive(req.keep_alive());
    return res;
}

[[nodiscard]] Response errorJson(const request& req, const status st, const std::string_view code,
                                 const std::string_view message, const json& extra = json::object(),
                                 const std::optional<std::string>& etag = std::nullopt,
                                 const std::optional<std::string>& retryAfter = std::nullopt) {
    json error = {{"code", code}, {"message", message}};
    if (etag) error["etag"] = *etag;
    json body = extra.is_object() ? extra : json::object();
    body.erase("error_etag");
    body["error"] = std::move(error);
    auto res = jsonResponse(req, st, body);
    auto& r = std::get<string_response>(res);
    if (etag) r.set(field::etag, *etag);
    if (retryAfter) r.set(field::retry_after, *retryAfter);
    return res;
}

[[nodiscard]] Response errorFor(const request& req, const std::exception& e) {
    if (const auto* h = dynamic_cast<const HttpError*>(&e))
        return errorJson(req, h->st, h->code, h->what(), h->extra, h->etag, h->retryAfter);
    if (dynamic_cast<const access::Unauthorized*>(&e)) return errorJson(req, status::unauthorized, "unauthorized", e.what());
    if (dynamic_cast<const access::Forbidden*>(&e)) return errorJson(req, status::forbidden, "forbidden", e.what());
    if (dynamic_cast<const access::NotFound*>(&e)) return errorJson(req, status::not_found, "not_found", "Not found");
    if (dynamic_cast<const access::BadRequest*>(&e)) return errorJson(req, status::bad_request, "bad_request", e.what());
    if (dynamic_cast<const json::exception*>(&e)) return errorJson(req, status::bad_request, "bad_request", e.what());
    log::Registry::http()->error("[ResumableUpload] {} {} failed: {}", std::string(req.method_string()),
                                 std::string(req.target()), e.what());
    return errorJson(req, status::internal_server_error, "internal", "Internal error");
}

[[noreturn]] void notFound() { throw HttpError(status::not_found, "not_found", "Upload session not found"); }

// ---- small helpers ---------------------------------------------------------------------------------------------

[[nodiscard]] std::string hex(const unsigned char* data, const std::size_t n) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0f]);
    }
    return out;
}

[[nodiscard]] bool validId(const std::string_view v) {
    if (v.empty() || v.size() > 96) return false;
    return std::ranges::all_of(v, [](const unsigned char c) { return std::isalnum(c) || c == '-' || c == '_'; });
}

[[nodiscard]] std::vector<std::string> routeParts(std::string_view target) {
    if (const auto q = target.find('?'); q != std::string_view::npos) target = target.substr(0, q);
    std::vector<std::string> parts;
    while (!target.empty()) {
        const auto slash = target.find('/');
        const auto part = target.substr(0, slash);
        if (!part.empty()) parts.emplace_back(part);
        if (slash == std::string_view::npos) break;
        target.remove_prefix(slash + 1);
    }
    return parts;
}

[[nodiscard]] std::optional<uint64_t> parseU64(const std::string_view text) {
    uint64_t v = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), v);
    if (ec != std::errc{} || ptr != text.data() + text.size() || text.empty()) return std::nullopt;
    return v;
}

[[nodiscard]] std::string trimmed(std::string_view v) {
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
    return std::string(v);
}

// RFC 9530 Content-Digest: the sha-256 member (`sha-256=:<base64>:`), or nullopt when the header has none.
[[nodiscard]] std::optional<std::array<unsigned char, 32>> contentDigest(const request& req) {
    const auto it = req.find("Content-Digest");
    if (it == req.end()) return std::nullopt;
    std::string_view rest(it->value().data(), it->value().size());
    while (!rest.empty()) {
        const auto comma = rest.find(',');
        const auto member = trimmed(rest.substr(0, comma));
        if (const auto eq = member.find('='); eq != std::string::npos) {
            auto key = member.substr(0, eq);
            std::ranges::transform(key, key.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (key == "sha-256") {
                const auto value = trimmed(std::string_view(member).substr(eq + 1));
                if (value.size() < 2 || value.front() != ':' || value.back() != ':')
                    throw HttpError(status::bad_request, "bad_request", "Content-Digest sha-256 must be :<base64>:");
                const auto b64 = value.substr(1, value.size() - 2);
                std::array<unsigned char, 32> out{};
                std::size_t len = 0;
                if (sodium_base642bin(out.data(), out.size(), b64.data(), b64.size(), nullptr, &len, nullptr,
                                      sodium_base64_VARIANT_ORIGINAL) != 0 || len != out.size())
                    throw HttpError(status::bad_request, "bad_request", "Content-Digest sha-256 is not a SHA-256 digest");
                return out;
            }
        }
        if (comma == std::string_view::npos) break;
        rest.remove_prefix(comma + 1);
    }
    return std::nullopt;
}

[[nodiscard]] std::vector<uint8_t> randomIv() {
    std::vector<uint8_t> iv(crypto::util::AES_IV_SIZE);
    randombytes_buf(iv.data(), iv.size());
    return iv;
}

[[nodiscard]] std::array<uint8_t, crypto::util::AES_IV_SIZE> ivFrom(const std::string& b64) {
    const auto raw = crypto::util::b64_decode(b64);
    if (raw.size() != crypto::util::AES_IV_SIZE) throw std::runtime_error("Malformed upload IV");
    std::array<uint8_t, crypto::util::AES_IV_SIZE> out{};
    std::ranges::copy(raw, out.begin());
    return out;
}

void writeAll(const int fd, const uint8_t* data, std::size_t n, uint64_t offset) {
    while (n > 0) {
        const auto w = ::pwrite(fd, data, n, static_cast<off_t>(offset));
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) throw std::system_error(errno, std::generic_category(), "writing the upload spool");
        data += w;
        n -= static_cast<std::size_t>(w);
        offset += static_cast<uint64_t>(w);
    }
}

void readExact(const int fd, uint8_t* data, std::size_t n, uint64_t offset) {
    while (n > 0) {
        const auto r = ::pread(fd, data, n, static_cast<off_t>(offset));
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) throw std::system_error(errno, std::generic_category(), "reading the upload spool");
        if (r == 0) throw std::runtime_error("The upload spool file is shorter than recorded");
        data += r;
        n -= static_cast<std::size_t>(r);
        offset += static_cast<uint64_t>(r);
    }
}

void syncFd(const int fd, const char* what) {
    if (platform::durable::sync(fd) != 0) throw std::system_error(errno, std::generic_category(), what);
}

void syncDir(const std::filesystem::path& dir) {
    const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) throw std::system_error(errno, std::generic_category(), "opening the upload spool directory");
    const int rc = platform::durable::sync(fd);
    const int err = errno;
    ::close(fd);
    if (rc != 0) throw std::system_error(err, std::generic_category(), "flushing the upload spool directory");
}


// ---- state -----------------------------------------------------------------------------------------------------

}  // namespace

// The session state, in a named namespace: Part::Impl (external linkage) holds these, and GCC refuses members of
// internal-linkage types there (-Wsubobject-linkage).
namespace detail {

struct Fd {
    int fd{-1};
    Fd() = default;
    explicit Fd(const int f) : fd(f) {}
    Fd(Fd&& o) noexcept : fd(std::exchange(o.fd, -1)) {}
    Fd& operator=(Fd&& o) noexcept {
        if (this != &o) {
            reset();
            fd = std::exchange(o.fd, -1);
        }
        return *this;
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() { reset(); }
    void reset() noexcept {
        if (fd >= 0) ::close(fd);
        fd = -1;
    }
};

enum class FileState { Receiving, Sealing, Committing, Committed, Failed };
enum class Pre { Reject, CreateOnly, IfMatch };

[[nodiscard]] std::string_view stateName(const FileState s) {
    switch (s) {
        case FileState::Receiving: return "receiving";
        case FileState::Sealing: return "sealing";
        case FileState::Committing: return "committing";
        case FileState::Committed: return "committed";
        case FileState::Failed: return "failed";
    }
    return "failed";
}

[[nodiscard]] FileState stateFrom(const std::string_view s) {
    if (s == "receiving") return FileState::Receiving;
    if (s == "sealing") return FileState::Sealing;
    if (s == "committing") return FileState::Committing;
    if (s == "committed") return FileState::Committed;
    return FileState::Failed;
}

[[nodiscard]] std::string_view preName(const Pre p) {
    switch (p) {
        case Pre::Reject: return "reject";
        case Pre::CreateOnly: return "create_only";
        case Pre::IfMatch: return "if_match";
    }
    return "reject";
}

[[nodiscard]] Pre preFrom(const std::string_view s) {
    if (s == "create_only") return Pre::CreateOnly;
    if (s == "if_match") return Pre::IfMatch;
    return Pre::Reject;
}

[[nodiscard]] bool terminal(const FileState s) { return s == FileState::Committed || s == FileState::Failed; }

struct Failure {
    std::string code;
    std::string message;
    std::optional<std::string> etag;
};

struct StoredPart {
    uint64_t length{};
    std::string iv;  // base64, the part's own GCM IV
};

// The sealing cursor: the file's GCM stream (and the BLAKE2b of its ciphertext) fed in order with the stored parts,
// written to <ordinal>.sealed. Only the task holding the file's `busy` flag touches it.
struct Cursor {
    uint64_t fed{0};
    std::unique_ptr<crypto::util::GcmStreamEncryptor> enc;
    crypto_generichash_state hash{};
    Fd fd;
    std::optional<std::string> mime;  // sniffed from the first plaintext bytes
};

struct UFile {
    std::string id;
    uint32_t ordinal{};
    std::string path;     // vault path
    std::string display;  // as the client addressed it
    uint64_t size{};
    std::optional<std::string> clientMime;
    Pre pre{Pre::Reject};
    std::optional<std::string> expectedSource;
    std::string iv;  // base64, "" for an empty file
    uint32_t keyVersion{};
    FileState state{FileState::Receiving};
    std::optional<Failure> error;
    std::optional<uint32_t> entryId;
    uint64_t sealed{0};  // durably sealed prefix
    std::map<uint64_t, StoredPart> parts;
    std::vector<std::pair<uint64_t, uint64_t>> inflight;
    bool busy{false};
    bool again{false};
    std::unique_ptr<Cursor> cursor;
    std::optional<std::string> contentHash;
    std::string shareUploadId;
    std::string shareParent;
};

struct USession {
    std::string id;
    bool share{false};
    uint32_t userId{};
    std::string shareSessionId;
    uint32_t vaultId{};
    std::time_t created{};
    std::time_t lastActivity{};
    bool removed{false};
    std::vector<UFile> files;
    unsigned inFlight{0};
    std::shared_ptr<ws::Session> shareCaller;  // the owning share session's latest request (commits need it)
    std::mutex m;
    std::condition_variable cv;
};

using SessionPtr = std::shared_ptr<USession>;

}  // namespace detail

namespace {

using detail::Fd;
using detail::FileState;
using detail::Pre;
using detail::stateName;
using detail::stateFrom;
using detail::preName;
using detail::preFrom;
using detail::terminal;
using detail::Failure;
using detail::StoredPart;
using detail::Cursor;
using detail::UFile;
using detail::USession;
using detail::SessionPtr;

struct Uploads {
    std::mutex m;
    std::unordered_map<std::string, SessionPtr> sessions;

    std::mutex qm;
    std::condition_variable qcv;
    std::deque<std::pair<SessionPtr, uint32_t>> queue;
    std::vector<std::thread> workers;
    std::atomic<bool> stopping{false};  // read without qm (sealing checks it under a session lock)
    unsigned running{0};

    std::atomic<unsigned> activeParts{0};
    std::atomic<bool> holdCommits{false};
    std::mutex holdM;
    std::vector<std::pair<SessionPtr, uint32_t>> held;  // tests: commits parked until released

    Service::Clock clock;
    std::chrono::milliseconds finishWait{5000};
};

[[nodiscard]] Uploads& reg() {
    static Uploads r;
    return r;
}

[[nodiscard]] std::time_t now() { return reg().clock ? reg().clock() : std::time(nullptr); }

[[nodiscard]] config::TransferConfig cfg() { return config::Registry::get().transfer; }

[[nodiscard]] bool workersStopping() { return reg().stopping.load(); }

[[nodiscard]] std::time_t expiresAt(const USession& s, const config::TransferConfig& c) {
    return std::min<std::time_t>(s.lastActivity + static_cast<std::time_t>(c.session_idle_ttl_hours) * 3600,
                                 s.created + static_cast<std::time_t>(c.session_max_age_hours) * 3600);
}

[[nodiscard]] std::filesystem::path sessionDir(const std::string& id) { return Service::spoolRoot() / id; }

[[nodiscard]] std::filesystem::path sealedPath(const std::string& id, const uint32_t ordinal) {
    return sessionDir(id) / (std::to_string(ordinal) + ".sealed");
}

[[nodiscard]] std::filesystem::path partPath(const std::string& id, const uint32_t ordinal, const uint64_t offset) {
    return sessionDir(id) / (std::to_string(ordinal) + "." + std::to_string(offset) + ".part");
}

void ensureDir(const std::filesystem::path& dir) {
    std::filesystem::create_directories(dir);
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
}

void removeQuietly(const std::filesystem::path& p) noexcept {
    std::error_code ec;
    std::filesystem::remove(p, ec);
}

void removeTreeQuietly(const std::filesystem::path& p) noexcept {
    std::error_code ec;
    std::filesystem::remove_all(p, ec);
}

[[nodiscard]] std::shared_ptr<storage::Engine> engineFor(const uint32_t vaultId) {
    auto engine = access::hooks::engineResolver()(vaultId);
    if (!engine || !engine->vault || !engine->paths) throw HttpError(status::not_found, "not_found", "Vault not found");
    return engine;
}

// Coalesced half-open ranges the server holds durably: the sealed prefix and every stored part.
[[nodiscard]] std::vector<std::pair<uint64_t, uint64_t>> rangesOf(const UFile& f) {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    if (f.state == FileState::Committed) {
        if (f.size > 0) out.emplace_back(0, f.size);
        return out;
    }
    if (f.sealed > 0) out.emplace_back(0, f.sealed);
    for (const auto& [offset, part] : f.parts) {
        const auto end = offset + part.length;
        if (!out.empty() && offset <= out.back().second) out.back().second = std::max(out.back().second, end);
        else out.emplace_back(offset, end);
    }
    return out;
}

[[nodiscard]] uint64_t receivedOf(const UFile& f) {
    uint64_t n = 0;
    for (const auto& [a, b] : rangesOf(f)) n += b - a;
    return n;
}

[[nodiscard]] bool covered(const UFile& f) {
    const auto r = rangesOf(f);
    return f.size == 0 || (r.size() == 1 && r.front().first == 0 && r.front().second == f.size);
}

[[nodiscard]] bool onDeviceListener() { return access::DevicePrincipalScope::current() != nullptr; }

struct PartLimits {
    uint64_t defaultBytes, minBytes, maxBytes;
    uint32_t maxInFlight;
};

[[nodiscard]] PartLimits partLimits(const config::TransferConfig& c, const bool device) {
    const auto maxBytes = device ? c.max_part_bytes : std::min(c.max_part_bytes, c.http.max_part_bytes);
    return {.defaultBytes = std::min(c.part_default_bytes, maxBytes), .minBytes = c.part_min_bytes,
            .maxBytes = maxBytes, .maxInFlight = c.max_parts_in_flight};
}

[[nodiscard]] json partJson(const PartLimits& p) {
    return {{"default_bytes", p.defaultBytes}, {"min_bytes", p.minBytes}, {"max_bytes", p.maxBytes},
            {"max_in_flight", p.maxInFlight}};
}

// Whole-session state: cancelled sessions are gone (404), so it is derived from the files.
[[nodiscard]] std::string_view sessionStateLocked(const USession& s) {
    bool receiving = false, pending = false, failed = false;
    for (const auto& f : s.files) {
        if (f.state == FileState::Receiving) receiving = true;
        else if (f.state == FileState::Sealing || f.state == FileState::Committing) pending = true;
        else if (f.state == FileState::Failed) failed = true;
    }
    if (receiving) return "open";
    if (pending) return "finalizing";
    return failed ? "failed" : "complete";
}

[[nodiscard]] json entryJson(const USession& s, const UFile& f) {
    if (f.state != FileState::Committed || !f.entryId) return nullptr;
    if (s.share)
        return {{"id", *f.entryId}, {"path", f.display}, {"transfer_id", f.shareUploadId}};
    try {
        const auto engine = access::hooks::engineResolver()(s.vaultId);
        const auto& cache = runtime::Deps::get().fsCache;
        if (engine && cache) {
            const auto file = std::dynamic_pointer_cast<vh::fs::model::File>(
                cache->getEntry(engine->vaultPathToFusePath(f.path)));
            if (file && file->id == *f.entryId) return json(*file);
        }
    } catch (const std::exception&) {
    }
    return {{"id", *f.entryId}, {"path", f.display}};
}

[[nodiscard]] json fileJsonLocked(const USession& s, const UFile& f) {
    json ranges = json::array();
    for (const auto& [a, b] : rangesOf(f)) ranges.push_back({a, b});
    json out = {{"file_id", f.id}, {"path", f.display}, {"size", f.size}, {"state", stateName(f.state)},
                {"received_bytes", receivedOf(f)}, {"ranges", std::move(ranges)}, {"error", nullptr},
                {"entry", entryJson(s, f)}};
    if (f.error) {
        out["error"] = {{"code", f.error->code}, {"message", f.error->message}};
        if (f.error->etag) out["error"]["etag"] = *f.error->etag;
    }
    if (s.share) out["transfer_id"] = f.shareUploadId;
    return out;
}

[[nodiscard]] json statusJsonLocked(const USession& s) {
    const auto c = cfg();
    json files = json::array();
    for (const auto& f : s.files) files.push_back(fileJsonLocked(s, f));
    return {{"upload_id", s.id}, {"state", sessionStateLocked(s)}, {"expires_at", expiresAt(s, c)},
            {"part", partJson(partLimits(c, onDeviceListener()))}, {"files", std::move(files)}};
}

[[nodiscard]] UFile* fileById(USession& s, const std::string_view id) {
    for (auto& f : s.files)
        if (f.id == id) return &f;
    return nullptr;
}

// ---- share helpers ---------------------------------------------------------------------------------------------

[[nodiscard]] std::shared_ptr<share::Manager> shareManager() {
    auto m = access::hooks::shareManager()();
    if (!m) throw std::runtime_error("Share services are unavailable");
    return m;
}

[[nodiscard]] std::shared_ptr<share::TargetResolver> shareResolver() {
    auto r = access::hooks::shareResolver()();
    if (!r) throw std::runtime_error("Share services are unavailable");
    return r;
}

// The share session's principal as it is now (link and session still active, policy switches re-checked).
[[nodiscard]] std::shared_ptr<share::Principal> freshPrincipal(const std::shared_ptr<ws::Session>& session,
                                                               share::Manager& manager) {
    if (!session || !session->isShareMode() || session->user || session->shareSessionToken().empty())
        throw access::Unauthorized("Unauthorized: requires a ready share session");
    std::shared_ptr<share::Principal> principal;
    try {
        principal = manager.resolvePrincipal(session->shareSessionToken(),
                                             session->ipAddress.empty() ? std::nullopt : std::make_optional(session->ipAddress),
                                             session->userAgent.empty() ? std::nullopt : std::make_optional(session->userAgent));
    } catch (const std::exception& e) {
        throw access::Forbidden(std::string("Share access denied: ") + e.what());
    }
    if (!principal) throw access::Forbidden("Share access denied");
    session->setSharePrincipal(principal, session->shareSessionToken());
    return principal;
}

[[nodiscard]] std::string joinVaultPath(const std::string& parent, const std::string& name) {
    const auto p = share::Scope::normalizeVaultPath(parent);
    return p == "/" ? "/" + name : p + "/" + name;
}

// ---- worker pool -----------------------------------------------------------------------------------------------

void stepFile(const SessionPtr& s, uint32_t ordinal);

void workerLoop() {
    auto& r = reg();
    for (;;) {
        std::pair<SessionPtr, uint32_t> task;
        {
            std::unique_lock lock(r.qm);
            r.qcv.wait(lock, [&] { return r.stopping || !r.queue.empty(); });
            if (r.stopping) return;
            task = std::move(r.queue.front());
            r.queue.pop_front();
            ++r.running;
        }
        try {
            stepFile(task.first, task.second);
        } catch (const std::exception& e) {
            log::Registry::http()->error("[ResumableUpload] Worker step failed for {}: {}", task.first->id, e.what());
        } catch (...) {
            log::Registry::http()->error("[ResumableUpload] Worker step failed for {}", task.first->id);
        }
        {
            std::scoped_lock lock(r.qm);
            --r.running;
        }
        r.qcv.notify_all();
    }
}

void startWorkersLocked(Uploads& r) {
    if (!r.workers.empty() || r.stopping) return;
    const auto n = std::clamp<uint32_t>(cfg().commit_workers, 1, 8);
    for (uint32_t i = 0; i < n; ++i) r.workers.emplace_back(workerLoop);
}

// Queues one step for the file, unless one is queued or running already (then it runs again after).
void enqueue(const SessionPtr& s, const uint32_t ordinal) {
    {
        std::scoped_lock lock(s->m);
        if (s->removed || ordinal >= s->files.size()) return;
        auto& f = s->files[ordinal];
        if (terminal(f.state)) return;
        if (f.busy) {
            f.again = true;
            return;
        }
        f.busy = true;
        f.again = false;
    }
    auto& r = reg();
    bool queued = false;
    {
        std::scoped_lock lock(r.qm);
        if (!r.stopping) {
            startWorkersLocked(r);
            r.queue.emplace_back(s, ordinal);
            queued = true;
        }
    }
    if (!queued) {  // never s->m inside qm: sealing reads `stopping` under s->m
        std::scoped_lock sl(s->m);
        s->files[ordinal].busy = false;
        return;
    }
    r.qcv.notify_one();
}

// ---- terminal transitions --------------------------------------------------------------------------------------

void settleSessionIfDone(const SessionPtr& s) {
    std::string state;
    {
        std::scoped_lock lock(s->m);
        if (s->removed) return;
        if (!std::ranges::all_of(s->files, [](const UFile& f) { return terminal(f.state); })) return;
        state = std::string(sessionStateLocked(*s));
    }
    removeTreeQuietly(sessionDir(s->id));
    try {
        q::Resumable::setSessionState(s->id, state);
    } catch (const std::exception& e) {
        log::Registry::http()->warn("[ResumableUpload] Could not record session {} as {}: {}", s->id, state, e.what());
    }
}

void failFile(const SessionPtr& s, const uint32_t ordinal, const std::string& code, const std::string& message,
              const std::optional<std::string>& etag = std::nullopt) {
    std::string fileId, shareUploadId;
    std::vector<std::filesystem::path> spool;
    std::shared_ptr<ws::Session> shareCaller;
    {
        std::scoped_lock lock(s->m);
        auto& f = s->files[ordinal];
        if (terminal(f.state)) return;
        f.state = FileState::Failed;
        f.error = Failure{.code = code, .message = message, .etag = etag};
        f.cursor.reset();
        fileId = f.id;
        shareUploadId = f.shareUploadId;
        shareCaller = s->shareCaller;
        spool.push_back(sealedPath(s->id, f.ordinal));
        for (const auto& [offset, _] : f.parts) spool.push_back(partPath(s->id, f.ordinal, offset));
    }
    s->cv.notify_all();
    log::Registry::http()->info("[ResumableUpload] {} file {} failed: {} ({})", s->id, fileId, code, message);
    try {
        q::Resumable::markFailed(s->id, fileId, code, message, etag);
    } catch (const std::exception& e) {
        log::Registry::http()->warn("[ResumableUpload] Could not record the failure of {}/{}: {}", s->id, fileId, e.what());
    }
    for (const auto& p : spool) removeQuietly(p);
    if (s->share && !shareUploadId.empty() && shareCaller) {
        try {
            if (const auto principal = shareCaller->sharePrincipal())
                shareManager()->failUpload(*principal, shareUploadId, "resumable_" + code);
        } catch (const std::exception&) {
        }
    }
    settleSessionIfDone(s);
}

// ---- sealing cursor --------------------------------------------------------------------------------------------

struct FileKey {
    crypto::SecretKeyPtr key;
    std::array<uint8_t, crypto::util::AES_IV_SIZE> iv{};
};

// The file's key, or a key_rotated failure: the version it was created under must still be the vault's current key.
[[nodiscard]] std::optional<FileKey> fileKeyOrFail(const SessionPtr& s, const uint32_t ordinal,
                                                   const std::shared_ptr<storage::Engine>& engine,
                                                   const uint32_t keyVersion, const std::string& iv) {
    try {
        const auto& em = engine->encryptionManager;
        if (!em || em->currentKey().version != keyVersion) {
            failFile(s, ordinal, "key_rotated", "The vault key was rotated during the upload; upload the file again");
            return std::nullopt;
        }
        return FileKey{.key = em->keySnapshot(keyVersion), .iv = ivFrom(iv)};
    } catch (const std::exception&) {
        failFile(s, ordinal, "key_rotated", "The vault key was rotated during the upload; upload the file again");
        return std::nullopt;
    }
}

void sniff(Cursor& c, const uint64_t at, const uint8_t* plain, const std::size_t n) {
    if (at != 0 || c.mime || n == 0) return;
    try {
        const std::vector<uint8_t> head(plain, plain + std::min(n, kSniffBytes));
        if (auto m = vh::fs::metadata::Magic::get_mime_type_from_buffer(head); !m.empty()) c.mime = std::move(m);
    } catch (const std::exception&) {
    }
}

// Opens the cursor: the sealed file's durable prefix is read back (decrypted at its offset and re-encrypted through
// the file's stream, which must reproduce it byte for byte), and anything past it is cut off.
[[nodiscard]] std::unique_ptr<Cursor> openCursor(const std::filesystem::path& sealed, const FileKey& key,
                                                 const uint64_t prefix) {
    auto c = std::make_unique<Cursor>();
    c->enc = std::make_unique<crypto::util::GcmStreamEncryptor>(key.key->bytes(), key.iv);
    crypto_generichash_init(&c->hash, nullptr, 0, crypto_generichash_BYTES);
    c->fd = Fd(::open(sealed.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600));
    if (c->fd.fd < 0) throw std::system_error(errno, std::generic_category(), "opening the sealed spool file");
    struct stat st{};
    if (::fstat(c->fd.fd, &st) != 0) throw std::system_error(errno, std::generic_category(), "stat sealed spool");
    // Once committed, the sealed file is a vault backing file (a hard link): never write it again.
    if (st.st_nlink > 1) throw storage::IntegrityError("The sealed spool file is linked elsewhere");
    std::vector<uint8_t> ct(kIoChunk), plain(kIoChunk), again(kIoChunk);
    for (uint64_t pos = 0; pos < prefix;) {
        const auto n = static_cast<std::size_t>(std::min<uint64_t>(kIoChunk, prefix - pos));
        readExact(c->fd.fd, ct.data(), n, pos);
        crypto::util::gcmCtrDecryptAt(key.key->bytes(), key.iv, pos, {ct.data(), n}, {plain.data(), n});
        sniff(*c, pos, plain.data(), n);
        c->enc->update({plain.data(), n}, {again.data(), n});
        if (std::memcmp(again.data(), ct.data(), n) != 0)
            throw storage::IntegrityError("The sealed spool prefix does not match the file's stream");
        crypto_generichash_update(&c->hash, ct.data(), n);
        pos += n;
    }
    sodium_memzero(plain.data(), plain.size());
    if (::ftruncate(c->fd.fd, static_cast<off_t>(prefix)) != 0)
        throw std::system_error(errno, std::generic_category(), "truncating the sealed spool file");
    c->fed = prefix;
    return c;
}

// Feeds every stored part that continues the sealed prefix, checkpoints, and (once the whole file is fed) finishes
// the tag. Returns true when the file is ready to commit.
[[nodiscard]] bool sealStep(const SessionPtr& s, const uint32_t ordinal) {
    std::string id = s->id, iv;
    uint32_t keyVersion{};
    uint64_t size{}, durable{};
    {
        std::scoped_lock lock(s->m);
        const auto& f = s->files[ordinal];
        iv = f.iv;
        keyVersion = f.keyVersion;
        size = f.size;
        durable = f.sealed;
    }
    const auto engine = engineFor(s->vaultId);
    const auto key = fileKeyOrFail(s, ordinal, engine, keyVersion, iv);
    if (!key) return false;

    std::unique_ptr<Cursor> cursor;
    {
        std::scoped_lock lock(s->m);
        cursor = std::move(s->files[ordinal].cursor);
    }
    const auto sealed = sealedPath(id, ordinal);
    if (!cursor) cursor = openCursor(sealed, *key, durable);

    std::vector<uint8_t> ct(kIoChunk), plain(kIoChunk), out(kIoChunk);
    std::vector<uint64_t> consumed;
    uint64_t unsynced = 0;
    const auto checkpoint = [&] {
        if (consumed.empty()) return;
        syncFd(cursor->fd.fd, "flushing the sealed spool file");
        q::Resumable::setSealed(id, s->files[ordinal].id, cursor->fed);
        {
            std::scoped_lock lock(s->m);
            s->files[ordinal].sealed = cursor->fed;
        }
        for (const auto offset : consumed) removeQuietly(partPath(id, ordinal, offset));
        consumed.clear();
        unsynced = 0;
    };

    for (;;) {
        StoredPart part;
        uint64_t offset = cursor->fed;
        {
            std::scoped_lock lock(s->m);
            if (s->removed) return false;
            if (workersStopping()) break;  // shutting down: checkpoint what is fed, resume after the restart
            const auto& f = s->files[ordinal];
            const auto it = f.parts.find(offset);
            if (it == f.parts.end()) break;
            part = it->second;
        }
        const auto partFile = partPath(id, ordinal, offset);
        Fd in(::open(partFile.c_str(), O_RDONLY | O_CLOEXEC));
        if (in.fd < 0) throw std::system_error(errno, std::generic_category(), "opening a stored part");
        const auto partIv = ivFrom(part.iv);
        crypto::util::GcmStreamDecryptor dec(key->key->bytes(), partIv);
        for (uint64_t pos = 0; pos < part.length;) {
            const auto n = static_cast<std::size_t>(std::min<uint64_t>(kIoChunk, part.length - pos));
            readExact(in.fd, ct.data(), n, pos);
            dec.update({ct.data(), n}, {plain.data(), n});
            sniff(*cursor, offset + pos, plain.data(), n);
            cursor->enc->update({plain.data(), n}, {out.data(), n});
            writeAll(cursor->fd.fd, out.data(), n, offset + pos);
            crypto_generichash_update(&cursor->hash, out.data(), n);
            pos += n;
        }
        std::array<uint8_t, crypto::util::AES_TAG_SIZE> tag{};
        readExact(in.fd, tag.data(), tag.size(), part.length);
        sodium_memzero(plain.data(), plain.size());
        if (!dec.finish(tag)) {
            failFile(s, ordinal, "integrity", "A stored part failed its integrity check");
            return false;
        }
        cursor->fed = offset + part.length;
        consumed.push_back(offset);
        unsynced += part.length;
        if (unsynced >= kSealCheckpointBytes) checkpoint();
    }

    if (cursor->fed < size) {
        checkpoint();
        std::scoped_lock lock(s->m);
        s->files[ordinal].cursor = std::move(cursor);
        return false;
    }

    const auto tag = cursor->enc->finish();
    writeAll(cursor->fd.fd, tag.data(), tag.size(), size);
    crypto_generichash_update(&cursor->hash, tag.data(), tag.size());
    std::array<unsigned char, crypto_generichash_BYTES> digest{};
    crypto_generichash_final(&cursor->hash, digest.data(), digest.size());
    syncFd(cursor->fd.fd, "flushing the sealed spool file");
    cursor->fd.reset();
    const auto& fileId = s->files[ordinal].id;
    q::Resumable::setSealed(id, fileId, size);
    q::Resumable::setFileState(id, fileId, "committing");
    {
        std::scoped_lock lock(s->m);
        auto& f = s->files[ordinal];
        f.sealed = size;
        f.contentHash = hex(digest.data(), digest.size());
        if (cursor->mime) f.clientMime = cursor->mime;  // the sniffed type wins over the client's
        if (f.state == FileState::Receiving || f.state == FileState::Sealing) f.state = FileState::Committing;
    }
    for (const auto offset : consumed) removeQuietly(partPath(id, ordinal, offset));
    s->cv.notify_all();
    return true;
}

// ---- commit ----------------------------------------------------------------------------------------------------

struct CommitPlan {
    std::string fileId, path, iv, shareUploadId, shareParent;
    uint64_t size{};
    Pre pre{};
    std::optional<std::string> expectedSource, mime, contentHash;
    uint32_t keyVersion{};
};

[[nodiscard]] std::optional<std::string> currentEtag(const std::shared_ptr<vh::fs::model::Entry>& entry) {
    if (const auto file = std::dynamic_pointer_cast<vh::fs::model::File>(entry)) return storage::generationOf(*file).etag();
    return std::nullopt;
}

void markCommitted(const SessionPtr& s, const uint32_t ordinal, const std::shared_ptr<vh::fs::model::File>& file,
                   const std::shared_ptr<storage::Engine>& engine) {
    std::string fileId;
    {
        std::scoped_lock lock(s->m);
        auto& f = s->files[ordinal];
        f.state = FileState::Committed;
        f.entryId = file->id;
        f.sealed = f.size;
        f.cursor.reset();
        fileId = f.id;
    }
    try {
        q::Resumable::markCommitted(s->id, fileId, file->id);
    } catch (const std::exception& e) {
        log::Registry::http()->warn("[ResumableUpload] Could not record the commit of {}/{}: {}", s->id, fileId, e.what());
    }
    removeQuietly(sealedPath(s->id, ordinal));
    s->cv.notify_all();
    log::Registry::audit()->info("[http] upload.resumable.commit session={} file={} vault={} entry={} path={} ({} bytes)",
                                 s->id, fileId, s->vaultId, file->id, file->path.string(), file->size_bytes);
    try {
        if (const auto& sync = runtime::Deps::get().syncController) sync->runNow(engine->vault->id);
    } catch (const std::exception& e) {
        log::Registry::sync()->warn("[ResumableUpload] Could not trigger sync for vault {}: {}", s->vaultId, e.what());
    }
    settleSessionIfDone(s);
}

void commitFile(const SessionPtr& s, const uint32_t ordinal) {
    if (workersStopping()) return;  // the commit resumes after the restart (its state is in the database)
    if (reg().holdCommits.load()) {
        std::scoped_lock lock(reg().holdM);
        reg().held.emplace_back(s, ordinal);
        return;
    }
    CommitPlan plan;
    std::shared_ptr<ws::Session> shareCaller;
    {
        std::scoped_lock lock(s->m);
        if (s->removed) return;
        const auto& f = s->files[ordinal];
        if (f.state != FileState::Committing) return;
        plan = {.fileId = f.id, .path = f.path, .iv = f.iv, .shareUploadId = f.shareUploadId,
                .shareParent = f.shareParent, .size = f.size, .pre = f.pre, .expectedSource = f.expectedSource,
                .mime = f.clientMime, .contentHash = f.contentHash, .keyVersion = f.keyVersion};
        shareCaller = s->shareCaller;
    }
    const auto engine = engineFor(s->vaultId);
    const auto fusePath = engine->vaultPathToFusePath(plan.path);
    const auto& cache = runtime::Deps::get().fsCache;
    const auto spool = sealedPath(s->id, ordinal);

    // Committed already (a restart between the commit and its record): the file there carries this upload's IV.
    if (!plan.iv.empty() && cache) {
        if (const auto there = std::dynamic_pointer_cast<vh::fs::model::File>(cache->getEntry(fusePath));
            there && there->encryption_iv == plan.iv) {
            markCommitted(s, ordinal, there, engine);
            return;
        }
    }
    if (plan.size > 0) {
        std::error_code ec;
        const auto onDisk = std::filesystem::file_size(spool, ec);
        if (ec || onDisk != plan.size + crypto::util::AES_TAG_SIZE) {
            failFile(s, ordinal, "internal", "The sealed upload is missing from the spool");
            return;
        }
        if (engine->encryptionManager->currentKey().version != plan.keyVersion) {
            failFile(s, ordinal, "key_rotated", "The vault key was rotated during the upload; upload the file again");
            return;
        }
    }

    // Who the file is committed as, authorized again as they are now.
    std::shared_ptr<identities::User> user;
    std::shared_ptr<share::Manager> manager;
    std::shared_ptr<share::Principal> principal;
    try {
        if (!s->share) {
            user = vh::identities::manager().user(s->userId);
            if (!user || !user->authorizing()) throw access::Forbidden("The uploading account is no longer active");
            access::requireUser(user, engine, plan.path, plan.pre == Pre::IfMatch ? FsAction::Overwrite : FsAction::Write);
        } else {
            if (!shareCaller) return;  // after a restart: waits for the share session's next request
            manager = shareManager();
            principal = freshPrincipal(shareCaller, *manager);
            const auto actor = shareCaller->rbacActor();
            try {
                (void)shareResolver()->resolve(actor, {.path = plan.shareParent,
                                                       .operation = share::Operation::Upload,
                                                       .path_mode = share::TargetPathMode::VaultRelative,
                                                       .expected_target_type = share::TargetType::Directory,
                                                       .vault_id = s->vaultId});
            } catch (const std::exception& e) {
                throw access::Forbidden(std::string("Share upload target denied: ") + e.what());
            }
            const auto scope = manager->authorize(actor, share::Operation::Upload, plan.path, share::TargetType::File,
                                                  s->vaultId);
            if (!scope.allowed) throw access::Forbidden("Share upload scope denied: " + scope.reason);
            if (principal->link_created_by == 0) throw access::Forbidden("The share link's creator is missing");
            user = vh::identities::User::detached(principal->link_created_by, {});
        }
    } catch (const access::Forbidden& e) {
        failFile(s, ordinal, "forbidden", e.what());
        return;
    } catch (const access::Unauthorized& e) {
        failFile(s, ordinal, "forbidden", e.what());
        return;
    } catch (const access::BadRequest& e) {
        failFile(s, ordinal, "forbidden", e.what());
        return;
    }

    if (!s->share) {
        if (const auto err = vh::fs::Filesystem::mkdir({.path = fusePath.parent_path(), .engine = engine, .user = user});
            err) {
            failFile(s, ordinal, "conflict", "The parent folder could not be created");
            return;
        }
    }

    const bool createOnly = plan.pre != Pre::IfMatch;
    std::optional<CreateClaim> claim;
    const auto refuseExisting = [&](const std::shared_ptr<vh::fs::model::Entry>& existing) {
        if (existing && !std::dynamic_pointer_cast<vh::fs::model::File>(existing))
            failFile(s, ordinal, "conflict", "Something that is not a file exists at that path");
        else if (plan.pre == Pre::Reject)
            failFile(s, ordinal, "already_exists", "A file already exists at that path");
        else
            failFile(s, ordinal, "precondition_failed", "The file changed since the upload began",
                     currentEtag(existing));
    };
    if (createOnly) {
        claim.emplace(std::to_string(s->vaultId) + ":" + plan.path);
        const auto existing = cache ? cache->getEntry(fusePath) : nullptr;
        if (!claim->held() || existing) {
            refuseExisting(existing);
            return;
        }
    }

    const auto size = plan.size;
    vh::fs::NewFileContext ctx{.path = plan.path, .fuse_path = fusePath, .engine = engine, .user = user};
    ctx.overwrite = true;  // with expected_source_id: a create is "only if nothing is there", a replace is a CAS
    ctx.expected_source_id = createOnly ? std::string{} : plan.expectedSource.value_or(std::string{});
    ctx.sealed = [&](const std::filesystem::path& dst) -> vh::fs::SealedContent {
        if (size == 0) {
            const int fd = ::open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (fd < 0) throw std::system_error(errno, std::generic_category(), "creating an empty upload");
            ::close(fd);
            return {.encryption_iv = {}, .key_version = 0, .plaintext_size = 0, .mime_type = plan.mime,
                    .content_hash = std::nullopt};
        }
        // The sealed spool file becomes the backing file: a hard link (no copy), so the spool keeps it until the
        // commit is recorded and a failed commit can be retried. Another file system: copied.
        if (::link(spool.c_str(), dst.c_str()) != 0) {
            const int err = errno;
            if (err != EXDEV && err != EPERM && err != EMLINK && err != ENOTSUP && err != EOPNOTSUPP)
                throw std::system_error(err, std::generic_category(), "linking the sealed upload into place");
            std::filesystem::copy_file(spool, dst);
        }
        return {.encryption_iv = plan.iv, .key_version = plan.keyVersion, .plaintext_size = size,
                .mime_type = plan.mime, .content_hash = plan.contentHash};
    };

    std::shared_ptr<vh::fs::model::File> created;
    try {
        created = vh::fs::Filesystem::createFile(ctx);
    } catch (const vh::fs::ContentConflict&) {
        refuseExisting(cache ? cache->getEntry(fusePath) : nullptr);
        return;
    } catch (const std::filesystem::filesystem_error& e) {
        if (e.code() == std::errc::file_exists) {
            failFile(s, ordinal, "conflict", "Something that is not a file exists at that path");
            return;
        }
        throw;
    }
    if (!created) {
        failFile(s, ordinal, "internal", "The commit produced no file");
        return;
    }

    if (s->share && manager && principal) {
        try {
            manager->finishUpload({.principal = *principal, .upload_id = plan.shareUploadId,
                                   .created_entry_id = created->id, .content_hash = created->content_hash.value_or(""),
                                   .mime_type = created->mime_type});
        } catch (const std::exception& e) {
            log::Registry::http()->warn("[ResumableUpload] Share upload {} committed but not recorded: {}",
                                        plan.shareUploadId, e.what());
        }
    }
    markCommitted(s, ordinal, created, engine);
}

void stepFile(const SessionPtr& s, const uint32_t ordinal) {
    for (;;) {
        FileState state;
        {
            std::scoped_lock lock(s->m);
            if (s->removed) {
                s->files[ordinal].busy = false;
                s->cv.notify_all();
                return;
            }
            state = s->files[ordinal].state;
        }
        try {
            if (state == FileState::Receiving || state == FileState::Sealing) {
                if (sealStep(s, ordinal)) commitFile(s, ordinal);
            } else if (state == FileState::Committing) {
                commitFile(s, ordinal);
            }
        } catch (const storage::IntegrityError& e) {
            failFile(s, ordinal, "integrity", e.what());
        } catch (const std::exception& e) {
            log::Registry::http()->error("[ResumableUpload] {} file #{}: {}", s->id, ordinal, e.what());
            bool removed;
            {
                std::scoped_lock lock(s->m);
                removed = s->removed;
                s->files[ordinal].cursor.reset();
            }
            if (!removed) failFile(s, ordinal, "internal", "The upload could not be finalized");
        }
        std::scoped_lock lock(s->m);
        auto& f = s->files[ordinal];
        if (f.again && !terminal(f.state) && !s->removed) {
            f.again = false;
            continue;
        }
        f.busy = false;
        s->cv.notify_all();
        return;
    }
}

// ---- lookup, ownership, removal --------------------------------------------------------------------------------

[[nodiscard]] SessionPtr lookup(const std::string& id) {
    if (!validId(id)) return nullptr;
    SessionPtr s;
    {
        std::scoped_lock lock(reg().m);
        const auto it = reg().sessions.find(id);
        if (it == reg().sessions.end()) return nullptr;
        s = it->second;
    }
    std::scoped_lock lock(s->m);
    if (s->removed || expiresAt(*s, cfg()) <= now()) return nullptr;
    return s;
}

struct Owned {
    access::Caller caller;
    SessionPtr session;
};

[[nodiscard]] Owned owned(const request& req, const std::string& id) {
    const auto params = access::parseQuery(std::string_view(req.target().data(), req.target().size()));
    Owned out{.caller = access::authenticate(req, params), .session = lookup(id)};
    if (!out.session) notFound();
    auto& s = *out.session;
    if (s.share) {
        if (!out.caller.share || out.caller.session->shareSessionId() != s.shareSessionId) notFound();
        std::vector<uint32_t> waiting;
        {
            std::scoped_lock lock(s.m);
            const bool hadCaller = static_cast<bool>(s.shareCaller);
            s.shareCaller = out.caller.session;
            // After a restart a share file's commit waits for its share session: this request provides it.
            if (!hadCaller)
                for (const auto& f : s.files)
                    if (f.state == FileState::Committing && !f.busy) waiting.push_back(f.ordinal);
        }
        for (const auto i : waiting) enqueue(out.session, i);
    } else {
        if (out.caller.share || !out.caller.session->user || out.caller.session->user->id != s.userId) notFound();
    }
    return out;
}

// Removes a session at once (cancel, expiry): rows, spool, and the share records of files not committed.
void removeSession(const SessionPtr& s, const std::string& reason) {
    std::vector<std::string> openShareUploads;
    std::shared_ptr<ws::Session> shareCaller;
    {
        std::scoped_lock lock(s->m);
        if (s->removed) return;
        s->removed = true;
        for (auto& f : s->files) {
            f.cursor.reset();
            if (s->share && !terminal(f.state) && !f.shareUploadId.empty()) openShareUploads.push_back(f.shareUploadId);
        }
        shareCaller = s->shareCaller;
    }
    s->cv.notify_all();
    {
        std::scoped_lock lock(reg().m);
        reg().sessions.erase(s->id);
    }
    try {
        q::Resumable::remove(s->id);
    } catch (const std::exception& e) {
        log::Registry::http()->warn("[ResumableUpload] Could not delete session {}: {}", s->id, e.what());
    }
    removeTreeQuietly(sessionDir(s->id));
    if (!openShareUploads.empty() && shareCaller) {
        try {
            const auto manager = shareManager();
            if (const auto principal = shareCaller->sharePrincipal())
                for (const auto& id : openShareUploads) {
                    try {
                        if (reason == "http_upload_cancelled") manager->cancelUpload(*principal, id);
                        else manager->failUpload(*principal, id, reason);
                    } catch (const std::exception&) {
                    }
                }
        } catch (const std::exception&) {
        }
    }
    log::Registry::http()->info("[ResumableUpload] Session {} removed ({})", s->id, reason);
}

// Bytes promised to open sessions of a vault (files not yet committed or failed), counted against its free space.
[[nodiscard]] uint64_t reservedBytes(const uint32_t vaultId) {
    std::vector<SessionPtr> all;
    {
        std::scoped_lock lock(reg().m);
        for (const auto& [_, s] : reg().sessions) all.push_back(s);
    }
    uint64_t total = 0;
    for (const auto& s : all) {
        std::scoped_lock lock(s->m);
        if (s->removed || s->vaultId != vaultId) continue;
        for (const auto& f : s->files)
            if (!terminal(f.state)) total += f.size;
    }
    return total;
}

// ---- create ----------------------------------------------------------------------------------------------------

struct NewFile {
    q::FileRow row;
    std::string shareFilename;
};

[[nodiscard]] Response create(const request& req) {
    const auto params = access::parseQuery(std::string_view(req.target().data(), req.target().size()));
    const auto caller = access::authenticate(req, params);
    json body;
    try {
        body = req.body().empty() ? json::object() : json::parse(req.body());
    } catch (const json::exception&) {
        throw HttpError(status::bad_request, "bad_request", "The body must be JSON");
    }
    if (!body.is_object() || !body.contains("files") || !body.at("files").is_array() || body.at("files").empty())
        throw HttpError(status::bad_request, "bad_request", "files must be a non-empty array");
    const auto c = cfg();
    if (body.at("files").size() > c.max_session_files)
        throw HttpError(status::bad_request, "bad_request",
                        "A session holds at most " + std::to_string(c.max_session_files) + " files");

    const auto id = ws::Session::generateUUIDv4();
    const bool shareMode = caller.share;
    std::shared_ptr<share::Manager> manager;
    std::shared_ptr<share::TargetResolver> resolver;
    std::shared_ptr<share::Principal> principal;
    uint32_t vaultId = 0;
    if (shareMode) {
        manager = shareManager();
        resolver = shareResolver();
        principal = freshPrincipal(caller.session, *manager);
        vaultId = principal->vault_id;
    } else {
        if (!body.contains("vault_id") || !body.at("vault_id").is_number_unsigned())
            throw HttpError(status::bad_request, "bad_request", "vault_id is required");
        vaultId = body.at("vault_id").get<uint32_t>();
    }
    const auto engine = engineFor(vaultId);
    const auto& cache = runtime::Deps::get().fsCache;
    const auto actor = shareMode ? std::make_optional(caller.session->rbacActor()) : std::nullopt;

    std::vector<NewFile> files;
    std::unordered_set<std::string> ids, targets;
    uint64_t total = 0;
    uint32_t ordinal = 0;
    for (const auto& item : body.at("files")) {
        if (!item.is_object()) throw HttpError(status::bad_request, "bad_request", "Every file must be an object");
        NewFile nf;
        auto& row = nf.row;
        row.upload_id = id;
        row.ordinal = ordinal++;
        row.file_id = item.contains("file_id") && !item.at("file_id").is_null() ? item.at("file_id").get<std::string>()
                                                                                : ws::Session::generateUUIDv4();
        if (!validId(row.file_id)) throw HttpError(status::bad_request, "bad_request", "file_id must match [A-Za-z0-9_-]{1,96}");
        if (!ids.insert(row.file_id).second) throw HttpError(status::bad_request, "bad_request", "Duplicate file_id " + row.file_id);
        const json fileRef = {{"file_id", row.file_id}};

        if (!item.contains("path") || !item.at("path").is_string())
            throw HttpError(status::bad_request, "bad_request", "path is required", fileRef);
        const auto raw = item.at("path").get<std::string>();
        if (raw.find('\0') != std::string::npos || !share::Scope::contains("/", raw))
            throw HttpError(status::bad_request, "bad_request", "The path escapes the vault", fileRef);
        const auto normalized = share::Scope::normalizeVaultPath(raw);
        if (normalized == "/" || raw.ends_with('/'))
            throw HttpError(status::bad_request, "bad_request", "The path must name a file", fileRef);

        const json& sizeNode = item.contains("size") ? item.at("size") : item.contains("size_bytes") ? item.at("size_bytes") : json();
        if (!sizeNode.is_number_unsigned() && !(sizeNode.is_number_integer() && sizeNode.get<int64_t>() >= 0))
            throw HttpError(status::bad_request, "bad_request", "size is required", fileRef);
        row.size_bytes = sizeNode.get<uint64_t>();
        if (row.size_bytes > kFormatMaxBytes || (c.max_file_bytes > 0 && row.size_bytes > c.max_file_bytes))
            throw HttpError(status::payload_too_large, "file_too_large", "The file exceeds the maximum upload size", fileRef);
        if (item.contains("mime_type") && item.at("mime_type").is_string()) row.mime_type = item.at("mime_type").get<std::string>();

        const bool hasPolicy = item.contains("duplicate_policy") && !item.at("duplicate_policy").is_null();
        const bool hasNone = item.contains("if_none_match") && !item.at("if_none_match").is_null();
        const bool hasMatch = item.contains("if_match") && !item.at("if_match").is_null();
        if (int{hasPolicy} + int{hasNone} + int{hasMatch} > 1)
            throw HttpError(status::bad_request, "bad_request", "Give at most one of duplicate_policy, if_none_match, if_match", fileRef);
        Pre pre = Pre::Reject;
        if (hasPolicy && item.at("duplicate_policy") != "reject")
            throw HttpError(status::bad_request, "bad_request", "duplicate_policy must be \"reject\"", fileRef);
        if (hasNone) {
            if (item.at("if_none_match") != "*") throw HttpError(status::bad_request, "bad_request", "if_none_match must be \"*\"", fileRef);
            pre = Pre::CreateOnly;
        }
        std::string ifMatch;
        if (hasMatch) {
            if (!item.at("if_match").is_string() || item.at("if_match").get<std::string>().empty() || item.at("if_match") == "*")
                throw HttpError(status::bad_request, "bad_request", "if_match must be a content_version", fileRef);
            ifMatch = item.at("if_match").get<std::string>();
            pre = Pre::IfMatch;
        }
        row.precondition = std::string(preName(pre));

        std::shared_ptr<vh::fs::model::Entry> existing;
        if (!shareMode) {
            row.path = normalized;
            row.display_path = normalized;
            if (pre == Pre::IfMatch) {
                const auto target = access::resolvePath(caller, vaultId, row.path, access::Need::Overwrite, access::Expect::File);
                const auto current = storage::generationOf(*target.file);
                if (current.etag() != ifMatch)
                    throw withEtag(HttpError(status::precondition_failed, "precondition_failed",
                                             "The file changed since that version", fileRef), current.etag());
                if (target.file->inode && fuse::WorkingCopies::instance().isOpen(*target.file->inode))
                    throw withEtag(HttpError(status::precondition_failed, "precondition_failed",
                                             "The file is open through the mounted filesystem", fileRef), current.etag());
                row.expected_source_id = current.sourceId();
            } else {
                access::requireUser(caller.session->user, engine, row.path, FsAction::Write);
                existing = cache ? cache->getEntry(engine->vaultPathToFusePath(row.path)) : nullptr;
            }
        } else {
            if (pre == Pre::IfMatch) throw HttpError(status::forbidden, "forbidden", "Replacing files through share links is not supported", fileRef);
            const std::filesystem::path p(normalized);
            nf.shareFilename = p.filename().string();
            const auto parentShare = p.parent_path().empty() ? std::string("/") : p.parent_path().string();
            share::ResolvedTarget parent;
            try {
                parent = resolver->resolve(*actor, {.path = parentShare, .operation = share::Operation::Upload,
                                                    .path_mode = share::TargetPathMode::ShareRelative,
                                                    .expected_target_type = share::TargetType::Directory});
            } catch (const std::exception& e) {
                throw HttpError(status::forbidden, "forbidden", std::string("Share upload target denied: ") + e.what(), fileRef);
            }
            if (parent.vault_id != vaultId) throw HttpError(status::forbidden, "forbidden", "Share upload target denied", fileRef);
            row.path = joinVaultPath(parent.vault_path, nf.shareFilename);
            row.display_path = normalized;
            row.share_parent_path = parent.vault_path;
            const auto scope = manager->authorize(*actor, share::Operation::Upload, row.path, share::TargetType::File, vaultId);
            if (!scope.allowed) throw HttpError(status::forbidden, "forbidden", "Share upload scope denied: " + scope.reason, fileRef);
            existing = cache ? cache->getEntry(engine->vaultPathToFusePath(row.path)) : nullptr;
        }
        if (existing) {
            if (!std::dynamic_pointer_cast<vh::fs::model::File>(existing))
                throw HttpError(status::conflict, "conflict", "Something that is not a file exists at that path", fileRef);
            if (pre == Pre::CreateOnly)
                throw withEtag(HttpError(status::precondition_failed, "precondition_failed", "The file already exists", fileRef),
                               currentEtag(existing));
            throw HttpError(status::conflict, "already_exists", "A file already exists at that path", fileRef);
        }
        if (!targets.insert(row.path).second) throw HttpError(status::bad_request, "bad_request", "Duplicate upload target", fileRef);
        total += row.size_bytes;
        files.push_back(std::move(nf));
    }

    const auto reserved = reservedBytes(vaultId);
    const auto available = engine->freeSpace();
    if (total > available || reserved > available - total)
        throw HttpError(status::insufficient_storage, "insufficient_storage", "Not enough space in the vault");

    const auto current = engine->encryptionManager->currentKey();
    for (auto& nf : files) {
        if (nf.row.size_bytes == 0) {
            nf.row.encryption_iv.clear();
            nf.row.key_version = 0;
            nf.row.state = "committing";
        } else {
            nf.row.encryption_iv = crypto::util::b64_encode(randomIv());
            nf.row.key_version = current.version;
        }
    }

    // Share records (link limits: max_upload_size_bytes, file count/total, MIME and extension rules).
    std::vector<std::string> started;
    if (shareMode) {
        for (auto& nf : files) {
            try {
                const auto parentEntry = cache ? cache->getEntry(engine->vaultPathToFusePath(*nf.row.share_parent_path)) : nullptr;
                auto res = manager->startUpload({.principal = *principal,
                                                 .target_parent_entry_id = parentEntry ? parentEntry->id : 0,
                                                 .target_path = nf.row.path,
                                                 .original_filename = nf.shareFilename,
                                                 .resolved_filename = nf.shareFilename,
                                                 .expected_size_bytes = nf.row.size_bytes,
                                                 .mime_type = nf.row.mime_type});
                if (!res.upload) throw std::runtime_error("The share upload was not recorded");
                nf.row.share_upload_id = res.upload->id;
                started.push_back(res.upload->id);
            } catch (const std::exception& e) {
                for (const auto& sid : started) {
                    try {
                        manager->failUpload(*principal, sid, "resumable_create_failed");
                    } catch (const std::exception&) {
                    }
                }
                if (dynamic_cast<const std::invalid_argument*>(&e) || dynamic_cast<const ops::Invalid*>(&e))
                    throw HttpError(status::bad_request, "bad_request", e.what(), {{"file_id", nf.row.file_id}});
                throw HttpError(status::forbidden, "forbidden", e.what(), {{"file_id", nf.row.file_id}});
            }
        }
    }

    auto s = std::make_shared<USession>();
    s->id = id;
    s->share = shareMode;
    s->vaultId = vaultId;
    s->created = s->lastActivity = now();
    if (shareMode) {
        s->shareSessionId = principal->share_session_id;
        s->shareCaller = caller.session;
    } else {
        s->userId = caller.session->user->id;
    }

    q::SessionRow srow{.id = id, .mode = shareMode ? "share" : "user",
                       .user_id = shareMode ? std::nullopt : std::make_optional(s->userId),
                       .share_session_id = shareMode ? std::make_optional(s->shareSessionId) : std::nullopt,
                       .vault_id = vaultId, .state = "open", .created_at = s->created, .last_activity_at = s->created};
    std::vector<q::FileRow> rows;
    for (const auto& nf : files) rows.push_back(nf.row);
    try {
        ensureDir(Service::spoolRoot());
        ensureDir(sessionDir(id));
        q::Resumable::create(srow, rows);
    } catch (...) {
        removeTreeQuietly(sessionDir(id));
        for (const auto& sid : started) {
            try {
                manager->failUpload(*principal, sid, "resumable_create_failed");
            } catch (const std::exception&) {
            }
        }
        throw;
    }

    for (const auto& nf : files) {
        UFile f;
        f.id = nf.row.file_id;
        f.ordinal = nf.row.ordinal;
        f.path = nf.row.path;
        f.display = nf.row.display_path;
        f.size = nf.row.size_bytes;
        f.clientMime = nf.row.mime_type;
        f.pre = preFrom(nf.row.precondition);
        f.expectedSource = nf.row.expected_source_id;
        f.iv = nf.row.encryption_iv;
        f.keyVersion = nf.row.key_version;
        f.state = stateFrom(nf.row.state);
        f.shareUploadId = nf.row.share_upload_id.value_or("");
        f.shareParent = nf.row.share_parent_path.value_or("");
        s->files.push_back(std::move(f));
    }
    {
        std::scoped_lock lock(reg().m);
        reg().sessions.emplace(id, s);
    }
    log::Registry::http()->info("[ResumableUpload] Session {} created: {} file(s), {} bytes, vault {}{}", id, files.size(),
                                total, vaultId, shareMode ? " (share)" : "");
    for (uint32_t i = 0; i < s->files.size(); ++i)
        if (s->files[i].size == 0) enqueue(s, i);

    json out;
    {
        std::scoped_lock lock(s->m);
        out = statusJsonLocked(*s);
    }
    out["resumable"] = true;
    return jsonResponse(req, status::created, out);
}

// ---- status / finish / cancel ----------------------------------------------------------------------------------

[[nodiscard]] Response statusOf(const request& req, const std::string& id) {
    const auto o = owned(req, id);
    std::scoped_lock lock(o.session->m);
    return jsonResponse(req, status::ok, statusJsonLocked(*o.session));
}

[[nodiscard]] Response finish(const request& req, const std::string& id) {
    const auto o = owned(req, id);
    const auto& s = o.session;
    if (s->share) {
        // Commits of a share session run with its principal as it is now (and resume here after a restart).
        (void)freshPrincipal(o.caller.session, *shareManager());
    }
    std::vector<uint32_t> requeue;
    {
        std::scoped_lock lock(s->m);
        if (std::ranges::any_of(s->files, [](const UFile& f) { return f.state == FileState::Receiving; })) {
            auto body = statusJsonLocked(*s);
            return errorJson(req, status::conflict, "incomplete", "Some files are missing bytes", body);
        }
        for (const auto& f : s->files)
            if (f.state == FileState::Committing && !f.busy) requeue.push_back(f.ordinal);
    }
    for (const auto i : requeue) enqueue(s, i);

    std::unique_lock lock(s->m);
    s->cv.wait_for(lock, reg().finishWait, [&] {
        return s->removed || std::ranges::all_of(s->files, [](const UFile& f) { return terminal(f.state); });
    });
    if (s->removed) notFound();
    auto body = statusJsonLocked(*s);
    const auto state = body.at("state").get<std::string>();
    if (state == "finalizing") {
        auto res = jsonResponse(req, status::accepted, body);
        std::get<string_response>(res).set(field::retry_after, "1");
        return res;
    }
    return jsonResponse(req, status::ok, body);
}

[[nodiscard]] Response cancel(const request& req, const std::string& id) {
    const auto o = owned(req, id);
    removeSession(o.session, "http_upload_cancelled");
    string_response res{status::no_content, req.version()};
    res.set(field::cache_control, "no-store");
    res.keep_alive(req.keep_alive());
    res.prepare_payload();
    return res;
}

[[nodiscard]] Response route(request& req) {
    const auto parts = routeParts(std::string_view(req.target().data(), req.target().size()));
    if (parts.size() < 2 || parts[0] != "upload" || parts[1] != "sessions") notFound();
    const auto method = req.method();
    if (parts.size() == 2) {
        if (method != verb::post) throw HttpError(status::method_not_allowed, "method_not_allowed", "POST required");
        return create(req);
    }
    const auto& id = parts[2];
    if (!validId(id)) notFound();
    if (parts.size() == 3) {
        if (method == verb::get) return statusOf(req, id);
        if (method == verb::delete_) return cancel(req, id);
        throw HttpError(status::method_not_allowed, "method_not_allowed", "GET or DELETE required");
    }
    if (parts.size() == 4 && parts[3] == "finish") {
        if (method != verb::post) throw HttpError(status::method_not_allowed, "method_not_allowed", "POST required");
        return finish(req, id);
    }
    notFound();
}

}  // namespace

// ---- Part ------------------------------------------------------------------------------------------------------

struct Part::Impl {
    SessionPtr session;
    uint32_t ordinal{};
    std::string fileId;
    uint64_t offset{}, length{}, received{};
    bool verify{false};
    bool reserved{false};
    bool done{false};
    Fd fd;
    std::filesystem::path attempt, target;
    crypto::SecretKeyPtr key;
    std::array<uint8_t, crypto::util::AES_IV_SIZE> iv{};           // write: this attempt's IV; verify: the stored one's
    std::unique_ptr<crypto::util::GcmStreamEncryptor> enc;
    uint64_t sourceBase{};  // verify: where the stored bytes start (0 in a part file, the offset in the sealed file)
    std::unique_ptr<crypto::util::EvpDigest> sha;
    std::optional<std::array<unsigned char, 32>> expectedDigest;
    bool mismatch{false};
    std::vector<uint8_t> buf, cmp;
    std::chrono::nanoseconds writeTime{0};
    std::shared_ptr<share::Manager> manager;
    std::shared_ptr<share::Principal> principal;
    std::string shareUploadId;

    void release() noexcept {
        if (!reserved) return;
        reserved = false;
        try {
            std::scoped_lock lock(session->m);
            auto& in = session->files[ordinal].inflight;
            std::erase(in, std::make_pair(offset, offset + length));
            if (session->inFlight > 0) --session->inFlight;
        } catch (...) {
        }
        --reg().activeParts;
    }

    ~Impl() {
        fd.reset();
        if (!attempt.empty()) removeQuietly(attempt);
        release();
    }
};

Part::Part() = default;
Part::Part(Part&& other) noexcept = default;
Part& Part::operator=(Part&& other) noexcept = default;
Part::~Part() = default;

void Part::write(const void* data, const std::size_t size) {
    if (!impl_ || impl_->done) throw std::runtime_error("The part is not open");
    auto& p = *impl_;
    if (size > p.length - p.received) throw std::length_error("The body exceeds its Content-Length");
    const auto* in = static_cast<const uint8_t*>(data);
    const auto t0 = std::chrono::steady_clock::now();
    for (std::size_t done = 0; done < size;) {
        const auto n = std::min(size - done, kIoChunk);
        p.sha->update(in + done, n);
        if (p.verify) {
            if (!p.mismatch) {
                p.buf.resize(n);
                p.cmp.resize(n);
                readExact(p.fd.fd, p.buf.data(), n, p.sourceBase + p.received);
                crypto::util::gcmCtrDecryptAt(p.key->bytes(), p.iv, p.sourceBase + p.received, {p.buf.data(), n},
                                              {p.cmp.data(), n});
                if (sodium_memcmp(p.cmp.data(), in + done, n) != 0) p.mismatch = true;
                sodium_memzero(p.cmp.data(), p.cmp.size());
            }
        } else {
            p.buf.resize(n);
            p.enc->update({in + done, n}, {p.buf.data(), n});
            writeAll(p.fd.fd, p.buf.data(), n, p.received);
        }
        p.received += n;
        done += n;
    }
    p.writeTime += std::chrono::steady_clock::now() - t0;
}

model::preview::Response Part::finish(const request& req, const std::chrono::nanoseconds receive) {
    if (!impl_) return errorJson(req, status::internal_server_error, "internal", "The part is not open");
    auto& p = *impl_;
    try {
        if (p.received != p.length)
            throw HttpError(status::bad_request, "bad_request", "The body is shorter than its Content-Length");
        const auto digest = p.sha->finish();
        if (p.expectedDigest && (digest.size() != p.expectedDigest->size() ||
                                 !std::equal(digest.begin(), digest.end(), p.expectedDigest->begin())))
            throw HttpError(status::bad_request, "digest_mismatch", "The body does not match its Content-Digest");
        if (p.verify && p.mismatch)
            throw HttpError(status::conflict, "part_conflict", "A part with different bytes is stored at that range");

        const auto t0 = std::chrono::steady_clock::now();
        if (!p.verify) {
            const auto tag = p.enc->finish();
            writeAll(p.fd.fd, tag.data(), tag.size(), p.length);
            syncFd(p.fd.fd, "flushing an upload part");
            p.fd.reset();
            std::filesystem::rename(p.attempt, p.target);
            p.attempt.clear();
            syncDir(p.target.parent_path());
            {
                std::scoped_lock lock(p.session->m);
                if (p.session->removed) notFound();
            }
            try {
                q::Resumable::insertPart({.upload_id = p.session->id, .file_id = p.fileId, .offset = p.offset,
                                          .length = p.length, .encryption_iv = crypto::util::b64_encode(
                                              std::vector<uint8_t>(p.iv.begin(), p.iv.end()))},
                                         now());
            } catch (...) {
                removeQuietly(p.target);
                throw;
            }
            if (p.manager && p.principal) {
                try {
                    p.manager->recordUploadChunk(*p.principal, p.shareUploadId, p.length);
                } catch (const std::exception& e) {
                    try {
                        q::Resumable::deletePart(p.session->id, p.fileId, p.offset);
                    } catch (const std::exception&) {
                    }
                    removeQuietly(p.target);
                    throw HttpError(status::forbidden, "forbidden", std::string("Share upload refused: ") + e.what());
                }
            }
        }
        const auto syncTime = std::chrono::steady_clock::now() - t0;

        bool sealing = false;
        json body;
        {
            std::scoped_lock lock(p.session->m);
            auto& f = p.session->files[p.ordinal];
            if (!p.verify) {
                f.parts[p.offset] = StoredPart{.length = p.length,
                                               .iv = crypto::util::b64_encode(std::vector<uint8_t>(p.iv.begin(), p.iv.end()))};
                p.session->lastActivity = now();
                if (f.state == FileState::Receiving && covered(f)) {
                    f.state = FileState::Sealing;
                    sealing = true;
                }
            }
            json ranges = json::array();
            for (const auto& [a, b] : rangesOf(f)) ranges.push_back({a, b});
            body = {{"file_id", f.id}, {"offset", p.offset}, {"length", p.length},
                    {"sha256", hex(digest.data(), digest.size())}, {"received_bytes", receivedOf(f)},
                    {"ranges", std::move(ranges)}, {"state", stateName(f.state)}};
        }
        p.done = true;
        p.release();
        if (sealing) {
            try {
                q::Resumable::setFileState(p.session->id, p.fileId, "sealing");
            } catch (const std::exception& e) {
                log::Registry::http()->warn("[ResumableUpload] Could not record {}/{} as sealing: {}", p.session->id,
                                            p.fileId, e.what());
            }
        }
        if (!p.verify) enqueue(p.session, p.ordinal);

        auto res = jsonResponse(req, status::ok, body);
        const auto ms = [](const auto d) {
            return std::chrono::duration_cast<std::chrono::microseconds>(d).count() / 1000.0;
        };
        std::get<string_response>(res).set("Server-Timing", fmt::format("recv;dur={:.1f}, write;dur={:.1f}, sync;dur={:.1f}",
                                                                        ms(receive), ms(p.writeTime), ms(syncTime)));
        return res;
    } catch (const std::exception& e) {
        return errorFor(req, e);
    }
}

PartBegun beginPart(const request& req, const std::optional<uint64_t> contentLength) {
    PartBegun out;
    try {
        const std::string_view target(req.target().data(), req.target().size());
        const auto parts = routeParts(target);
        if (parts.size() != 5 || parts[0] != "upload" || parts[1] != "sessions" || parts[3] != "files") notFound();
        if (req.method() != verb::put) throw HttpError(status::method_not_allowed, "method_not_allowed", "PUT required");
        const auto o = owned(req, parts[2]);
        const auto params = access::parseQuery(target);
        const auto offsetIt = params.find("offset");
        const auto offset = offsetIt == params.end() ? std::nullopt : parseU64(offsetIt->second);
        if (!offset) throw HttpError(status::bad_request, "bad_request", "offset is required");
        if (!contentLength) throw HttpError(status::length_required, "length_required", "Content-Length is required");
        const auto length = *contentLength;
        const auto expectedDigest = contentDigest(req);
        const auto limits = partLimits(cfg(), onDeviceListener());

        auto impl = std::make_unique<Part::Impl>();
        impl->session = o.session;
        impl->offset = *offset;
        impl->length = length;
        impl->expectedDigest = expectedDigest;
        auto& s = *o.session;

        std::string fileIv;
        uint32_t keyVersion{};
        std::optional<StoredPart> stored;
        bool storedInSealed = false;
        {
            std::scoped_lock lock(s.m);
            auto* f = fileById(s, parts[4]);
            if (!f) throw HttpError(status::not_found, "not_found", "No such file in this upload");
            impl->ordinal = f->ordinal;
            impl->fileId = f->id;
            impl->shareUploadId = f->shareUploadId;
            if (f->state != FileState::Receiving)
                throw HttpError(status::conflict, "file_state", std::string("The file is ") + std::string(stateName(f->state)),
                                {{"state", stateName(f->state)}});
            if (length == 0) throw HttpError(status::bad_request, "bad_request", "A part carries at least one byte");
            if (*offset > f->size || length > f->size - *offset)
                throw HttpError(status::bad_request, "bad_request", "The part ends past the file's size");
            if (length > limits.maxBytes)
                throw HttpError(status::payload_too_large, "part_too_large",
                                "A part is at most " + std::to_string(limits.maxBytes) + " bytes here");
            if (length < limits.minBytes && *offset + length != f->size)
                throw HttpError(status::bad_request, "bad_request",
                                "Every part but a file's last carries at least " + std::to_string(limits.minBytes) + " bytes");
            const auto end = *offset + length;
            if (const auto it = f->parts.find(*offset); it != f->parts.end() && it->second.length == length) {
                stored = it->second;
            }
            const bool exact = stored.has_value();
            if (!exact) {
                const auto overlaps = [&](const uint64_t a, const uint64_t b) { return *offset < b && a < end; };
                bool clash = f->sealed > 0 && overlaps(0, f->sealed);
                for (const auto& [po, sp] : f->parts) clash = clash || overlaps(po, po + sp.length);
                for (const auto& [a, b] : f->inflight) clash = clash || overlaps(a, b);
                if (clash) throw HttpError(status::conflict, "part_overlap", "The range overlaps stored or in-flight parts");
            } else {
                for (const auto& [a, b] : f->inflight)
                    if (*offset < b && a < end)
                        throw HttpError(status::conflict, "part_overlap", "That range is being received right now");
                storedInSealed = *offset < f->sealed;  // its part file may be gone: compare with the sealed file
            }
            if (s.inFlight >= limits.maxInFlight) {
                HttpError e(status::too_many_requests, "too_many_parts_in_flight",
                            "At most " + std::to_string(limits.maxInFlight) + " parts may be in flight per session");
                e.retryAfter = "1";
                throw e;
            }
            if (reg().activeParts.load() >= kMaxActiveParts) {
                HttpError e(status::service_unavailable, "busy", "The server is receiving too many parts; retry shortly");
                e.retryAfter = "1";
                throw e;
            }
            ++reg().activeParts;
            ++s.inFlight;
            f->inflight.emplace_back(*offset, end);
            impl->reserved = true;
            fileIv = f->iv;
            keyVersion = f->keyVersion;
        }

        const auto engine = engineFor(s.vaultId);
        if (const auto& em = engine->encryptionManager; !em || em->currentKey().version != keyVersion) {
            const auto ordinal = impl->ordinal;
            impl.reset();  // releases the range first
            failFile(o.session, ordinal, "key_rotated", "The vault key was rotated during the upload; upload the file again");
            throw HttpError(status::conflict, "file_state", "The file is failed (key_rotated)", {{"state", "failed"}});
        }
        impl->key = engine->encryptionManager->keySnapshot(keyVersion);
        impl->sha = std::make_unique<crypto::util::EvpDigest>(EVP_sha256());
        if (s.share) {
            impl->manager = shareManager();
            impl->principal = freshPrincipal(o.caller.session, *impl->manager);
        }

        if (stored) {
            impl->verify = true;
            if (storedInSealed) {
                impl->fd = Fd(::open(sealedPath(s.id, impl->ordinal).c_str(), O_RDONLY | O_CLOEXEC));
                impl->iv = ivFrom(fileIv);
                impl->sourceBase = *offset;
            } else {
                impl->fd = Fd(::open(partPath(s.id, impl->ordinal, *offset).c_str(), O_RDONLY | O_CLOEXEC));
                impl->iv = ivFrom(stored->iv);
                impl->sourceBase = 0;
            }
            if (impl->fd.fd < 0) throw std::system_error(errno, std::generic_category(), "opening a stored part");
        } else {
            const auto dir = sessionDir(s.id);
            ensureDir(dir);
            randombytes_buf(impl->iv.data(), impl->iv.size());
            impl->enc = std::make_unique<crypto::util::GcmStreamEncryptor>(impl->key->bytes(), impl->iv);
            impl->target = partPath(s.id, impl->ordinal, *offset);
            impl->attempt = dir / (std::to_string(impl->ordinal) + "." + std::to_string(*offset) + "." +
                                   hex(impl->iv.data(), 6) + ".tmp");
            impl->fd = Fd(::open(impl->attempt.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
            if (impl->fd.fd < 0) {
                impl->attempt.clear();
                throw std::system_error(errno, std::generic_category(), "creating an upload part");
            }
        }
        out.part.impl_ = std::move(impl);
        return out;
    } catch (const std::exception& e) {
        out.part = Part{};
        out.refusal = errorFor(req, e);
        return out;
    }
}

bool isRoute(const std::string_view target) {
    constexpr std::string_view base = "/upload/sessions";
    if (!target.starts_with(base)) return false;
    return target.size() == base.size() || target[base.size()] == '/' || target[base.size()] == '?';
}

bool isPartRequest(const boost::beast::http::verb method, const std::string_view target) {
    if (method != verb::put || !isRoute(target)) return false;
    const auto parts = routeParts(target);
    return parts.size() == 5 && parts[3] == "files";
}

model::preview::Response handle(request&& req) {
    try {
        if (isPartRequest(req.method(), std::string_view(req.target().data(), req.target().size()))) {
            std::optional<uint64_t> length;
            if (const auto it = req.find(field::content_length); it != req.end()) {
                length = parseU64(std::string_view(it->value().data(), it->value().size()));
                if (!length) return errorJson(req, status::bad_request, "bad_request", "Invalid Content-Length");
            }
            auto begun = beginPart(req, length);
            if (begun.refusal) return std::move(*begun.refusal);
            begun.part.write(req.body().data(), req.body().size());
            return begun.part.finish(req, std::chrono::nanoseconds{0});
        }
        return route(req);
    } catch (const std::exception& e) {
        return errorFor(req, e);
    }
}

model::preview::Response errorResponse(const request& req, const std::exception& e) { return errorFor(req, e); }

// ---- Service ---------------------------------------------------------------------------------------------------

std::filesystem::path Service::spoolRoot() { return paths::getBackingPath() / ".upload-spool"; }

void Service::recover() {
    const auto c = cfg();
    const auto t = now();
    std::vector<q::LoadedSession> loaded;
    try {
        loaded = q::Resumable::loadAll();
    } catch (const std::exception& e) {
        log::Registry::http()->error("[ResumableUpload] Could not load upload sessions: {}", e.what());
        return;
    }
    std::vector<SessionPtr> live;
    std::map<std::string, SessionPtr> known;
    for (auto& l : loaded) {
        auto s = std::make_shared<USession>();
        s->id = l.session.id;
        s->share = l.session.mode == "share";
        s->userId = l.session.user_id.value_or(0);
        s->shareSessionId = l.session.share_session_id.value_or("");
        s->vaultId = l.session.vault_id;
        s->created = l.session.created_at;
        s->lastActivity = l.session.last_activity_at;
        if (expiresAt(*s, c) <= t || l.session.state == "cancelled") {
            try {
                q::Resumable::remove(s->id);
            } catch (const std::exception&) {
            }
            removeTreeQuietly(sessionDir(s->id));
            continue;
        }
        for (const auto& row : l.files) {
            UFile f;
            f.id = row.file_id;
            f.ordinal = row.ordinal;
            f.path = row.path;
            f.display = row.display_path;
            f.size = row.size_bytes;
            f.clientMime = row.mime_type;
            f.pre = preFrom(row.precondition);
            f.expectedSource = row.expected_source_id;
            f.iv = row.encryption_iv;
            f.keyVersion = row.key_version;
            f.state = stateFrom(row.state);
            f.sealed = row.sealed_bytes;
            f.entryId = row.entry_id;
            if (row.error_code) f.error = Failure{.code = *row.error_code, .message = row.error_message.value_or(""),
                                                  .etag = row.error_etag};
            f.shareUploadId = row.share_upload_id.value_or("");
            f.shareParent = row.share_parent_path.value_or("");
            if (f.ordinal != s->files.size()) {
                log::Registry::http()->error("[ResumableUpload] Session {} has a gap in its files; dropping it", s->id);
                s->files.clear();
                break;
            }
            s->files.push_back(std::move(f));
        }
        if (s->files.empty()) {
            try {
                q::Resumable::remove(s->id);
            } catch (const std::exception&) {
            }
            removeTreeQuietly(sessionDir(s->id));
            continue;
        }
        for (const auto& part : l.parts) {
            auto* f = fileById(*s, part.file_id);
            if (!f || terminal(f->state)) continue;
            // A part below the sealed prefix lives on in the sealed file; one above it must still be in the spool.
            if (part.offset >= f->sealed && !std::filesystem::exists(partPath(s->id, f->ordinal, part.offset))) {
                try {
                    q::Resumable::deletePart(s->id, part.file_id, part.offset);
                } catch (const std::exception&) {
                }
                continue;
            }
            f->parts[part.offset] = StoredPart{.length = part.length, .iv = part.encryption_iv};
        }
        for (auto& f : s->files)
            if (f.state == FileState::Receiving && covered(f)) f.state = FileState::Sealing;
        known.emplace(s->id, s);
        live.push_back(s);
    }

    // The spool holds nothing a row doesn't describe: unfinished attempts, unrecorded parts and orphaned sessions go.
    std::error_code ec;
    for (const auto& dir : std::filesystem::directory_iterator(spoolRoot(), ec)) {
        const auto name = dir.path().filename().string();
        if (!known.contains(name)) {
            removeTreeQuietly(dir.path());
            continue;
        }
        const auto& s = *known.at(name);
        std::error_code ec2;
        for (const auto& entry : std::filesystem::directory_iterator(dir.path(), ec2)) {
            const auto file = entry.path().filename().string();
            bool keep = false;
            for (const auto& f : s.files) {
                if (terminal(f.state)) continue;
                const auto prefix = std::to_string(f.ordinal) + ".";
                if (file == prefix + "sealed") keep = true;
                for (const auto& [offset, _] : f.parts)
                    if (file == prefix + std::to_string(offset) + ".part") keep = true;
            }
            if (!keep) removeQuietly(entry.path());
        }
    }

    {
        std::scoped_lock lock(reg().m);
        for (const auto& s : live) reg().sessions[s->id] = s;
    }
    std::size_t resumed = 0;
    for (const auto& s : live) {
        for (uint32_t i = 0; i < s->files.size(); ++i) {
            const auto st = s->files[i].state;
            if (st == FileState::Sealing || st == FileState::Committing ||
                (st == FileState::Receiving && s->files[i].parts.contains(s->files[i].sealed))) {
                enqueue(s, i);
                ++resumed;
            }
        }
        settleSessionIfDone(s);
    }
    if (!live.empty())
        log::Registry::http()->info("[ResumableUpload] Recovered {} upload session(s), resuming {} file(s)", live.size(),
                                    resumed);
}

void Service::shutdown() {
    auto& r = reg();
    std::vector<std::thread> workers;
    {
        std::scoped_lock lock(r.qm);
        r.stopping = true;
        workers.swap(r.workers);
    }
    r.qcv.notify_all();
    for (auto& w : workers)
        if (w.joinable()) w.join();
    std::deque<std::pair<SessionPtr, uint32_t>> dropped;
    {
        std::scoped_lock lock(r.qm);
        dropped.swap(r.queue);
        r.stopping = false;
    }
    for (const auto& [s, i] : dropped) {
        std::scoped_lock lock(s->m);
        s->files[i].busy = false;
        s->files[i].cursor.reset();
    }
}

std::size_t Service::sweepExpired() {
    const auto c = cfg();
    const auto t = now();
    std::vector<SessionPtr> all;
    {
        std::scoped_lock lock(reg().m);
        for (const auto& [_, s] : reg().sessions) all.push_back(s);
    }
    std::size_t removed = 0;
    std::set<std::string> live;
    for (const auto& s : all) {
        bool expired;
        {
            std::scoped_lock lock(s->m);
            const bool active = s->inFlight > 0 || std::ranges::any_of(s->files, [](const UFile& f) { return f.busy; });
            expired = !active && expiresAt(*s, c) <= t;
        }
        if (expired) {
            removeSession(s, "http_upload_expired");
            ++removed;
        } else {
            live.insert(s->id);
        }
    }
    // Rows this process never loaded (or that outlived a crash) and spool directories without a session.
    try {
        for (const auto& id : q::Resumable::expired(t, static_cast<int64_t>(c.session_idle_ttl_hours) * 3600,
                                                    static_cast<int64_t>(c.session_max_age_hours) * 3600)) {
            if (live.contains(id)) continue;
            q::Resumable::remove(id);
            removeTreeQuietly(sessionDir(id));
            ++removed;
        }
        std::error_code ec;
        for (const auto& dir : std::filesystem::directory_iterator(spoolRoot(), ec)) {
            const auto name = dir.path().filename().string();
            if (live.contains(name)) continue;
            if (!q::Resumable::exists(name)) removeTreeQuietly(dir.path());
        }
    } catch (const std::exception& e) {
        log::Registry::http()->warn("[ResumableUpload] Expiry sweep incomplete: {}", e.what());
    }
    return removed;
}

void Service::forgetForTesting() {
    shutdown();
    std::scoped_lock lock(reg().m);
    for (auto& [_, s] : reg().sessions) {
        std::scoped_lock sl(s->m);
        s->removed = true;  // a step still holding it stops; its state is the database's now
    }
    reg().sessions.clear();
}

void Service::setClockForTesting(Clock clock) { reg().clock = std::move(clock); }
void Service::resetClockForTesting() { reg().clock = nullptr; }
void Service::setFinishWaitForTesting(const std::chrono::milliseconds wait) { reg().finishWait = wait; }

bool Service::waitIdleForTesting(const std::chrono::milliseconds timeout) {
    auto& r = reg();
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        bool idle;
        {
            std::scoped_lock lock(r.qm);
            idle = r.queue.empty() && r.running == 0;
        }
        if (idle) {
            std::vector<SessionPtr> all;
            {
                std::scoped_lock lock(r.m);
                for (const auto& [_, s] : r.sessions) all.push_back(s);
            }
            for (const auto& s : all) {
                std::scoped_lock lock(s->m);
                if (std::ranges::any_of(s->files, [](const UFile& f) { return f.busy; })) idle = false;
            }
        }
        if (idle) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

void Service::holdCommitsForTesting(const bool hold) {
    reg().holdCommits.store(hold);
    if (hold) return;
    std::vector<std::pair<SessionPtr, uint32_t>> held;
    {
        std::scoped_lock lock(reg().holdM);
        held.swap(reg().held);
    }
    for (const auto& [s, i] : held) enqueue(s, i);
}

}
