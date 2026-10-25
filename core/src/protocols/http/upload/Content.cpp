#include "protocols/http/upload/Content.hpp"

#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "fuse/WorkingCopies.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "platform/Durable.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/handler/Common.hpp"
#include "protocols/http/upload/Staging.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Controller.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <charconv>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <mutex>
#include <set>
#include <string>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace vh::protocols::http::upload::content {

namespace detail {
enum class Mode { Replace, Create };
}

namespace {

using detail::Mode;

using handler::jsonError;

// The same per-file ceiling as /upload/session.
constexpr uint64_t kMaxContentBytes = 8ull * 1024ull * 1024ull * 1024ull;

[[nodiscard]] std::string_view trimmed(std::string_view v) {
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
    return v;
}

[[nodiscard]] std::optional<std::string> headerOf(const request& req, const field name) {
    const auto it = req.find(name);
    if (it == req.end()) return std::nullopt;
    return std::string(trimmed(std::string_view(it->value().data(), it->value().size())));
}

// A refusal: {"error", "code"} plus the current version when there is one (also as ETag), so a client can tell what
// it raced with. Every refusal closes the connection when the body is still unread (the session decides that).
[[nodiscard]] model::preview::Response refuse(const request& req, const status code, const std::string_view errorCode,
                                              const std::string_view message,
                                              const std::optional<std::string>& currentVersion = std::nullopt) {
    auto res = jsonError(req, code, errorCode, message);
    if (currentVersion) {
        auto& r = std::get<string_response>(res);
        auto body = nlohmann::json::parse(r.body());
        body["content_version"] = *currentVersion;
        r.body() = body.dump();
        r.set(field::etag, *currentVersion);
        r.prepare_payload();
    }
    return res;
}

[[nodiscard]] std::optional<std::string> currentVersionAt(const std::shared_ptr<vh::storage::Engine>& engine,
                                                          const std::string& vaultPath) {
    const auto& cache = vh::runtime::Deps::get().fsCache;
    if (!cache || !engine) return std::nullopt;
    const auto file = std::dynamic_pointer_cast<vh::fs::model::File>(cache->getEntry(engine->vaultPathToFusePath(vaultPath)));
    if (!file) return std::nullopt;
    return vh::storage::generationOf(*file).etag();
}

// Creates of one path through this lane commit one at a time: the second finds the first's file (412), instead of
// both taking the new-file branch of createFile.
[[nodiscard]] std::mutex& creatingMutex() {
    static std::mutex m;
    return m;
}

[[nodiscard]] std::set<std::string>& creating() {
    static std::set<std::string> s;
    return s;
}

class CreateClaim {
public:
    explicit CreateClaim(std::string key) : key_(std::move(key)) {
        std::scoped_lock lock(creatingMutex());
        held_ = creating().insert(key_).second;
    }
    ~CreateClaim() {
        if (!held_) return;
        std::scoped_lock lock(creatingMutex());
        creating().erase(key_);
    }
    CreateClaim(const CreateClaim&) = delete;
    CreateClaim& operator=(const CreateClaim&) = delete;
    [[nodiscard]] bool held() const { return held_; }

private:
    std::string key_;
    bool held_{false};
};

void removeStaging(const std::filesystem::path& staging, const std::filesystem::path& fuseStaging) noexcept {
    if (staging.empty()) return;
    std::error_code ec;
    std::filesystem::remove(staging, ec);
    try {
        const auto& cache = vh::runtime::Deps::get().fsCache;
        if (cache && !fuseStaging.empty() && cache->entryExists(fuseStaging)) cache->evictPath(fuseStaging);
    } catch (...) {
    }
}

}

struct Upload::Impl {
    using Mode = detail::Mode;
    access::Params params;
    access::Caller caller;
    Mode mode{Mode::Replace};
    std::shared_ptr<vh::storage::Engine> engine;
    std::string vaultPath;
    std::filesystem::path fusePath;
    std::optional<std::string> expectedSourceId;  // Replace: the generation that was authorized and matched If-Match
    uint64_t expected{};
    uint64_t received{};
    std::filesystem::path staging;      // the staged plaintext
    std::filesystem::path fuseStaging;  // its FS-cache key, when staging lives in the mount
    int fd{-1};
    bool done{false};

    ~Impl() {
        if (fd >= 0) ::close(fd);
        if (!done) removeStaging(staging, fuseStaging);
    }
};

Upload::Upload() = default;
Upload::Upload(Upload&& other) noexcept = default;
Upload& Upload::operator=(Upload&& other) noexcept = default;
Upload::~Upload() = default;

bool isRequest(const boost::beast::http::verb method, const std::string_view target) {
    if (method != boost::beast::http::verb::put) return false;
    constexpr std::string_view route = "/upload/content";
    return target.starts_with(route) && (target.size() == route.size() || target[route.size()] == '?');
}

Begun begin(const request& req, const std::optional<uint64_t> contentLength) {
    Begun out;
    try {
        auto impl = std::make_unique<Upload::Impl>();
        impl->params = access::parseQuery(std::string_view(req.target().data(), req.target().size()));
        impl->caller = access::authenticate(req, impl->params);
        if (impl->caller.share) {
            out.refusal = jsonError(req, status::forbidden, "denied", "Uploading through share links uses the share upload lane");
            return out;
        }

        const auto ifMatch = headerOf(req, field::if_match);
        const auto ifNoneMatch = headerOf(req, field::if_none_match);
        if (ifMatch && !ifNoneMatch && *ifMatch != "*" && !ifMatch->empty()) impl->mode = Mode::Replace;
        else if (ifNoneMatch && !ifMatch && *ifNoneMatch == "*") impl->mode = Mode::Create;
        else {
            out.refusal = jsonError(req, status::precondition_required, "precondition_required",
                                    "Send If-Match with the content_version being replaced, or If-None-Match: * to "
                                    "create a file that does not exist");
            return out;
        }

        if (!contentLength) {
            out.refusal = jsonError(req, status::length_required, "length_required", "Content-Length is required");
            return out;
        }
        if (*contentLength > kMaxContentBytes) {
            out.refusal = jsonError(req, status::payload_too_large, "limit_exceeded", "The file exceeds the maximum upload size");
            return out;
        }
        impl->expected = *contentLength;

        access::Target target;
        if (impl->mode == Mode::Replace) {
            target = access::resolve(impl->caller, impl->params, access::Need::Overwrite, access::Expect::File);
            const auto current = vh::storage::generationOf(*target.file);
            if (*ifMatch != current.etag()) {
                out.refusal = refuse(req, status::precondition_failed, "conflict", "The file changed since that version",
                                     current.etag());
                return out;
            }
            if (target.file->inode && vh::fuse::WorkingCopies::instance().isOpen(*target.file->inode)) {
                out.refusal = refuse(req, status::precondition_failed, "conflict",
                                     "The file is open through the mounted filesystem", current.etag());
                return out;
            }
            impl->expectedSourceId = current.sourceId();
        } else {
            target = access::resolveCreate(impl->caller, impl->params);
            if (target.file) {
                out.refusal = refuse(req, status::precondition_failed, "conflict", "The file already exists",
                                     vh::storage::generationOf(*target.file).etag());
                return out;
            }
            if (target.entry) {
                out.refusal = jsonError(req, status::conflict, "conflict", "Something that is not a file exists at that path");
                return out;
            }
        }
        impl->engine = target.engine;
        impl->vaultPath = target.vaultPath;
        impl->fusePath = impl->engine->vaultPathToFusePath(impl->vaultPath);

        // Space as for an upload: the whole body must fit (a replacement's old bytes may be kept as a version).
        if (impl->engine->freeSpace() < impl->expected) {
            out.refusal = jsonError(req, status::payload_too_large, "limit_exceeded", "Not enough space in the vault");
            return out;
        }

        if (impl->mode == Mode::Create) {
            // Missing parent folders are created, as for an upload (Write on the file's path was checked).
            if (const auto err = vh::fs::Filesystem::mkdir({.path = impl->fusePath.parent_path(), .engine = impl->engine,
                                                        .user = impl->caller.session->user});
                err)
                throw std::runtime_error("Failed to create the parent folder");
        }

        const auto absPath = impl->engine->paths->absPath(impl->vaultPath, vh::fs::model::PathType::VAULT_ROOT);
        impl->staging = staging::pathFor(absPath, impl->engine->vault->id,
                                         ".upload-http-content-" + vh::protocols::ws::Session::generateUUIDv4() + ".part");
        if (staging::insideMount())
            impl->fuseStaging = impl->engine->paths->absRelToRoot(impl->staging, vh::fs::model::PathType::FUSE_ROOT);
        std::filesystem::create_directories(impl->staging.parent_path());
        impl->fd = ::open(impl->staging.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (impl->fd < 0)
            throw std::runtime_error(std::string("Unable to open the upload staging file: ") + std::strerror(errno));

        out.upload.impl_ = std::move(impl);
        return out;
    } catch (const std::exception& e) {
        out.upload = Upload{};
        out.refusal = handler::errorFor(req, e);
        return out;
    }
}

void Upload::write(const void* data, const std::size_t size) {
    if (!impl_ || impl_->fd < 0) throw std::runtime_error("Upload is not open");
    if (size == 0) return;
    if (size > impl_->expected - impl_->received) throw std::length_error("The body exceeds its Content-Length");
    const auto* p = static_cast<const char*>(data);
    std::size_t left = size;
    while (left) {
        const auto n = ::write(impl_->fd, p, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) throw std::runtime_error(std::string("Writing the upload staging file failed: ") + std::strerror(errno));
        p += n;
        left -= static_cast<std::size_t>(n);
    }
    impl_->received += size;
}

model::preview::Response Upload::commit(const request& req) {
    if (!impl_) return jsonError(req, status::internal_server_error, "internal", "Upload is not open");
    auto& u = *impl_;
    try {
        if (u.received != u.expected)
            return jsonError(req, status::bad_request, "invalid", "The body is shorter than its Content-Length");
        if (vh::platform::durable::sync(u.fd) != 0)
            throw std::runtime_error(std::string("Flushing the upload staging file failed: ") + std::strerror(errno));
        if (::close(u.fd) != 0) {
            u.fd = -1;
            throw std::runtime_error(std::string("Closing the upload staging file failed: ") + std::strerror(errno));
        }
        u.fd = -1;

        // Access again, with the caller as they are now: a session ended or a role revoked during the body commits
        // nothing, and a replacement must still find the file it was authorized for.
        const auto caller = access::authenticate(req, u.params);
        std::optional<CreateClaim> claim;
        if (u.mode == Mode::Replace) {
            (void)access::resolve(caller, u.params, access::Need::Overwrite, access::Expect::File);
        } else {
            claim.emplace(std::to_string(u.engine->vault->id) + ":" + u.vaultPath);
            const auto target = access::resolveCreate(caller, u.params);
            if (!claim->held() || target.file)
                return refuse(req, status::precondition_failed, "conflict", "The file already exists",
                              currentVersionAt(u.engine, u.vaultPath));
            if (target.entry)
                return jsonError(req, status::conflict, "conflict", "Something that is not a file exists at that path");
        }

        // The streaming seal and compare-and-swap every conditional writer uses. Create: an expected generation of
        // "" means "only if nothing is there". An empty body takes the empty-buffer branch, as an upload's does.
        std::shared_ptr<vh::fs::model::File> saved;
        try {
            vh::fs::NewFileContext ctx{.path = u.vaultPath, .fuse_path = u.fusePath, .engine = u.engine,
                                   .user = caller.session->user, .overwrite = true,
                                   .expected_source_id = u.mode == Mode::Replace ? u.expectedSourceId : std::string{}};
            if (u.expected > 0) ctx.source_path = u.staging;
            saved = vh::fs::Filesystem::createFile(ctx);
        } catch (const vh::fs::ContentConflict& e) {
            return refuse(req, status::precondition_failed, "conflict", e.what(), currentVersionAt(u.engine, u.vaultPath));
        } catch (const std::filesystem::filesystem_error& e) {
            if (e.code() == std::errc::file_exists)
                return jsonError(req, status::conflict, "conflict", "Something that is not a file exists at that path");
            throw;
        }
        if (!saved) throw std::runtime_error("The upload produced no file");

        u.done = true;
        removeStaging(u.staging, u.fuseStaging);

        access::Target committed;
        committed.engine = u.engine;
        committed.entry = saved;
        committed.file = saved;
        committed.vaultId = u.engine->vault->id;
        committed.vaultPath = u.vaultPath;
        access::recordHumanAccess(caller, committed, u.mode == Mode::Create ? "content.create" : "content.replace");
        vh::log::Registry::audit()->info("PUT /upload/content: {} {} vault {} path {} ({} bytes)",
                                     caller.session->user->name(), u.mode == Mode::Create ? "created" : "replaced",
                                     committed.vaultId, u.vaultPath, saved->size_bytes);
        try {
            if (const auto& sync = vh::runtime::Deps::get().syncController) sync->runNow(committed.vaultId);
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->warn("[HttpUpload] Could not trigger sync for vault {}: {}", committed.vaultId, e.what());
        }

        const auto etag = vh::storage::generationOf(*saved).etag();
        const nlohmann::json body = {{"created", u.mode == Mode::Create}, {"entry", *saved}};
        auto res = Router::makeJsonResponse(req, body);
        auto& r = std::get<string_response>(res);
        if (u.mode == Mode::Create) r.result(status::created);
        r.set(field::etag, etag);
        r.set(field::cache_control, "no-store");
        return res;
    } catch (const std::exception& e) {
        return handler::errorFor(req, e);
    }
}

model::preview::Response handle(request&& req) {
    if (!isRequest(req.method(), std::string_view(req.target().data(), req.target().size())))
        return jsonError(req, status::method_not_allowed, "invalid", "PUT required");
    std::optional<uint64_t> length;
    if (const auto it = req.find(field::content_length); it != req.end()) {
        uint64_t value = 0;
        const std::string_view text(it->value().data(), it->value().size());
        const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
        if (ec != std::errc{} || ptr != text.data() + text.size())
            return jsonError(req, status::bad_request, "invalid", "Invalid Content-Length");
        length = value;
    }
    auto begun = begin(req, length);
    if (begun.refusal) return std::move(*begun.refusal);
    try {
        begun.upload.write(req.body().data(), req.body().size());
    } catch (const std::exception& e) {
        return handler::errorFor(req, e);
    }
    return begun.upload.commit(req);
}

}
