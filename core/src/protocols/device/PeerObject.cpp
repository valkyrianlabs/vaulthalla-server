#include "protocols/device/PeerObject.hpp"

#include "config/Registry.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/mirror/Contents.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "fs/model/File.hpp"
#include "log/Registry.hpp"
#include "mirror/submit/Contents.hpp"
#include "peer/ObjectClient.hpp"
#include "peer/Peer.hpp"
#include "protocols/http/handler/Common.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/Content.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <list>
#include <mutex>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

namespace vh::protocols::device::peer_object {

namespace {

using http::field;
using http::status;
using http::verb;
using http::handler::jsonError;

// The sealed bytes of one generation, read from the descriptor the checks opened (the inode they checked, whatever
// a later rename does to the path). Bytes as they are: nothing is opened or decrypted.
class SealedFdReader final : public vh::storage::PlaintextReader {
public:
    SealedFdReader(const int fd, const uint64_t size, vh::storage::Generation generation)
        : fd_(fd), size_(size), generation_(std::move(generation)) {}
    ~SealedFdReader() override {
        if (fd_ >= 0) ::close(fd_);
    }
    SealedFdReader(const SealedFdReader&) = delete;
    SealedFdReader& operator=(const SealedFdReader&) = delete;

    [[nodiscard]] uint64_t size() const override { return size_; }
    [[nodiscard]] const vh::storage::Generation& generation() const override { return generation_; }

    std::size_t read(const uint64_t offset, const std::span<uint8_t> out) override {
        if (offset >= size_) return 0;
        const auto want = static_cast<std::size_t>(std::min<uint64_t>(out.size(), size_ - offset));
        std::size_t done = 0;
        while (done < want) {
            const auto n = ::pread(fd_, out.data() + done, want - done, static_cast<off_t>(offset + done));
            if (n < 0) {
                if (errno == EINTR) continue;
                throw std::system_error(errno, std::generic_category(), "read sealed bytes");
            }
            if (n == 0) break;
            done += static_cast<std::size_t>(n);
        }
        return done;
    }

private:
    int fd_{-1};
    uint64_t size_{};
    vh::storage::Generation generation_;
};

// An empty plain file: nothing to read.
class EmptyReader final : public vh::storage::PlaintextReader {
public:
    [[nodiscard]] uint64_t size() const override { return 0; }
    [[nodiscard]] const vh::storage::Generation& generation() const override { return generation_; }
    std::size_t read(uint64_t, std::span<uint8_t>) override { return 0; }

private:
    vh::storage::Generation generation_;
};

struct UniqueFd {
    explicit UniqueFd(const int fd) : fd_(fd) {}
    ~UniqueFd() {
        if (fd_ >= 0) ::close(fd_);
    }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    [[nodiscard]] int get() const noexcept { return fd_; }
    int release() noexcept { return std::exchange(fd_, -1); }

private:
    int fd_;
};

struct Tracked {
    uint32_t peer;
    std::function<void()> close;
};

std::mutex& trackedMutex() {
    static std::mutex m;
    return m;
}

std::list<Tracked>& tracked() {
    static std::list<Tracked> l;
    return l;
}

http::model::preview::Response notFound(const http::request& req) {
    return jsonError(req, status::not_found, "not_found", "Not found");
}

}

bool isTarget(const std::string_view target) noexcept {
    constexpr std::string_view prefix = "/peer/object";
    return target.starts_with(prefix) &&
           (target.size() == prefix.size() || target[prefix.size()] == '/' || target[prefix.size()] == '?');
}

http::model::preview::Response serve(const http::request& req, const vh::peer::Principal& caller) {
    // Off: the lane does not exist.
    if (!vh::config::Registry::get().peers.experimental) return notFound(req);
    if (req.method() != verb::get && req.method() != verb::head) {
        auto res = jsonError(req, status::method_not_allowed, "method_not_allowed", "GET, HEAD or PUT only");
        std::get<http::string_response>(res).set(field::allow, "GET, HEAD, PUT");
        return res;
    }
    // The link as it is now, not as it was at the handshake: unlinked since, or its key replaced.
    const auto row = db::query::peer::Peers::byId(caller.peer_id);
    if (!row || row->revoked() || row->spki_sha256 != caller.spki_hex)
        return jsonError(req, status::forbidden, "peer_revoked", "This server is no longer linked");

    const std::string_view target(req.target().data(), req.target().size());
    const auto address = vh::peer::object::parseTarget(target);
    if (!address) return jsonError(req, status::bad_request, "invalid", "Not a sealed object address");

    // The vault's linked server, whichever role this server has; a vault mirrored with another server, or not at all,
    // is not there for this caller.
    const auto found = db::query::mirror::SealedObjects::find(address->vault, address->object);
    if (!found || found->peer_id != caller.peer_id || (found->role != "core" && found->role != "mirror") ||
        found->file_id == 0)
        return notFound(req);
    if (found->generation != address->generation)
        return jsonError(req, status::gone, "generation_not_current", "That generation is not the file's current one");

    vh::vault::content::Format format{};
    try {
        format = vh::vault::content::formatOf(found->generation);
    } catch (const std::invalid_argument&) {
        return jsonError(req, status::internal_server_error, "internal", "Internal error");
    }
    if (format == vh::vault::content::Format::Gcm0 || (format == vh::vault::content::Format::Plain && found->size_bytes > 0))
        return jsonError(req, status::unprocessable_entity, "format_not_portable",
                         "The file is in a format that binds nothing (gcm0 or plain): it is never sent");

    vh::storage::Generation generation;
    generation.vault_id = found->vault_id;
    generation.file_id = found->file_id;
    generation.iv_b64 = found->generation;
    generation.key_version = found->key_version;
    generation.size = found->size_bytes;

    http::handler::ServeSpec spec;
    spec.etag = vh::peer::object::etagOf(found->generation);
    spec.contentType = "application/octet-stream";
    spec.cacheControl = "no-store";
    spec.extraHeaders.emplace_back("X-Content-Type-Options", "nosniff");

    if (format == vh::vault::content::Format::Plain) {
        spec.size = 0;
        spec.open = [] { return std::make_shared<EmptyReader>(); };
        return http::handler::serve(req, std::move(spec));
    }

    const auto file = vh::db::query::fs::File::getFileById(found->file_id);
    if (!file) return notFound(req);
    UniqueFd fd(::open(file->backing_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd.get() < 0)
        return jsonError(req, status::not_found, "not_held", "The file's bytes are not on this server's disk");
    // A content replacement writes the row first, then renames the new bytes over the path: the row read again after
    // the open says whether the inode this descriptor holds is still the generation asked for.
    if (db::query::mirror::SealedObjects::generationOf(found->file_id) != address->generation)
        return jsonError(req, status::gone, "generation_not_current", "That generation is not the file's current one");
    struct stat st{};
    if (::fstat(fd.get(), &st) != 0 || !S_ISREG(st.st_mode))
        return jsonError(req, status::not_found, "not_held", "The file's bytes are not on this server's disk");
    const auto sealed = vh::vault::content::sealedSize(found->size_bytes, format);
    if (static_cast<uint64_t>(st.st_size) != sealed) {
        log::Registry::http()->warn("[PeerObject] File {} of vault {}: {} bytes on disk, its generation seals to {}",
                                    found->file_id, found->vault_id, st.st_size, sealed);
        return jsonError(req, status::not_found, "not_held", "The bytes on this server's disk are not that generation's");
    }
    auto reader = std::make_shared<SealedFdReader>(fd.release(), sealed, generation);
    spec.size = sealed;
    spec.open = [reader] { return reader; };
    log::Registry::http()->debug("[PeerObject] Serving file {} of vault {} to linked server {} ({} sealed bytes)",
                                 found->file_id, found->vault_id, caller.node_id, sealed);
    return http::handler::serve(req, std::move(spec));
}

PutStart beginPut(const http::request& req, const vh::peer::Principal& caller, const std::optional<uint64_t> contentLength) {
    PutStart out;
    if (!vh::config::Registry::get().peers.experimental) {
        out.refusal = notFound(req);
        return out;
    }
    const auto row = db::query::peer::Peers::byId(caller.peer_id);
    if (!row || row->revoked() || row->spki_sha256 != caller.spki_hex) {
        out.refusal = jsonError(req, status::forbidden, "peer_revoked", "This server is no longer linked");
        return out;
    }
    const std::string_view target(req.target().data(), req.target().size());
    const auto address = vh::peer::object::parseTarget(target);
    if (!address) {
        out.refusal = jsonError(req, status::bad_request, "invalid", "Not a sealed object address");
        return out;
    }
    // Only the core of a vault takes bytes, and only from that vault's mirror.
    const auto mv = db::query::mirror::MirrorVaults::byVaultUid(vh::crypto::id::toUuid(address->vault));
    if (!mv || mv->role != "core" || mv->peer_id != caller.peer_id || mv->state != "live") {
        out.refusal = notFound(req);
        return out;
    }
    const auto header = [&](const std::string_view name) {
        const auto it = req.find(boost::beast::string_view(name.data(), name.size()));
        return it == req.end() ? std::string() : std::string(it->value());
    };
    const auto number = [](const std::string& text) -> std::optional<uint64_t> {
        if (text.empty() || text.size() > 19 || !std::ranges::all_of(text, [](const char c) { return c >= '0' && c <= '9'; }))
            return std::nullopt;
        return std::stoull(text);
    };
    const auto size = number(header(vh::peer::object::kSizeHeader));
    const auto version = number(header(vh::peer::object::kKeyVersionHeader));
    const auto hash = header(vh::peer::object::kContentHashHeader);
    if (!size || !version || *version > 0xffffffffULL || hash.empty() || hash.size() > 128 || !vh::vault::content::isVhf1(address->generation)) {
        out.refusal = jsonError(req, status::bad_request, "invalid", "The sealed bytes' facts are missing or malformed");
        return out;
    }
    const auto sealed = vh::vault::content::sealedSizeOf(*size, address->generation);
    if (!contentLength || *contentLength != sealed) {
        out.refusal = jsonError(req, status::bad_request, "invalid", "The body is not that generation's sealed length");
        return out;
    }
    out.target = PutTarget{.vault_id = mv->vault_id,
                           .object_uuid = vh::crypto::id::toUuid(address->object),
                           .generation = address->generation,
                           .key_version = static_cast<uint32_t>(*version),
                           .plaintext_size = *size,
                           .content_hash = hash,
                           .sealed_size = sealed,
                           .receiving = vh::mirror::submit::contents::receivingPath(mv->vault_id).string()};
    return out;
}

http::model::preview::Response finishPut(const http::request& req, const PutTarget& target) {
    const auto staged = vh::mirror::submit::contents::stage(
        target.vault_id, target.object_uuid,
        {.generation = target.generation, .key_version = target.key_version, .size = target.plaintext_size,
         .content_hash = target.content_hash},
        target.receiving);
    if (!staged.ok)
        return jsonError(req, static_cast<status>(staged.http_status), staged.code, staged.error);
    log::Registry::http()->debug("[PeerObject] Staged {} sealed bytes for vault {} from its mirror", target.sealed_size,
                                 target.vault_id);
    http::string_response res{status::created, req.version()};
    res.set(field::content_type, "application/json");
    res.set(field::cache_control, "no-store");
    res.body() = nlohmann::json{{"staged", true}}.dump();
    res.prepare_payload();
    return res;
}

Registration track(const uint32_t peerId, std::function<void()> close) {
    struct Token {
        std::list<Tracked>::iterator it{};
        bool armed{false};
        Token() = default;
        Token(const Token&) = delete;
        Token& operator=(const Token&) = delete;
        ~Token() {
            if (!armed) return;
            std::scoped_lock lock(trackedMutex());
            tracked().erase(it);
        }
    };
    auto token = std::make_shared<Token>();
    std::scoped_lock lock(trackedMutex());
    token->it = tracked().insert(tracked().end(), Tracked{peerId, std::move(close)});
    token->armed = true;
    return token;
}

std::size_t closeConnections(const uint32_t peerId) {
    std::vector<std::function<void()>> closing;
    {
        std::scoped_lock lock(trackedMutex());
        for (const auto& t : tracked())
            if (t.peer == peerId) closing.push_back(t.close);
    }
    for (const auto& c : closing) c();
    return closing.size();
}

std::size_t closeAllConnections() {
    std::vector<std::function<void()>> closing;
    {
        std::scoped_lock lock(trackedMutex());
        for (const auto& t : tracked()) closing.push_back(t.close);
    }
    for (const auto& c : closing) c();
    return closing.size();
}

}
