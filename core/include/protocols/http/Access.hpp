#pragma once

#include "fs/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "rbac/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"
#include "share/Fwd.hpp"
#include "storage/Fwd.hpp"

#include <boost/beast/http.hpp>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace vh::share {
    struct ResolvedTarget;
}

// Authentication and authorization for every HTTP lane (/preview*, /download*, /upload/text). One place maps a
// route's need onto RBAC: human sessions through rbac::resolver::Vault, share sessions through
// share::TargetResolver. Nothing here trusts the client about capability; handlers only see resolved targets.
namespace vh::protocols::http::access {

using Params = std::unordered_map<std::string, std::string>;
using Request = boost::beast::http::request<boost::beast::http::string_body>;

// Typed failures, mapped to HTTP status by the router (never by string matching).
struct Unauthorized final : std::runtime_error { using std::runtime_error::runtime_error; };  // 401
struct Forbidden final : std::runtime_error { using std::runtime_error::runtime_error; };     // 403
struct NotFound final : std::runtime_error { using std::runtime_error::runtime_error; };      // 404
struct BadRequest final : std::runtime_error { using std::runtime_error::runtime_error; };    // 400

enum class Need {
    Preview,    // lossy server renders only (human: Read; share: Preview)
    Download,   // original bytes or full-fidelity derivatives (human: Read [+List for dirs]; share: Download)
    Overwrite,  // replace an existing file's content (human: Overwrite; shares: not supported)
    List        // a directory's entries (human: List; share: List)
};

enum class Expect { File, Directory, Any };

struct Caller {
    std::shared_ptr<ws::Session> session;
    bool share{false};
};

struct ShareContext {
    std::shared_ptr<share::Manager> manager;
    std::shared_ptr<share::TargetResolver> resolver;
    std::shared_ptr<share::Principal> principal;
    std::shared_ptr<share::ResolvedTarget> resolved;
    std::string sharePath;   // path as the share recipient addressed it
};

struct Target {
    std::shared_ptr<storage::Engine> engine;
    std::shared_ptr<fs::model::Entry> entry;
    std::shared_ptr<fs::model::File> file;  // null for directories
    uint32_t vaultId{};
    std::string vaultPath;                  // normalized vault-relative path
    std::optional<ShareContext> share;
};

[[nodiscard]] Params parseQuery(std::string_view target);
[[nodiscard]] bool isShareLane(const Params& params);

// Resolves the session behind the request's cookie (`refresh`, or `share_refresh` on the ?share=1 lane).
[[nodiscard]] Caller authenticate(const Request& req, const Params& params);

// Resolves the addressed entry and enforces `need`. Throws Unauthorized/Forbidden/NotFound/BadRequest.
[[nodiscard]] Target resolve(const Caller& caller, const Params& params, Need need, Expect expect = Expect::File);
[[nodiscard]] Target resolvePath(const Caller& caller, uint32_t vaultId, const std::string& path, Need need,
                                 Expect expect = Expect::File);
// The same human resolution for a caller that isn't an HTTP session (`vh fs`, whose user comes from the CLI socket's
// peer credentials): one evaluator, one path normalization, one no-existence-oracle rule for every surface.
[[nodiscard]] Target resolveUserPath(const std::shared_ptr<identities::User>& user, uint32_t vaultId,
                                     const std::string& path, Need need, Expect expect = Expect::File);
// Throws Forbidden unless `user` holds `action` on `vaultPath` (normalized) in the engine's vault.
void requireUser(const std::shared_ptr<identities::User>& user, const std::shared_ptr<storage::Engine>& engine,
                 const std::filesystem::path& vaultPath, rbac::permission::vault::FilesystemAction action);

// Human directory archives: every child must be readable (and directories listable).
void requireHumanChild(const Caller& caller, const Target& root, const std::shared_ptr<fs::model::Entry>& child);

// Share accounting, coalesced so a media player's range requests don't write the database on every request:
// one audit event (and, for downloads, one max_downloads unit) per share session, file generation and kind of
// access within a window. Returns false when a new download would exceed the link's max_downloads.
[[nodiscard]] bool recordShareAccess(const Target& target, std::string_view eventType, bool countsAsDownload,
                                     std::optional<uint64_t> bytes);
// Human access audit (log channel), coalesced the same way.
void recordHumanAccess(const Caller& caller, const Target& target, std::string_view eventType);

void clearCachesForTesting();

}
