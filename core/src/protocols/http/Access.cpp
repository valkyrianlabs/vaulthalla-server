#include "protocols/http/Access.hpp"

#include "auth/session/Manager.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "protocols/cookie.hpp"
#include "protocols/http/AccessHooks.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/PolicyEpoch.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/Vault.hpp"
#include "runtime/Deps.hpp"
#include "share/Manager.hpp"
#include "share/Principal.hpp"
#include "share/Scope.hpp"
#include "share/TargetResolver.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/model/Vault.hpp"

#include <sodium.h>

#include <array>
#include <charconv>
#include <chrono>
#include <limits>
#include <future>
#include <mutex>

namespace vh::protocols::http::access {

namespace {

using Clock = std::chrono::steady_clock;
using FsAction = rbac::permission::vault::FilesystemAction;

constexpr auto kPrincipalTtl = std::chrono::seconds(15);
constexpr auto kAuditWindow = std::chrono::minutes(30);

[[nodiscard]] std::string digest(const std::string_view value) {
    std::array<unsigned char, crypto_generichash_BYTES> out{};
    crypto_generichash(out.data(), out.size(), reinterpret_cast<const unsigned char*>(value.data()), value.size(),
                       nullptr, 0);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(out.size() * 2);
    for (const auto b : out) {
        hex.push_back(kHex[b >> 4]);
        hex.push_back(kHex[b & 0x0f]);
    }
    return hex;
}

struct CachedPrincipal {
    std::shared_ptr<share::Principal> principal;
    Clock::time_point at;
    uint64_t epoch{};
};

std::mutex& cacheMutex() {
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, CachedPrincipal>& principals() {
    static std::unordered_map<std::string, CachedPrincipal> map;
    return map;
}

std::unordered_map<std::string, Clock::time_point>& recentAccess() {
    static std::unordered_map<std::string, Clock::time_point> map;
    return map;
}

// Share accounting decisions, single-flight per key: concurrent first requests for the same logical download wait
// for (and share) the one atomic max_downloads decision instead of each assuming it was counted.
struct ShareAccessSlot {
    Clock::time_point at;
    std::shared_future<bool> allowed;
};

std::unordered_map<std::string, ShareAccessSlot>& shareAccess() {
    static std::unordered_map<std::string, ShareAccessSlot> map;
    return map;
}

void pruneLocked(const Clock::time_point now) {
    auto& access = recentAccess();
    if (access.size() > 4096)
        std::erase_if(access, [now](const auto& item) { return now - item.second > kAuditWindow; });
    auto& cached = principals();
    if (cached.size() > 4096)
        std::erase_if(cached, [now](const auto& item) { return now - item.second.at > kPrincipalTtl; });
    auto& shares = shareAccess();
    if (shares.size() > 4096)
        std::erase_if(shares, [now](const auto& item) { return now - item.second.at > kAuditWindow; });
}

// True the first time `key` is seen within the window (and records it).
[[nodiscard]] bool firstInWindow(const std::string& key) {
    const auto now = Clock::now();
    std::scoped_lock lock(cacheMutex());
    pruneLocked(now);
    auto& access = recentAccess();
    if (const auto it = access.find(key); it != access.end() && now - it->second < kAuditWindow) return false;
    access[key] = now;
    return true;
}



[[nodiscard]] std::string urlDecode(const std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        const char c = value[i];
        if (c == '%') {
            if (i + 2 >= value.size()) throw BadRequest("Invalid percent-encoding in URL");
            unsigned int byte = 0;
            const auto [ptr, ec] = std::from_chars(value.data() + i + 1, value.data() + i + 3, byte, 16);
            if (ec != std::errc{} || ptr != value.data() + i + 3) throw BadRequest("Invalid percent-encoding in URL");
            out.push_back(static_cast<char>(byte));
            i += 2;
        } else if (c == '+') {
            out.push_back(' ');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

[[nodiscard]] uint32_t parseVaultId(const Params& params) {
    const auto it = params.find("vault_id");
    if (it == params.end() || it->second.empty()) throw BadRequest("Missing required parameter: vault_id");
    uint32_t value = 0;
    const auto& raw = it->second;
    const auto [ptr, ec] = std::from_chars(raw.data(), raw.data() + raw.size(), value);
    if (ec != std::errc{} || ptr != raw.data() + raw.size()) throw BadRequest("Invalid numeric parameter: vault_id");
    return value;
}

[[nodiscard]] std::string pathParam(const Params& params) {
    const auto it = params.find("path");
    return it == params.end() || it->second.empty() ? std::string{"/"} : it->second;
}

[[nodiscard]] std::shared_ptr<share::Principal> sharePrincipal(const Caller& caller,
                                                               const std::shared_ptr<share::Manager>& manager) {
    const auto& session = caller.session;
    const auto token = session->shareSessionToken();
    if (token.empty()) throw Unauthorized("Share session token is missing");

    const auto key = digest(token);
    const auto now = Clock::now();
    const auto epoch = rbac::policyEpoch();
    {
        std::scoped_lock lock(cacheMutex());
        if (const auto it = principals().find(key); it != principals().end() && it->second.epoch == epoch &&
                                                    now - it->second.at < kPrincipalTtl && it->second.principal &&
                                                    it->second.principal->isActive(std::time(nullptr))) {
            session->setSharePrincipal(it->second.principal, token);
            return it->second.principal;
        }
    }

    std::shared_ptr<share::Principal> principal;
    try {
        principal = manager->resolvePrincipal(
            token,
            session->ipAddress.empty() ? std::nullopt : std::make_optional(session->ipAddress),
            session->userAgent.empty() ? std::nullopt : std::make_optional(session->userAgent));
    } catch (const std::exception& e) {
        throw Forbidden(std::string("Share access denied: ") + e.what());
    }
    if (!principal) throw Forbidden("Share access denied");
    session->setSharePrincipal(principal, token);
    {
        std::scoped_lock lock(cacheMutex());
        pruneLocked(now);
        principals()[key] = CachedPrincipal{principal, now, epoch};
    }
    return principal;
}

[[nodiscard]] share::Operation shareOperationFor(const Need need) {
    switch (need) {
        case Need::Preview: return share::Operation::Preview;
        case Need::Download: return share::Operation::Download;
        case Need::Overwrite: return share::Operation::Overwrite;
        case Need::List: return share::Operation::List;
    }
    return share::Operation::Preview;
}

void requireUserAction(const std::shared_ptr<identities::User>& user, const std::shared_ptr<storage::Engine>& engine,
                       const std::filesystem::path& vaultPath, const FsAction action) {
    if (!user) throw Unauthorized("Request requires a user");
    if (!engine || !engine->vault) throw NotFound("Storage engine is unavailable");
    if (!rbac::resolver::Vault::has<FsAction>({
            .user = user,
            .permission = action,
            .vault_id = engine->vault->id,
            .path = engine->vaultPathToFusePath(vaultPath)
        }))
        throw Forbidden("Permission denied");
}

void requireUserNeed(const std::shared_ptr<identities::User>& user, const std::shared_ptr<storage::Engine>& engine,
                     const std::shared_ptr<fs::model::Entry>& entry, const Need need) {
    switch (need) {
        case Need::Preview:
        case Need::Download:
            requireUserAction(user, engine, entry->path, FsAction::Read);
            if (entry->isDirectory()) requireUserAction(user, engine, entry->path, FsAction::List);
            return;
        case Need::Overwrite:
            requireUserAction(user, engine, entry->path, FsAction::Overwrite);
            return;
        case Need::List:
            requireUserAction(user, engine, entry->path, FsAction::List);
            return;
    }
}

void requireHumanNeed(const Caller& caller, const std::shared_ptr<storage::Engine>& engine,
                      const std::shared_ptr<fs::model::Entry>& entry, const Need need) {
    if (!caller.session || !caller.session->user) throw Unauthorized("Request requires a user session");
    requireUserNeed(caller.session->user, engine, entry, need);
}

void checkExpect(const std::shared_ptr<fs::model::Entry>& entry, const Expect expect) {
    const bool isFile = static_cast<bool>(std::dynamic_pointer_cast<fs::model::File>(entry));
    // Symlinks (and anything else that is neither a file nor a directory) are never HTTP targets: the handlers
    // dereference the File they are given.
    if (!isFile && !entry->isDirectory()) throw BadRequest("Target is not a regular file or directory");
    if (expect == Expect::File && !isFile) throw BadRequest("Target is not a regular file");
    if (expect == Expect::Directory && !entry->isDirectory()) throw BadRequest("Target is not a directory");
}

[[nodiscard]] Target fromEntry(std::shared_ptr<storage::Engine> engine, std::shared_ptr<fs::model::Entry> entry,
                               const uint32_t vaultId, std::string vaultPath) {
    Target target;
    target.engine = std::move(engine);
    target.file = std::dynamic_pointer_cast<fs::model::File>(entry);
    target.entry = std::move(entry);
    target.vaultId = vaultId;
    target.vaultPath = std::move(vaultPath);
    return target;
}

}

Params parseQuery(const std::string_view target) {
    Params params;
    const auto pos = target.find('?');
    if (pos == std::string_view::npos) return params;
    auto query = target.substr(pos + 1);
    while (!query.empty()) {
        const auto amp = query.find('&');
        const auto pair = query.substr(0, amp);
        if (const auto eq = pair.find('='); eq != std::string_view::npos)
            params[urlDecode(pair.substr(0, eq))] = urlDecode(pair.substr(eq + 1));
        if (amp == std::string_view::npos) break;
        query.remove_prefix(amp + 1);
    }
    return params;
}

bool isShareLane(const Params& params) {
    const auto it = params.find("share");
    return it != params.end() && it->second == "1";
}

namespace {
thread_local const std::shared_ptr<ws::Session>* devicePrincipal = nullptr;
}

DevicePrincipalScope::DevicePrincipalScope(std::shared_ptr<ws::Session> principal)
    : principal_(std::move(principal)), previous_(devicePrincipal) {
    devicePrincipal = &principal_;
}

DevicePrincipalScope::~DevicePrincipalScope() { devicePrincipal = previous_; }

const std::shared_ptr<ws::Session>* DevicePrincipalScope::current() noexcept { return devicePrincipal; }

Caller authenticate(const Request& req, const Params& params) {
    Caller caller;
    caller.share = isShareLane(params);
    if (const auto* device = DevicePrincipalScope::current()) {
        // A paired device is its user: the human lanes only, never a share link's.
        if (caller.share) throw Forbidden("share links are not served on the device listener");
        if (!*device || !(*device)->user || (*device)->closing() || !(*device)->user->authorizing())
            throw Unauthorized("Unauthorized: this device session has ended");
        caller.session = *device;
        return caller;
    }
    try {
        caller.session = hooks::sessionResolver()(req);
    } catch (const std::exception& e) {
        throw Unauthorized(std::string("Unauthorized: ") + e.what());
    }
    if (!caller.session) throw Unauthorized("Unauthorized: no session");
    if (caller.share) {
        if (!caller.session->isShareMode() || caller.session->user)
            throw Unauthorized("Unauthorized: requires a ready share session");
    } else if (!caller.session->user) {
        throw Unauthorized("Unauthorized: requires a user session");
    }
    return caller;
}

Target resolveUserPath(const std::shared_ptr<identities::User>& user, const uint32_t vaultId, const std::string& rawPath,
                       const Need need, const Expect expect) {
    if (!share::Scope::contains("/", rawPath)) throw BadRequest("Path escapes the vault");
    const auto vaultPath = share::Scope::normalizeVaultPath(rawPath);

    const auto engine = hooks::engineResolver()(vaultId);
    if (!engine) throw NotFound("Not found");

    const auto& cache = runtime::Deps::get().fsCache;
    const auto entry = cache ? cache->getEntry(engine->vaultPathToFusePath(vaultPath)) : nullptr;
    if (!entry) {
        // Only a caller who can read the nearest existing ancestor learns that a path doesn't exist there; anyone
        // else gets the same 403 an existing path would give (no existence oracle under denied subtrees).
        std::filesystem::path ancestor = std::filesystem::path(vaultPath).parent_path();
        while (cache && ancestor != ancestor.root_path() && !cache->getEntry(engine->vaultPathToFusePath(ancestor)))
            ancestor = ancestor.parent_path();
        requireUserAction(user, engine, ancestor.empty() ? std::filesystem::path("/") : ancestor, FsAction::Read);
        throw NotFound("Not found");
    }
    requireUserNeed(user, engine, entry, need);
    checkExpect(entry, expect);
    return fromEntry(engine, entry, vaultId, vaultPath);
}

void requireUser(const std::shared_ptr<identities::User>& user, const std::shared_ptr<storage::Engine>& engine,
                 const std::filesystem::path& vaultPath, const FsAction action) {
    if (!share::Scope::contains("/", vaultPath.string())) throw BadRequest("Path escapes the vault");
    requireUserAction(user, engine, share::Scope::normalizeVaultPath(vaultPath.string()), action);
}

Target resolveCreate(const Caller& caller, const Params& params) {
    if (caller.share) throw Forbidden("Uploading through share links is not supported on this lane");
    const auto& user = caller.session ? caller.session->user : nullptr;
    if (!user) throw Unauthorized("Request requires a user session");

    const auto vaultId = parseVaultId(params);
    const auto rawPath = pathParam(params);
    if (!share::Scope::contains("/", rawPath)) throw BadRequest("Path escapes the vault");
    const auto vaultPath = share::Scope::normalizeVaultPath(rawPath);
    if (vaultPath == "/" || rawPath.ends_with('/')) throw BadRequest("The path must name a file");

    const auto engine = hooks::engineResolver()(vaultId);
    if (!engine) throw NotFound("Not found");
    requireUserAction(user, engine, vaultPath, FsAction::Write);

    const auto& cache = runtime::Deps::get().fsCache;
    auto entry = cache ? cache->getEntry(engine->vaultPathToFusePath(vaultPath)) : nullptr;
    return fromEntry(engine, std::move(entry), vaultId, vaultPath);
}

Target resolvePath(const Caller& caller, const uint32_t vaultId, const std::string& rawPath, const Need need,
                   const Expect expect) {
    if (caller.share) throw BadRequest("Share requests address paths relative to the share");
    return resolveUserPath(caller.session ? caller.session->user : nullptr, vaultId, rawPath, need, expect);
}

Target resolve(const Caller& caller, const Params& params, const Need need, const Expect expect) {
    if (!caller.share) return resolvePath(caller, parseVaultId(params), pathParam(params), need, expect);
    if (need == Need::Overwrite) throw Forbidden("Editing through share links is not supported");

    const auto manager = hooks::shareManager()();
    const auto resolver = hooks::shareResolver()();
    if (!manager || !resolver) throw std::runtime_error("Share services are unavailable");
    const auto principal = sharePrincipal(caller, manager);
    const auto actor = caller.session->rbacActor();
    const auto sharePath = pathParam(params);

    share::ResolvedTarget resolved;
    try {
        resolved = resolver->resolve(actor, {
            .path = sharePath,
            .operation = shareOperationFor(need),
            .path_mode = share::TargetPathMode::ShareRelative,
            .expected_target_type = expect == Expect::File ? std::make_optional(share::TargetType::File)
                                    : expect == Expect::Directory ? std::make_optional(share::TargetType::Directory)
                                                                  : std::nullopt
        });
        if (resolved.target_type == share::TargetType::Directory)
            (void)resolver->resolve(actor, {
                .path = sharePath,
                .operation = share::Operation::List,
                .path_mode = share::TargetPathMode::ShareRelative,
                .expected_target_type = share::TargetType::Directory
            });
    } catch (const std::exception& e) {
        const std::string message = e.what();
        if (message.find("not found") != std::string::npos) throw NotFound("Not found");
        throw Forbidden(message);
    }
    if (!resolved.entry) throw NotFound("Not found");

    const auto engine = hooks::engineResolver()(resolved.vault_id);
    if (!engine) throw NotFound("Not found");
    auto target = fromEntry(engine, resolved.entry, resolved.vault_id, resolved.vault_path);
    const auto sharePathResolved = resolved.share_path;
    target.share = ShareContext{.manager = manager,
                                .resolver = resolver,
                                .principal = principal,
                                .resolved = std::make_shared<share::ResolvedTarget>(std::move(resolved)),
                                .sharePath = sharePathResolved};
    return target;
}

void requireHumanChild(const Caller& caller, const Target& root, const std::shared_ptr<fs::model::Entry>& child) {
    if (!child) throw NotFound("Archive child is unavailable");
    requireHumanNeed(caller, root.engine, child, Need::Download);
}

bool recordShareAccess(const Target& target, const std::string_view eventType, const bool countsAsDownload,
                       const std::optional<uint64_t> bytes) {
    if (!target.share || !target.share->principal || !target.share->manager || !target.entry) return true;
    const auto& principal = *target.share->principal;
    const auto generation = target.file ? storage::generationOf(*target.file).sourceId() : std::string{"dir"};
    const auto key = std::string(eventType) + "|" + principal.share_session_id + "|" +
                     std::to_string(target.entry->id) + "|" + generation;

    std::promise<bool> decision;
    std::shared_future<bool> pending;
    {
        const auto now = Clock::now();
        std::scoped_lock lock(cacheMutex());
        pruneLocked(now);
        auto& shares = shareAccess();
        if (const auto it = shares.find(key); it != shares.end() && now - it->second.at < kAuditWindow) {
            pending = it->second.allowed;
        } else {
            shares[key] = ShareAccessSlot{now, decision.get_future().share()};
        }
    }
    if (pending.valid()) {
        // Another request owns this logical download's decision; follow it (fail closed if it never settles).
        return pending.wait_for(std::chrono::seconds(30)) == std::future_status::ready && pending.get();
    }

    bool allowed = true;
    try {
        if (countsAsDownload) allowed = target.share->manager->consumeDownload(principal);
    } catch (const std::exception& e) {
        log::Registry::http()->warn("[HttpAccess] Share download accounting failed (refusing): {}", e.what());
        allowed = false;
    }
    if (allowed) {
        try {
            target.share->manager->appendAccessAuditEvent(principal, {
                .event_type = std::string(eventType),
                .target = {
                    .vault_id = target.vaultId,
                    .target_entry_id = target.entry->id,
                    .target_path = target.vaultPath
                },
                .status = share::AuditStatus::Success,
                .bytes_transferred = bytes,
                .error_code = std::nullopt,
                .error_message = std::nullopt
            });
        } catch (const std::exception& e) {
            log::Registry::http()->warn("[HttpAccess] Share audit write failed: {}", e.what());
        }
    }
    decision.set_value(allowed);
    if (!allowed) {
        std::scoped_lock lock(cacheMutex());
        shareAccess().erase(key);  // a refused download is decided again next time (the limit may have been raised)
    }
    return allowed;
}

void recordHumanAccess(const Caller& caller, const Target& target, const std::string_view eventType) {
    if (!caller.session || !caller.session->user || !target.entry) return;
    const auto generation = target.file ? storage::generationOf(*target.file).sourceId() : std::string{"dir"};
    const auto key = std::string(eventType) + "|u" + std::to_string(caller.session->user->id) + "|" +
                     std::to_string(target.entry->id) + "|" + generation;
    if (!firstInWindow(key)) return;
    log::Registry::audit()->info("[http] {} user={} vault={} entry={} path={}", eventType, caller.session->user->id,
                                 target.vaultId, target.entry->id, target.vaultPath);
}

void clearCachesForTesting() {
    std::scoped_lock lock(cacheMutex());
    principals().clear();
    recentAccess().clear();
    shareAccess().clear();
}

namespace hooks {

namespace {
std::shared_ptr<ws::Session> defaultSessionResolver(const Request& req) {
    if (isShareLane(parseQuery(std::string_view(req.target().data(), req.target().size())))) {
        const auto token = protocols::extractCookie(req, "share_refresh");
        if (token.empty()) throw std::runtime_error("Share refresh token not set");
        return runtime::Deps::get().sessionManager->validateRawShareRefreshToken(token);
    }
    const auto token = protocols::extractCookie(req, "refresh");
    if (token.empty()) throw std::runtime_error("Refresh token not set");
    return runtime::Deps::get().sessionManager->validateRawRefreshToken(token);
}
}

SessionResolver& sessionResolver() {
    static SessionResolver value = defaultSessionResolver;
    return value;
}

ShareManagerFactory& shareManager() {
    static ShareManagerFactory value = [] { return std::make_shared<share::Manager>(); };
    return value;
}

ShareResolverFactory& shareResolver() {
    static ShareResolverFactory value = [] { return std::make_shared<share::TargetResolver>(); };
    return value;
}

EngineResolver& engineResolver() {
    static EngineResolver value = [](const uint32_t vaultId) {
        return runtime::Deps::get().storageManager->getEngine(vaultId);
    };
    return value;
}

void resetSessionResolver() { sessionResolver() = defaultSessionResolver; }
void resetShareManager() { shareManager() = [] { return std::make_shared<share::Manager>(); }; }
void resetShareResolver() { shareResolver() = [] { return std::make_shared<share::TargetResolver>(); }; }
void resetEngineResolver() {
    engineResolver() = [](const uint32_t vaultId) { return runtime::Deps::get().storageManager->getEngine(vaultId); };
}

}

}
