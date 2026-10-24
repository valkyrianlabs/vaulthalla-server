#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/fs.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/SocketIO.hpp"
#include "protocols/shell/Table.hpp"
#include "protocols/shell/Transfer.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/http/Access.hpp"
#include "CommandUsage.hpp"
#include "config/Registry.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "platform/Durable.hpp"
#include "rbac/fs/Visibility.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "runtime/Deps.hpp"
#include "share/Scope.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Controller.hpp"
#include "usage/include/UsageManager.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>
#include <paths.h>
#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// `vh fs ls|get|put` (#229): vault file access for a local operator when there is no mount (macOS: FUSE disabled or
// service-private). The caller is the peer-credential-mapped user like every `vh` command; authorization is the HTTP
// lane's evaluator (protocols/http/Access: same path normalization, same no-existence-oracle rule); bytes move in the
// bounded frames of protocols/shell/Transfer.hpp and the daemon never touches a caller-local path.
namespace vh::protocols::shell::commands {

namespace {

namespace tx = transfer;
using FsAction = ::vh::rbac::permission::vault::FilesystemAction;
using Clock = std::chrono::steady_clock;

// Work one client can hold: one transfer per connection (the socket's own concurrency limit applies on top), at most
// this many at once daemon-wide, and none longer than the deadline. `put` keeps one chunk in memory and stages the
// rest on disk; `get` holds one chunk.
constexpr int kMaxConcurrentGets = 4;
constexpr int kMaxConcurrentPuts = 2;
constexpr auto kMaxTransferDuration = std::chrono::hours(6);
// Authorization is re-evaluated (with the user reloaded) every this many chunks of a download, and before a put is
// committed: revoking access stops a long transfer within 8 MiB.
constexpr std::uint64_t kRecheckEveryChunks = 32;

std::atomic<int> activeGets{0};
std::atomic<int> activePuts{0};

class Slot {
public:
    Slot(std::atomic<int>& counter, const int max) : counter_(counter) {
        if (counter_.fetch_add(1) >= max) { counter_.fetch_sub(1); return; }
        held_ = true;
    }
    ~Slot() { if (held_) counter_.fetch_sub(1); }
    Slot(const Slot&) = delete;
    Slot& operator=(const Slot&) = delete;
    explicit operator bool() const { return held_; }
private:
    std::atomic<int>& counter_;
    bool held_{false};
};

CommandResult fail(const int code, const std::string& prefix, const std::string& msg) {
    return {code, "", prefix + ": " + msg};
}

// The access layer's typed failures as exit codes. Forbidden covers a missing path under a subtree the caller can't
// read (no existence oracle), exactly as the HTTP lane answers 403 there.
CommandResult accessFailure(const std::string& prefix) {
    try {
        throw;
    } catch (const http::access::Forbidden&) {
        return fail(tx::exitcode::kNoPerm, prefix, "permission denied");
    } catch (const http::access::Unauthorized&) {
        return fail(tx::exitcode::kNoPerm, prefix, "permission denied");
    } catch (const http::access::NotFound&) {
        return fail(tx::exitcode::kNoInput, prefix, "no such file or directory");
    } catch (const http::access::BadRequest& e) {
        return fail(tx::exitcode::kUsage, prefix, e.what());
    }
}

struct VaultRef {
    std::shared_ptr<::vh::vault::model::Vault> vault;
    std::shared_ptr<storage::Engine> engine;
};

std::optional<VaultRef> vaultFor(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage,
                                 const std::string& prefix, std::string& error) {
    const auto lookup = vault::resolveVault(call, call.positionals.at(0), usage, prefix);
    if (!lookup) { error = lookup.error; return std::nullopt; }
    auto engine = runtime::Deps::get().storageManager->getEngine(lookup.ptr->id);
    if (!engine) { error = prefix + ": vault " + std::to_string(lookup.ptr->id) + " has no storage engine"; return std::nullopt; }
    return VaultRef{lookup.ptr, std::move(engine)};
}

// The user as the daemon knows it now (roles reloaded); null if the account is gone.
std::shared_ptr<identities::User> currentUser(const CommandCall& call) {
    if (!call.user) return nullptr;
    if (call.user->id == 0) return call.user;  // the synthetic users of read-only commands never reach here
    return identities::manager().user(call.user->id);
}

bool stillAllowed(const CommandCall& call, const std::shared_ptr<storage::Engine>& engine,
                  const std::string& vaultPath, const FsAction action) {
    try {
        const auto user = currentUser(call);
        if (!user) return false;
        http::access::requireUser(user, engine, vaultPath, action);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::string utc(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%SZ", &tm);
    return buf;
}

std::string humanSize(const uintmax_t bytes) {
    static constexpr const char* kUnits[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = static_cast<double>(bytes);
    std::size_t u = 0;
    while (v >= 1024.0 && u + 1 < std::size(kUnits)) { v /= 1024.0; ++u; }
    char buf[32];
    if (u == 0) std::snprintf(buf, sizeof(buf), "%ju B", bytes);
    else std::snprintf(buf, sizeof(buf), "%.1f %s", v, kUnits[u]);
    return buf;
}

// ---------------------------------------------------------------------------------------------------------- ls ----

CommandResult handleLs(const CommandCall& call) {
    const std::string prefix = "fs ls";
    const auto usage = resolveUsage({"fs", "ls"});
    if (call.positionals.size() != usage->positionals.size())
        return fail(tx::exitcode::kUsage, prefix, "usage: vh fs ls <vault> <path>");
    std::string error;
    const auto ref = vaultFor(call, usage, prefix, error);
    if (!ref) return {tx::exitcode::kNoInput, "", error};

    http::access::Target target;
    try {
        target = http::access::resolveUserPath(call.user, ref->vault->id, call.positionals.at(1),
                                               http::access::Need::List, http::access::Expect::Any);
    } catch (const http::access::Forbidden&) {
        // A file: listing it is reading its metadata, which needs Read on the file itself.
        try {
            target = http::access::resolveUserPath(call.user, ref->vault->id, call.positionals.at(1),
                                                   http::access::Need::Download, http::access::Expect::File);
        } catch (...) {
            return accessFailure(prefix);
        }
    } catch (...) {
        return accessFailure(prefix);
    }

    std::vector<std::shared_ptr<fs::model::Entry>> entries;
    // Children the caller cannot Lookup are left out, as in FUSE readdir and ws fs.dir.list (#170, #255).
    if (target.entry->isDirectory()) {
        auto children = runtime::Deps::get().fsCache->listDir(target.entry->id, false);
        entries = ::vh::rbac::fs::visibility::visibleChildren(call.user, target.entry, std::move(children));
    }
    else entries.push_back(target.entry);
    std::ranges::sort(entries, [](const auto& a, const auto& b) {
        if (a->isDirectory() != b->isDirectory()) return a->isDirectory();
        return a->name < b->name;
    });

    Table table({
        {.header = "TYPE"},
        {.header = "SIZE", .align = Align::Right},
        {.header = "MODIFIED"},
        {.header = "NAME", .ellipsize_middle = true},
    });
    for (const auto& e : entries)
        table.add_row({e->isDirectory() ? "dir" : e->isSymlink() ? "link" : "file",
                       e->isDirectory() ? "-" : humanSize(e->size_bytes), utc(e->updated_at),
                       e->name + (e->isDirectory() ? "/" : "")});
    return {0, entries.empty() ? std::string{} : table.render(), ""};
}

// --------------------------------------------------------------------------------------------------------- get ----

CommandResult handleGet(const CommandCall& call) {
    const std::string prefix = "fs get";
    const auto usage = resolveUsage({"fs", "get"});
    if (call.positionals.size() != usage->positionals.size())
        return fail(tx::exitcode::kUsage, prefix, "usage: vh fs get <vault> <path> [-o <file>|-]");
    if (!call.transfer)
        return fail(tx::exitcode::kUsage, prefix, "this vh client can't receive files; use the vh that came with the daemon");
    std::string error;
    const auto ref = vaultFor(call, usage, prefix, error);
    if (!ref) return {tx::exitcode::kNoInput, "", error};

    http::access::Target target;
    try {
        target = http::access::resolveUserPath(call.user, ref->vault->id, call.positionals.at(1),
                                               http::access::Need::Download, http::access::Expect::File);
    } catch (...) {
        return accessFailure(prefix);
    }

    const Slot slot(activeGets, kMaxConcurrentGets);
    if (!slot) return fail(tx::exitcode::kTempFail, prefix, "too many file transfers in progress; try again shortly");

    // Optimistic: bytes are released as they are read and the whole GCM message is authenticated before the result
    // says ok. The client keeps the file only on an ok result (stdout readers get the exit code).
    std::unique_ptr<storage::PlaintextReader> reader;
    try {
        reader = target.engine->openPlaintextReader(target.file, {.integrity = storage::IntegrityPolicy::Optimistic});
    } catch (const storage::ContentUnavailable& e) {
        return fail(1, prefix, std::string("the content is not available locally: ") + e.what());
    }
    const auto size = reader->size();
    const int fd = call.transfer->fd;
    if (!SocketIO::send_json(fd, {{"type", "transfer"}, {"size", size}}))
        return fail(tx::exitcode::kTempFail, prefix, "the client went away");

    const auto started = Clock::now();
    std::vector<std::uint8_t> chunk(tx::kChunkBytes);
    std::uint64_t offset = 0, seq = 0;
    while (offset < size) {
        const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(chunk.size(), size - offset));
        const auto n = reader->read(offset, std::span(chunk.data(), want));
        if (n == 0) return fail(1, prefix, "the stored file is shorter than its recorded size");
        if (!SocketIO::send_json(fd, {{"type", "data"}, {"seq", seq}, {"b64", tx::encode(std::span(chunk.data(), n))}}))
            return fail(tx::exitcode::kTempFail, prefix, "the client stopped reading");  // SO_SNDTIMEO or hang-up
        offset += n;
        ++seq;
        if (seq % kRecheckEveryChunks == 0 && !stillAllowed(call, target.engine, target.vaultPath, FsAction::Read))
            return fail(tx::exitcode::kNoPerm, prefix, "permission revoked during the transfer");
        if (Clock::now() - started > kMaxTransferDuration) return fail(tx::exitcode::kTempFail, prefix, "transfer took too long");
    }
    try {
        reader->requireAuthenticated();
    } catch (const std::exception& e) {
        log::Registry::audit()->warn("vh fs get: {} vault {} path {}: integrity check failed: {}", call.user->name(),
                                     ref->vault->id, target.vaultPath, e.what());
        return fail(1, prefix, "the stored file failed its integrity check; discard what was received");
    }
    if (!stillAllowed(call, target.engine, target.vaultPath, FsAction::Read))
        return fail(tx::exitcode::kNoPerm, prefix, "permission revoked during the transfer");

    log::Registry::audit()->info("vh fs get: {} read vault {} path {} ({} bytes)", call.user->name(), ref->vault->id,
                                 target.vaultPath, size);
    return {0, "", ""};
}

// --------------------------------------------------------------------------------------------------------- put ----

// The bytes of one put, in a 0600 file inside a 0700 directory under the daemon's private state root (never the
// mount, never the caller's filesystem), removed on every path out unless committed. Leftovers from a crash are
// plaintext and are swept when the CLI server starts.
class Staged {
public:
    explicit Staged(const std::filesystem::path& dir) {
        std::filesystem::create_directories(dir);
        if (::chmod(dir.c_str(), 0700) != 0) throw std::runtime_error("cannot make the staging directory private");
        unsigned char id[16];
        randombytes_buf(id, sizeof id);
        std::string name = "put-";
        static constexpr char kHex[] = "0123456789abcdef";
        for (const auto b : id) { name.push_back(kHex[b >> 4]); name.push_back(kHex[b & 15]); }
        path_ = dir / (name + ".part");
        fd_ = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd_ < 0) throw std::runtime_error(std::string("cannot create the staging file: ") + std::strerror(errno));
    }
    ~Staged() {
        if (fd_ >= 0) ::close(fd_);
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    Staged(const Staged&) = delete;
    Staged& operator=(const Staged&) = delete;

    void write(const std::vector<std::uint8_t>& bytes) const {
        const auto* p = bytes.data();
        std::size_t left = bytes.size();
        while (left) {
            const auto w = ::write(fd_, p, left);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) throw std::runtime_error(std::string("writing the staging file failed: ") + std::strerror(errno));
            p += w;
            left -= static_cast<std::size_t>(w);
        }
    }
    void finish() {
        if (platform::durable::sync(fd_) != 0) throw std::runtime_error(std::string("fsync of the staging file failed: ") + std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
    }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
    int fd_{-1};
};

std::filesystem::path stagingDir() { return paths::getBackingPath() / ".cli-staging"; }

CommandResult handlePut(const CommandCall& call) {
    const std::string prefix = "fs put";
    const auto usage = resolveUsage({"fs", "put"});
    if (call.positionals.size() != usage->positionals.size())
        return fail(tx::exitcode::kUsage, prefix, "usage: vh fs put <vault> <local-file|-> <path> [--overwrite]");
    if (!call.transfer || !call.transfer->putSize)
        return fail(tx::exitcode::kUsage, prefix, "this vh client can't send files; use the vh that came with the daemon");
    // positionals[1] is the caller's local file: the client reads it and sends the bytes; the daemon never opens it.
    const auto& rawPath = call.positionals.at(2);
    if (!share::Scope::contains("/", rawPath)) return fail(tx::exitcode::kUsage, prefix, "the path escapes the vault");
    const auto vaultPath = share::Scope::normalizeVaultPath(rawPath);
    if (vaultPath == "/" || rawPath.ends_with('/'))
        return fail(tx::exitcode::kUsage, prefix, "the vault path must name a file, not a directory");

    const auto size = *call.transfer->putSize;
    const auto limit = config::Registry::get().websocket.max_upload_size_bytes;
    if (size > limit)
        return fail(1, prefix, "the file is " + std::to_string(size) + " bytes; the upload limit is " + std::to_string(limit));

    std::string error;
    const auto ref = vaultFor(call, usage, prefix, error);
    if (!ref) return {tx::exitcode::kNoInput, "", error};
    const auto& engine = ref->engine;
    const auto fusePath = engine->vaultPathToFusePath(vaultPath);
    const bool overwrite = hasFlag(call, "overwrite");

    // Same rules as the HTTP lanes: creating needs Write on the target path (missing parents are created, as an
    // upload does); replacing needs Overwrite on the existing file and is a compare-and-swap on the generation that
    // was authorized, so a concurrent change is a conflict, never silently lost.
    const auto existing = runtime::Deps::get().fsCache->getEntry(fusePath);
    std::optional<std::string> expectedSource;
    FsAction commitAction = FsAction::Write;
    try {
        if (existing && overwrite) {
            const auto target = http::access::resolveUserPath(call.user, ref->vault->id, vaultPath,
                                                              http::access::Need::Overwrite, http::access::Expect::File);
            expectedSource = storage::generationOf(*target.file).sourceId();
            commitAction = FsAction::Overwrite;
        } else {
            http::access::requireUser(call.user, engine, vaultPath, FsAction::Write);
            if (existing)
                return fail(tx::exitcode::kCantCreat, prefix, vaultPath + " already exists (use --overwrite to replace it)");
        }
    } catch (...) {
        return accessFailure(prefix);
    }
    if (engine->freeSpace() < size) return fail(1, prefix, "not enough space in the vault");

    const Slot slot(activePuts, kMaxConcurrentPuts);
    if (!slot) return fail(tx::exitcode::kTempFail, prefix, "too many file transfers in progress; try again shortly");

    Staged staged(stagingDir());
    const int fd = call.transfer->fd;
    if (!SocketIO::send_json(fd, {{"type", "transfer-ready"}, {"size", size}}))
        return fail(tx::exitcode::kTempFail, prefix, "the client went away");

    // Every frame is size-checked before it is read into memory (recv_json), every chunk before it is decoded.
    // A hang-up, a stall past the socket's receive timeout or an oversized frame throws: the staging file goes with
    // the stack and the client (if still there) gets the error.
    const auto started = Clock::now();
    std::uint64_t received = 0, seq = 0;
    for (;;) {
        const auto frame = SocketIO::recv_json(fd, tx::kMaxTransferFrameBytes);
        const auto type = frame.value("type", std::string{});
        if (type == "data") {
            if (!frame.contains("seq") || !frame["seq"].is_number_unsigned() || frame["seq"].get<std::uint64_t>() != seq)
                return fail(tx::exitcode::kDataErr, prefix, "a data frame arrived out of order");
            if (!frame.contains("b64") || !frame["b64"].is_string())
                return fail(tx::exitcode::kDataErr, prefix, "a data frame has no payload");
            const auto bytes = tx::decodeChunk(frame["b64"].get_ref<const std::string&>());
            if (!bytes || bytes->empty()) return fail(tx::exitcode::kDataErr, prefix, "a data frame is malformed");
            if (bytes->size() > size - received)
                return fail(tx::exitcode::kDataErr, prefix, "more bytes arrived than were announced");
            staged.write(*bytes);
            received += bytes->size();
            ++seq;
        } else if (type == "transfer-end") {
            if (!frame.contains("bytes") || !frame["bytes"].is_number_unsigned() ||
                frame["bytes"].get<std::uint64_t>() != size || received != size)
                return fail(tx::exitcode::kDataErr, prefix, "the transfer ended with " + std::to_string(received) +
                                                                " of " + std::to_string(size) + " bytes; nothing was stored");
            break;
        } else if (type == "transfer-abort") {
            return fail(1, prefix, "cancelled by the client; nothing was stored");
        } else {
            return fail(tx::exitcode::kDataErr, prefix, "unexpected frame during the transfer");
        }
        if (Clock::now() - started > kMaxTransferDuration) return fail(tx::exitcode::kTempFail, prefix, "transfer took too long");
    }
    staged.finish();

    // Authorization is evaluated again with the user as it is now: a role revoked mid-upload commits nothing.
    const auto user = currentUser(call);
    if (!user || !stillAllowed(call, engine, vaultPath, commitAction))
        return fail(tx::exitcode::kNoPerm, prefix, "permission revoked during the transfer; nothing was stored");

    try {
        if (!existing) {
            if (fs::Filesystem::mkdir({.path = fusePath.parent_path(), .engine = engine, .user = user}) != 0)
                return fail(1, prefix, "cannot create the parent directory");
        }
        // Seal (fresh IV) from the staged plaintext straight into the vault, then the row; for a replacement the
        // ciphertext lands in a sidecar first and is renamed over the old bytes only after the row (fs::Filesystem).
        const auto stored = fs::Filesystem::createFile({.path = vaultPath, .fuse_path = fusePath,
                                                        .source_path = staged.path(), .engine = engine, .user = user,
                                                        .overwrite = static_cast<bool>(existing),
                                                        .expected_source_id = expectedSource});
        if (!stored) return fail(1, prefix, "the file could not be stored");
    } catch (const fs::ContentConflict& e) {
        return fail(1, prefix, std::string("the file changed while uploading (") + e.what() + "); nothing was stored");
    } catch (const std::filesystem::filesystem_error& e) {
        if (e.code() == std::errc::file_exists)
            return fail(tx::exitcode::kCantCreat, prefix, vaultPath + " was created by someone else meanwhile, or is a directory");
        throw;
    }

    try {
        if (const auto& sync = runtime::Deps::get().syncController) sync->runNow(ref->vault->id);
    } catch (const std::exception& e) {
        log::Registry::sync()->warn("[vh fs put] could not trigger sync for vault {}: {}", ref->vault->id, e.what());
    }
    log::Registry::audit()->info("vh fs put: {} {} vault {} path {} ({} bytes)", user->name(),
                                 existing ? "replaced" : "created", ref->vault->id, vaultPath, size);
    return {0, "stored " + humanSize(size) + " at " + vaultPath + "\n", ""};
}

CommandResult handleFs(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"fs", "ls"}, sub)) return handleLs(subcall);
    if (isCommandMatch({"fs", "get"}, sub)) return handleGet(subcall);
    if (isCommandMatch({"fs", "put"}, sub)) return handlePut(subcall);
    return invalid(call.constructFullArgs(), "Unknown fs subcommand: '" + std::string(sub) + "'");
}

}

void sweepFsStaging() noexcept {
    std::error_code ec;
    const auto dir = stagingDir();
    if (!std::filesystem::is_directory(dir, ec)) return;
    std::size_t removed = 0;
    for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
        if (!e.path().filename().string().ends_with(".part")) continue;
        std::error_code rm;
        if (std::filesystem::remove(e.path(), rm)) ++removed;
    }
    if (removed) log::Registry::shell()->warn("[vh fs] removed {} unfinished upload(s) left by an earlier run", removed);
}

void registerFsCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("fs"), handleFs);
}

}
