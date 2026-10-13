#include "protocols/shell/Server.hpp"
#include "protocols/shell/Transfer.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/Parser.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/fs.hpp"
#include "db/query/identities/User.hpp"
#include "log/Registry.hpp"
#include "protocols/shell/SocketIO.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "platform/Fd.hpp"
#include "platform/LocalAccounts.hpp"
#include "platform/PeerCredentials.hpp"

#include <paths.h>
#include <version.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include <grp.h>
#include <pwd.h>

using nlohmann::json;

using namespace vh::protocols::shell;

namespace {

bool in_group(const uid_t uid, const gid_t admin_gid) {
    return uid == 0 || vh::platform::accounts::isMember(uid, admin_gid);
}

void setCliSocketTimeout(const int fd, const int opt, const std::chrono::milliseconds timeout) {
    timeval tv{};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    (void)::setsockopt(fd, SOL_SOCKET, opt, &tv, sizeof(tv));
}

// Legacy (type-less) reply: every vh client version treats it as the final frame.
void sendCliError(const int fd, const int exitCode, const std::string& message) {
    (void)SocketIO::send_json(fd, {{"ok", false}, {"exit_code", exitCode}, {"stderr", message}});
}

// Commands that must keep working when the database is down, because they are how an operator finds out.
// They need no per-user authorization beyond the socket's group gate.
bool cliCommandRunsWithoutUserLookup(const std::string& cmd) {
    return cmd == "status" || cmd == "version";
}

gid_t lookupCliAdminGid() {
    if (const group* grp = getgrnam(VH_SERVICE_ACCOUNT)) return grp->gr_gid;
    vh::log::Registry::shell()->error("[CtlServerService] Group '" VH_SERVICE_ACCOUNT "' not found; only root can use "
                                      "the CLI");
    return static_cast<gid_t>(-1);
}

} // namespace

Server::Server()
    : AsyncService("vaulthalla-cli"),
      router_(std::make_shared<shell::Router>()),
      socketPath_(paths::getCliSocketPath().string()),
      adminGid_(lookupCliAdminGid()),
      adminUIDSet_(false) {

    commands::registerAllCommands(router_);

    try {
        const auto admin = vh::identities::manager().userByName("admin");
        if (!admin) log::Registry::shell()->warn("[CtlServerService] No 'admin' user found in database");
        if (admin && admin->linuxUid().has_value()) adminUIDSet_.store(true);
        adminStateKnown_.store(true);
    } catch (const std::exception& e) {
        // Unknown is not "unset": don't let the first connecting user claim the admin account because the DB
        // was unreachable at startup. The lookup is retried on the next connection.
        log::Registry::shell()->warn("[CtlServerService] Could not read the 'admin' user's Linux UID yet: {}", e.what());
    }
}

Server::~Server() {
    // AsyncService::~AsyncService() stops too, but by then this subclass is gone; stop while members exist.
    stop();
    closeListener(true);
}

std::size_t Server::activeClients() const {
    std::scoped_lock lock(clientsMutex_);
    return static_cast<std::size_t>(std::ranges::count_if(clients_, [](const ClientSlot& c) { return !c.done; }));
}

int Server::bindListener() {
    ::unlink(socketPath_.c_str());

    sockaddr_un addr{};
    // sun_path is 108 bytes on Linux but 104 on macOS (whose $TMPDIR paths are long): refuse instead of truncating.
    if (socketPath_.size() >= sizeof(addr.sun_path))
        throw std::runtime_error("CLI socket path too long for a unix socket: " + socketPath_);

    const int fd = vh::platform::fd::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error(std::string("socket(): ") + std::strerror(errno));

    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, socketPath_.c_str(), socketPath_.size() + 1);
    // offsetof, not sizeof(sa_family_t): BSD's sockaddr_un starts with sun_len (on Linux the two are equal).
    const auto addrLen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + socketPath_.size() + 1);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), addrLen) != 0) {
        const auto err = errno;
        ::close(fd);
        throw std::runtime_error("bind(" + socketPath_ + "): " + std::strerror(err));
    }
    ::chmod(socketPath_.c_str(), 0660);

    if (::listen(fd, 64) != 0) {
        const auto err = errno;
        ::close(fd);
        throw std::runtime_error(std::string("listen(): ") + std::strerror(err));
    }

    struct stat st{};
    if (::stat(socketPath_.c_str(), &st) != 0) {
        const auto err = errno;
        ::close(fd);
        throw std::runtime_error("stat(" + socketPath_ + "): " + std::strerror(err));
    }

    std::scoped_lock lock(fdMutex_);
    listenFd_ = fd;
    listenDev_ = st.st_dev;
    listenIno_ = st.st_ino;
    return fd;
}

bool Server::listenerPathIsOurs() const {
    struct stat st{};
    if (::stat(socketPath_.c_str(), &st) != 0) return false;
    std::scoped_lock lock(fdMutex_);
    return st.st_dev == listenDev_ && st.st_ino == listenIno_;
}

void Server::closeListener(const bool unlinkPath) {
    std::scoped_lock lock(fdMutex_);
    if (listenFd_ >= 0) {
        // shutdown() is the reliable unblock path for a thread blocked in accept4()/poll()
        ::shutdown(listenFd_, SHUT_RDWR);
        ::close(listenFd_);
        listenFd_ = -1;
    }
    // Only remove the path if it is still ours; never unlink a listener somebody else bound there.
    if (unlinkPath && listenIno_ != 0) {
        struct stat st{};
        if (::stat(socketPath_.c_str(), &st) == 0 && st.st_dev == listenDev_ && st.st_ino == listenIno_)
            ::unlink(socketPath_.c_str());
    }
    listenDev_ = 0;
    listenIno_ = 0;
}

void Server::shutdownClients() {
    std::scoped_lock lock(clientsMutex_);
    for (const auto& c : clients_)
        if (c.fd >= 0) ::shutdown(c.fd, SHUT_RDWR); // the client thread owns close()
}

void Server::reapFinishedClients(const bool joinAll) {
    std::list<ClientSlot> finished;
    {
        std::scoped_lock lock(clientsMutex_);
        for (auto it = clients_.begin(); it != clients_.end();) {
            if (it->done || joinAll) {
                auto next = std::next(it);
                finished.splice(finished.end(), clients_, it);
                it = next;
            } else ++it;
        }
    }
    for (auto& c : finished)
        if (c.thread.joinable()) c.thread.join();
}

void Server::onStop() {
    // Unblock client threads (reads/prompts) first, then the accept loop.
    shutdownClients();
    closeListener(true);
}

void Server::initAdminUid(const uid_t uid) {
    const auto msg = fmt::format(
        "[CtlServerService] 'admin' user has no Linux UID set; Assigning first user UID {} to 'admin'", uid);
    log::Registry::shell()->info(msg);
    log::Registry::audit()->info(msg);

    const struct passwd* pw = getpwuid(uid);
    if (!pw) throw std::runtime_error("Unable to resolve UID to username");
    const std::string uname = pw->pw_name;

    // Assign UID to admin
    if (const auto admin = vh::identities::manager().userByName("admin"))
        vh::identities::manager().bindLinuxUid(admin->id, uid, std::nullopt);
    else
        throw std::runtime_error("admin user record not found");
    adminUIDSet_.store(true);

    log::Registry::shell()->info("[CtlServerService] Assigned UID {} to 'admin' user", uid);

    // No group change here: the connection already passed the 'vaulthalla' group gate (handleClient), and the
    // daemon runs unprivileged, so it could not change group membership anyway.
    log::Registry::audit()->info("Bound user '{}' (UID {}) to the 'admin' account", uname, uid);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

void Server::handleClient(const int cfd) {
    try {
        // Bounded reads/writes from the first byte: a client that connects and goes quiet, or stops reading,
        // costs one thread slot for a bounded time and never blocks anyone else.
        setCliSocketTimeout(cfd, SO_RCVTIMEO, kRequestTimeout);
        setCliSocketTimeout(cfd, SO_SNDTIMEO, kSendTimeout);

        const auto p = vh::platform::peerCredentials(cfd);
        log::Registry::shell()->debug("[CtlServerService] Connection from UID {} (PID {})", p.uid, p.pid);

        if (!in_group(p.uid, adminGid_)) {
            log::Registry::shell()->debug("[CtlServerService] Connection from UID {} (PID {}) not in "
                                          VH_SERVICE_ACCOUNT " group", p.uid, p.pid);
            sendCliError(cfd, 77, "permission denied: this user is not in the '" VH_SERVICE_ACCOUNT "' group (" +
                                      vh::platform::accounts::addMemberCommand("$USER", VH_SERVICE_ACCOUNT) +
                                      ", then log in again; or use sudo)");
            return;
        }

        // Tells the client the daemon accepted it. A client that never sees this is talking to a listener
        // nobody serves (daemon down or wedged) and reports that instead of hanging.
        if (!SocketIO::send_json(cfd, {{"type", "hello"}, {"version", VH_VERSION}})) return;

        const json req = SocketIO::recv_json(cfd);
        std::string cmd = req.value("cmd", "");
        if (cmd.empty()) cmd = "help";

        if (!req.contains("line") || !req["line"].is_string()) {
            log::Registry::shell()->error("[CtlServerService] No 'line' field in request from UID {} (PID {})",
                                          p.uid, p.pid);
            sendCliError(cfd, 1, "invalid request");
            return;
        }

        std::shared_ptr<identities::User> user;
        if (cliCommandRunsWithoutUserLookup(cmd)) {
            // Read-only health/version output must not depend on the DB it reports on.
            identities::UserState synthetic;
            synthetic.name = p.uid == 0 ? "root" : "uid:" + std::to_string(p.uid);
            user = identities::User::detached(0, std::move(synthetic));
        } else {
            if (!paths::testMode && p.uid != 0 && p.uid >= vh::platform::accounts::firstHumanUid() && !adminUIDSet_.load()) {
                std::scoped_lock adminLock(adminInitMutex_);
                if (!adminStateKnown_.load()) {
                    const auto admin = vh::identities::manager().userByName("admin");
                    if (admin && admin->linuxUid().has_value()) adminUIDSet_.store(true);
                    adminStateKnown_.store(true);
                }
                if (!adminUIDSet_.load()) initAdminUid(p.uid);
            }

            user = p.uid == 0 ?
                vh::identities::manager().userByName("root") :
                vh::identities::manager().userByLinuxUid(p.uid);

            if (!user) {
                log::Registry::shell()->debug("[CtlServerService] No user found for UID {} (PID {})", p.uid, p.pid);
                sendCliError(cfd, 1, "user not found: no Vaulthalla user is mapped to Linux UID " + std::to_string(p.uid));
                return;
            }
        }

        auto line = req["line"].get<std::string>();
        if (line.empty()) line = "help";

        // `vh fs get|put`: the client says it speaks the transfer frames. A transfer is never interactive, so its
        // reads keep the short request timeout (a stalled peer can't hold a slot for the prompt timeout).
        std::optional<TransferPeer> peer;
        if (req.contains("transfer")) {
            const auto& t = req["transfer"];
            if (!t.is_object() || t.value("v", 0) != transfer::kVersion ||
                (t.contains("put_size") && !t["put_size"].is_number_unsigned())) {
                sendCliError(cfd, transfer::exitcode::kDataErr, "invalid transfer request (is vh newer than the daemon?)");
                return;
            }
            peer = TransferPeer{.fd = cfd, .putSize = t.contains("put_size")
                                                              ? std::make_optional(t["put_size"].get<uint64_t>())
                                                              : std::nullopt};
        }

        std::unique_ptr<SocketIO> io;
        if (!peer && req.value("interactive", false)) {
            io = std::make_unique<SocketIO>(cfd);
            setCliSocketTimeout(cfd, SO_RCVTIMEO, kPromptTimeout); // a person answering prompts gets longer
        }

        try {
            const auto res = router_->executeLine(line, user, io.get(), std::move(peer));

            json reply{
                {"type", "result"},
                {"ok", res.exit_code == 0},
                {"exit_code", res.exit_code}
            };
            if (!res.stdout_text.empty()) reply["stdout"] = res.stdout_text;
            if (!res.stderr_text.empty()) reply["stderr"] = res.stderr_text;

            (void)SocketIO::send_json(cfd, reply);
        } catch (const std::exception& e) {
            (void)SocketIO::send_json(cfd, {
                {"type", "result"},
                {"ok", false},
                {"exit_code", 1},
                {"stderr", e.what()}
            });
        }
    } catch (const std::exception& e) {
        log::Registry::shell()->error("[CtlServerService] Client error: {}", e.what());
        sendCliError(cfd, 1, e.what());
    } catch (...) {
        sendCliError(cfd, 1, "internal error");
    }
}

void Server::runLoop() {
    commands::sweepFsStaging();
    int listenFd = bindListener();
    log::Registry::shell()->info("[CtlServerService] Listening on {}", socketPath_);

    while (!shouldStop()) {
        reapFinishedClients(false);

        pollfd pfd{.fd = listenFd, .events = POLLIN, .revents = 0};
        const int rc = ::poll(&pfd, 1, static_cast<int>(kListenerCheckInterval.count()));
        if (shouldStop()) break;

        if (rc == 0) {
            // Something else took the path (a stale vaulthalla-cli.socket unit, a second daemon) or removed it.
            // Clients connecting to that path would queue on a listener nobody serves, so take it back.
            if (!listenerPathIsOurs()) {
                log::Registry::shell()->warn(
                    "[CtlServerService] {} no longer refers to this daemon's listener (replaced or removed; "
                    "a stale vaulthalla-cli.socket unit?). Rebinding.", socketPath_);
                closeListener(false);
                listenFd = bindListener();
                listenerRebinds_.fetch_add(1);
            }
            continue;
        }
        if (rc < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("poll(): ") + std::strerror(errno));
        }

        const int cfd = vh::platform::fd::accept(listenFd, nullptr, nullptr);
        if (cfd < 0) {
            if (shouldStop()) break;
            continue;
        }
        vh::platform::fd::suppressSigpipe(cfd);

        std::scoped_lock lock(clientsMutex_);
        const auto inFlight = static_cast<std::size_t>(
            std::ranges::count_if(clients_, [](const ClientSlot& c) { return !c.done; }));
        if (inFlight >= kMaxConcurrentClients) {
            setCliSocketTimeout(cfd, SO_SNDTIMEO, std::chrono::seconds(1));
            sendCliError(cfd, 75, "vaulthalla CLI server is busy (" + std::to_string(inFlight) +
                                " commands in flight); try again shortly");
            ::close(cfd);
            continue;
        }

        auto& slot = clients_.emplace_back();
        slot.fd = cfd;
        slot.thread = std::thread([this, &slot, cfd] {
            handleClient(cfd);
            std::scoped_lock done(clientsMutex_);
            ::shutdown(cfd, SHUT_RDWR);
            ::close(cfd);
            slot.fd = -1;
            slot.done = true;
        });
    }

    // Stop path: unblock and join every client so none outlives this service (or touches a reused fd).
    shutdownClients();
    reapFinishedClients(true);
}
