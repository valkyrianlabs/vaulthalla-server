#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <cstring>
#include <fmt/core.h>
#include <fmt/format.h>
#include <algorithm>
#include <ranges>
#include <cctype>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <cerrno>
#include <initializer_list>
#include <cstddef>
#include <chrono>
#include <mutex>

#include "cli_client.hpp"
#include "platform/Fd.hpp"
#include "protocols/shell/Transfer.hpp"
#include <paths.h>  // generated: VH_CLI_SOCKET_PATH, VH_LIFECYCLE_PATH, VH_HINT_*

static bool readn(const int fd, void* b, size_t n) {
    auto* p = static_cast<uint8_t*>(b);
    while (n) {
        const ssize_t r = ::read(fd, p, n);
        if (r <= 0) return false;
        p += r;
        n -= r;
    }
    return true;
}

static bool writen(const int fd, const void* b, size_t n) {
    const auto* p = static_cast<const uint8_t*>(b);
    while (n) {
        const ssize_t w = ::send(fd, p, n, MSG_NOSIGNAL);
        if (w <= 0) return false;
        p += w;
        n -= w;
    }
    return true;
}

static bool send_json_frame(const int fd, const nlohmann::json& j) {
    const auto s = j.dump();
    uint32_t n = htonl(static_cast<uint32_t>(s.size()));
    return writen(fd, &n, 4) && writen(fd, s.data(), s.size());
}

// Any reply frame (a command's whole output); during a file transfer the much smaller transfer limit applies.
static constexpr uint32_t kMaxReplyFrameBytes = 64u << 20;

// The length is checked before anything is allocated for the body.
static bool recv_json_frame(const int fd, nlohmann::json& out, const uint32_t maxBytes = kMaxReplyFrameBytes) {
    uint32_t len_be = 0;
    if (!readn(fd, &len_be, 4)) return false;
    const uint32_t len = ntohl(len_be);
    if (len > maxBytes) return false;
    std::string body(len, '\0');
    if (!readn(fd, body.data(), len)) return false;
    out = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    return !out.is_discarded();
}

static std::string ensureNewLine(const std::string& s) {
    if (s.empty() || s.back() != '\n') return s + '\n';
    return s;
}

static bool needs_quotes(std::string_view s) {
    if (s.empty()) return true;
    return std::ranges::any_of(s, [](const auto c) { return c == ' ' || c == '\t' || c == '"' || c == '\\'; });
}

static std::string dq_quote(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (const char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

// Heuristic: if tail has obvious "value" chars, treat "-Xtail" as glued value
static bool looks_glued_value(std::string_view tail) {
    if (tail.empty()) return false;
    return std::ranges::any_of(tail, [](const char c) {
        return c == '/' || c == '.' || c == ':' || c == '=';
    });
}

// Normalize argv tokens: split --key=value and -Xvalue (heuristic), keep -abc bundles as-is
static std::vector<std::string> normalize_tokens(const std::vector<std::string>& in) {
    std::vector<std::string> out;
    out.reserve(in.size() + 4);
    for (auto a : in) {

        if (a == "--") { out.emplace_back("--"); continue; }

        if (a.rfind("--", 0) == 0) {
            const auto eq = a.find('=');
            if (eq != std::string::npos) {
                out.emplace_back(a.substr(0, eq));          // --key
                out.emplace_back(a.substr(eq + 1));         // value
            } else {
                out.emplace_back(std::move(a));
            }
            continue;
        }

        if (a.size() > 2 && a[0] == '-' && a[1] != '-') {
            // Could be -abc bundle OR -Xvalue
            std::string tail = a.substr(2);
            if (!tail.empty() && looks_glued_value(tail)) {
                out.emplace_back(std::string("-") + a[1]);  // -X
                if (tail[0] == '=') tail.erase(tail.begin());
                out.emplace_back(std::move(tail));          // value
            } else {
                out.emplace_back(std::move(a));             // keep bundle as-is
            }
            continue;
        }

        out.emplace_back(std::move(a)); // plain arg
    }
    return out;
}

static bool is_root_command_token(const std::string& token) {
    return token == "vh" || token == "vaulthalla" || token == "vaulthalla-cli";
}

static std::vector<std::string> canonicalize_argv_norm(const int argc, char** argv) {
    std::vector<std::string> raw;
    raw.reserve(argc > 1 ? static_cast<size_t>(argc) - 1 : 1);
    for (int i = 1; i < argc; ++i) {
        if (argv[i]) raw.emplace_back(argv[i]);
    }

    while (!raw.empty() && is_root_command_token(raw.front()))
        raw.erase(raw.begin());

    if (raw.empty()) raw.emplace_back("help");
    return normalize_tokens(raw);
}

static std::string build_line_from_tokens(const std::vector<std::string>& tokens) {
    std::string line;
    for (const auto& t : tokens) {
        if (!line.empty()) line.push_back(' ');
        line += needs_quotes(t) ? dq_quote(t) : t;
    }
    return line;
}

static bool has_flag(const std::vector<std::string>& argv_norm, std::string_view flag) {
    return std::ranges::any_of(argv_norm, [&](const std::string& a){ return a == flag; });
}

static bool is_help_request(const std::vector<std::string>& argv_norm) {
    return has_flag(argv_norm, "--help") || has_flag(argv_norm, "--h") || has_flag(argv_norm, "-h") || has_flag(argv_norm, "?");
}

static bool is_interactive_allowed(const std::vector<std::string>& argv_norm) {
    // Hard opt-out via env or flags
    if (const char* env = std::getenv("VAULTHALLA_NONINTERACTIVE")) {
        if (std::string_view(env) == "1" || std::string_view(env) == "true") return false;
    }
    if (has_flag(argv_norm, "--non-interactive") || has_flag(argv_norm, "--yes"))
        return false;
    // Avoid interactivity if stdin isn't a TTY
    return ::isatty(STDIN_FILENO) == 1;
}

static std::string read_line_from_stdin() {
    std::string line;
    std::getline(std::cin, line);
    return line;
}

static std::string read_secret_line_from_stdin() {
    termios oldTerm{};
    const bool haveTerm = ::tcgetattr(STDIN_FILENO, &oldTerm) == 0;
    termios newTerm = oldTerm;

    if (haveTerm) {
        newTerm.c_lflag &= static_cast<tcflag_t>(~ECHO);
        (void)::tcsetattr(STDIN_FILENO, TCSAFLUSH, &newTerm);
    }

    std::string line;
    std::getline(std::cin, line);

    if (haveTerm) {
        (void)::tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldTerm);
        fmt::print("\n");
    }

    return line;
}

// Canonical lifecycle subcommand for an alias accepted by the usage book (core/usage/src/usages/{setup,teardown}.cpp),
// or "" when the command is not a lifecycle operation. The lifecycle utility only knows the canonical names.
static std::string lifecycle_subcommand(const std::vector<std::string>& argv_norm) {
    if (argv_norm.size() < 2) return {};
    const auto& cmd = argv_norm[0];
    const auto& sub = argv_norm[1];
    const auto in = [&sub](std::initializer_list<std::string_view> names) {
        return std::ranges::any_of(names, [&sub](const std::string_view n) { return sub == n; });
    };

    if (cmd == "setup") {
        if (in({"db", "database", "postgres"})) return "db";
        if (in({"remote-db", "remote_db", "remote", "rdb"})) return "remote-db";
        if (in({"nginx", "proxy"})) return "nginx";
        if (in({"caddy", "https"})) return "caddy";
    } else if (cmd == "teardown") {
        if (in({"db", "database", "postgres"})) return "db";
        if (in({"nginx", "proxy"})) return "nginx";
        if (in({"caddy", "https"})) return "caddy";
    }
    return {};
}

static bool is_lifecycle_command(const std::vector<std::string>& argv_norm) {
    return !lifecycle_subcommand(argv_norm).empty();
}

static int lifecycle_sudo_required(const std::vector<std::string>& argv_norm) {
    std::ostringstream out;
    out << "This lifecycle command must be run with elevated privileges.\n";
    out << "Re-run with sudo:\n";
    out << "  sudo vh";
    for (const auto& token : argv_norm)
        out << " " << (needs_quotes(token) ? dq_quote(token) : token);
    out << "\n";
    fmt::print(stderr, "{}", out.str());
    return 2;
}

static std::string lifecycle_binary_path() {
    if (const char* env = std::getenv("VAULTHALLA_LIFECYCLE_BIN"); env && *env)
        return env;
    return VH_LIFECYCLE_PATH;
}

// `vh setup|teardown caddy` is macOS's HTTPS front end (deploy/launchd/vaulthalla-caddy); Linux has nginx. Said before
// asking for sudo, so nobody elevates just to hear it.
static bool lifecycle_unsupported_here(const std::vector<std::string>& argv_norm) {
    if (lifecycle_subcommand(argv_norm) != "caddy" || !std::string_view(VH_CADDY_TOOL_PATH).empty()) return false;
    fmt::print(stderr, "vh {} caddy is for macOS. On Linux, HTTPS goes through nginx: vh {} nginx --help\n",
               argv_norm[0], argv_norm[0]);
    return true;
}

static int run_lifecycle_command(const std::vector<std::string>& argv_norm) {
    if (lifecycle_unsupported_here(argv_norm)) return 2;
    const bool caddy = lifecycle_subcommand(argv_norm) == "caddy";
    const auto lifecycleBin = caddy ? std::string(VH_CADDY_TOOL_PATH) : lifecycle_binary_path();
    if (::access(lifecycleBin.c_str(), F_OK) != 0) {
        fmt::print(
            stderr,
            "Lifecycle utility not found: {}\n"
            "Install Vaulthalla lifecycle payload or set VAULTHALLA_LIFECYCLE_BIN to the utility path.\n",
            lifecycleBin
        );
        return 127;
    }
    if (::access(lifecycleBin.c_str(), X_OK) != 0) {
        fmt::print(
            stderr,
            "Lifecycle utility is not executable: {}\n"
            "Expected an executable script/binary. Reinstall Vaulthalla or fix file permissions.\n",
            lifecycleBin
        );
        return 126;
    }

    std::vector<std::string> args;
    args.reserve(argv_norm.size() + 1);
    args.push_back(lifecycleBin);
    args.insert(args.end(), argv_norm.begin(), argv_norm.end());
    args[2] = lifecycle_subcommand(argv_norm); // alias -> canonical ("setup database" -> "setup db")

    std::vector<char*> execArgv;
    execArgv.reserve(args.size() + 1);
    for (auto& arg : args) execArgv.push_back(arg.data());
    execArgv.push_back(nullptr);

    ::execv(execArgv[0], execArgv.data());
    const auto err = errno;
    fmt::print(
        stderr,
        "Failed to execute lifecycle utility '{}': {}\n",
        lifecycleBin,
        std::strerror(err)
    );
    return err == ENOENT ? 127 : 126;
}

static bool should_append_status_systemd_summary(const std::vector<std::string>& argv_norm) {
    if (argv_norm.empty() || argv_norm[0] != "status") return false;
    if (::geteuid() != 0) return false;
    return !is_help_request(argv_norm);
}

static std::string shell_quote(const std::string& s) {
    std::string out{"'"};
    for (const char c : s) {
        if (c == '\'') out += "'\"'\"'";
        else out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

static std::string trim_copy(std::string s) {
    const auto ws = [](const unsigned char c) { return std::isspace(c) != 0; };
    s.erase(s.begin(), std::ranges::find_if(s.begin(), s.end(), [&](const unsigned char c) { return !ws(c); }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [&](const unsigned char c) { return !ws(c); }).base(), s.end());
    return s;
}

struct CaptureResult {
    int code = 0;
    std::string output;
};

static CaptureResult run_capture(const std::string& command) {
    const auto wrapped = command + " 2>&1";
    std::array<char, 4096> buf{};
    std::string output;

    FILE* pipe = ::popen(wrapped.c_str(), "r");
    if (!pipe) return {.code = 1, .output = "failed to execute command"};

    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr)
        output += buf.data();

    const int status = ::pclose(pipe);
    int code = status;
    if (WIFEXITED(status)) code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) code = 128 + WTERMSIG(status);

    return {.code = code, .output = output};
}

static bool command_exists(const std::string& command) {
    return run_capture("command -v " + shell_quote(command) + " >/dev/null").code == 0;
}

static std::string systemd_unit_state(const std::string& unit) {
    const auto state = run_capture("systemctl is-active " + shell_quote(unit));
    const auto trimmed = trim_copy(state.output);
    if (state.code == 0 && !trimmed.empty()) return trimmed;
    if (!trimmed.empty()) return trimmed;
    return "unknown (exit " + std::to_string(state.code) + ")";
}

static void append_status_systemd_summary_if_needed(const std::vector<std::string>& argv_norm) {
    // Shown for healthy and unhealthy results alike: the unit states matter most when status is not healthy.
    if (!should_append_status_systemd_summary(argv_norm)) return;
    if (!command_exists("systemctl")) return;

    std::ostringstream out;
    out << "systemd summary (supplemental):\n";
    constexpr std::array<std::string_view, 2> units{
        "vaulthalla.service",
        "vaulthalla-web.service"
    };
    for (const auto unit : units)
        out << "  " << unit << ": " << systemd_unit_state(std::string(unit)) << "\n";

    fmt::print("{}", ensureNewLine(out.str()));
}

/* ----------------------------------------------------------------- */

// Distinct exit codes (sysexits.h values) so scripts and the maintainer scripts can tell "the daemon is not
// there" apart from "the command failed".
namespace exit_code {
constexpr int kProtocol = 76;     // EX_PROTOCOL: malformed/incomplete reply
constexpr int kUnavailable = 69;  // EX_UNAVAILABLE: no daemon listening
constexpr int kTempFail = 75;     // EX_TEMPFAIL: daemon not responding / busy
constexpr int kNoPerm = 77;       // EX_NOPERM: not allowed to use the control socket
constexpr int kDeadline = 124;    // vh mcp: no result before the call's deadline (as timeout(1))
constexpr int kCancelled = 130;   // vh mcp: the agent cancelled the call
}

static constexpr const char* kDefaultSocketPath = VH_CLI_SOCKET_PATH;

// VAULTHALLA_CLI_SOCKET points `vh` at another daemon's socket (a private test instance). The daemon still decides
// who the caller is from the peer credentials, so this grants nothing.
static const char* socket_path() {
    static const char* path = [] {
        const char* env = std::getenv("VAULTHALLA_CLI_SOCKET");
        return env && *env ? env : kDefaultSocketPath;
    }();
    return path;
}

static int connect_timeout_seconds() {
    if (const char* env = std::getenv("VAULTHALLA_CLI_TIMEOUT"); env && *env) {
        char* end = nullptr;
        const long v = std::strtol(env, &end, 10);
        if (end && *end == '\0' && v > 0 && v <= 3600) return static_cast<int>(v);
    }
    return 10;
}

static std::string not_responding_message(const int seconds) {
    const std::string running = std::string("Is ") + VH_HINT_SERVICE_NAME + " running?";
    return fmt::format("vh: the vaulthalla daemon is not responding at {} (no reply within {}s).\n"
                       "    {}  {}\n"
                       "    {:<{}}{}\n"
                       "    (Set VAULTHALLA_CLI_TIMEOUT=<seconds> to wait longer.)\n",
                       socket_path(), seconds, running, VH_HINT_SERVICE_STATUS, "Recent daemon log:",
                       running.size() + 3, VH_HINT_SERVICE_LOG);
}

static int report_not_responding(const int seconds) {
    fmt::print(stderr, "{}", not_responding_message(seconds));
    return exit_code::kTempFail;
}

// Why connect() failed, as an exit code and the message to show.
static vh::cli::Reply connect_failure(const int err, const int seconds) {
    switch (err) {
        case EACCES:
        case EPERM:
            return {exit_code::kNoPerm, {},
                    fmt::format("vh: permission denied opening {}.\n"
                                "    The control socket is restricted to the 'vaulthalla' group. Either run with sudo, or add\n"
                                "    yourself to the group and start a new login session:\n"
                                "      {}\n",
                                socket_path(), VH_HINT_CLI_ENROLL)};
        case ENOENT:
        case ECONNREFUSED:
            return {exit_code::kUnavailable, {},
                    fmt::format("vh: the vaulthalla daemon is not running (nothing is listening at {}).\n"
                                "    Check the service:  {}\n"
                                "    Recent daemon log:  {}\n",
                                socket_path(), VH_HINT_SERVICE_STATUS, VH_HINT_SERVICE_LOG)};
        case EAGAIN:
        case ETIMEDOUT:
        case EINPROGRESS:
            return {exit_code::kTempFail, {}, not_responding_message(seconds)};
        default:
            return {exit_code::kUnavailable, {},
                    fmt::format("vh: cannot connect to {}: {}\n", socket_path(), std::strerror(err))};
    }
}

static int report_connect_error(const int err, const int seconds) {
    const auto failure = connect_failure(err, seconds);
    fmt::print(stderr, "{}", failure.err);
    return failure.exit_code;
}

// Connects to the control socket: the fd, or -1 with `err` (an errno, or 0 with `message` set for a local problem).
static int open_control_socket(const int timeoutSeconds, int& err, std::string& message) {
    err = 0;
    sockaddr_un addr{};
    const std::string_view path = socket_path();
    if (path.size() >= sizeof(addr.sun_path)) {
        message = fmt::format("vh: control socket path is too long for a unix socket: {}\n", path);
        return -1;
    }

    const int s = vh::platform::fd::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        message = fmt::format("vh: socket: {}\n", std::strerror(errno));
        return -1;
    }
    vh::platform::fd::suppressSigpipe(s);

    // Bounds connect() when the listener's backlog is full (a wedged daemon that stopped accepting).
    timeval tv{.tv_sec = timeoutSeconds, .tv_usec = 0};
    (void)::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.data(), path.size());
    // offsetof, not sizeof(sa_family_t): BSD's sockaddr_un starts with sun_len (on Linux the two are equal).
    const auto addrLen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1);
    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), addrLen) != 0) {
        err = errno;
        ::close(s);
        return -1;
    }
    return s;
}

// Waits up to `seconds` for the socket to become readable. False on timeout.
static bool wait_readable(const int fd, const int seconds) {
    pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
    for (;;) {
        const int rc = ::poll(&pfd, 1, seconds * 1000);
        if (rc < 0 && errno == EINTR) continue;
        return rc > 0;
    }
}

static void print_text_field(const nlohmann::json& frame, const char* key, FILE* stream) {
    if (!frame.contains(key) || frame[key].is_null()) return;
    const auto& v = frame[key];
    fmt::print(stream, "{}", ensureNewLine(v.is_string() ? v.get<std::string>() : v.dump()));
}

// Final reply → process exit code. A reply without exit_code is only a success if it explicitly says ok.
static int final_exit_code(const nlohmann::json& frame) {
    if (frame.contains("exit_code") && frame["exit_code"].is_number_integer())
        return frame["exit_code"].get<int>();
    if (frame.contains("ok") && frame["ok"].is_boolean())
        return frame["ok"].get<bool>() ? 0 : 1;
    fmt::print(stderr, "vh: the daemon's reply had no exit status; treating it as a failure\n");
    return exit_code::kProtocol;
}

namespace tx = vh::protocols::shell::transfer;

// `vh fs get`: where the bytes go. A named file is written to a temporary sibling (0600) and renamed over the target
// only after the daemon's result says every byte arrived and authenticated; on anything else the temporary file is
// removed. Stdout gets the bytes as they come, binary-safe (write(2), never stdio), and the exit status decides.
struct GetSink {
    int fd = STDOUT_FILENO;
    std::string target, temp;
    bool committed = false;

    GetSink() = default;
    GetSink(const GetSink&) = delete;
    GetSink& operator=(const GetSink&) = delete;
    ~GetSink() {
        if (temp.empty() || committed) return;
        ::close(fd);
        ::unlink(temp.c_str());
    }

    bool open(const std::string& path, std::string& error) {
        if (path.empty()) return true;
        struct stat st{};
        if (path.back() == '/' || (::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode))) {
            error = path + " is a directory";
            return false;
        }
        const auto slash = path.rfind('/');
        const std::string dir = slash == std::string::npos ? "." : slash == 0 ? "/" : path.substr(0, slash);
        const std::string base = slash == std::string::npos ? path : path.substr(slash + 1);
        std::string tmpl = dir + "/." + base + ".vh-XXXXXX";
        const int tfd = ::mkstemp(tmpl.data());
        if (tfd < 0) {
            error = "cannot create a file next to " + path + ": " + std::strerror(errno);
            return false;
        }
        fd = tfd;
        target = path;
        temp = tmpl;
        return true;
    }

    bool write(const uint8_t* p, size_t n) const {
        while (n) {
            const ssize_t w = ::write(fd, p, n);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) return false;
            p += w;
            n -= static_cast<size_t>(w);
        }
        return true;
    }

    bool commit(std::string& error) {
        if (temp.empty()) return true;
        const mode_t mask = ::umask(0);
        ::umask(mask);
        if (::fchmod(fd, 0666 & ~mask) != 0 || ::fsync(fd) != 0) {
            error = std::string("cannot finish ") + target + ": " + std::strerror(errno);
            return false;
        }
        ::close(fd);
        fd = -1;
        if (::rename(temp.c_str(), target.c_str()) != 0) {
            error = "cannot replace " + target + ": " + std::strerror(errno);
            ::unlink(temp.c_str());
            committed = true;  // nothing left to clean up
            return false;
        }
        committed = true;
        return true;
    }
};

// `vh fs put`: what is read. A regular file is sent as it is (its size is announced first, and a file that changes
// size while being sent is abandoned); standard input is spooled to an unlinked temporary file first so its size is
// known before anything is sent.
struct PutSource {
    int fd = -1;
    uint64_t size = 0;

    PutSource() = default;
    PutSource(const PutSource&) = delete;
    PutSource& operator=(const PutSource&) = delete;
    ~PutSource() { if (fd >= 0) ::close(fd); }

    bool open(const std::string& path, std::string& error) {
        if (path == "-") return spoolStdin(error);
        fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            error = "cannot read " + path + ": " + std::strerror(errno);
            return false;
        }
        struct stat st{};
        if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            error = path + " is not a regular file";
            return false;
        }
        size = static_cast<uint64_t>(st.st_size);
        return true;
    }

    bool spoolStdin(std::string& error) {
        const char* tmpdir = std::getenv("TMPDIR");
        std::string tmpl = std::string(tmpdir && *tmpdir ? tmpdir : "/tmp") + "/vh-put-XXXXXX";
        fd = ::mkstemp(tmpl.data());
        if (fd < 0) {
            error = std::string("cannot spool standard input: ") + std::strerror(errno);
            return false;
        }
        ::unlink(tmpl.c_str());
        std::vector<uint8_t> buf(tx::kChunkBytes);
        for (;;) {
            const ssize_t r = ::read(STDIN_FILENO, buf.data(), buf.size());
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) { error = std::string("reading standard input failed: ") + std::strerror(errno); return false; }
            if (r == 0) break;
            if (!writen_file(buf.data(), static_cast<size_t>(r))) {
                error = std::string("spooling standard input failed: ") + std::strerror(errno);
                return false;
            }
            size += static_cast<uint64_t>(r);
        }
        return true;
    }

private:
    bool writen_file(const uint8_t* p, size_t n) const {
        while (n) {
            const ssize_t w = ::write(fd, p, n);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) return false;
            p += w;
            n -= static_cast<size_t>(w);
        }
        return true;
    }
};

static bool daemon_has_spoken(const int s) {
    pollfd pfd{.fd = s, .events = POLLIN, .revents = 0};
    return ::poll(&pfd, 1, 0) > 0;
}

static int connection_lost() {
    fmt::print(stderr, "vh: the connection to the vaulthalla daemon closed before the transfer finished\n");
    return exit_code::kTempFail;
}

static int run_get(const int s, GetSink& sink, const int timeoutSeconds) {
    std::optional<uint64_t> expected;
    uint64_t received = 0, seq = 0;
    bool first = true;
    for (;;) {
        if (first && !wait_readable(s, timeoutSeconds)) return report_not_responding(timeoutSeconds);
        first = false;
        nlohmann::json frame;
        if (!recv_json_frame(s, frame, expected ? tx::kMaxTransferFrameBytes : kMaxReplyFrameBytes))
            return connection_lost();
        const auto type = frame.value("type", std::string{});
        if (type == "hello") continue;
        if (type == "transfer") {
            if (expected || !frame.contains("size") || !frame["size"].is_number_unsigned()) break;
            expected = frame["size"].get<uint64_t>();
            continue;
        }
        if (type == "data") {
            if (!expected || !frame.contains("seq") || !frame["seq"].is_number_unsigned() ||
                frame["seq"].get<uint64_t>() != seq || !frame.contains("b64") || !frame["b64"].is_string())
                break;
            const auto bytes = tx::decodeChunk(frame["b64"].get_ref<const std::string&>());
            if (!bytes || bytes->empty() || bytes->size() > *expected - received) break;
            if (!sink.write(bytes->data(), bytes->size())) {
                fmt::print(stderr, "vh: writing {} failed: {}\n", sink.target.empty() ? "stdout" : sink.target,
                           std::strerror(errno));
                return tx::exitcode::kIoErr;
            }
            received += bytes->size();
            ++seq;
            continue;
        }
        if (type == "output") {
            fmt::print(stderr, "{}", ensureNewLine(frame.value("text", std::string{})));
            continue;
        }
        if (type == "result") {
            print_text_field(frame, "stderr", stderr);
            const int ec = final_exit_code(frame);
            if (ec != 0) return ec;
            if (!expected || received != *expected) {
                fmt::print(stderr, "vh: received {} of {} bytes; nothing was kept\n", received, expected.value_or(0));
                return tx::exitcode::kDataErr;
            }
            std::string error;
            if (!sink.commit(error)) {
                fmt::print(stderr, "vh: {}\n", error);
                return tx::exitcode::kCantCreat;
            }
            return 0;
        }
        break;
    }
    fmt::print(stderr, "vh: the daemon sent a malformed transfer; nothing was kept\n");
    return tx::exitcode::kDataErr;
}

static int run_put(const int s, const PutSource& source, const int timeoutSeconds) {
    bool first = true;
    for (;;) {
        if (first && !wait_readable(s, timeoutSeconds)) return report_not_responding(timeoutSeconds);
        first = false;
        nlohmann::json frame;
        if (!recv_json_frame(s, frame)) return connection_lost();
        const auto type = frame.value("type", std::string{});
        if (type == "hello") continue;
        if (type == "output") {
            fmt::print("{}", ensureNewLine(frame.value("text", std::string{})));
            continue;
        }
        if (type == "result") {
            print_text_field(frame, "stdout", stdout);
            print_text_field(frame, "stderr", stderr);
            return final_exit_code(frame);
        }
        if (type != "transfer-ready") {
            fmt::print(stderr, "vh: unexpected reply from the daemon during the upload\n");
            return tx::exitcode::kDataErr;
        }

        // Stream, but stop as soon as the daemon says anything (a refusal, a revocation): its result is read next.
        std::vector<uint8_t> buf(tx::kChunkBytes);
        uint64_t offset = 0, seq = 0;
        bool sent = true;
        while (offset < source.size && !daemon_has_spoken(s)) {
            const auto want = static_cast<size_t>(std::min<uint64_t>(buf.size(), source.size - offset));
            ssize_t n = ::pread(source.fd, buf.data(), want, static_cast<off_t>(offset));
            while (n < 0 && errno == EINTR) n = ::pread(source.fd, buf.data(), want, static_cast<off_t>(offset));
            if (n <= 0) {
                (void)send_json_frame(s, {{"type", "transfer-abort"}});
                fmt::print(stderr, "vh: the local file changed or became unreadable while it was being sent; "
                                   "nothing was stored\n");
                return tx::exitcode::kIoErr;
            }
            if (!send_json_frame(s, {{"type", "data"}, {"seq", seq},
                                     {"b64", tx::encode(std::span<const uint8_t>(buf.data(), static_cast<size_t>(n)))}})) {
                sent = false;
                break;
            }
            offset += static_cast<uint64_t>(n);
            ++seq;
        }
        if (sent && offset == source.size)
            (void)send_json_frame(s, {{"type", "transfer-end"}, {"bytes", source.size}});
        // Whatever happened, the daemon's verdict follows (or the connection is gone).
    }
}

static std::string frame_text(const nlohmann::json& frame, const char* key) {
    if (!frame.contains(key) || frame[key].is_null()) return {};
    const auto& v = frame[key];
    return v.is_string() ? v.get<std::string>() : v.dump();
}

namespace vh::cli {

// Cancels the call: its socket is shut down, so a read in progress returns at once (the fd is closed by the owner).
void CallControl::cancel() {
    std::scoped_lock lock(mutex);
    cancelled = true;
    if (fd >= 0) ::shutdown(fd, SHUT_RDWR);
}

namespace {

// The socket of a captured call, registered with its CallControl while open.
struct CapturedSocket {
    int fd = -1;
    CallControl* control = nullptr;

    ~CapturedSocket() {
        if (control) {
            std::scoped_lock lock(control->mutex);
            control->fd = -1;
        }
        if (fd >= 0) ::close(fd);
    }
};

bool cancelled(const CallControl* control) {
    if (!control) return false;
    std::scoped_lock lock(control->mutex);
    return control->cancelled;
}

}

// One non-interactive command over the control socket, everything it prints captured (vh mcp's tool calls). Same
// request as a plain `vh` run with stdin not a terminal, so the daemon authorizes it by peer UID exactly the same way.
// `control` lets another thread cancel it; `deadlineSeconds` (0: none) bounds the whole call.
Reply runCaptured(const std::vector<std::string>& argv, const std::string& line, CallControl* control,
                  const int deadlineSeconds) {
    using clock = std::chrono::steady_clock;
    const auto deadline = deadlineSeconds > 0 ? clock::now() + std::chrono::seconds(deadlineSeconds) : clock::time_point::max();
    const auto cancelledReply = [] { return Reply{.exit_code = exit_code::kCancelled, .out = {},
                                                  .err = "vh: the call was cancelled; the daemon may still finish the "
                                                         "command, so check its state before retrying\n"}; };
    const int timeoutSeconds = connect_timeout_seconds();
    int err = 0;
    std::string message;
    CapturedSocket sock{.fd = open_control_socket(timeoutSeconds, err, message), .control = nullptr};
    if (sock.fd < 0) return err == 0 ? Reply{1, {}, message} : connect_failure(err, timeoutSeconds);
    if (control) {
        std::scoped_lock lock(control->mutex);
        if (control->cancelled) return cancelledReply();
        control->fd = sock.fd;
        sock.control = control;
    }
    const int s = sock.fd;

    nlohmann::json request{{"cmd", argv.empty() ? std::string("help") : argv.front()},
                           {"args", argv.size() > 1 ? std::vector<std::string>(argv.begin() + 1, argv.end())
                                                    : std::vector<std::string>{}},
                           {"argv", argv},
                           {"line", line},
                           {"interactive", false}};
    Reply reply;
    if (!send_json_frame(s, request)) {
        if (cancelled(control)) return cancelledReply();
        return {exit_code::kTempFail, {}, "vh: the vaulthalla daemon closed the connection before the command was sent\n"};
    }
    bool first = true;
    for (;;) {
        if (first && !wait_readable(s, timeoutSeconds)) {
            if (cancelled(control)) return cancelledReply();
            return {exit_code::kTempFail, {}, not_responding_message(timeoutSeconds)};
        }
        first = false;
        // The deadline: wait for the next frame no longer than what is left, and bound a frame's own read too.
        if (deadline != clock::time_point::max()) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock::now()).count();
            pollfd pfd{.fd = s, .events = POLLIN, .revents = 0};
            int rc = 0;
            do rc = left > 0 ? ::poll(&pfd, 1, static_cast<int>(std::min<long long>(left, 1LL << 30))) : 0;
            while (rc < 0 && errno == EINTR);
            if (rc == 0) {
                reply.exit_code = exit_code::kDeadline;
                reply.err += fmt::format("vh: no result within {}s (VAULTHALLA_MCP_TIMEOUT); the call was abandoned. "
                                         "The daemon may still finish the command: check its state before retrying.\n",
                                         deadlineSeconds);
                return reply;
            }
            timeval tv{.tv_sec = std::max<long long>(1, left / 1000), .tv_usec = 0};
            (void)::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        }
        nlohmann::json frame;
        if (!recv_json_frame(s, frame)) {
            if (cancelled(control)) return cancelledReply();
            reply.exit_code = exit_code::kTempFail;
            reply.err += "vh: connection to the vaulthalla daemon closed before the command finished\n";
            return reply;
        }
        const auto type = frame.value("type", std::string{});
        if (type == "hello") continue;
        if (type == "output") {
            auto& sink = frame.value("stream", std::string{"stdout"}) == "stderr" ? reply.err : reply.out;
            sink += ensureNewLine(frame.value("text", std::string{}));
            continue;
        }
        if (type == "prompt") {
            // Never answered: the request is not interactive, so a prompt here is a daemon bug, not a question.
            reply.exit_code = 1;
            reply.err += "vh: the command asked an interactive question, which agents can't answer: " +
                         frame.value("text", std::string{}) + "\n";
            return reply;
        }
        if (type == "result" || !frame.contains("type")) {
            reply.out += frame_text(frame, "stdout");
            reply.err += frame_text(frame, "stderr");
            reply.exit_code = final_exit_code(frame);
            // Optional (newer daemons): the refusal was for want of a confirmation, and which flags give it.
            if (const auto c = frame.find("confirmation"); c != frame.end() && c->is_object()) {
                reply.confirmation = Confirmation{};
                if (const auto code = c->find("code"); code != c->end() && code->is_string())
                    reply.confirmation->code = code->get<std::string>();
                if (const auto flags = c->find("flags"); flags != c->end() && flags->is_array())
                    for (const auto& f : *flags)
                        if (f.is_string()) reply.confirmation->flags.push_back(f.get<std::string>());
            }
            return reply;
        }
    }
}

}

int main(const int argc, char** argv) {
    std::vector<std::string> argv_norm = canonicalize_argv_norm(argc, argv);

    // Client-side commands: the MCP server (it connects per tool call) and agent skill installation (no daemon).
    if (argv_norm.front() == "mcp") return vh::cli::runMcp(argv_norm);
    if (argv_norm.front() == "skill" || argv_norm.front() == "skills") return vh::cli::runSkill(argv_norm);

    // Legacy: vaulthalla-cli.service used to run `vaulthalla-cli --systemd` behind vaulthalla-cli.socket. That mode
    // never existed; the unit connected to its own socket and hung forever. The daemon owns the socket now.
    if (argv_norm.size() == 1 && argv_norm.front() == "--systemd") {
        fmt::print(stderr,
                   "vaulthalla-cli --systemd is obsolete: vaulthalla.service owns {} directly.\n"
                   "Disable the stale units:  sudo systemctl disable --now vaulthalla-cli.socket vaulthalla-cli.service\n",
                   socket_path());
        return 0;
    }

    // Help for a lifecycle command comes from the usage book like any other command, so it needs no sudo. Only when
    // the daemon is unreachable (e.g. before `setup db`) does root fall back to the lifecycle utility's own --help.
    const bool lifecycleHelp = is_lifecycle_command(argv_norm) && is_help_request(argv_norm);
    if (is_lifecycle_command(argv_norm) && !lifecycleHelp) {
        if (lifecycle_unsupported_here(argv_norm)) return 2;
        if (::geteuid() != 0)
            return lifecycle_sudo_required(argv_norm);
        return run_lifecycle_command(argv_norm);
    }

    // Quoted line for legacy servers
    std::string line = build_line_from_tokens(argv_norm);
    const int timeoutSeconds = connect_timeout_seconds();

    // `vh fs get|put`: the local side is prepared before connecting, so a missing input or an unwritable output never
    // reaches the daemon. The daemon gets only the vault path; the local file stays in this process.
    const auto plan = is_help_request(argv_norm) ? tx::LocalPlan{} : tx::planLocal(argv_norm);
    if (!plan.error.empty()) {
        fmt::print(stderr, "vh: {}\n", plan.error);
        return tx::exitcode::kUsage;
    }
    GetSink sink;
    PutSource source;
    if (plan.kind == tx::LocalPlan::Kind::Get) {
        if (plan.local.empty() && !plan.explicitStdout && ::isatty(STDOUT_FILENO)) {
            fmt::print(stderr, "vh: refusing to write file contents to a terminal; use -o <file>, or -o - to insist\n");
            return tx::exitcode::kUsage;
        }
        std::string error;
        if (!sink.open(plan.local, error)) {
            fmt::print(stderr, "vh: {}\n", error);
            return tx::exitcode::kCantCreat;
        }
    } else if (plan.kind == tx::LocalPlan::Kind::Put) {
        std::string error;
        if (!source.open(plan.local, error)) {
            fmt::print(stderr, "vh: {}\n", error);
            return tx::exitcode::kNoInput;
        }
    }

    int connectErr = 0;
    std::string connectMessage;
    const int s = open_control_socket(timeoutSeconds, connectErr, connectMessage);
    if (s < 0) {
        if (connectErr == 0) {
            fmt::print(stderr, "{}", connectMessage);
            return 1;
        }
        if (lifecycleHelp && ::geteuid() == 0) return run_lifecycle_command(argv_norm);
        return report_connect_error(connectErr, timeoutSeconds);
    }

    // Prepare request
    const bool interactive = is_interactive_allowed(argv_norm);

    nlohmann::json j;
    j["cmd"]  = argv_norm.front();
    if (argv_norm.size() > 1) {
        std::vector<std::string> args(argv_norm.begin() + 1, argv_norm.end());
        j["args"] = args;
    } else {
        j["args"] = nlohmann::json::array();
    }
    j["argv"] = argv_norm;
    j["line"] = line;
    j["interactive"] = interactive;
    if (plan.kind != tx::LocalPlan::Kind::None) {
        j["interactive"] = false;
        j["transfer"] = {{"v", tx::kVersion}};
        if (plan.kind == tx::LocalPlan::Kind::Put) j["transfer"]["put_size"] = source.size;
    }

    // Send request
    (void)send_json_frame(s, j);

    if (plan.kind == tx::LocalPlan::Kind::Get) {
        const int rc = run_get(s, sink, timeoutSeconds);
        ::close(s);
        return rc;
    }
    if (plan.kind == tx::LocalPlan::Kind::Put) {
        const int rc = run_put(s, source, timeoutSeconds);
        ::close(s);
        return rc;
    }

    // A connect() to a unix socket succeeds as soon as the connection is queued, even when nobody will ever
    // accept it (daemon crash-looping, a stale listener left by another unit). The daemon answers every accepted
    // connection right away (a "hello" frame, or an error), so silence here means nobody is serving the socket.
    // After the first frame there is no client-side limit: commands and prompts take as long as they take.
    bool first = true;

    // Frame loop: handle both streaming (type-based) and legacy single-reply
    for (;;) {
        if (first && !wait_readable(s, timeoutSeconds)) {
            ::close(s);
            return report_not_responding(timeoutSeconds);
        }
        first = false;

        nlohmann::json frame;
        if (!recv_json_frame(s, frame)) {
            // connection closed unexpectedly
            ::close(s);
            fmt::print(stderr, "vh: connection to the vaulthalla daemon closed before the command finished "
                               "(daemon restarted or crashed? {})\n", VH_HINT_SERVICE_LOG);
            return exit_code::kTempFail;
        }

        // Legacy reply: has no "type", but includes exit_code/ok/stdout/stderr
        if (!frame.contains("type")) {
            print_text_field(frame, "stdout", stdout);
            print_text_field(frame, "stderr", stderr);
            const int ec = final_exit_code(frame);
            append_status_systemd_summary_if_needed(argv_norm);
            ::close(s);
            return ec;
        }

        const auto type = frame.value("type", std::string{});

        if (type == "hello") continue; // daemon accepted the connection

        if (type == "output") {
            // {type:"output", text:"...", stream?: "stdout"|"stderr"}
            const auto text = frame.value("text", std::string{});
            const auto stream = frame.value("stream", std::string{"stdout"});
            if (stream == "stderr")
                fmt::print(stderr, "{}", ensureNewLine(text));
            else
                fmt::print("{}", ensureNewLine(text));
            continue;
        }

        if (type == "prompt") {
            // {type:"prompt", style:"confirm"|"input"|"secret", id:"...", text:"...", default:"yes"|"no"|""}
            const auto id     = frame.value("id", std::string{});
            const auto style  = frame.value("style", std::string{"input"});
            const auto text   = frame.value("text", std::string{});
            const auto defval = frame.value("default", std::string{});

            // If we somehow got a prompt in non-interactive mode, bail cleanly
            if (!interactive) {
                fmt::print(stderr, "{}", "Interactive input requested but disabled. Re-run with --yes/flags.\n");
                ::close(s);
                return 1;
            }

            // Print the prompt exactly as sent
            if (!text.empty()) {
                // Don't double-append newline if server already included it
                if (text.back() == '\n')
                    fmt::print("{}", text);
                else
                    fmt::print("{} ", text);
                std::fflush(stdout);
            }

            // Read one line from user
            std::string value = style == "secret"
                ? read_secret_line_from_stdin()
                : read_line_from_stdin();
            if (value.empty()) value = defval; // honor default on empty submit

            // Send response frame
            nlohmann::json reply{
                {"type","input"},
                {"id", id},
                {"value", value}
            };
            (void)send_json_frame(s, reply);
            continue;
        }

        if (type == "result") {
            // {type:"result", ok:bool, exit_code:int, stdout?:..., stderr?:..., data?:...}
            print_text_field(frame, "stdout", stdout);
            print_text_field(frame, "stderr", stderr);
            const int ec = final_exit_code(frame);
            append_status_systemd_summary_if_needed(argv_norm);
            ::close(s);
            return ec;
        }

        // Unknown frame type; print to stderr and continue
        fmt::print(stderr, "Unknown frame type: {}\n", type);
    }
}
