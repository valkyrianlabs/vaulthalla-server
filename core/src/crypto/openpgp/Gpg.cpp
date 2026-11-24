#include "crypto/openpgp/Gpg.hpp"

#include "fs/ops/file.hpp"
#include "platform/Fd.hpp"

#include <fmt/format.h>
#include <paths.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <span>
#include <sstream>

namespace vh::crypto::openpgp {

namespace {

constexpr std::size_t kMaxCapture = 4 * 1024 * 1024;

std::mutex& executableMutex() {
    static std::mutex m;
    return m;
}

std::optional<std::filesystem::path>& executableOverride() {
    static std::optional<std::filesystem::path> p;
    return p;
}

// Owns one descriptor.
struct Fd {
    int fd{-1};
    Fd() = default;
    explicit Fd(const int f) : fd(f) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() { reset(); }
    void reset() {
        if (fd >= 0) ::close(fd);
        fd = -1;
    }
};

struct SocketPair {
    Fd parent, child;
    SocketPair() {
        int fds[2];
        if (platform::fd::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
            throw std::runtime_error(std::string("socketpair failed: ") + std::strerror(errno));
        parent.fd = fds[0];
        child.fd = fds[1];
        platform::fd::suppressSigpipe(parent.fd);
    }
};

void setNonBlocking(const int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) (void)::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

std::vector<std::string> split(const std::string& line, const char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (const char c : line) {
        if (c == sep) {
            out.push_back(std::move(cur));
            cur.clear();
        } else {
            cur += c;
        }
    }
    out.push_back(std::move(cur));
    return out;
}

// gpg's colon listings escape ':' and other bytes as \xNN.
std::string unescapeColon(const std::string& s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 3 < s.size() && s[i + 1] == 'x' &&
            std::isxdigit(static_cast<unsigned char>(s[i + 2])) && std::isxdigit(static_cast<unsigned char>(s[i + 3]))) {
            out += static_cast<char>(std::stoi(s.substr(i + 2, 2), nullptr, 16));
            i += 3;
        } else {
            out += s[i];
        }
    }
    return out;
}

std::optional<std::time_t> epochField(const std::vector<std::string>& f, const std::size_t i) {
    if (i >= f.size() || f[i].empty()) return std::nullopt;
    try {
        return static_cast<std::time_t>(std::stoll(f[i]));
    } catch (const std::exception&) {
        return std::nullopt;   // an ISO date (gpg only prints those with --fixed-list-mode off)
    }
}

std::string field(const std::vector<std::string>& f, const std::size_t i) { return i < f.size() ? f[i] : std::string{}; }

std::string algorithmName(const std::vector<std::string>& f) {
    if (const auto curve = field(f, 16); !curve.empty()) return curve;
    const auto algo = field(f, 3);
    const auto bits = field(f, 2);
    if (algo == "1" || algo == "2" || algo == "3") return "rsa" + bits;
    if (algo == "16") return "elg" + bits;
    if (algo == "17") return "dsa" + bits;
    return "algorithm-" + algo;
}

bool validityUnusable(const std::string& v) { return v == "r" || v == "e" || v == "i" || v == "d" || v == "n"; }

std::vector<std::string> baseArgs(const std::filesystem::path& home) {
    return {"--homedir", home.string(), "--no-options", "--batch", "--no-tty", "--no-autostart",
            "--no-permission-warning", "--quiet", "--no-auto-key-locate", "--no-auto-key-retrieve"};
}

std::filesystem::path requireExecutable() {
    const auto exe = executable();
    if (!exe) throw Unavailable("OpenPGP needs GnuPG (gpg), which is not installed on this server");
    return *exe;
}

// First lines of gpg's complaint, without its "gpg: " prefixes.
std::string gpgMessage(const std::string& err) {
    std::istringstream in(err);
    std::string line, out;
    int n = 0;
    while (std::getline(in, line) && n < 3) {
        if (line.starts_with("gpg: ")) line = line.substr(5);
        if (line.empty()) continue;
        out += (out.empty() ? "" : "; ") + line;
        ++n;
    }
    return out.empty() ? "gpg failed" : out;
}

std::string isoDate(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::array<char, 32> buf{};
    (void)std::strftime(buf.data(), buf.size(), "%Y-%m-%d", &tm);
    return buf.data();
}

}  // namespace

// ---------------------------------------------------------------------------------------------------- KeyInfo

std::optional<std::string> KeyInfo::unusableReason() const {
    if (revoked) return "the key " + fingerprint + " is revoked";
    if (expired)
        return "the key " + fingerprint + " expired" + (expires_at ? " on " + isoDate(*expires_at) : std::string{});
    if (invalid)
        return "the key " + fingerprint + " is not valid (no valid self-signature or user ID; a keyserver may have "
               "stripped its user IDs: give the complete key)";
    if (encryption_keys.empty())
        return "the key " + fingerprint + " has no valid encryption-capable subkey (a sign-only key, or its encryption "
               "subkeys are revoked or expired)";
    return std::nullopt;
}

std::string normalizeFingerprint(const std::string_view text) {
    std::string out;
    for (const char c : text) {
        if (c == ' ' || c == '\t') continue;
        out += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    if (out.size() != 40 || !std::ranges::all_of(out, [](const unsigned char c) { return std::isxdigit(c) != 0; }))
        throw std::invalid_argument("an OpenPGP fingerprint is 40 hex digits (the full fingerprint, never a key id)");
    return out;
}

// ---------------------------------------------------------------------------------------------------- process

std::optional<std::filesystem::path> executable() {
    {
        std::scoped_lock lock(executableMutex());
        if (paths::testMode && executableOverride()) return *executableOverride();
    }
    for (const char* candidate : {"/usr/bin/gpg", "/opt/homebrew/bin/gpg", "/usr/local/bin/gpg"})
        if (::access(candidate, X_OK) == 0) return std::filesystem::path(candidate);
    return std::nullopt;
}

void setExecutableForTesting(std::optional<std::filesystem::path> path) {
    if (!paths::testMode) return;
    std::scoped_lock lock(executableMutex());
    executableOverride() = std::move(path);
}

bool available() { return executable().has_value(); }

RunResult run(const std::filesystem::path& exe, const std::vector<std::string>& args, const std::string_view input,
              const std::chrono::seconds timeout) {
    SocketPair in, out, err;

    std::vector<std::string> argvStore;
    argvStore.reserve(args.size() + 1);
    argvStore.push_back(exe.string());
    for (const auto& a : args) argvStore.push_back(a);
    std::vector<char*> argv;
    for (auto& a : argvStore) argv.push_back(a.data());
    argv.push_back(nullptr);
    std::array<std::string, 2> envStore{"LC_ALL=C", "PATH=/usr/bin:/bin"};
    std::array<char*, 3> envp{envStore[0].data(), envStore[1].data(), nullptr};

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, in.child.fd, STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, out.child.fd, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, err.child.fd, STDERR_FILENO);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    short flags = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
#if defined(__APPLE__)
    // Every descriptor not named by the file actions is closed in the child.
    flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
#elif defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
    posix_spawn_file_actions_addclosefrom_np(&actions, 3);
#endif
    posix_spawnattr_setflags(&attr, flags);
    sigset_t none, all;
    sigemptyset(&none);
    sigfillset(&all);
    sigdelset(&all, SIGKILL);
    sigdelset(&all, SIGSTOP);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setsigdefault(&attr, &all);

    pid_t pid = -1;
    const int spawned = ::posix_spawn(&pid, exe.c_str(), &actions, &attr, argv.data(), envp.data());
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    in.child.reset();
    out.child.reset();
    err.child.reset();
    if (spawned != 0) throw Unavailable("could not run " + exe.string() + ": " + std::strerror(spawned));

    setNonBlocking(in.parent.fd);
    setNonBlocking(out.parent.fd);
    setNonBlocking(err.parent.fd);

    RunResult result;
    std::size_t written = 0;
    if (input.empty()) in.parent.reset();
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (out.parent.fd >= 0 || err.parent.fd >= 0) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            result.timed_out = true;
            break;
        }
        std::array<pollfd, 3> fds{};
        nfds_t n = 0;
        int inIdx = -1, outIdx = -1, errIdx = -1;
        if (in.parent.fd >= 0) { fds[n] = {in.parent.fd, POLLOUT, 0}; inIdx = static_cast<int>(n++); }
        if (out.parent.fd >= 0) { fds[n] = {out.parent.fd, POLLIN, 0}; outIdx = static_cast<int>(n++); }
        if (err.parent.fd >= 0) { fds[n] = {err.parent.fd, POLLIN, 0}; errIdx = static_cast<int>(n++); }
        const int ready = ::poll(fds.data(), n, static_cast<int>(std::min<long long>(left.count(), 1000)));
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (inIdx >= 0 && fds[static_cast<std::size_t>(inIdx)].revents != 0) {
            const auto sent = ::send(in.parent.fd, input.data() + written, input.size() - written, MSG_NOSIGNAL);
            if (sent > 0) written += static_cast<std::size_t>(sent);
            if ((sent < 0 && errno != EAGAIN && errno != EINTR) || written == input.size()) in.parent.reset();
        }
        const auto drain = [](Fd& fd, std::string& into) {
            std::array<char, 16384> buf{};
            const auto got = ::recv(fd.fd, buf.data(), buf.size(), 0);
            if (got > 0) {
                if (into.size() < kMaxCapture) into.append(buf.data(), std::min<std::size_t>(static_cast<std::size_t>(got), kMaxCapture - into.size()));
            } else if (got == 0 || (errno != EAGAIN && errno != EINTR)) {
                fd.reset();
            }
        };
        if (outIdx >= 0 && fds[static_cast<std::size_t>(outIdx)].revents != 0) drain(out.parent, result.out);
        if (errIdx >= 0 && fds[static_cast<std::size_t>(errIdx)].revents != 0) drain(err.parent, result.err);
    }
    in.parent.reset();
    out.parent.reset();
    err.parent.reset();
    if (result.timed_out) (void)::kill(pid, SIGKILL);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return result;
}

TempHome::TempHome() {
    std::error_code ec;
    auto base = std::filesystem::temp_directory_path(ec);
    if (ec) base = "/tmp";
    std::string tmpl = (base / "vh-gpg-XXXXXX").string();
    if (!::mkdtemp(tmpl.data())) throw std::runtime_error(std::string("could not create a gpg home: ") + std::strerror(errno));
    path_ = tmpl;
    std::filesystem::permissions(path_, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
}

TempHome::~TempHome() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
}

// ---------------------------------------------------------------------------------------------------- keys

KeyInfo inspect(const std::string& armored) {
    if (armored.empty()) throw BadKey("no OpenPGP public key was given");
    if (armored.size() > 1024 * 1024) throw BadKey("the OpenPGP key is larger than 1 MiB");
    const auto exe = requireExecutable();
    const TempHome home;
    auto args = baseArgs(home.path());
    for (const char* a : {"--with-colons", "--with-fingerprint", "--with-subkey-fingerprint", "--show-keys"})
        args.emplace_back(a);
    const auto r = run(exe, args, armored);
    if (r.timed_out) throw BadKey("gpg did not answer in time while reading the key");

    std::vector<KeyInfo> keys;
    bool secret = false;
    enum class Last { None, Primary, Sub } last = Last::None;
    struct Sub {
        std::string validity, caps, fpr, algorithm;
    };
    std::vector<Sub> subs;
    std::string primaryCaps;
    const auto finish = [&] {
        if (keys.empty()) return;
        auto& k = keys.back();
        if (primaryCaps.find('e') != std::string::npos && !k.revoked && !k.expired && !k.invalid) {
            k.encryption_keys.push_back(k.fingerprint);
            k.encryption_algorithms.push_back(k.algorithm);
        }
        for (const auto& s : subs)
            if (s.caps.find('e') != std::string::npos && !validityUnusable(s.validity) && !s.fpr.empty()) {
                k.encryption_keys.push_back(s.fpr);
                k.encryption_algorithms.push_back(s.algorithm);
            }
        // gpg's key-wide capability letters: an upper-case E only while some key can still encrypt.
        if (primaryCaps.find('E') == std::string::npos) {
            k.encryption_keys.clear();
            k.encryption_algorithms.clear();
        }
        subs.clear();
    };

    std::istringstream lines(r.out);
    std::string line;
    while (std::getline(lines, line)) {
        const auto f = split(line, ':');
        const auto& type = f[0];
        if (type == "sec" || type == "ssb") secret = true;
        if (type == "pub" || type == "sec") {
            finish();
            KeyInfo k;
            const auto validity = field(f, 1);
            k.revoked = validity == "r";
            k.expired = validity == "e";
            k.invalid = validity == "i";
            k.created_at = epochField(f, 5).value_or(0);
            k.expires_at = epochField(f, 6);
            k.algorithm = algorithmName(f);
            primaryCaps = field(f, 11);
            keys.push_back(std::move(k));
            last = Last::Primary;
        } else if (type == "sub" || type == "ssb") {
            subs.push_back({.validity = field(f, 1), .caps = field(f, 11), .fpr = {}, .algorithm = algorithmName(f)});
            last = Last::Sub;
        } else if (type == "fpr") {
            if (last == Last::Primary && !keys.empty() && keys.back().fingerprint.empty())
                keys.back().fingerprint = field(f, 9);
            else if (last == Last::Sub && !subs.empty() && subs.back().fpr.empty())
                subs.back().fpr = field(f, 9);
        } else if (type == "uid" && !keys.empty()) {
            keys.back().user_ids.push_back(unescapeColon(field(f, 9)));
        }
    }
    finish();

    if (secret) throw BadKey("this is a secret key: give the recipient's public key only (gpg --export --armor <fingerprint>)");
    if (keys.empty())
        throw BadKey("no OpenPGP public key found" + (r.err.empty() ? std::string{} : " (" + gpgMessage(r.err) + ")"));
    if (keys.size() > 1) throw BadKey("the input holds " + std::to_string(keys.size()) + " keys; give exactly one");
    auto key = std::move(keys.front());
    if (key.fingerprint.size() != 40)
        throw BadKey("only version 4 OpenPGP keys (40-digit fingerprints) are supported");
    return key;
}

void requireEncryptable(const KeyInfo& key) {
    if (const auto why = key.unusableReason()) throw BadKey(*why);
}

std::string encrypt(const std::string_view plaintext, const std::vector<std::string>& armoredKeys) {
    if (armoredKeys.empty()) throw BadKey("an OpenPGP message needs at least one recipient");
    for (const auto& k : armoredKeys) requireEncryptable(inspect(k));

    const auto exe = requireExecutable();
    const TempHome home;
    auto args = baseArgs(home.path());
    for (const char* a : {"--trust-model", "always", "--compress-algo", "none", "--armor", "--output", "-"})
        args.emplace_back(a);
    for (std::size_t i = 0; i < armoredKeys.size(); ++i) {
        const auto file = home.path() / ("recipient-" + std::to_string(i) + ".asc");
        // A public key (inspect() above refused anything holding secret material), created exclusively with mode 0600
        // in the 0700 throwaway home: never an existing name, never the plaintext (that goes over stdin only).
        const auto& key = armoredKeys[i];
        ::vh::fs::ops::writeFileExclusive(file, std::span(reinterpret_cast<const uint8_t*>(key.data()), key.size()), 0600);
        args.emplace_back("--recipient-file");
        args.push_back(file.string());
    }
    args.emplace_back("--encrypt");

    const auto r = run(exe, args, plaintext);
    if (r.timed_out) throw BadKey("gpg did not finish encrypting in time");
    if (r.exit_code != 0 || !r.out.starts_with("-----BEGIN PGP MESSAGE-----"))
        throw BadKey("gpg could not encrypt to the recipient keys: " + gpgMessage(r.err));
    return r.out;
}

}
