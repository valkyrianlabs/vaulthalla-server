// vh_fs_actor: a filesystem actor for the integration harnesses (Tier A in core/tests/integrations and the Python
// engine in tools/harness). It replaces fork()-from-the-daemon probes: the harness posix_spawn()s one actor per
// (uid, gid), the actor switches to that identity at startup before it reads any input, and then serves one JSON
// request per line on stdin with one JSON reply per line on stdout. It is single-threaded and links no daemon code,
// so it can't inherit a lock held by another thread, and the parent enforces per-op deadlines (a wedged FUSE request
// leaves this process stuck, never the harness).
//
//   argv:    vh_fs_actor --uid U --gid G [--groups g1,g2,...]
//   ready:   {"ready":true,"uid":U,"gid":G,"pid":P}
//   request: {"id":N,"op":OP,"path":"...","to":"...","data_b64":"...","offset":N,"size":N,"mode":N}
//            OP: write (create/truncate + write data), append, pwrite (at offset), read (whole file, or size bytes at
//            offset), ls, stat, mkdir, rmdir, unlink, rename (path -> to), truncate (to size), chmod, rm_rf,
//            cp_tree (path -> to, like cp -a), fsync, hold (open path and keep it open until release), release, exit
//   reply:   {"id":N,"errno":E,"error":"strerror text","size":N,"sha256":"hex of bytes read or written",
//             "data_b64":"(read only, when size <= 1 MiB)","entries":["name",...](ls, sorted),"mode":N,
//             "type":"file|dir|other"}; errno 0 is success.
//
// The protocol is shared with tools/harness; keep it exactly.

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <spawn.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

extern char** environ;

namespace {

using json = nlohmann::ordered_json;  // replies keep the protocol's field order

constexpr std::size_t kInlineReadLimit = 1024 * 1024;

std::string base64Encode(const std::string_view in) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        const auto n = (static_cast<uint32_t>(static_cast<uint8_t>(in[i])) << 16) |
                       (static_cast<uint32_t>(static_cast<uint8_t>(in[i + 1])) << 8) |
                       static_cast<uint32_t>(static_cast<uint8_t>(in[i + 2]));
        out += kAlphabet[(n >> 18) & 63];
        out += kAlphabet[(n >> 12) & 63];
        out += kAlphabet[(n >> 6) & 63];
        out += kAlphabet[n & 63];
    }
    if (i + 1 == in.size()) {
        const auto n = static_cast<uint32_t>(static_cast<uint8_t>(in[i])) << 16;
        out += kAlphabet[(n >> 18) & 63];
        out += kAlphabet[(n >> 12) & 63];
        out += "==";
    } else if (i + 2 == in.size()) {
        const auto n = (static_cast<uint32_t>(static_cast<uint8_t>(in[i])) << 16) |
                       (static_cast<uint32_t>(static_cast<uint8_t>(in[i + 1])) << 8);
        out += kAlphabet[(n >> 18) & 63];
        out += kAlphabet[(n >> 12) & 63];
        out += kAlphabet[(n >> 6) & 63];
        out += '=';
    }
    return out;
}

std::optional<std::string> base64Decode(const std::string_view in) {
    auto value = [](const char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    if (in.size() % 4 != 0) return std::nullopt;
    std::string out;
    out.reserve(in.size() / 4 * 3);
    for (std::size_t i = 0; i < in.size(); i += 4) {
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = in[i + static_cast<std::size_t>(k)];
            if (c == '=' && i + 4 == in.size() && k >= 2) {
                v[k] = 0;
                ++pad;
                continue;
            }
            if (pad) return std::nullopt;
            v[k] = value(c);
            if (v[k] < 0) return std::nullopt;
        }
        const uint32_t n = (static_cast<uint32_t>(v[0]) << 18) | (static_cast<uint32_t>(v[1]) << 12) |
                           (static_cast<uint32_t>(v[2]) << 6) | static_cast<uint32_t>(v[3]);
        out += static_cast<char>((n >> 16) & 0xFF);
        if (pad < 2) out += static_cast<char>((n >> 8) & 0xFF);
        if (pad < 1) out += static_cast<char>(n & 0xFF);
    }
    return out;
}

std::string sha256Hex(const std::string_view data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr) != 1) return {};
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out += kHex[md[i] >> 4];
        out += kHex[md[i] & 0xF];
    }
    return out;
}

int writeAll(const int fd, const std::string_view data) {
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t w = ::write(fd, data.data() + off, data.size() - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return errno;
        }
        off += static_cast<std::size_t>(w);
    }
    return 0;
}

int pwriteAll(const int fd, const std::string_view data, off_t offset) {
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t w = ::pwrite(fd, data.data() + off, data.size() - off, offset);
        if (w < 0) {
            if (errno == EINTR) continue;
            return errno;
        }
        off += static_cast<std::size_t>(w);
        offset += w;
    }
    return 0;
}

// Close errors matter on FUSE (flush/release report write-back failures there), so they are returned.
int closeChecked(const int fd) { return ::close(fd) == 0 ? 0 : errno; }

struct Reply {
    json j;
    explicit Reply(const json& id) : j{{"id", id}, {"errno", 0}, {"error", ""}} {}
    Reply& fail(const int err, const std::string& why = {}) {
        j["errno"] = err;
        j["error"] = why.empty() ? std::string(std::strerror(err)) : why;
        return *this;
    }
};

class Actor {
public:
    void serve() {
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line.empty()) continue;
            json reply = handle(line);
            std::cout << reply.dump(-1, ' ', false, json::error_handler_t::replace) << '\n' << std::flush;
            if (exitRequested_) break;
        }
        for (auto& [path, fds] : held_)
            for (const int fd : fds) ::close(fd);
    }

private:
    std::map<std::string, std::vector<int>> held_;
    bool exitRequested_ = false;

    json handle(const std::string& line) {
        json req;
        try {
            req = json::parse(line);
        } catch (const std::exception& e) {
            return Reply(nullptr).fail(EINVAL, std::string("bad request: ") + e.what()).j;
        }
        if (!req.is_object()) return Reply(nullptr).fail(EINVAL, "bad request: not an object").j;
        Reply r(req.contains("id") ? req["id"] : json(nullptr));
        try {
            dispatch(req, r);
        } catch (const std::exception& e) {
            r.fail(EINVAL, std::string("bad request: ") + e.what());
        }
        return r.j;
    }

    static std::string str(const json& req, const char* key) {
        if (!req.contains(key) || !req[key].is_string()) throw std::invalid_argument(std::string("missing ") + key);
        return req[key].get<std::string>();
    }

    template <typename T>
    static std::optional<T> num(const json& req, const char* key) {
        if (!req.contains(key) || req[key].is_null()) return std::nullopt;
        if (!req[key].is_number_integer()) throw std::invalid_argument(std::string(key) + " must be an integer");
        return req[key].get<T>();
    }

    static std::string data(const json& req) {
        if (!req.contains("data_b64") || req["data_b64"].is_null()) return {};
        auto decoded = base64Decode(req["data_b64"].get<std::string>());
        if (!decoded) throw std::invalid_argument("data_b64 is not base64");
        return *decoded;
    }

    void dispatch(const json& req, Reply& r) {
        const auto op = str(req, "op");
        if (op == "exit") {
            exitRequested_ = true;
            return;
        }
        const auto path = str(req, "path");
        const auto mode = static_cast<mode_t>(num<long long>(req, "mode").value_or(-1));
        const bool hasMode = num<long long>(req, "mode").has_value();

        if (op == "write" || op == "append" || op == "pwrite") {
            const auto bytes = data(req);
            int flags = O_WRONLY | O_CREAT | O_CLOEXEC;
            if (op == "write") flags |= O_TRUNC;
            if (op == "append") flags |= O_APPEND;
            const int fd = ::open(path.c_str(), flags, hasMode ? mode : 0644);
            if (fd < 0) return void(r.fail(errno));
            int err = op == "pwrite" ? pwriteAll(fd, bytes, num<off_t>(req, "offset").value_or(0)) : writeAll(fd, bytes);
            const int closeErr = closeChecked(fd);
            if (!err) err = closeErr;
            if (err) return void(r.fail(err));
            r.j["size"] = bytes.size();
            r.j["sha256"] = sha256Hex(bytes);
            return;
        }

        if (op == "read") {
            const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0) return void(r.fail(errno));
            std::string out;
            int err = 0;
            const auto size = num<long long>(req, "size");
            off_t offset = num<off_t>(req, "offset").value_or(0);
            char buf[65536];
            while (!size || static_cast<long long>(out.size()) < *size) {
                std::size_t want = sizeof(buf);
                if (size) want = std::min<std::size_t>(want, static_cast<std::size_t>(*size) - out.size());
                const ssize_t n = size || offset ? ::pread(fd, buf, want, offset) : ::read(fd, buf, want);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    err = errno;
                    break;
                }
                if (n == 0) break;
                out.append(buf, static_cast<std::size_t>(n));
                offset += n;
            }
            const int closeErr = closeChecked(fd);
            if (!err) err = closeErr;
            if (err) return void(r.fail(err));
            r.j["size"] = out.size();
            r.j["sha256"] = sha256Hex(out);
            if (out.size() <= kInlineReadLimit) r.j["data_b64"] = base64Encode(out);
            return;
        }

        if (op == "ls") {
            DIR* dir = ::opendir(path.c_str());
            if (!dir) return void(r.fail(errno));
            std::vector<std::string> entries;
            errno = 0;
            while (const dirent* e = ::readdir(dir)) {
                const std::string_view name = e->d_name;
                if (name != "." && name != "..") entries.emplace_back(name);
                errno = 0;
            }
            const int err = errno;
            ::closedir(dir);
            if (err) return void(r.fail(err));
            std::ranges::sort(entries);
            r.j["entries"] = entries;
            return;
        }

        if (op == "stat") {
            struct stat st{};
            if (::stat(path.c_str(), &st) != 0) return void(r.fail(errno));
            r.j["mode"] = st.st_mode & 07777;
            r.j["size"] = static_cast<long long>(st.st_size);
            r.j["type"] = S_ISREG(st.st_mode) ? "file" : S_ISDIR(st.st_mode) ? "dir" : "other";
            return;
        }

        if (op == "mkdir") return void(::mkdir(path.c_str(), hasMode ? mode : 0755) == 0 ? r : r.fail(errno));
        if (op == "rmdir") return void(::rmdir(path.c_str()) == 0 ? r : r.fail(errno));
        if (op == "unlink") return void(::unlink(path.c_str()) == 0 ? r : r.fail(errno));
        if (op == "rename") return void(::rename(path.c_str(), str(req, "to").c_str()) == 0 ? r : r.fail(errno));
        if (op == "chmod") {
            if (!hasMode) throw std::invalid_argument("missing mode");
            return void(::chmod(path.c_str(), mode) == 0 ? r : r.fail(errno));
        }
        if (op == "truncate") {
            const auto size = num<off_t>(req, "size");
            if (!size) throw std::invalid_argument("missing size");
            return void(::truncate(path.c_str(), *size) == 0 ? r : r.fail(errno));
        }

        if (op == "rm_rf") {
            std::error_code ec;
            const auto removed = std::filesystem::remove_all(path, ec);
            if (ec) return void(r.fail(ec.value()));
            r.j["size"] = removed;
            return;
        }

        if (op == "cp_tree") return cpTree(path, str(req, "to"), r);

        if (op == "fsync") {
            const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0) return void(r.fail(errno));
            int err = ::fsync(fd) == 0 ? 0 : errno;
            const int closeErr = closeChecked(fd);
            if (!err) err = closeErr;
            if (err) r.fail(err);
            return;
        }

        if (op == "hold") {
            int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
            if (fd < 0 && (errno == EACCES || errno == EISDIR || errno == EROFS || errno == EPERM))
                fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0) return void(r.fail(errno));
            held_[path].push_back(fd);
            return;
        }

        if (op == "release") {
            const auto it = held_.find(path);
            if (it == held_.end() || it->second.empty()) return void(r.fail(EBADF, "nothing held for this path"));
            const int fd = it->second.back();
            it->second.pop_back();
            if (it->second.empty()) held_.erase(it);
            if (const int err = closeChecked(fd)) r.fail(err);
            return;
        }

        r.fail(EINVAL, "unknown op: " + op);
    }

    // cp -a, run as this actor's identity. The actor is single-threaded, so spawning from it is safe.
    static void cpTree(const std::string& from, const std::string& to, Reply& r) {
        // The errno a caller would see doing it by hand, before cp collapses every failure to exit status 1:
        // an unreadable/missing source, a missing or unwritable destination parent.
        struct stat st{};
        if (::lstat(from.c_str(), &st) != 0) return void(r.fail(errno));
        const auto parent = std::filesystem::path(to).parent_path();
        if (::stat(parent.c_str(), &st) != 0) return void(r.fail(errno));
        if (::access(parent.c_str(), W_OK | X_OK) != 0) return void(r.fail(errno));
        std::string a0 = "cp", a1 = "-a";
        std::string src = from, dst = to;
        char* argv[] = {a0.data(), a1.data(), src.data(), dst.data(), nullptr};
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
        pid_t pid = -1;
        const int rc = ::posix_spawnp(&pid, "cp", &fa, nullptr, argv, environ);
        posix_spawn_file_actions_destroy(&fa);
        if (rc != 0) return void(r.fail(rc));
        int status = 0;
        while (::waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR) return void(r.fail(errno));
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            r.fail(EIO, "cp -a exited with status " + std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : 128));
    }
};

[[noreturn]] void refuse(const std::string& why) {
    std::cout << json{{"ready", false}, {"error", why}}.dump() << '\n' << std::flush;
    std::exit(1);
}

std::optional<unsigned long> parseId(const std::string_view s) {
    if (s.empty()) return std::nullopt;
    unsigned long v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        v = v * 10 + static_cast<unsigned long>(c - '0');
        if (v > 0xFFFFFFFEul) return std::nullopt;
    }
    return v;
}

}

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);

    std::optional<unsigned long> uid, gid;
    std::vector<gid_t> groups;
    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        const bool hasValue = i + 1 < argc;
        if (a == "--uid" && hasValue) uid = parseId(argv[++i]);
        else if (a == "--gid" && hasValue) gid = parseId(argv[++i]);
        else if (a == "--groups" && hasValue) {
            std::string_view rest = argv[++i];
            while (!rest.empty()) {
                const auto comma = rest.find(',');
                const auto g = parseId(rest.substr(0, comma));
                if (!g) refuse("bad --groups");
                groups.push_back(static_cast<gid_t>(*g));
                rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
            }
        } else refuse("usage: vh_fs_actor --uid U --gid G [--groups g1,g2,...]");
    }
    if (!uid || !gid) refuse("usage: vh_fs_actor --uid U --gid G [--groups g1,g2,...]");

    // Switch identity before reading any input. Root drops to exactly (uid, gid, groups); anyone else may only be
    // themselves.
    if (::geteuid() == 0) {
        if (::setgroups(groups.size(), groups.empty() ? nullptr : groups.data()) != 0)
            refuse(std::string("setgroups: ") + std::strerror(errno));
        if (::setresgid(static_cast<gid_t>(*gid), static_cast<gid_t>(*gid), static_cast<gid_t>(*gid)) != 0)
            refuse(std::string("setresgid: ") + std::strerror(errno));
        if (::setresuid(static_cast<uid_t>(*uid), static_cast<uid_t>(*uid), static_cast<uid_t>(*uid)) != 0)
            refuse(std::string("setresuid: ") + std::strerror(errno));
    } else if (::geteuid() != *uid || ::getegid() != *gid) {
        refuse("not root: can only act as the current uid/gid");
    }
    if (::getuid() != *uid || ::geteuid() != *uid || ::getgid() != *gid || ::getegid() != *gid)
        refuse("identity switch did not take effect");

    // Die with the harness (set after the switch: a credential change clears it).
    ::prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (::getppid() == 1) return 1;

    std::ios::sync_with_stdio(false);
    std::cout << json{{"ready", true}, {"uid", *uid}, {"gid", *gid}, {"pid", ::getpid()}}.dump() << '\n' << std::flush;

    Actor{}.serve();
    return 0;
}
