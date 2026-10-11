#pragma once

#include "fuse/Actor.hpp"
#include "types/Type.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

// Filesystem probes as a given uid/gid, run by vh_fs_actor (fuse/Actor.hpp) rather than fork()ed from the daemon.
// Each helper returns an ExecResult: exit_code is the errno of the operation that decided the outcome (0 = success),
// stdout_text keeps the "OK <op> ..." lines the scenarios match on, `command` says what ran, and `wedge` marks a
// deadline expiry.
namespace vh::test::integration::fuse {
    namespace detail {
        inline std::string oct(const mode_t mode) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%o", static_cast<unsigned>(mode));
            return buf;
        }

        inline std::string b64(const std::string_view in) {
            static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            std::size_t i = 0;
            for (; i + 2 < in.size(); i += 3) {
                const auto n = (static_cast<uint32_t>(static_cast<uint8_t>(in[i])) << 16) |
                               (static_cast<uint32_t>(static_cast<uint8_t>(in[i + 1])) << 8) |
                               static_cast<uint32_t>(static_cast<uint8_t>(in[i + 2]));
                for (const int shift : {18, 12, 6, 0}) out += kAlphabet[(n >> shift) & 63];
            }
            if (const auto rest = in.size() - i; rest > 0) {
                uint32_t n = static_cast<uint32_t>(static_cast<uint8_t>(in[i])) << 16;
                if (rest == 2) n |= static_cast<uint32_t>(static_cast<uint8_t>(in[i + 1])) << 8;
                out += kAlphabet[(n >> 18) & 63];
                out += kAlphabet[(n >> 12) & 63];
                out += rest == 2 ? kAlphabet[(n >> 6) & 63] : '=';
                out += '=';
            }
            return out;
        }

        inline std::string unb64(const std::string_view in) {
            auto value = [](const char c) -> int {
                if (c >= 'A' && c <= 'Z') return c - 'A';
                if (c >= 'a' && c <= 'z') return c - 'a' + 26;
                if (c >= '0' && c <= '9') return c - '0' + 52;
                if (c == '+') return 62;
                if (c == '/') return 63;
                return -1;
            };
            std::string out;
            uint32_t acc = 0;
            int bits = 0;
            for (const char c : in) {
                const int v = value(c);
                if (v < 0) continue;  // '=' padding
                acc = (acc << 6) | static_cast<uint32_t>(v);
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    out += static_cast<char>((acc >> bits) & 0xFF);
                }
            }
            return out;
        }

        inline std::string describe(const uid_t uid, const gid_t gid, const std::string_view op,
                                    const std::filesystem::path& p, const std::filesystem::path& to = {}) {
            std::string s = "vh_fs_actor uid=" + std::to_string(uid) + " gid=" + std::to_string(gid) + " " +
                            std::string(op) + " " + p.string();
            if (!to.empty()) s += " -> " + to.string();
            return s;
        }

        inline ActorReply call(const uid_t uid, const gid_t gid, nlohmann::json request) {
            return actors().get(uid, gid).call(std::move(request));
        }

        inline ExecResult result(const ActorReply& r, std::string command, std::string okText = {}) {
            ExecResult e;
            e.exit_code = r.err;
            e.command = std::move(command);
            e.wedge = r.wedge;
            if (r.err == 0) e.stdout_text = std::move(okText);
            else e.stderr_text = r.error;
            return e;
        }

        inline nlohmann::json req(const char* op, const std::filesystem::path& p) {
            return {{"op", op}, {"path", p.string()}};
        }
    }

    // mkdir -p, then chmod of the last component (what std::filesystem::create_directories + chmod did).
    inline ExecResult mkdir_as(const uid_t uid, const gid_t gid, const std::filesystem::path& p, const mode_t mode = 0755) {
        const auto command = detail::describe(uid, gid, "mkdir -p", p);
        std::vector<std::filesystem::path> chain;
        for (auto q = p.lexically_normal(); !q.empty() && q != q.root_path(); q = q.parent_path()) chain.push_back(q);
        for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
            auto r = detail::call(uid, gid, {{"op", "mkdir"}, {"path", it->string()}, {"mode", 0755}});
            if (r.err == EEXIST && !r.wedge) continue;
            if (r.err != 0) return detail::result(r, command);
        }
        const auto r = detail::call(uid, gid, {{"op", "chmod"}, {"path", p.string()}, {"mode", mode}});
        return detail::result(r, command, "OK mkdir " + p.string() + "\n");
    }

    inline ExecResult write_as(const uid_t uid, const gid_t gid, const std::filesystem::path& p,
                               const std::string_view data, const mode_t mode = 0644) {
        auto request = detail::req("write", p);
        request["data_b64"] = detail::b64(data);
        request["mode"] = mode;
        const auto r = detail::call(uid, gid, std::move(request));
        return detail::result(r, detail::describe(uid, gid, "write", p),
                              "OK write " + p.string() + " bytes=" + std::to_string(data.size()) + "\n");
    }

    inline ExecResult read_as(const uid_t uid, const gid_t gid, const std::filesystem::path& p) {
        const auto r = detail::call(uid, gid, detail::req("read", p));
        std::string out = "OK read " + p.string() + ":\n";
        if (r.err == 0) {
            if (r.body.contains("data_b64")) out += detail::unb64(r.body["data_b64"].get<std::string>());
            else out += "(" + std::to_string(r.body.value("size", 0LL)) + " bytes, sha256 " +
                        r.body.value("sha256", std::string()) + ")";
        }
        return detail::result(r, detail::describe(uid, gid, "read", p), out);
    }

    inline ExecResult ls_as(const uid_t uid, const gid_t gid, const std::filesystem::path& p) {
        const auto r = detail::call(uid, gid, detail::req("ls", p));
        std::string out;
        if (r.err == 0 && r.body.contains("entries"))
            for (const auto& e : r.body["entries"]) out += e.get<std::string>() + "\n";
        return detail::result(r, detail::describe(uid, gid, "ls", p), out);
    }

    inline ExecResult rmrf_as(const uid_t uid, const gid_t gid, const std::filesystem::path& p) {
        const auto r = detail::call(uid, gid, detail::req("rm_rf", p));
        return detail::result(r, detail::describe(uid, gid, "rm -rf", p),
                              "OK rm -rf " + p.string() + " removed=" + std::to_string(r.body.value("size", 0LL)) + "\n");
    }

    inline ExecResult mv_as(const uid_t uid, const gid_t gid,
                            const std::filesystem::path& from, const std::filesystem::path& to) {
        auto request = detail::req("rename", from);
        request["to"] = to.string();
        const auto r = detail::call(uid, gid, std::move(request));
        return detail::result(r, detail::describe(uid, gid, "rename", from, to),
                              "OK mv " + from.string() + " -> " + to.string() + "\n");
    }

    inline ExecResult chmod_as(const uid_t uid, const gid_t gid, const std::filesystem::path& p, const mode_t mode) {
        const auto r = detail::call(uid, gid, {{"op", "chmod"}, {"path", p.string()}, {"mode", mode}});
        return detail::result(r, detail::describe(uid, gid, "chmod " + detail::oct(mode), p),
                              "OK chmod " + p.string() + " " + detail::oct(mode) + "\n");
    }

    // cp -a of a small tree with git-like metadata (restrictive dir modes, a read-only object) into `destination`.
    inline ExecResult cp_preserve_tree_as(const uid_t uid, const gid_t gid, const std::filesystem::path& destination) {
        const auto source = std::filesystem::temp_directory_path() /
            ("vh_fuse_cp_source_" + std::to_string(uid) + "_" + std::to_string(::getpid()));
        const auto command = detail::describe(uid, gid, "cp -a", source, destination);

        const auto fail = [&](const ActorReply& r) { return detail::result(r, command); };
        const auto run = [&](nlohmann::json request) { return detail::call(uid, gid, std::move(request)); };
        const auto write = [&](const std::filesystem::path& p, const std::string_view data, const mode_t mode) {
            auto r = run({{"op", "write"}, {"path", p.string()}, {"data_b64", detail::b64(data)}, {"mode", mode}});
            if (r.err) return r;
            return run({{"op", "chmod"}, {"path", p.string()}, {"mode", mode}});
        };

        if (auto r = run(detail::req("rm_rf", source)); r.err) return fail(r);
        for (const auto& dir : {source, source / ".git", source / ".git" / "objects", source / ".git" / "objects" / "aa",
                                source / "src"})
            if (auto r = run({{"op", "mkdir"}, {"path", dir.string()}, {"mode", 0755}}); r.err) return fail(r);
        if (auto r = write(source / ".git" / "config", "[core]\nrepositoryformatversion = 0\n", 0600); r.err) return fail(r);
        if (auto r = write(source / ".git" / "objects" / "aa" / "seed", "object\n", 0440); r.err) return fail(r);
        if (auto r = write(source / "src" / "main.cpp", "int main() { return 0; }\n", 0640); r.err) return fail(r);
        if (auto r = run({{"op", "chmod"}, {"path", (source / ".git").string()}, {"mode", 0700}}); r.err) return fail(r);
        if (auto r = run({{"op", "chmod"}, {"path", (source / "src").string()}, {"mode", 0750}}); r.err) return fail(r);
        if (auto r = run(detail::req("rm_rf", destination)); r.err) return fail(r);

        auto copy = detail::req("cp_tree", source);
        copy["to"] = destination.string();
        const auto r = run(std::move(copy));
        (void)run(detail::req("rm_rf", source));
        return detail::result(r, command, "OK cp -a " + source.string() + " -> " + destination.string() + "\n");
    }

    inline ExecResult stat_mode_as(const uid_t uid, const gid_t gid, const std::filesystem::path& p, const mode_t expected) {
        const auto r = detail::call(uid, gid, detail::req("stat", p));
        auto e = detail::result(r, detail::describe(uid, gid, "stat", p));
        if (r.err == 0) {
            const auto actual = static_cast<mode_t>(r.body.value("mode", 0));
            e.stdout_text = "OK stat " + p.string() + " mode=" + detail::oct(actual) + "\n";
            if (actual != expected) e.exit_code = EINVAL;
        }
        return e;
    }

    // The size stat(2) reports: through the mount that must be the plaintext size (#173).
    inline ExecResult stat_size_as(const uid_t uid, const std::filesystem::path& p) {
        const auto r = detail::call(uid, uid, detail::req("stat", p));
        return detail::result(r, detail::describe(uid, uid, "stat", p),
                              "OK stat " + p.string() + " size=" + std::to_string(r.body.value("size", 0LL)) + "\n");
    }

    // unlink(2) / rmdir(2) of exactly one entry (rm -rf would hide what a single delete does to its parents).
    inline ExecResult unlink_as(const uid_t uid, const std::filesystem::path& p) {
        const auto r = detail::call(uid, uid, detail::req("unlink", p));
        return detail::result(r, detail::describe(uid, uid, "unlink", p), "OK unlink " + p.string() + "\n");
    }

    inline ExecResult rmdir_as(const uid_t uid, const std::filesystem::path& p) {
        const auto r = detail::call(uid, uid, detail::req("rmdir", p));
        return detail::result(r, detail::describe(uid, uid, "rmdir", p), "OK rmdir " + p.string() + "\n");
    }

    inline ExecResult truncate_as(const uid_t uid, const std::filesystem::path& p, const off_t size) {
        const auto r = detail::call(uid, uid, {{"op", "truncate"}, {"path", p.string()}, {"size", size}});
        return detail::result(r, detail::describe(uid, uid, "truncate " + std::to_string(size), p),
                              "OK truncate " + p.string() + "\n");
    }

    // uid-only overloads: the probe runs with gid == uid (the scenario users' private groups).
    inline ExecResult mkdir_as(const uid_t uid, const std::filesystem::path& p, const mode_t mode = 0755) {
        return mkdir_as(uid, uid, p, mode);
    }

    inline ExecResult write_as(const uid_t uid, const std::filesystem::path& p,
                               const std::string_view data, const mode_t mode = 0644) {
        return write_as(uid, uid, p, data, mode);
    }

    inline ExecResult read_as(const uid_t uid, const std::filesystem::path& p) { return read_as(uid, uid, p); }

    inline ExecResult ls_as(const uid_t uid, const std::filesystem::path& p) { return ls_as(uid, uid, p); }

    inline ExecResult rmrf_as(const uid_t uid, const std::filesystem::path& p) { return rmrf_as(uid, uid, p); }

    inline ExecResult mv_as(const uid_t uid, const std::filesystem::path& from, const std::filesystem::path& to) {
        return mv_as(uid, uid, from, to);
    }

    inline ExecResult chmod_as(const uid_t uid, const std::filesystem::path& p, const mode_t mode) {
        return chmod_as(uid, uid, p, mode);
    }

    inline ExecResult cp_preserve_tree_as(const uid_t uid, const std::filesystem::path& destination) {
        return cp_preserve_tree_as(uid, uid, destination);
    }

    inline ExecResult stat_mode_as(const uid_t uid, const std::filesystem::path& p, const mode_t expected) {
        return stat_mode_as(uid, uid, p, expected);
    }
}
