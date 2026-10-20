// `vh skill install --agent <claude|codex> [--scope user|project] [--no-register] [--force]`: writes the vaulthalla
// agent skill (the hand-written SKILL.md and references/commands.md generated from the usage book, both compiled
// into vh) and registers `vh mcp` with the agent's own CLI. Needs no daemon. Idempotent: an identical skill is left
// alone, a different one is only replaced with --force.

#include "cli_client.hpp"

#include "Mcp.hpp"
#include "version.h"

#include <fmt/core.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace vh::cli {

namespace {

namespace sk = mcp::skill;

struct Options {
    std::optional<sk::Agent> agent{};
    sk::Scope scope = sk::Scope::User;
    bool registerServer = true;
    bool force = false;
};

int usageError(const std::string& message) {
    fmt::print(stderr, "vh skill: {}\n(see 'vh skill install --help')\n", message);
    return 2;
}

std::string homeDir() {
    if (const char* h = std::getenv("HOME"); h && *h) return h;
    if (const auto* pw = ::getpwuid(::getuid()); pw && pw->pw_dir) return pw->pw_dir;
    return {};
}

std::string currentDir() {
    std::array<char, 4096> buf{};
    return ::getcwd(buf.data(), buf.size()) ? std::string(buf.data()) : std::string{};
}

bool isDir(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool makeDirs(const std::string& path) {
    std::string partial;
    std::istringstream in(path);
    if (path.starts_with('/')) partial = "/";
    for (std::string part; std::getline(in, part, '/');) {
        if (part.empty()) continue;
        partial += (partial.empty() || partial.back() == '/' ? "" : "/") + part;
        if (::mkdir(partial.c_str(), 0755) != 0 && errno != EEXIST) return false;
        if (!isDir(partial)) return false;
    }
    return true;
}

std::optional<std::string> readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream s;
    s << in.rdbuf();
    return s.str();
}

// Written next to the target and renamed over it, so a reader never sees half a file.
bool writeFile(const std::string& path, const std::string& content, std::string& error) {
    const auto tmp = path + ".vh-tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        out << content;
        if (!out.flush()) {
            error = "cannot write " + tmp + ": " + std::strerror(errno);
            return false;
        }
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        error = "cannot replace " + path + ": " + std::strerror(errno);
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
}

std::optional<std::string> findOnPath(const std::string& name) {
    const char* path = std::getenv("PATH");
    if (!path) return std::nullopt;
    std::istringstream in(path);
    for (std::string dir; std::getline(in, dir, ':');) {
        if (dir.empty()) continue;
        const auto candidate = dir + "/" + name;
        struct stat st{};
        if (::stat(candidate.c_str(), &st) == 0 && S_ISREG(st.st_mode) && ::access(candidate.c_str(), X_OK) == 0)
            return candidate;
    }
    return std::nullopt;
}

std::string shellQuote(const std::string& s) {
    if (!s.empty() && s.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./=") ==
                          std::string::npos)
        return s;
    std::string out{"'"};
    for (const char c : s) {
        if (c == '\'') out += "'\"'\"'";
        else out.push_back(c);
    }
    return out + "'";
}

std::string commandText(const std::vector<std::string>& argv) {
    std::string out;
    for (const auto& a : argv) out += (out.empty() ? "" : " ") + shellQuote(a);
    return out;
}

struct Ran {
    int code = 1;
    std::string output{};
};

Ran runCommand(const std::vector<std::string>& argv) {
    FILE* pipe = ::popen((commandText(argv) + " 2>&1 </dev/null").c_str(), "r");
    if (!pipe) return {1, "cannot run " + argv.front()};
    Ran r;
    std::array<char, 4096> buf{};
    while (std::fgets(buf.data(), static_cast<int>(buf.size()), pipe)) r.output += buf.data();
    const int status = ::pclose(pipe);
    r.code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    return r;
}

// Codex without its CLI, or for a project (`codex mcp add` only writes ~/.codex/config.toml): the stanza is written
// with --force when the file doesn't name the server yet, otherwise printed.
int registerCodexToml(const std::string& configPath, const bool force) {
    const auto stanza = sk::codexTomlStanza("vh");
    const auto existing = readFile(configPath).value_or("");
    if (existing.find("[mcp_servers." + std::string(sk::kName) + "]") != std::string::npos) {
        fmt::print("MCP server already configured in {}.\n", configPath);
        return 0;
    }
    if (!force) {
        fmt::print("To register the MCP server, add this to {} (or re-run with --force to append it):\n\n{}",
                   configPath, stanza);
        return 0;
    }
    const auto slash = configPath.rfind('/');
    if (slash != std::string::npos && !makeDirs(configPath.substr(0, slash))) {
        fmt::print(stderr, "vh skill: cannot create {}: {}\n", configPath.substr(0, slash), std::strerror(errno));
        return 1;
    }
    std::string error;
    const auto content = existing + (existing.empty() || existing.ends_with("\n\n") ? "" : existing.ends_with('\n') ? "\n" : "\n\n") + stanza;
    if (!writeFile(configPath, content, error)) {
        fmt::print(stderr, "vh skill: {}\n", error);
        return 1;
    }
    fmt::print("Registered the MCP server in {}.\n", configPath);
    return 0;
}

int registerServer(const Options& o, const std::string& home, const std::string& cwd) {
    const auto agent = *o.agent;
    const auto argv = sk::registerCommand(agent, o.scope, "vh");
    if (agent == sk::Agent::Codex && (argv.empty() || !findOnPath("codex")))
        return registerCodexToml(o.scope == sk::Scope::Project ? cwd + "/.codex/config.toml" : home + "/.codex/config.toml",
                                 o.force);
    if (!findOnPath(argv.front())) {
        fmt::print("{} CLI not found on PATH. To register the MCP server, run:\n  {}\n", sk::agentName(agent),
                   commandText(argv));
        return 0;
    }
    const auto ran = runCommand(argv);
    if (ran.code == 0) {
        fmt::print("Registered the MCP server: {}\n", commandText(argv));
        return 0;
    }
    if (ran.output.find("already exists") != std::string::npos) {
        fmt::print("MCP server '{}' is already registered with {}.\n", sk::kName, sk::agentName(agent));
        return 0;
    }
    fmt::print(stderr, "vh skill: registering failed (exit {}): {}\n{}", ran.code, commandText(argv), ran.output);
    return 1;
}

int install(const Options& o) {
    const auto home = homeDir();
    const auto cwd = currentDir();
    if (o.scope == sk::Scope::User && home.empty()) return usageError("HOME is not set");
    if (o.scope == sk::Scope::Project && cwd.empty()) return usageError("cannot determine the current directory");

    const auto dir = sk::skillDir(*o.agent, o.scope, home, cwd);
    const mcp::Catalog catalog;
    const std::vector<std::pair<std::string, std::string>> files{
        {dir + "/SKILL.md", sk::skillMarkdown()},
        {dir + "/references/commands.md", catalog.commandReference(VH_VERSION)},
    };

    bool same = isDir(dir);
    for (const auto& [path, content] : files) same = same && readFile(path) == content;
    if (same) {
        fmt::print("The {} skill for {} is up to date: {}\n", sk::kName, sk::agentName(*o.agent), dir);
    } else {
        if (isDir(dir) && !o.force) {
            fmt::print(stderr, "vh skill: {} already exists and differs from this version's skill; re-run with --force "
                               "to replace it\n", dir);
            return 1;
        }
        if (!makeDirs(dir + "/references")) {
            fmt::print(stderr, "vh skill: cannot create {}: {}\n", dir, std::strerror(errno));
            return 1;
        }
        for (const auto& [path, content] : files) {
            std::string error;
            if (!writeFile(path, content, error)) {
                fmt::print(stderr, "vh skill: {}\n", error);
                return 1;
            }
        }
        fmt::print("Installed the {} skill for {}: {}\n", sk::kName, sk::agentName(*o.agent), dir);
    }
    if (!o.registerServer) return 0;
    return registerServer(o, home, cwd);
}

}

int runSkill(const std::vector<std::string>& argv) {
    const auto help = [](const std::vector<std::string>& path) {
        fmt::print("{}", localHelp(path));
        return 0;
    };
    if (argv.size() < 2) return help({"skill"});
    if (argv[1] == "--help" || argv[1] == "-h" || argv[1] == "help") return help({"skill"});
    if (argv[1] != "install") return usageError("unknown subcommand '" + argv[1] + "'");

    Options o;
    for (size_t i = 2; i < argv.size(); ++i) {
        const auto& a = argv[i];
        const auto value = [&]() -> std::optional<std::string> {
            if (i + 1 >= argv.size() || argv[i + 1].starts_with("-")) return std::nullopt;
            return argv[++i];
        };
        if (a == "--help" || a == "-h") return help({"skill", "install"});
        if (a == "--agent") {
            const auto v = value();
            if (!v || !(o.agent = sk::parseAgent(*v))) return usageError("--agent takes claude or codex");
        } else if (a == "--scope") {
            const auto v = value();
            const auto scope = v ? sk::parseScope(*v) : std::nullopt;
            if (!scope) return usageError("--scope takes user or project");
            o.scope = *scope;
        } else if (a == "--no-register") {
            o.registerServer = false;
        } else if (a == "--force") {
            o.force = true;
        } else {
            return usageError("unexpected argument '" + a + "'");
        }
    }
    if (!o.agent) return usageError("--agent claude|codex is required");
    return install(o);
}

}
