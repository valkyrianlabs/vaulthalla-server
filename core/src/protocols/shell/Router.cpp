#include "protocols/shell/Router.hpp"
#include "protocols/shell/Token.hpp"
#include "protocols/shell/Parser.hpp"
#include "log/Registry.hpp"
#include "identities/User.hpp"
#include "CommandUsage.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/usageOptions.hpp"
#include "protocols/ws/LogRedaction.hpp"

#include <fmt/core.h>
#include <cctype>
#include <string>
#include <algorithm>
#include <optional>
#include <utility>

using vh::identities::User;
using vh::identities::Group;

using namespace vh::protocols::shell;

namespace vh::protocols::shell {

namespace {
thread_local std::optional<ConfirmationNeeded> tlsConfirmationNeeded;
thread_local bool tlsAgentCall = false;
}

AgentCallScope::AgentCallScope() : previous_(std::exchange(tlsAgentCall, true)) {}

AgentCallScope::~AgentCallScope() { tlsAgentCall = previous_; }

bool AgentCallScope::active() noexcept { return tlsAgentCall; }

void noteConfirmationNeeded(std::string code, std::vector<std::string> flags) {
    tlsConfirmationNeeded = ConfirmationNeeded{.code = std::move(code), .flags = std::move(flags)};
}

std::optional<ConfirmationNeeded> takeConfirmationNeeded() { return std::exchange(tlsConfirmationNeeded, std::nullopt); }

// The command line for the debug log, with the values of credential options (--secret, --password, --token, …; see
// ws::isSensitiveLogKey) replaced: `vh api-key create … --secret <value>` used to land in the log verbatim.
std::string redactLineForLog(const std::string& line) {
    std::string out;
    out.reserve(line.size());
    bool redactNext = false;
    size_t i = 0;
    while (i < line.size()) {
        if (std::isspace(static_cast<unsigned char>(line[i]))) {
            out.push_back(line[i++]);
            continue;
        }
        // One token, honouring quotes the way the tokenizer does.
        const size_t start = i;
        char quote = 0;
        while (i < line.size() && (quote || !std::isspace(static_cast<unsigned char>(line[i])))) {
            if (quote) {
                if (line[i] == '\\' && i + 1 < line.size()) ++i;
                else if (line[i] == quote) quote = 0;
            } else if (line[i] == '"' || line[i] == '\'') {
                quote = line[i];
            }
            ++i;
        }
        const std::string token = line.substr(start, i - start);
        if (redactNext) {
            redactNext = false;
            if (!token.starts_with("-")) {
                out += "[REDACTED]";
                continue;
            }
        }
        if (const auto dashes = token.find_first_not_of('-'); token.starts_with("-") && dashes != std::string::npos) {
            const auto bare = token.substr(dashes);
            const auto eq = bare.find('=');
            auto name = bare.substr(0, eq);
            std::ranges::replace(name, '-', '_');
            if (vh::protocols::ws::isSensitiveLogKey(name)) {
                if (eq != std::string::npos) {
                    out += token.substr(0, token.size() - (bare.size() - eq - 1)) + "[REDACTED]";
                    continue;
                }
                redactNext = true;
            }
        }
        out += token;
    }
    return out;
}

}

namespace {


// Options are definition-driven: each must be declared by the command or by a subcommand its positionals select
// (or belong to a family the definition declares in option_prefixes). Unknown options used to be silently
// discarded, so a typo like --description for --desc did nothing and still reported success.
std::optional<std::string> unknownOptionError(const CommandCall& call, const std::shared_ptr<CommandUsage>& root) {
    if (!root || call.options.empty()) return std::nullopt;

    // Subcommands can follow argument positionals (`s3-gateway creds scope <cred> set`), so argument words are
    // skipped rather than ending the walk.
    std::vector<std::shared_ptr<CommandUsage>> path{root};
    for (const auto& positional : call.positionals)
        if (auto child = path.back()->findSubcommand(positional)) path.push_back(std::move(child));

    for (const auto& opt : call.options) {
        if (opt.key == "help" || opt.key == "h") continue;
        if (std::ranges::any_of(path, [&](const auto& node) {
                return usageDeclaresOption(*node, opt.key) ||
                       std::ranges::any_of(node->option_prefixes, [&](const std::string& p) { return opt.key.starts_with(p); });
            })) continue;

        std::string command = "vh";
        for (const auto& node : path) command += " " + node->primary();
        const auto dashes = opt.key.size() == 1 ? "-" : "--";
        return "unknown option '" + std::string(dashes) + opt.key + "' for '" + command + "' (see '" + command + " --help')";
    }
    return std::nullopt;
}

}

void Router::registerCommand(const std::shared_ptr<CommandUsage>& usage, CommandHandler handler) {
    std::string key = normalize(usage->primary());

    CommandInfo info{usage->description.empty() ? "No description provided." : usage->description, std::move(handler), usage, {}};

    for (const std::string& alias : usage->aliases) {
        std::string a = alias;
        if (aliasMap_.contains(a) && aliasMap_.at(a) != key) {
            log::Registry::shell()->warn("Alias '{}' already mapped to '{}'; skipping duplicate for '{}'",
                                       a, aliasMap_.at(a), key);
            continue;
        }
        info.aliases.insert(a);
        aliasMap_[a] = key;
        log::Registry::shell()->debug("Alias '{}' mapped to '{}'", a, key);
    }

    if (usage->pluralAliasImpliesList) pluralMap_[key + "s"] = key;

    commands_[key] = std::move(info);
}

std::string Router::canonicalFor(const std::string& nameOrAlias) const {
    std::string n = normalize(nameOrAlias);
    if (commands_.contains(n)) return n;
    if (aliasMap_.contains(n)) return aliasMap_.at(n);
    if (pluralMap_.contains(n)) return pluralMap_.at(n);
    return n; // unknown; let caller error
}

CommandResult Router::executeLine(const std::string& line, const std::shared_ptr<User>& user, SocketIO* io,
                                  std::optional<TransferPeer> transfer, std::optional<std::string> input) const {
    log::Registry::shell()->debug("[Router] Executing line: '{}'", redactLineForLog(line));

    auto call = parseTokens(tokenize(line));
    call.original_positionals = call.positionals;
    call.user = user;
    call.io = io;
    call.transfer = std::move(transfer);
    call.input = std::move(input);

    if (call.name.empty()) return invalid("No command provided.");

    const auto canonical = canonicalFor(call.name);

    if (call.user->name() == "system" && call.user->isSuperAdmin() && canonical != "status") {
        static const std::unordered_set<std::string> allowed{ "status", "setup", "teardown" };
        if (!allowed.contains(canonical))
            return invalid(call.constructFullArgs(), fmt::format("[Router] System user cannot execute command: {}", canonical));
    }

    if (call.positionals.empty() && pluralMap_.contains(call.name)) {
        call.name = canonical;
        call.positionals.emplace_back("list");
    }

    log::Registry::shell()->debug("[Router] Executing command: '{}'", canonical);

    if (!commands_.contains(canonical))
        return invalid(call.constructFullArgs(), fmt::format("[Router] Unknown command or alias: {}", call.name));

    const auto& info = commands_.at(canonical);
    if (const auto err = unknownOptionError(call, info.usage)) return invalid(*err);
    (void)takeConfirmationNeeded();
    auto result = info.handler(call);
    // Only a refusal carries it; a note left by a path that went on to succeed is dropped.
    if (auto needed = takeConfirmationNeeded(); needed && result.exit_code != 0 && !result.confirmation)
        result.confirmation = std::move(needed);
    return result;
}

std::optional<std::string> Router::optionError(const std::string& line) const {
    auto call = parseTokens(tokenize(line));
    if (call.name.empty()) return std::nullopt;
    const auto canonical = canonicalFor(call.name);
    if (call.positionals.empty() && pluralMap_.contains(call.name)) call.positionals.emplace_back("list");
    if (!commands_.contains(canonical)) return "unknown command: " + call.name;
    return unknownOptionError(call, commands_.at(canonical).usage);
}

std::string Router::normalize(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (const unsigned char c : s) out.push_back(static_cast<char>(std::tolower(c)));
    return out;
}

std::string Router::strip_leading_dashes(const std::string& s) {
    size_t i = 0; while (i < s.size() && s[i] == '-') ++i;
    return std::string{s.substr(i)};
}

std::string Router::normalize_alias(const std::string& s) {
    return normalize(strip_leading_dashes(s));
}

std::string Router::joinAliases(const std::unordered_set<std::string>& aliases) {
    if (aliases.empty()) return "-";
    std::vector v(aliases.begin(), aliases.end());
    std::ranges::sort(v.begin(), v.end());
    std::string out;
    for (size_t i=0;i<v.size();++i) { if (i) out += ", "; out += v[i]; }
    return out;
}

std::string Router::pretty_alias(const std::string& a) {
    if (a == "?") return "?";
    if (a.size() == 1) return fmt::format("-{}", a);
    return fmt::format("--{}", a);
}
