// `vh health [list] | ack | silence | unsilence` (design/health/findings.md): ops::health, the same checks as ws
// health.* (admin.stats.view to read, admin.stats.manage to change).

#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "ops/Health.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <ctime>
#include <string>

namespace vh::protocols::shell::commands::health_cli {

namespace {

// "30m", "24h", "7d" -> seconds.
std::uint64_t durationArg(const std::string& value) {
    std::uint64_t amount = 0;
    const auto* end = value.data() + value.size();
    const auto [p, ec] = std::from_chars(value.data(), end, amount);
    if (ec == std::errc{} && p + 1 == end && amount > 0) {
        if (*p == 'm') return amount * 60;
        if (*p == 'h') return amount * 3600;
        if (*p == 'd') return amount * 86400;
    }
    throw ops::Invalid("--for takes a number with m, h or d (30m, 24h, 7d), not '" + value + "'");
}

std::string when(const nlohmann::json& epoch) {
    if (epoch.is_null()) return "";
    const auto t = static_cast<std::time_t>(epoch.get<std::uint64_t>());
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M UTC", &tm);
    return buf;
}

std::string markLine(const nlohmann::json& mark) {
    auto out = mark.at("state").get<std::string>() + " by " + mark.at("set_by_name").get<std::string>();
    if (!mark.at("expires_at").is_null()) out += " until " + when(mark.at("expires_at"));
    if (!mark.at("note").is_null()) out += ": " + mark.at("note").get<std::string>();
    return out;
}

std::string format(const nlohmann::json& health) {
    std::string out;
    const auto& findings = health.at("findings");
    if (findings.empty()) out += "No health findings.\n";
    for (const auto& f : findings) {
        out += f.at("severity").get<std::string>() + "  " + f.at("class").get<std::string>() + "  " +
               f.at("message").get<std::string>() + "\n";
        if (!f.at("mark").is_null()) out += "    " + markLine(f.at("mark")) + "\n";
    }
    if (const auto& silences = health.at("silences"); !silences.empty()) {
        out += "Silenced, not active now:\n";
        for (const auto& s : silences) out += "  " + s.at("class").get<std::string>() + "  " + markLine(s) + "\n";
    }
    const auto errors = health.at("unattended_error_count").get<std::uint64_t>();
    const auto warnings = health.at("unattended_warning_count").get<std::uint64_t>();
    if (!findings.empty())
        out += std::to_string(errors) + " error(s) and " + std::to_string(warnings) +
               " warning(s) still ask for a person.\n";
    return out;
}

bool wantsJson(const CommandCall& call, const std::string& leaf) {
    return hasFlag(call, resolveUsage({"health", leaf})->resolveFlag("json_output")->aliases);
}

CommandResult answer(const std::string_view prefix, const bool json, const std::function<nlohmann::json()>& op,
                     const bool statusFromFindings = false) {
    std::optional<nlohmann::json> health;
    auto out = runOp(prefix, op, [&](const nlohmann::json& h) {
        health = h;
        return json ? nlohmann::json{{"health", h}}.dump(2) + "\n" : format(h);
    });
    if (statusFromFindings && health) {
        if (health->at("unattended_error_count").get<std::uint64_t>() > 0) out.exit_code = 2;
        else if (health->at("unattended_warning_count").get<std::uint64_t>() > 0) out.exit_code = 1;
    }
    return out;
}

CommandResult list(const CommandCall& call) {
    return answer("health", wantsJson(call, "list"), [&] { return ops::health::list(call.user); }, true);
}

CommandResult ack(const CommandCall& call) {
    if (call.positionals.empty()) return invalid(call.constructFullArgs(), "health ack: which class?");
    return answer("health ack", wantsJson(call, "ack"), [&] {
        return ops::health::acknowledge(call.user, call.positionals[0], "", optVal(call, "note"));
    });
}

CommandResult silence(const CommandCall& call) {
    if (call.positionals.empty()) return invalid(call.constructFullArgs(), "health silence: which class?");
    return answer("health silence", wantsJson(call, "silence"), [&] {
        ops::health::SilenceRequest request{.cls = call.positionals[0]};
        if (const auto duration = optVal(call, "for")) request.forSeconds = durationArg(*duration);
        request.severity = optVal(call, "severity");
        request.note = optVal(call, "note");
        return ops::health::silence(call.user, request);
    });
}

CommandResult unsilence(const CommandCall& call) {
    if (call.positionals.empty()) return invalid(call.constructFullArgs(), "health unsilence: which class?");
    return answer("health unsilence", wantsJson(call, "unsilence"),
                  [&] { return ops::health::unsilence(call.user, call.positionals[0], ""); });
}

CommandResult handle(const CommandCall& call) {
    // Help for the group or the subcommand named, before anything runs (`vh health --help` used to list).
    if (hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    // `vh health` alone lists.
    if (call.positionals.empty()) return list(call);
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"health", "list"}, sub)) return list(subcall);
    if (isCommandMatch({"health", "ack"}, sub)) return ack(subcall);
    if (isCommandMatch({"health", "silence"}, sub)) return silence(subcall);
    if (isCommandMatch({"health", "unsilence"}, sub)) return unsilence(subcall);
    return invalid(call.constructFullArgs(), "Unknown health subcommand: '" + std::string(sub) + "'");
}

}

}

void vh::protocols::shell::commands::registerHealthCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("health"), health_cli::handle);
}
