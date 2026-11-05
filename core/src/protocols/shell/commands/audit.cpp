// `vh audit list|verify|export` (#323): ops::audit, the same checks as ws audit.* (admin.audits.view).

#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "ops/Audit.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <ctime>
#include <string>

namespace vh::protocols::shell::commands::audit_cli {

namespace {

// "YYYY-MM-DD" (UTC midnight) or Unix seconds -> µs since the epoch.
std::optional<uint64_t> timeArg(const CommandCall& call, const std::string& key) {
    const auto value = optVal(call, key);
    if (!value) return std::nullopt;
    const auto& v = *value;
    uint64_t seconds = 0;
    if (const auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), seconds);
        ec == std::errc{} && p == v.data() + v.size())
        return seconds * 1'000'000;
    std::tm tm{};
    int y = 0, m = 0, d = 0;
    if (v.size() == 10 && std::sscanf(v.c_str(), "%4d-%2d-%2d", &y, &m, &d) == 3 && m >= 1 && m <= 12 && d >= 1 &&
        d <= 31) {
        tm.tm_year = y - 1900;
        tm.tm_mon = m - 1;
        tm.tm_mday = d;
        return static_cast<uint64_t>(timegm(&tm)) * 1'000'000;
    }
    throw ops::Invalid("--" + key + " must be YYYY-MM-DD or Unix seconds, not '" + v + "'");
}

std::string formatEvents(const ops::audit::Page& page) {
    if (page.events.empty()) return "No audit events.\n";
    std::string out;
    for (const auto& r : page.events) {
        const auto j = ops::audit::toJson(r);
        out += std::to_string(r.seq) + "  " + j.at("occurred_at").get<std::string>() + "  " + r.action + "  " +
               r.outcome + "  " + (r.actor.empty() ? std::string("-") : r.actor) + "  " + r.message + "\n";
    }
    if (page.next_before) out += "(older events: --until or a larger --limit)\n";
    return out;
}

std::string formatVerification(const ops::audit::Verification& v) {
    std::string out = v.ok ? "Audit trail intact.\n" : "AUDIT TRAIL FAILED VERIFICATION.\n";
    out += "  events checked: " + std::to_string(v.events_checked);
    if (v.first_seq) out += " (" + std::to_string(*v.first_seq) + ".." + std::to_string(v.last_seq.value_or(0)) + ")";
    out += "\n";
    if (v.anchor_seq) out += "  starts after retention checkpoint " + std::to_string(*v.anchor_seq) + "\n";
    out += "  signed heads: " + std::to_string(v.heads_valid) + " valid, " + std::to_string(v.heads_invalid) +
           " invalid; " + std::to_string(v.unsigned_events) + " event(s) since the last signed head\n";
    if (v.broken_at) out += "  broken at event " + std::to_string(*v.broken_at) + ": " + v.problem + "\n";
    for (const auto& p : v.head_problems) out += "  " + p + "\n";
    return out;
}

CommandResult list(const CommandCall& call) {
    const bool json = hasFlag(call, "json_output");
    return runOp("audit list", [&] {
        ops::audit::Filter filter;
        filter.action_prefix = optVal(call, "action");
        filter.since_us = timeArg(call, "since");
        filter.until_us = timeArg(call, "until");
        std::size_t limit = 50;
        if (const auto n = optVal(call, "limit")) {
            const auto [p, ec] = std::from_chars(n->data(), n->data() + n->size(), limit);
            if (ec != std::errc{} || p != n->data() + n->size()) throw ops::Invalid("--limit must be a number");
        }
        return ops::audit::list(call.user, filter, limit);
    }, [&](const ops::audit::Page& page) {
        if (!json) return formatEvents(page);
        nlohmann::json events = nlohmann::json::array();
        for (const auto& r : page.events) events.push_back(ops::audit::toJson(r));
        return nlohmann::json{{"events", events}}.dump(2) + "\n";
    });
}

CommandResult verify(const CommandCall& call) {
    const bool json = hasFlag(call, "json_output");
    std::optional<ops::audit::Verification> result;
    auto out = runOp("audit verify", [&] { return ops::audit::verify(call.user); },
                     [&](const ops::audit::Verification& v) {
                         result = v;
                         return json ? ops::audit::toJson(v).dump(2) + "\n" : formatVerification(v);
                     });
    if (result && !result->ok) out.exit_code = 1;
    return out;
}

CommandResult exportEvents(const CommandCall& call) {
    std::string ndjson;
    return runOp("audit export", [&] {
        return ops::audit::exportNdjson(call.user, timeArg(call, "since"), timeArg(call, "until"),
                                        [&](const std::string_view line) {
                                            ndjson.append(line);
                                            ndjson.push_back('\n');
                                        });
    }, [&](uint64_t) { return std::move(ndjson); });
}

CommandResult handle(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"audit", "list"}, sub)) return list(subcall);
    if (isCommandMatch({"audit", "verify"}, sub)) return verify(subcall);
    if (isCommandMatch({"audit", "export"}, sub)) return exportEvents(subcall);
    return invalid(call.constructFullArgs(), "Unknown audit subcommand: '" + std::string(sub) + "'");
}

}

}

void vh::protocols::shell::commands::registerAuditCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("audit"), audit_cli::handle);
}
