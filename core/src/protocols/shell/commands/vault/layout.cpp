// `vh vault migrate-layout`: the CLI adapter for ops::vault_layout (#373), the bucket layout migration path_v0 ->
// opaque_v1 (status, start, cleanup dry run and confirmation).

#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "CommandUsage.hpp"

#include "fs/ops/file.hpp"
#include "ops/Error.hpp"
#include "ops/VaultLayout.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <optional>
#include <string>

namespace vh::protocols::shell::commands::vault {

namespace layout_cli {

namespace vlops = vh::ops::vault_layout;
namespace lm = vh::vault::layout;

std::string when(const std::optional<std::time_t>& t) {
    if (!t) return "-";
    std::tm tm{};
    gmtime_r(&*t, &tm);
    char buf[32];
    return std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M UTC", &tm) ? std::string(buf) : std::string("-");
}

std::string entryLine(const lm::CleanupEntry& e) {
    std::string out = "    " + e.key;
    if (e.version_id) out += "@" + *e.version_id;
    if (e.delete_marker) out += " (delete marker)";
    if (!e.reason.empty()) out += ": " + e.reason;
    if (e.retain_until) out += ", until " + when(e.retain_until);
    return out + "\n";
}

std::string counts(const vlops::ItemCounts& c) {
    return fmt::format("{} verified, {} superseded, {} pending, {} kept, {} failed", c.verified, c.superseded,
                       c.pending, c.skipped, c.failed);
}

std::string statusText(const vlops::Status& s) {
    std::string out = fmt::format("vault {} ({}): layout {}\n", s.vault_id, s.vault_name, s.layout);
    if (!s.migration) {
        out += s.layout == "path_v0" ? "  no migration yet: vh vault migrate-layout " + std::to_string(s.vault_id) + "\n"
                                     : "  nothing to migrate\n";
        return out;
    }
    const auto& m = *s.migration;
    out += fmt::format("  state:         {}{}\n", lm::to_string(m.state),
                       m.attempts ? fmt::format(" (attempt {})", m.attempts + 1) : std::string{});
    out += fmt::format("  started:       {}\n", when(m.started_at));
    if (m.cutover_at) out += fmt::format("  cut over:      {}\n", when(m.cutover_at));
    if (m.cleanup_after) out += fmt::format("  cleanup after: {}\n", when(m.cleanup_after));
    if (m.cutover_at)
        out += fmt::format("  manifest:      {}\n", m.manifest_verified_at ? "verified from the bucket " + when(m.manifest_verified_at)
                                                                           : std::string("not verified yet"));
    if (m.completed_at) out += fmt::format("  complete:      {}\n", when(m.completed_at));
    out += fmt::format("  versions:      {}\n", counts(s.versions));
    out += fmt::format("  markers:       {}\n", counts(s.markers));
    out += fmt::format("  backlog:       {}\n", counts(s.backlog));
    out += fmt::format("  files:         {}\n", counts(s.current));
    out += fmt::format("  legacy left:   {} version(s) and marker(s) with path names ({} deleted)\n", s.legacy_listed,
                       s.legacy_deleted);
    if (m.estimate) {
        const auto e = lm::estimateFromJson(*m.estimate);
        out += fmt::format("  estimate:      {} LIST, {} HEAD, {} GET, {} PUT, {} DELETE; {} down, {} up{}\n",
                           e.list_requests, e.head_requests, e.get_requests, e.put_requests, e.delete_requests,
                           vh::fs::ops::bytesToSize(e.download_bytes), vh::fs::ops::bytesToSize(e.upload_bytes),
                           e.estimated_cost ? " (" + *e.estimated_cost + ")" : std::string(" (unpriced)"));
    }
    if (m.last_error) out += "  last error:    " + *m.last_error + "\n";
    if (s.blocked_total) {
        out += fmt::format("  staying in the bucket ({}):\n", s.blocked_total);
        for (const auto& e : s.blocked) out += entryLine(e);
        if (s.blocked_total > s.blocked.size()) out += fmt::format("    ... {} more\n", s.blocked_total - s.blocked.size());
    }
    return out;
}

std::string cleanupText(const vlops::CleanupAnswer& a, const std::string& vaultName) {
    const auto& p = a.plan;
    std::string out;
    if (a.started)
        out += fmt::format("Cleanup confirmed: {} legacy version(s) and marker(s) ({}) are deleted by version id in the "
                           "background. vh vault migrate-layout {} --status follows it.\n",
                           p.deletable, vh::fs::ops::bytesToSize(p.deletable_bytes), vaultName);
    else
        out += fmt::format("Dry run (nothing deleted): {} legacy version(s) and marker(s), {}, would be deleted by "
                           "version id; {} stay.\n",
                           p.deletable, vh::fs::ops::bytesToSize(p.deletable_bytes), p.kept.size());
    if (p.oldest) out += fmt::format("  oldest {}, newest {}\n", when(p.oldest), when(p.newest));
    if (a.cleanup_after) out += fmt::format("  allowed from {}\n", when(a.cleanup_after));
    if (!p.kept.empty()) {
        out += "  staying:\n";
        for (std::size_t i = 0; i < p.kept.size() && i < 200; ++i) out += entryLine(p.kept[i]);
    }
    if (!a.started)
        out += fmt::format("Confirm with: vh vault migrate-layout {} --cleanup --confirm {}\n", vaultName, vaultName);
    return out;
}

}

CommandResult handle_vault_migrate_layout(const CommandCall& call) {
    namespace d = layout_cli;
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto book = resolveUsage({"vault", "migrate-layout"});
    validatePositionals(call, book);
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    try {
        const auto lookup = resolveVault(call, call.positionals[0], book, "vault migrate-layout");
        if (!lookup || !lookup.ptr) return invalid(lookup.error);
        const auto vaultId = lookup.ptr->id;
        const auto confirm = optVal(call, "confirm");
        if (confirm && !hasFlag(call, "cleanup")) return invalid("vault migrate-layout: --confirm goes with --cleanup");

        if (hasFlag(call, "cleanup")) {
            const auto answer = d::vlops::cleanup(call.user, {.vault_id = vaultId, .confirm = confirm});
            if (json) return ok(d::vlops::toJson(answer).dump(4));
            return ok(d::cleanupText(answer, lookup.ptr->name));
        }
        if (hasFlag(call, "status")) {
            const auto statuses = d::vlops::status(call.user, vaultId);
            if (json) return ok(d::vlops::toJson(statuses.front()).dump(4));
            return ok(d::statusText(statuses.front()));
        }
        const auto started = d::vlops::start(call.user, {.vault_id = vaultId,
                                                          .accept_unpriced = hasFlag(call, "accept-unpriced")});
        if (json) return ok(d::vlops::toJson(started).dump(4));
        return ok(fmt::format("Layout migration of vault {} ('{}') started; it runs in the background.\n"
                              "Follow it with: vh vault migrate-layout {} --status\n",
                              started.vault_id, started.vault_name, started.vault_id));
    } catch (const vh::ops::Error& e) {
        return invalid(std::string("vault migrate-layout: ") + e.what());
    }
}

}
