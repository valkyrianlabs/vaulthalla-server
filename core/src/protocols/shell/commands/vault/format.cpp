// `vh vault format status`: the CLI adapter for ops::vault_format (#372), the local format conversion's progress.

#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "CommandUsage.hpp"

#include "fs/ops/file.hpp"
#include "ops/VaultFormat.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace vh::protocols::shell::commands::vault {

namespace {

namespace vfops = vh::ops::vault_format;

std::string vfRemaining(const vfops::Remaining& r) {
    return fmt::format("{} ({})", r.items, vh::fs::ops::bytesToSize(r.bytes));
}

std::string vfText(const vfops::FormatStatus& s) {
    std::string out = fmt::format("vault {} ({})\n", s.vault_id, s.vault_name);
    out += fmt::format("  state:         {}{}\n", s.state, s.blocked_reason ? " (" + *s.blocked_reason + ")" : "");
    out += fmt::format("  remaining:     {} item(s)\n", vfRemaining(s.total));
    if (s.converts_live_files)
        out += fmt::format("    live files:  {}\n", vfRemaining(s.files));
    else
        out += fmt::format("    live files:  {}, converted with the bucket's layout migration\n", vfRemaining(s.files));
    out += fmt::format("    recovery:    {} blob(s)\n", vfRemaining(s.blobs));
    if (s.files_other_key_versions)
        out += fmt::format("  other keys:    {} legacy file(s) on a key version a rotation or salvage owns\n",
                           s.files_other_key_versions);
    if (s.last_pass) {
        const auto& p = *s.last_pass;
        out += fmt::format("  last pass:     {} file(s), {} blob(s), {} converted; {} failed, {} deferred, {} changed "
                           "meanwhile{}\n",
                           p.files, p.blobs, vh::fs::ops::bytesToSize(p.bytes), p.failed, p.deferred, p.conflicts,
                           p.blocked ? "; stopped: " + *p.blocked : std::string{});
        if (p.first_error) out += "  first error:   " + *p.first_error + "\n";
    }
    return out;
}

CommandResult vfStatus(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "format", "status"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, usage->resolveFlag("json_output")->aliases);
    try {
        std::optional<unsigned int> vaultId;
        if (call.positionals[0] != "all") {
            const auto lookup = resolveVault(call, call.positionals[0], usage, "vault format status");
            if (!lookup || !lookup.ptr) return invalid(lookup.error);
            vaultId = lookup.ptr->id;
        }
        const auto statuses = vfops::status(call.user, vaultId);
        if (json) {
            nlohmann::json out = nlohmann::json::array();
            for (const auto& s : statuses) out.push_back(vfops::toJson(s));
            return ok(nlohmann::json{{"vaults", out}}.dump(4));
        }
        if (statuses.empty()) return ok("No vaults.");
        std::string out;
        for (const auto& s : statuses) out += vfText(s);
        return ok(out);
    } catch (const vh::ops::Error& e) {
        return invalid(std::string("vault format status: ") + e.what());
    }
}

}

CommandResult handle_vault_format(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [subcommand, subcall] = descend(call);
    if (isCommandMatch({"vault", "format", "status"}, subcommand)) return vfStatus(subcall);
    return invalid("vault format: unknown subcommand '" + std::string(subcommand) + "'. Use: status");
}

}
