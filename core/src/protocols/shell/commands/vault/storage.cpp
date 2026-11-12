// `vh vault storage probe`: the CLI adapter for ops::vault_storage, what the vault's bucket supports for writes that
// must never overwrite (design/encryption/06-publish-without-preconditions.md §7).

#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "CommandUsage.hpp"

#include "ops/Error.hpp"
#include "ops/VaultStorage.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <string>

namespace vh::protocols::shell::commands::vault {

namespace storage_cli {

namespace vsops = vh::ops::vault_storage;
namespace s3cap = vh::storage::s3;

std::string when(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    return std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M UTC", &tm) ? std::string(buf) : std::string("-");
}

std::string probeText(const vsops::ProbeAnswer& a) {
    const auto& p = a.probe;
    std::string out = fmt::format("vault {} ({}): layout {}\n", a.vault_id, a.vault_name, a.layout);
    out += fmt::format("  capability:        {}{}\n", s3cap::to_string(p.capability),
                       a.previous != p.capability || a.previously_changed
                           ? fmt::format(" (was {}{})", s3cap::to_string(a.previous),
                                         a.previously_changed ? ", marked changed" : "")
                           : std::string{});
    out += fmt::format("  conditional PUT:   {}\n", p.conditional_put);
    out += fmt::format("  object versions:   {}\n", p.versioning ? "kept" : "not kept");
    out += fmt::format("  GET If-Match:      {}\n", p.get_if_match ? "honoured" : "not honoured");
    out += fmt::format("  MD5 ETags:         {}\n", p.md5_etags ? "yes" : "no");
    out += fmt::format("  probed:            {}\n", when(p.probed_at));
    if (p.leftover_versions)
        out += fmt::format("  left in the bucket: {} probe version(s) under .vaulthalla/probe/ (deletion refused)\n",
                           p.leftover_versions);
    out += "  " + p.reason + "\n";
    out += a.manifest_publishable
        ? std::string("  the vault's manifest can be published on this bucket\n")
        : std::string("  the vault's encrypted manifest can't be published on this bucket by this server version: its "
                      "sync stalls (manifest_publish_unsupported)\n");
    return out;
}

}

CommandResult handle_vault_storage(const CommandCall& call) {
    namespace d = storage_cli;
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (!isCommandMatch({"vault", "storage", "probe"}, sub))
        return invalid(call.constructFullArgs(), "Unknown vault storage subcommand: '" + std::string(sub) + "'");
    if (subcall.positionals.empty()) return usage(subcall.constructFullArgs());
    const auto book = resolveUsage({"vault", "storage", "probe"});
    validatePositionals(subcall, book);
    const bool json = hasFlag(subcall, book->resolveFlag("json_output")->aliases);
    try {
        const auto lookup = resolveVault(subcall, subcall.positionals[0], book, "vault storage probe");
        if (!lookup || !lookup.ptr) return invalid(lookup.error);
        const auto answer = d::vsops::probe(subcall.user, lookup.ptr->id);
        if (json) return ok(d::vsops::toJson(answer).dump(4));
        return ok(d::probeText(answer));
    } catch (const vh::ops::Error& e) {
        return invalid(std::string("vault storage probe: ") + e.what());
    }
}

}
