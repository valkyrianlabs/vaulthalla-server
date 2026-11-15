// `vh vault leave` and `vh vault replica remove` (replicated vaults, experimental; ops::vault_replicas). `vh vault join`
// is recover.cpp's (the same restore in join mode).
#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "CommandUsage.hpp"

#include "ops/Error.hpp"
#include "ops/VaultReplicas.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <string>

namespace vh::protocols::shell::commands::vault {

namespace replicas_cli {

namespace rops = vh::ops::vault_replicas;

rops::Channel channel() { return AgentCallScope::active() ? rops::Channel::Agent : rops::Channel::Cli; }

CommandResult refusal(const char* err, const vh::ops::Error& e, const bool json) {
    if (const auto* r = dynamic_cast<const vh::ops::Refused*>(&e)) {
        if (json) return invalid(nlohmann::json{{"error", r->code}, {"message", r->what()}}.dump(4));
        return invalid(std::string(err) + ": " + r->what() + " [" + r->code + "]");
    }
    return invalid(std::string(err) + ": " + e.what());
}

}  // namespace replicas_cli

CommandResult handle_vault_leave(const CommandCall& call) {
    using namespace replicas_cli;
    constexpr const auto* ERR = "vault leave";
    const auto book = resolveUsage({"vault", "leave"});
    validatePositionals(call, book);
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    const bool keep = hasFlag(call, "keep-local"), del = hasFlag(call, "delete-local");
    if (keep == del) return invalid(std::string(ERR) + ": say what happens to this server's copy: --keep-local or --delete-local");
    try {
        const auto lookup = resolveVault(call, call.positionals[0], book, ERR);
        if (!lookup || !lookup.ptr) return invalid(lookup.error);
        const auto r = rops::leave(call.user, lookup.ptr->id, del, channel());
        if (json) return ok(rops::toJson(r).dump(4));
        std::string out = r.published_epoch
            ? fmt::format("Vault {} left: manifest epoch {} no longer names this server; sync is off here.\n", r.vault_id,
                          *r.published_epoch)
            : fmt::format("Vault {}: sync is off here.\n", r.vault_id);
        if (r.deleted_local) out += "  This server's copy is deleted (the bucket and the other writers are untouched).\n";
        else out += "  This server's copy is kept as it is.\n";
        if (!r.note.empty()) out += "  " + r.note + "\n";
        return ok(out);
    } catch (const vh::ops::Error& e) {
        return refusal(ERR, e, json);
    }
}

CommandResult handle_vault_replica(const CommandCall& call) {
    using namespace replicas_cli;
    constexpr const auto* ERR = "vault replica remove";
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (!isCommandMatch({"vault", "replica", "remove"}, sub))
        return invalid(call.constructFullArgs(), "Unknown vault replica subcommand: '" + std::string(sub) + "'");
    const auto book = resolveUsage({"vault", "replica", "remove"});
    validatePositionals(subcall, book);
    const bool json = hasFlag(subcall, book->resolveFlag("json_output")->aliases);
    if (subcall.positionals.size() < 2) return usage(subcall.constructFullArgs());
    try {
        const auto lookup = resolveVault(subcall, subcall.positionals[0], book, ERR);
        if (!lookup || !lookup.ptr) return invalid(lookup.error);
        const auto r = rops::removeReplica(subcall.user, lookup.ptr->id, subcall.positionals[1], channel());
        if (json) return ok(rops::toJson(r).dump(4));
        return ok(fmt::format("Vault {}: {} is no longer a writer (manifest epoch {}).{}\n{}", r.vault_id, r.node,
                              r.published_epoch,
                              r.solo ? " This server is the only writer now: the vault is solo again." : "",
                              r.cloud.empty() ? "" : "  " + r.cloud + ".\n"));
    } catch (const vh::ops::Error& e) {
        return refusal(ERR, e, json);
    }
}

}
