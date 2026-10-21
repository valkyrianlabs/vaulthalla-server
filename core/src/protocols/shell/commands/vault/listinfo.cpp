#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"

#include "runtime/Deps.hpp"
#include "log/Registry.hpp"
#include "db/query/vault/Vault.hpp"

#include "storage/Manager.hpp"
#include "storage/Engine.hpp"

#include "vault/model/Vault.hpp"
#include "rbac/role/Vault.hpp"
#include "identities/User.hpp"

#include "config/Registry.hpp"
#include "CommandUsage.hpp"
#include "protocols/shell/Table.hpp"
#include "protocols/shell/util/lineHelpers.hpp"

#include <nlohmann/json.hpp>

#include "rbac/resolver/admin/all.hpp"

#include <optional>
#include <string>
#include <vector>
#include <memory>

#include "rbac/permission/admin/Vaults.hpp"

using namespace vh;
using namespace vh::protocols::shell;
using namespace vh::protocols::shell::commands::vault;
using namespace vh::vault::model;
using namespace vh::rbac;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::storage;
using namespace vh::config;
using namespace vh::crypto;

CommandResult commands::vault::handle_vault_info(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "info"});
    validatePositionals(call, usage);

    const auto vLkp = resolveVault(call, call.positionals[0], usage, "vault info");
    if (!vLkp || !vLkp.ptr) return invalid(vLkp.error);

    return runOp("vault info", [&] { return ops::vaults::get(call.user, vLkp.ptr->id); },
        [](const auto& details) { return to_string(details.vault); });
}

namespace {

// `vh vault list --accessible`: ops::vaults::listAccessible, the same rows as ws storage.vault.accessible.list.
CommandResult listAccessibleVaults(const CommandCall& call) {
    for (const auto* option : {"limit", "page", "sort", "direction", "filter"})
        if (optVal(call, option))
            return invalid(std::string("vault list --accessible: --") + option + " doesn't apply; it lists every vault you can reach");
    const bool json = hasFlag(call, "json");
    return runOp("vault list", [&] { return ops::vaults::listAccessible(call.user); },
        [&](const auto& entries) {
            if (json) {
                auto rows = nlohmann::json::array();
                for (const auto& entry : entries) rows.push_back(ops::vaults::toJson(entry));
                return nlohmann::json{{"vaults", std::move(rows)}}.dump(4);
            }
            Table tbl({
                {"ID", Align::Right, 2, 8, false, false},
                {"NAME", Align::Left, 4, 48, false, false},
                {"OWNER", Align::Left, 5, 24, false, false},
                {"TYPE", Align::Left, 4, 6, false, false},
                {"BROWSE", Align::Left, 6, 6, false, false},
                {"MANAGE", Align::Left, 6, 6, false, false},
                {"VIA", Align::Left, 12, 64, true, false},
            }, term_width());
            for (const auto& entry : entries) {
                std::string via;
                for (const auto reason : entry.via) via += (via.empty() ? "" : ", ") + std::string(ops::vaults::to_string(reason));
                tbl.add_row({std::to_string(entry.vault->id), entry.vault->name,
                             entry.owner_name.empty() ? std::string("N/A") : entry.owner_name,
                             to_string(entry.vault->type), entry.browse ? "yes" : "no", entry.manage ? "yes" : "no",
                             via});
            }
            auto out = tbl.render();
            if (entries.empty()) out += "\nNo vaults you can reach\n";
            return out;
        });
}

}

CommandResult commands::vault::handle_vaults_list(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "list"});
    validatePositionals(call, usage);

    if (hasFlag(call, usage->resolveFlag("accessible")->aliases)) {
        if (hasFlag(call, usage->resolveFlag("local")->aliases) || hasFlag(call, usage->resolveFlag("s3")->aliases))
            return invalid("vault list --accessible: --local and --s3 don't apply; it lists every vault you can reach");
        return listAccessibleVaults(call);
    }

    const bool f_local = hasFlag(call, usage->resolveFlag("local")->aliases);
    const bool f_s3 = hasFlag(call, usage->resolveFlag("s3")->aliases);
    if (f_local && f_s3) return invalid("vaults: --local and --s3 are mutually exclusive");

    std::optional<VaultType> typeFilter = std::nullopt;
    if (f_local) typeFilter = VaultType::Local;
    else if (f_s3) typeFilter = VaultType::S3;

    const bool json = hasFlag(call, "json");
    return runOp("vault list", [&] { return ops::vaults::list(call.user, parseListQuery(call), typeFilter); },
        [&](const auto& vaults) {
            if (json) return nlohmann::json(vaults).dump(4);
            return ::vh::vault::model::to_string(vaults);
        });
}
