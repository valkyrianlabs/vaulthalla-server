// `vh vault recover` (#371, design/encryption/03-metadata-recovery.md §6): ops::vault_recover over the CLI. The kit
// and the export are read by vh on the caller's side and arrive as one bundle (shell/ClientInput.hpp); the daemon
// never opens a path the caller names.

#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/ClientInput.hpp"
#include "protocols/shell/types.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "CommandUsage.hpp"
#include "ops/Error.hpp"
#include "ops/VaultRecover.hpp"
#include "identities/User.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <string>

namespace vh::protocols::shell::commands::vault {

namespace recover_cli {

namespace recover_ops = vh::ops::vault_recover;
namespace keys_ops = vh::ops::vault_keys;

// Best effort: the parsed documents' secrets (seed, key strings) are zeroed once the restore is done with them.
void wipe(nlohmann::json& j) {
    if (j.is_array()) {
        for (auto& e : j) wipe(e);
    } else if (j.is_object()) {
        for (auto it = j.begin(); it != j.end(); ++it) {
            if ((it.key() == "key" || it.key() == "recovery_seed") && it->is_string()) {
                auto& text = it->get_ref<std::string&>();
                std::fill(text.begin(), text.end(), '\0');
            } else {
                wipe(*it);
            }
        }
    }
}

std::string text(const recover_ops::Result& r) {
    const auto& j = r.report;
    std::string out;
    if (r.dry_run)
        out += fmt::format("Dry run: vault {} in the bucket (nothing was written)\n", j.value("vault_uid", ""));
    else
        out += fmt::format("Vault {} ('{}') restored from the bucket ({}){}\n", r.vault_id.value_or(0), r.vault_name,
                           r.mode, r.key_available ? "" : " [not started]");
    const auto& c = j["counts"];
    out += fmt::format("  manifest: {}; {}\n", j.value("blind", false) ? "none usable (blind rebuild)" : "epoch " +
                                               (j["epoch"].is_null() ? std::string("?") : j["epoch"].dump()),
                       j.value("freshness_report", ""));
    out += fmt::format("  {} file(s), {} folder(s), {} symlink(s), {} in the trash, {} provider version(s), {} snapshot(s) "
                       "({} of {} member(s) restorable from the bucket)\n",
                       c.value("files", 0), c.value("folders", 0), c.value("symlinks", 0), c.value("trashed", 0),
                       c.value("provider_versions", 0), c.value("snapshots", 0), c.value("snapshot_members_restorable", 0),
                       c.value("snapshot_members", 0));
    for (const auto& v : j["key_versions"])
        out += fmt::format("  key version {}: {} ({}{})\n", v.value("version", 0), v.value("state", ""),
                           v.value("verdict", ""), v.contains("detail") ? ": " + v["detail"].get<std::string>() : "");
    if (!j["orphans"].empty()) out += fmt::format("  {} orphan object(s) placed under /Recovered\n", j["orphans"].size());
    if (!j["missing_objects"].empty())
        out += fmt::format("  {} file(s) whose object is missing from the bucket (restored as unavailable)\n",
                           j["missing_objects"].size());
    if (!j["rejected_objects"].empty())
        out += fmt::format("  {} object(s) that did not authenticate (left untouched)\n", j["rejected_objects"].size());
    for (const auto& i : j["issues"]) out += "  issue: " + i.get<std::string>() + "\n";
    const auto& d = j["downloads"];
    out += fmt::format("  downloaded: {} manifest, {} envelope, {} header byte(s); {} content byte(s)\n",
                       d.value("manifest_bytes", 0), d.value("envelope_bytes", 0), d.value("header_bytes", 0),
                       d.value("content_bytes", 0));
    if (r.published_epoch) out += fmt::format("  published manifest epoch {}\n", *r.published_epoch);
    if (const auto& s = r.salvage)
        out += fmt::format("  salvage: {} file(s) re-encrypted under key version {}, {} unrecoverable, {} skipped "
                           "(remote), {} deferred, {} failed\n", s->salvaged, s->new_version.value_or(0),
                           s->unrecoverable, s->skipped_remote, s->deferred, s->failed);
    if (r.note) out += "  " + *r.note + "\n";
    return out;
}

}  // namespace recover_cli

CommandResult handle_vault_recover(const CommandCall& call) {
    using namespace recover_cli;
    constexpr const auto* ERR = "vault recover";
    const auto usage = resolveUsage({"vault", "recover"});
    validatePositionals(call, usage);
    if (!call.input)
        return invalid(std::string(ERR) + ": no recovery material came with the request. vh reads --kit and --export on "
                       "your side and sends their contents; the daemon never opens them (is vh older than the daemon?)");
    nlohmann::json bundle, kit, exported;
    try {
        bundle = nlohmann::json::parse(*call.input);
    } catch (const std::exception&) {
        return invalid(std::string(ERR) + ": the attached material is not what vh sends (is vh older than the daemon?)");
    }
    struct Wipe {
        nlohmann::json& a;
        nlohmann::json& b;
        nlohmann::json& c;
        ~Wipe() {
            recover_cli::wipe(a);
            recover_cli::wipe(b);
            for (auto& [_, v] : c.items())
                if (v.is_string()) {
                    auto& t = v.get_ref<std::string&>();
                    std::fill(t.begin(), t.end(), '\0');
                }
        }
    } wipeAll{kit, exported, bundle};
    if (!bundle.is_object() || bundle.value("type", "") != vh::protocols::shell::client_input::kBundleType)
        return invalid(std::string(ERR) + ": the attached material is not what vh sends (is vh older than the daemon?)");
    try {
        if (bundle.contains("kit")) kit = nlohmann::json::parse(bundle["kit"].get<std::string>());
    } catch (const std::exception&) {
        return invalid(std::string(ERR) + ": the --kit file is not a JSON recovery kit");
    }
    try {
        if (bundle.contains("export")) exported = nlohmann::json::parse(bundle["export"].get<std::string>());
    } catch (const std::exception&) {
        return invalid(std::string(ERR) + ": the --export file is not a JSON key export. Decrypt a GPG export first");
    }

    recover_ops::Request req;
    try {
        const auto keyId = apiKeyIdFromOption(call);
        if (!keyId) return invalid(std::string(ERR) + ": --api-key is required");
        req.api_key_id = *keyId;
        req.bucket = optVal(call, "bucket").value_or("");
        req.kit = kit.is_null() ? nullptr : &kit;
        req.exported = exported.is_null() ? nullptr : &exported;
        req.into = optVal(call, std::vector<std::string>{"into", "name"});
        req.vault_uid = optVal(call, "vault-uid");
        if (optVal(call, "owner")) req.owner_id = resolveOwner(call, usage)->id;
        req.accept_rollback = hasFlag(call, "accept-rollback");
        req.dry_run = hasFlag(call, "dry-run");
        req.salvage = hasFlag(call, "salvage");
        req.confirm_name = optVal(call, "confirm-name");
    } catch (const ops::Error& e) {
        return invalid(std::string(ERR) + ": " + e.what());
    }
    const bool json = hasFlag(call, usage->resolveFlag("json_output")->aliases);
    const auto channel = AgentCallScope::active() ? keys_ops::Channel::Agent : keys_ops::Channel::Cli;

    try {
        recover_ops::Result result;
        try {
            result = recover_ops::recover(call.user, req, channel);
        } catch (const ops::NeedsConfirmation& e) {
            if (req.confirm_name)
                return invalid(std::string(ERR) + ": --confirm-name is not the restored vault's name; nothing was written");
            if (!call.io) {
                noteConfirmationNeeded(e.code, {"--confirm-name"});
                return invalid(std::string(ERR) + ": " + e.what() +
                               "\nRe-run in a terminal, or pass --confirm-name <vault name>.");
            }
            req.confirm_name = call.io->prompt(std::string(e.what()) + "\nVault name: ", "");
            try {
                result = recover_ops::recover(call.user, req, channel);
            } catch (const ops::NeedsConfirmation&) {
                return invalid(std::string(ERR) + ": that is not the vault's name; nothing was written");
            }
        }
        if (json) return ok(recover_ops::toJson(result).dump(4));
        return ok(text(result));
    } catch (const ops::Refused& e) {
        if (json) return invalid(nlohmann::json{{"error", e.code}, {"message", e.what()}}.dump(4));
        return invalid(std::string(ERR) + ": " + e.what() + " [" + e.code + "]");
    } catch (const ops::Error& e) {
        return invalid(std::string(ERR) + ": " + e.what());
    }
}

}
