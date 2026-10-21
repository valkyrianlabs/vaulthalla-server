#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "runtime/Deps.hpp"
#include "CommandUsage.hpp"

#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Key.hpp"
#include "ops/Vaults.hpp"
#include "ops/VaultKeys.hpp"
#include "vault/Retention.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/Key.hpp"

#include "log/Registry.hpp"
#include "sync/Controller.hpp"

#include "storage/Manager.hpp"
#include "storage/Engine.hpp"

#include "vault/EncryptionManager.hpp"
#include "crypto/encryptors/GPG.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/encoding/timestamp.hpp"

#include "vault/model/Vault.hpp"
#include "vault/model/APIKey.hpp"
#include "identities/User.hpp"

#include "config/Registry.hpp"
#include "CommandUsage.hpp"
#include "usages.hpp"

#include "rbac/permission/admin/Keys.hpp"

#include <optional>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <sodium.h>

using namespace vh;
using namespace vh::protocols::shell;
using namespace vh::protocols::shell::commands::vault;


static CommandResult handle_key_encrypt_and_response(const CommandCall& call,
                                                     const nlohmann::json& output,
                                                     const std::shared_ptr<CommandUsage>& usage) {
    const auto outputOpt = optVal(call, usage->resolveOptional("output")->option_tokens);

    if (const auto recipientOpt = optVal(call, usage->resolveOptional("recipient")->option_tokens)) {
        if (recipientOpt->empty()) return invalid("vault keys export: --recipient requires a value");
        if (!outputOpt) return invalid("vault keys export: --recipient requires --output to specify the output file");

        if (const auto pathError = secretOutputPathError(*outputOpt)) return invalid("vault keys export: " + *pathError);

        try {
            writePrivateFile(*outputOpt, ""); // pre-create 0600 so gpg's output never exists with a looser mode
            crypto::encryptors::GPG::encryptToFile(output, *recipientOpt, *outputOpt);
            restrictToOwner(*outputOpt);
            return ok("Vault key successfully encrypted and saved to " + *outputOpt);
        } catch (const std::exception& e) {
            return invalid("vault keys export: failed to encrypt vault key: " + std::string(e.what()));
        }
    }

    if (outputOpt) {
        if (const auto pathError = secretOutputPathError(*outputOpt)) return invalid("vault keys export: " + *pathError);
        log::Registry::audit()->warn(
            "[shell::handle_key_encrypt_and_response] No recipient specified, saving unencrypted key(s) to " + *
            outputOpt);
        try {
            writePrivateFile(*outputOpt, output.dump(4)); // mode 0600, symlinks refused
            return {0, "Vault key(s) successfully saved to " + *outputOpt,
                    "\nWARNING: No recipient specified, key(s) are unencrypted.\n"
                    "\nConsider using --recipient with a GPG fingerprint to encrypt the key(s) before saving."};
        } catch (const std::exception& e) {
            return invalid("vault keys export: failed to write to output file: " + std::string(e.what()));
        }
    }

    log::Registry::audit()->warn(
        "[shell::handle_key_encrypt_and_response] No recipient specified, returning unencrypted key(s)");
    return {0, output.dump(4),
            "\nWARNING: No recipient specified, key(s) are unencrypted.\n"
            "\nConsider using --recipient with a GPG fingerprint along with --output\nto securely encrypt the key(s) to an output file."};
}


namespace keys_ops = vh::ops::vault_keys;

// D4: the local CLI may take key bytes; an MCP client (/mcp or a `vh mcp` call) may not.
static keys_ops::Channel cli_channel() {
    return AgentCallScope::active() ? keys_ops::Channel::Agent : keys_ops::Channel::Cli;
}

// The vault a key command names: a live vault (with or without a running engine), else a deleted one within its key
// retention window (by id or name, #162). Empty with `error` set when neither matches.
static std::optional<unsigned int> resolve_key_vault(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage,
                                                     const std::string& errPrefix, std::string& error) {
    const auto& arg = call.positionals[0];
    const auto lookup = resolveVault(call, arg, usage, errPrefix);
    if (lookup && lookup.ptr) return lookup.ptr->id;
    try {
        std::optional<unsigned int> ownerId;
        if (optVal(call, usage->resolveOptional("owner")->option_tokens)) ownerId = resolveOwner(call, usage)->id;
        return ops::vaults::findDeleted(call.user, arg, ownerId)->vault_id;
    } catch (const std::exception&) {
        error = lookup.error;
        return std::nullopt;
    }
}

static CommandResult export_one_key(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage) {
    std::string error;
    const auto vaultId = resolve_key_vault(call, usage, "vault keys export", error);
    if (!vaultId) return invalid(error);
    const auto exported = keys_ops::exportVault(call.user, *vaultId, cli_channel());
    const auto result = handle_key_encrypt_and_response(call, keys_ops::toJson(exported, call.user->name()), usage);
    if (result.exit_code == 0) keys_ops::recordExport(exported);
    return result;
}

static CommandResult export_all_keys(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage) {
    const auto all = keys_ops::exportAll(call.user, cli_channel());
    if (all.vaults.empty() && all.skipped.empty()) return invalid("vault keys export: no vaults found");

    nlohmann::json out = nlohmann::json::array();
    for (const auto& exported : all.vaults) out.push_back(keys_ops::toJson(exported, call.user->name()));
    auto result = handle_key_encrypt_and_response(call, out, usage);
    if (result.exit_code == 0)
        for (const auto& exported : all.vaults) keys_ops::recordExport(exported);
    for (const auto& skipped : all.skipped)
        result.stderr_text += "\nWARNING: not exported, the key can't be read on this host: " + skipped;
    if (!all.skipped.empty()) result.stderr_text += "\nRestore those keys with `vh vault keys import`.\n";
    return result;
}


static CommandResult handle_export_vault_keys(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "keys", "export"});
    validatePositionals(call, usage);
    try {
        if (call.positionals[0] == "all") return export_all_keys(call, usage);
        return export_one_key(call, usage);
    } catch (const ops::Error& e) {
        return invalid(std::string("vault keys export: ") + e.what());
    }
}

// Best effort: the parsed export's key strings are zeroed once the import is done with them.
static void wipe_keys(nlohmann::json& j) {
    if (j.is_array()) {
        for (auto& e : j) wipe_keys(e);
    } else if (j.is_object()) {
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (it.key() == "key" && it->is_string()) {
                auto& text = it->get_ref<std::string&>();
                std::fill(text.begin(), text.end(), '\0');
            } else {
                wipe_keys(*it);
            }
        }
    }
}

static std::string import_text(const keys_ops::ImportResult& r) {
    std::string out = fmt::format("Vault {} ('{}'){}: {}\n", r.vault_id, r.vault_name, r.deleted ? " [deleted]" : "",
                                  r.salvage ? "salvaged" : r.written ? "keys restored" : "nothing written");
    for (const auto& v : r.versions)
        out += fmt::format("  version {}: {} ({})\n", v.version, keys_ops::to_string(v.outcome), v.detail);
    if (const auto& s = r.salvage) {
        out += fmt::format("  salvage: {} file(s) re-encrypted under new key version {}, {} unrecoverable, {} skipped "
                           "(remote), {} deferred, {} failed\n", s->salvaged, s->new_version.value_or(0),
                           s->unrecoverable, s->skipped_remote, s->deferred, s->failed);
        for (const auto& f : s->failures)
            out += fmt::format("    {} {} (version {}): {}\n", f.kind, f.path, f.version, f.reason);
    }
    out += r.key_available ? "  the vault's key is available on this host\n" : "";
    if (r.note) out += "  " + *r.note + "\n";
    return out;
}

static CommandResult handle_vault_keys_import(const CommandCall& call) {
    constexpr const auto* ERR = "vault keys import";
    const auto usage = resolveUsage({"vault", "keys", "import"});
    validatePositionals(call, usage);
    if (!call.input)
        return invalid(std::string(ERR) + ": no key file came with the request. vh reads --file on your side and sends "
                       "its contents; the daemon never opens it (is vh older than the daemon?)");
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(*call.input);
    } catch (const std::exception&) {
        return invalid(std::string(ERR) + ": the file is not a JSON key export. Decrypt a GPG export first: gpg "
                       "--decrypt <file> | vh vault keys import <vault> --file - --confirm-name <vault name>");
    }
    struct Wipe {
        nlohmann::json& j;
        ~Wipe() { wipe_keys(j); }
    } wipe{doc};

    std::string error;
    const auto vaultId = resolve_key_vault(call, usage, ERR, error);
    if (!vaultId) return invalid(error);
    const bool json = hasFlag(call, usage->resolveFlag("json_output")->aliases);
    const auto confirmName = optVal(call, "confirm-name");
    const auto mode = hasFlag(call, usage->resolveFlag("salvage")->aliases) ? keys_ops::ImportMode::Salvage
                                                                            : keys_ops::ImportMode::Recover;
    const auto run = [&](const std::optional<std::string>& name) {
        return keys_ops::importKeys(call.user, {.vault_id = *vaultId, .keys = &doc, .confirm_name = name, .mode = mode},
                                    cli_channel());
    };

    try {
        keys_ops::ImportResult result;
        try {
            result = run(confirmName);
        } catch (const ops::NeedsConfirmation& e) {
            if (confirmName)
                return invalid(std::string(ERR) + ": --confirm-name is not the vault's name; nothing was written");
            if (!call.io) {
                noteConfirmationNeeded(e.code, {"--confirm-name"});
                return invalid(std::string(ERR) + ": " + e.what() +
                               "\nRe-run in a terminal, or pass --confirm-name <vault name>.");
            }
            const auto typed = call.io->prompt(std::string(e.what()) + "\nVault name: ", "");
            try {
                result = run(typed);
            } catch (const ops::NeedsConfirmation&) {
                return invalid(std::string(ERR) + ": that is not the vault's name; nothing was written");
            }
        }
        if (json) return ok(keys_ops::toJson(result).dump(4));
        return ok(import_text(result));
    } catch (const ops::Error& e) {
        return invalid(std::string(ERR) + ": " + e.what());
    }
}

static std::string status_text(const keys_ops::KeyStatus& s) {
    std::string out = fmt::format("Vault {} ('{}'){}\n", s.vault_id, s.vault_name, s.deleted ? " [deleted]" : "");
    out += fmt::format("  key version:   {}\n", s.version);
    out += fmt::format("  key check:     {}\n", s.key_check.value_or("unavailable"));
    if (s.unavailable_reason)
        out += "  unavailable:   " + *s.unavailable_reason + " (" + s.unavailable_detail.value_or("") + ")\n";
    if (s.exported_version)
        out += fmt::format("  exported:      version {}{}{}\n", *s.exported_version,
                           s.exported_at ? " at " + db::encoding::timestampToString(*s.exported_at) : std::string{},
                           *s.exported_version == s.version ? "" : " (stale: export the current version)");
    else
        out += "  exported:      never\n";
    out += fmt::format("  rotation:      {}\n", s.rotation_in_progress ? "in progress" : "none");
    for (const auto& n : s.needed_versions)
        out += fmt::format("  needed:        version {} ({}) {}\n", n.version, keys_ops::to_string(n.reason),
                           n.key_check.value_or("MISSING"));
    if (s.key_retain_until)
        out += "  key kept until " + db::encoding::timestampToString(*s.key_retain_until) + "\n";
    return out;
}

static CommandResult handle_vault_keys_status(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "keys", "status"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, usage->resolveFlag("json_output")->aliases);
    try {
        std::optional<unsigned int> vaultId;
        if (call.positionals[0] != "all") {
            std::string error;
            vaultId = resolve_key_vault(call, usage, "vault keys status", error);
            if (!vaultId) return invalid(error);
        }
        const auto statuses = keys_ops::status(call.user, vaultId);
        if (json) {
            nlohmann::json out = nlohmann::json::array();
            for (const auto& s : statuses) out.push_back(keys_ops::toJson(s));
            return ok(nlohmann::json{{"vaults", out}}.dump(4));
        }
        if (statuses.empty()) return ok("No vaults.");
        std::string out;
        for (const auto& s : statuses) out += status_text(s);
        return ok(out);
    } catch (const ops::Error& e) {
        return invalid(std::string("vault keys status: ") + e.what());
    }
}


static CommandResult handle_inspect_vault_key(const CommandCall& call) {
    constexpr const auto* ERR = "vault keys inspect";

    if (!call.user->isSuperAdmin()) {
        if (!call.user->encryptionKeysPerms().canView())
            return invalid("vault keys inspect: only super admins or users with view encryption keys permission can inspect vault keys");

        log::Registry::audit()->warn(
            "\n[shell::handle_inspect_vault_key] User {} called to inspect vault keys without super admin privileges\n"
            "WARNING: It is extremely dangerous to assign this permission to non super-admin users, proceed at your own risk.\n",
            call.user->name());
    }

    const auto usage = resolveUsage({"vault", "keys", "inspect"});
    validatePositionals(call, usage);

    const auto engLkp = resolveEngine(call, call.positionals[0], usage, ERR);
    if (!engLkp || !engLkp.ptr) return invalid(engLkp.error);
    const auto engine = engLkp.ptr;

    const auto vaultKey = db::query::vault::Key::getVaultKey(engine->vault->id);
    if (!vaultKey) return invalid("vault keys inspect: no key record found for vault ID " + std::to_string(engine->vault->id));

    return ok(generate_json_key_info_object(engine->vault, vaultKey, call.user->name()).dump(4));
}


static CommandResult handle_rotate_vault_keys(const CommandCall& call) {
    constexpr const auto* ERR = "vault keys rotate";

    if (!call.user->isSuperAdmin()) {
        if (!call.user->encryptionKeysPerms().canRotate())
            return invalid("vault keys rotate: only super admins or users with rotate encryption keys permission can rotate vault keys");

        log::Registry::audit()->warn(
            "\n[shell::handle_rotate_vault_keys] User {} called to rotate vault keys without super admin privileges\n"
            "WARNING: It is extremely dangerous to assign this permission to non super-admin users, proceed at your own risk.\n",
            call.user->name());
    }

    const auto usage = resolveUsage({"vault", "keys", "rotate"});
    validatePositionals(call, usage);

    const auto syncNow = hasFlag(call, usage->resolveFlag("now")->aliases);

    // Reports what actually happened per vault: prepare_key_rotation() is a silent no-op while a rotation is
    // already pending, so that case must not be announced as a fresh rotation.
    const auto rotateKey = [&syncNow](const std::shared_ptr<storage::Engine>& engine) -> std::string {
        const auto label = "'" + engine->vault->name + "' (ID: " + std::to_string(engine->vault->id) + ")";
        const bool alreadyPending = db::query::vault::Key::keyRotationInProgress(engine->vault->id);
        if (!alreadyPending) engine->encryptionManager->prepare_key_rotation();

        std::string line = alreadyPending
            ? "Key rotation for " + label + " is already pending; no new rotation was started."
            : "Key rotation started for " + label + ".";

        if (syncNow) {
            using RunNowResult = ::vh::sync::Controller::RunNowResult;
            switch (runtime::Deps::get().syncController->runNow(engine->vault->id)) {
                case RunNowResult::Started: line += " Sync triggered to re-encrypt data now."; break;
                case RunNowResult::Rerun: line += " Sync already running; an immediate rerun was queued."; break;
                case RunNowResult::NoTask:
                default: line += " WARNING: no sync task is loaded for this vault, so re-encryption did not start."; break;
            }
        } else {
            line += " Existing data is re-encrypted by the next scheduled sync (use --now to sync immediately).";
        }
        return line + "\n";
    };

    const auto vaultArg = call.positionals[0];

    if (vaultArg == "all") {
        std::string out;
        for (const auto& engine : runtime::Deps::get().storageManager->getEngines())
            out += rotateKey(engine);
        if (out.empty()) return invalid("vault keys rotate: no vaults found");
        return ok(out);
    }

    const auto engLkp = resolveEngine(call, vaultArg, usage, ERR);
    if (!engLkp || !engLkp.ptr) return invalid(engLkp.error);
    const auto engine = engLkp.ptr;

    return ok(rotateKey(engine));
}

static bool isVaultKeysMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"vault", "keys", cmd}, input);
}

CommandResult commands::vault::handle_vault_keys(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [subcommand, subcall] = descend(call);

    if (isVaultKeysMatch("export", subcommand)) return handle_export_vault_keys(subcall);
    if (isVaultKeysMatch("rotate", subcommand)) return handle_rotate_vault_keys(subcall);
    if (isVaultKeysMatch("inspect", subcommand)) return handle_inspect_vault_key(subcall);
    if (isVaultKeysMatch("status", subcommand)) return handle_vault_keys_status(subcall);
    if (isVaultKeysMatch("import", subcommand)) return handle_vault_keys_import(subcall);

    return invalid("vault keys: unknown subcommand '" + std::string(subcommand) +
                   "'. Use: status | export | import | rotate | inspect");
}
