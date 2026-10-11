#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "runtime/Deps.hpp"
#include "CommandUsage.hpp"

#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Key.hpp"
#include "ops/Vaults.hpp"
#include "vault/Retention.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/Key.hpp"

#include "log/Registry.hpp"
#include "sync/Controller.hpp"

#include "storage/Manager.hpp"
#include "storage/Engine.hpp"

#include "vault/EncryptionManager.hpp"
#include "crypto/encryptors/GPG.hpp"

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


// A deleted vault's key stays exportable for the key retention window (#162), from the sealed copy kept with the
// deletion record. Same permission as a live export; the exported_at mark stops the delete flows' warnings.
static CommandResult export_deleted_key(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage,
                                        const std::string& notFound) {
    std::shared_ptr<::vh::vault::model::Deletion> deletion;
    try {
        std::optional<unsigned int> ownerId;
        if (optVal(call, usage->resolveOptional("owner")->option_tokens)) ownerId = resolveOwner(call, usage)->id;
        deletion = ops::vaults::findDeleted(call.user, call.positionals[0], ownerId);
    } catch (const std::exception&) {
        return invalid(notFound);
    }
    if (!deletion->keyRetained())
        return invalid("vault keys export: the key of deleted vault '" + deletion->vault_name + "' was destroyed when its key "
                       "retention window ended");

    auto retained = ::vh::vault::retention::retainedKey(deletion->vault_id);
    auto v = std::make_shared<::vh::vault::model::Vault>();
    v->id = deletion->vault_id;
    v->name = deletion->vault_name;
    auto out = generate_json_key_object(v, retained.key, retained.record, call.user->name());
    sodium_memzero(retained.key.data(), retained.key.size());
    out["deleted_vault"] = true;
    const auto result = handle_key_encrypt_and_response(call, out, usage);
    if (result.exit_code == 0) db::query::vault::Deletion::markKeyExported(deletion->vault_id);
    return result;
}

static CommandResult export_one_key(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage) {
    constexpr const auto* ERR = "vault keys export";

    const auto vaultArg = call.positionals[0];

    const auto engLkp = resolveEngine(call, vaultArg, usage, ERR);
    if (!engLkp || !engLkp.ptr) return export_deleted_key(call, usage, engLkp.error);
    const auto engine = engLkp.ptr;

    const auto context = fmt::format("User: {} -> {}", call.user->name(), __func__);
    const auto& key = engine->encryptionManager->get_key(context);
    const auto vaultKey = db::query::vault::Key::getVaultKey(engine->vault->id);
    if (!vaultKey) return invalid("vault keys export: no key record found for vault ID " + std::to_string(engine->vault->id));

    const auto out = generate_json_key_object(engine->vault, key, vaultKey, call.user->name());
    const auto result = handle_key_encrypt_and_response(call, out, usage);
    if (result.exit_code == 0) db::query::vault::Key::markExported(engine->vault->id, vaultKey->version);
    return result;
}


static CommandResult export_all_keys(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage) {
    const auto engines = runtime::Deps::get().storageManager->getEngines();
    if (engines.empty()) return invalid("vault keys export: no vaults found");

    nlohmann::json out = nlohmann::json::array();

    const auto context = fmt::format("User: {} -> {}", call.user->name(), __func__);
    for (const auto& engine : engines) {
        const auto& key = engine->encryptionManager->get_key(context);
        const auto vaultKey = db::query::vault::Key::getVaultKey(engine->vault->id);
        if (!vaultKey) return invalid("vault keys export: no key record found for vault ID " + std::to_string(engine->vault->id));
        out.push_back(generate_json_key_object(engine->vault, key, vaultKey, call.user->name()));
    }

    const auto result = handle_key_encrypt_and_response(call, out, usage);
    if (result.exit_code == 0)
        for (const auto& item : out)
            db::query::vault::Key::markExported(item.at("vault_id").get<unsigned int>(),
                                                item.at("key_info").at("key_version").get<unsigned int>());
    return result;
}


static CommandResult handle_export_vault_keys(const CommandCall& call) {
    if (!call.user->isSuperAdmin()) {
        if (!call.user->encryptionKeysPerms().canExport()) return invalid(
            "vault keys export: only super admins or users with export encryption keys permission can export vault keys");

        log::Registry::audit()->warn(
            "\n[shell::handle_export_vault_keys] User {} called to export vault keys without super admin privileges\n"
            "WARNING: It is extremely dangerous to assign this permission to non super-admin users, proceed at your own risk.\n",
            call.user->name());
    }

    const auto usage = resolveUsage({"vault", "keys", "export"});
    validatePositionals(call, usage);

    if (call.positionals[0] == "all") return export_all_keys(call, usage);
    return export_one_key(call, usage);
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

    return invalid("vault keys: unknown subcommand '" + std::string(subcommand) + "'. Use: export | rotate | inspect");
}
