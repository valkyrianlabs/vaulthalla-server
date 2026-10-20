#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/SocketIO.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "config/util.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/query/vault/APIKey.hpp"
#include "identities/User.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"
#include "CommandUsage.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <memory>

namespace vh::protocols::shell::commands::vault {

CommandResult handle_vault_update(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "update"});
    validatePositionals(call, usage);

    const auto vLkp = resolveVault(call, call.positionals[0], usage, "vault update");
    if (!vLkp || !vLkp.ptr) return invalid(vLkp.error);
    const auto vault = vLkp.ptr;

    ops::vaults::Update req{.id = vault->id};
    try {
        req.description = optVal(call, usage->resolveOptional("description")->option_tokens);
        req.quota = quotaFromOption(call);
        // --owner names the owner a vault *name* is looked up under (so it matches and changes nothing); with an id
        // it reassigns the vault.
        if (optVal(call, usage->resolveOptional("owner")->option_tokens)) req.owner_id = resolveOwner(call, usage)->id;
        req.api_key_id = apiKeyIdFromOption(call);
        req.bucket = optVal(call, "bucket");
        if (const auto tier = optVal(call, std::vector<std::string>{"storage-tier", "storage-class"}))
            req.storage_tier = std::optional<std::string>{*tier};
        req.encrypt_upstream = encryptFromFlags(call);
        req.sync = syncPatchFromOptions(call);

        if (hasFlag(call, "interactive") && vault->type == ::vh::vault::model::VaultType::S3) {
            if (!call.io) return invalid("vault update --interactive: requires an interactive terminal");
            const auto s3 = std::static_pointer_cast<::vh::vault::model::S3Vault>(vault);
            const auto current = s3->storage_tier_id.value_or("provider default");
            req.storage_tier = std::optional<std::string>{call.io->prompt("Storage tier [provider default]:", current)};
        }
    } catch (const ops::Error& e) {
        return invalid("vault update: " + std::string(e.what()));
    }

    return runVaultChange(call, "vault update", [&](const bool accept) {
        auto attempt = req;
        attempt.accept_waiver = accept;
        return ops::vaults::update(call.user, attempt);
    }, [](const auto& v) { return "Successfully updated vault!\n" + to_string(v); });
}

namespace {

constexpr const char* kDeleteErr = "vault delete";

std::string lowercase(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string when(const std::time_t t) { return db::encoding::timestampToString(t); }

// What happened, and how to undo it while that is still possible.
std::string describeDeletion(const ::vh::vault::model::Deletion& d) {
    const auto id = std::to_string(d.vault_id);
    std::string out = "Vault '" + d.vault_name + "' (ID " + id + ") deleted.";
    if (d.restorable() && d.purge_after > d.deleted_at)
        out += " Restore it until " + when(d.purge_after) + " with: vh vault restore " + id + "\nAfter that its data is purged.";
    else out += " Its data is being purged now and it can no longer be restored.";
    out += " Its encryption key is kept until " + when(d.key_retain_until) + ".\n";
    if (d.isS3()) {
        const auto bucket = "bucket '" + d.bucket.value_or("?") + "'";
        out += d.delete_upstream ? "The objects in " + bucket + " are deleted when the vault is purged.\n"
                                 : "The objects in " + bucket + " are kept.\n";
        if (d.upstreamKeyAtRisk())
            out += "WARNING: they are encrypted with this vault's key, which was never exported. Export it before " +
                   when(d.key_retain_until) + " or that data can never be decrypted:\n  " +
                   ::vh::vault::model::keyExportCommand(d.vault_id) + "\n";
    }
    if (!d.keyExported() && !d.upstreamKeyAtRisk())
        out += "Note: no export of this vault's key was recorded. Encrypted backups of its contents can't be read without "
               "it. It stays exportable until " + when(d.key_retain_until) + ":\n  " +
               ::vh::vault::model::keyExportCommand(d.vault_id) + "\n";
    return out;
}

// The questions, in order: upstream data (S3), the key warning, how to delete, and once more for "now". Each one
// is skipped when its flag already answered it. Returns false when the person cancelled.
bool askHowToDelete(const CommandCall& call, const ops::vaults::RemovalPlan& plan, ops::vaults::Remove& req) {
    auto& io = *call.io;
    const auto& v = *plan.vault;
    const auto id = std::to_string(v.id);
    const bool isS3 = v.type == ::vh::vault::model::VaultType::S3;
    const auto window = ::vh::config::durationToString(plan.retention_window);

    std::string summary = "Delete vault '" + v.name + "' (ID " + id + (isS3 ? ", S3 " + plan.provider + ", bucket '" + plan.bucket + "'" : ", local") +
                          ")?\nIt disappears now and can be restored for " + window + " (vh vault restore " + id +
                          "); then its data is purged. Its encryption key is kept for " +
                          ::vh::config::durationToString(plan.key_retention_window) + ".\n";
    io.print(summary);

    if (isS3 && !req.delete_upstream)
        req.delete_upstream = io.confirm("You are deleting an S3-backed vault on " + (plan.provider.empty() ? std::string("S3") : plan.provider) +
                                         ". Also delete every object in bucket '" + plan.bucket +
                                         "' when the vault is purged? This cannot be undone. [no]", true);

    const bool keyAtRisk = isS3 && plan.encrypted_upstream && !req.delete_upstream.value_or(false) && !plan.keyExported();
    if (keyAtRisk && !req.accept_key_loss) {
        io.print("\n!! WARNING: the objects in bucket '" + plan.bucket + "' are encrypted with this vault's key, and that key\n"
                 "!! has NEVER been exported. Without it you lose the ability to decrypt that upstream data, for good.\n"
                 "!! Export it first:\n!!   " + plan.export_command + "\n"
                 "!! (it stays exportable with that command for " + ::vh::config::durationToString(plan.key_retention_window) +
                 " after the deletion)\n");
        if (io.prompt("Type DELETE WITHOUT KEY to delete anyway, or press Enter to cancel and export the key first:", "") !=
            "DELETE WITHOUT KEY")
            return false;
        req.accept_key_loss = true;
    } else if (!plan.keyExported()) {
        io.print("Note: no export of this vault's key was recorded. Encrypted backups of its contents can't be read "
                 "without it. To export it first:\n  " + plan.export_command + "\n");
    }

    if (!req.now) {
        const auto choice = lowercase(io.prompt("[d]elete (restorable for " + window + "), delete [n]ow, or [c]ancel? [c]", "c"));
        if (choice == "n" || choice == "now") req.now = true;
        else if (choice != "d" && choice != "delete") return false;
    }
    if (req.now && !req.confirm_now) {
        if (io.prompt("Delete '" + v.name + "' now? Its data is removed within moments and cannot be restored. Type the "
                      "vault name to confirm:", "") != v.name)
            return false;
        req.confirm_now = true;
    }
    return true;
}

// The op, repeated after a confirmation it asks for; without a terminal the refusal says which flag accepts it.
CommandResult runRemove(const CommandCall& call, ops::vaults::Remove req, const bool interactive) {
    const auto refused = [](const std::string& why) { return invalid(std::string(kDeleteErr) + ": " + why); };
    for (int attempt = 0; attempt < 3; ++attempt) {
        try {
            return ok(describeDeletion(*ops::vaults::remove(call.user, req)));
        } catch (const ops::NeedsConfirmation& e) {
            const bool keyLoss = e.code == ops::vaults::VAULT_UPSTREAM_KEY_LOSS;
            if (!interactive) {
                noteConfirmationNeeded(e.code, keyLoss ? std::vector<std::string>{"--accept-key-loss"}
                                                       : std::vector<std::string>{"--yes"});
                return refused(std::string(e.what()) + (keyLoss ? "\nRe-run with --accept-key-loss to delete anyway, or "
                                                                  "--delete-upstream to delete the upstream data too."
                                                                : "\nRe-run with --yes to confirm."));
            }
            if (keyLoss) {
                if (call.io->prompt(std::string(e.what()) + "\nType DELETE WITHOUT KEY to delete anyway:", "") != "DELETE WITHOUT KEY")
                    return refused("cancelled; nothing was deleted");
                req.accept_key_loss = true;
            } else {
                if (!call.io->confirm(std::string(e.what()) + " [no]", true)) return refused("cancelled; nothing was deleted");
                req.confirm_now = true;
            }
        } catch (const ops::Error& e) {
            return refused(e.what());
        }
    }
    return refused("too many confirmations; nothing was deleted");
}

}

CommandResult handle_vault_delete(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "delete"});
    validatePositionals(call, usage);

    const bool deleteUp = hasFlag(call, "delete-upstream"), keepUp = hasFlag(call, "keep-upstream");
    if (deleteUp && keepUp) return invalid("vault delete: --delete-upstream and --keep-upstream are mutually exclusive");
    const bool yes = hasFlag(call, "yes");
    const bool interactive = call.io && !yes;

    ops::vaults::Remove req{
        .id = 0,
        .now = hasFlag(call, "now"),
        .delete_upstream = deleteUp ? std::optional<bool>(true) : keepUp ? std::optional<bool>(false) : std::nullopt,
        .confirm_now = yes,
        .accept_key_loss = hasFlag(call, "accept-key-loss")
    };

    const auto vLkp = resolveVault(call, call.positionals[0], usage, kDeleteErr);
    if (!vLkp || !vLkp.ptr) {
        // Already deleted: --now purges it on the next pass.
        std::shared_ptr<::vh::vault::model::Deletion> pending;
        try {
            std::optional<unsigned int> ownerId;
            if (optVal(call, usage->resolveOptional("owner")->option_tokens)) ownerId = resolveOwner(call, usage)->id;
            pending = ops::vaults::findDeleted(call.user, call.positionals[0], ownerId);
        } catch (const std::exception&) {
            return invalid(vLkp.error);
        }
        if (!req.now || pending->state == ::vh::vault::model::DeletionState::Purged)
            return invalid(std::string(kDeleteErr) + ": vault '" + pending->vault_name + "' (ID " + std::to_string(pending->vault_id) +
                           ") is already deleted" +
                           (pending->restorable() ? "; restore it with `vh vault restore " + std::to_string(pending->vault_id) +
                                                        "`, or purge it now with --now"
                                                  : ""));
        req.id = pending->vault_id;
        return runRemove(call, req, interactive);
    }

    req.id = vLkp.ptr->id;
    if (interactive) {
        try {
            if (!askHowToDelete(call, ops::vaults::removalPlan(call.user, req.id), req))
                return invalid("vault delete: cancelled; nothing was deleted");
        } catch (const ops::Error& e) {
            return invalid(std::string(kDeleteErr) + ": " + e.what());
        }
    }
    return runRemove(call, req, interactive);
}

CommandResult handle_vault_restore(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "restore"});
    validatePositionals(call, usage);
    std::optional<unsigned int> ownerId;
    try {
        if (optVal(call, usage->resolveOptional("owner")->option_tokens)) ownerId = resolveOwner(call, usage)->id;
    } catch (const std::exception& e) {
        return invalid(std::string("vault restore: ") + e.what());
    }
    return runOp("vault restore", [&] {
        const auto d = ops::vaults::findDeleted(call.user, call.positionals[0], ownerId);
        return ops::vaults::restore(call.user, d->vault_id);
    }, [](const ops::vaults::VaultPtr& v) {
        return "Vault '" + v->name + "' (ID " + std::to_string(v->id) + ") restored.\n";
    });
}

CommandResult handle_vaults_deleted(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "deleted"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("vault deleted", [&] { return ops::vaults::listDeleted(call.user); },
        [&](const std::vector<ops::vaults::DeletionPtr>& deletions) {
            if (json) return nlohmann::json(deletions).dump(4);
            return ::vh::vault::model::to_string(deletions);
        });
}

}
