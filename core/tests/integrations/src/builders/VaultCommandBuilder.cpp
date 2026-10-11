#include "cmd/Builder.hpp"
#include "cmd/generators.hpp"
#include "cli/Context.hpp"
#include "CommandUsage.hpp"
#include "vault/model/Vault.hpp"
#include "identities/User.hpp"
#include "identities/Group.hpp"

using namespace vh::vault::model;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::rbac;

namespace vh::test::integration::cmd {
    VaultCommandBuilder::VaultCommandBuilder(const std::shared_ptr<protocols::shell::UsageManager>& usage, const std::shared_ptr<cli::Context>& ctx)
        : Builder(usage, ctx, "vault"), vaultAliases_(ctx) {}

    std::string VaultCommandBuilder::updateAndResolveVar(const std::shared_ptr<Vault>& entity, const std::string& field) {
        const std::string usagePath = "vault/update";

        if (vaultAliases_.isName(field)) {
            entity->name = generateName(usagePath);
            return entity->name;
        }

        if (vaultAliases_.isDescription(field)) {
            if (coin()) {
                entity->description = "This is a description for vault " + entity->name;
                return entity->description;
            }
            entity->description = std::string(""); // clear description
            return entity->description;
        }

        if (vaultAliases_.isQuota(field)) {
            entity->setQuotaFromStr(generateQuotaStr(usagePath));
            return entity->quotaStr();
        }

        if (vaultAliases_.isInterval(field)) {
            // TODO: add sync as var to vault or track, and track lifecycle
            return randomAlias(std::vector<std::string>{"15m","30m","1h","2h","6h","12h","24h"});
        }

        throw std::runtime_error("VaultCommandBuilder: unsupported vault field for update: " + field);
    }

    static std::string randomizePrimaryPositional(const std::shared_ptr<Vault>& entity) {
        if (coin()) return std::to_string(entity->id);
        return entity->name + " --owner " + std::to_string(entity->owner_id);
    }

    std::string VaultCommandBuilder::chooseVaultType() {
        // Bias to local so tests don’t demand S3 specifics unless you want them to
        return coin() ? "local" : "local"; // flip second to "s3" when you’re ready
    }

    // ---------------- core ----------------

    std::string VaultCommandBuilder::create(const std::shared_ptr<Vault>& v) {
        const auto cmd = root_->findSubcommand("create");
        if (!cmd) throw std::runtime_error("vault.create usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases) << ' ' << v->name;

        oss << " --owner " << v->owner_id;

        // required flags: type
        const auto type = chooseVaultType(); // "local" or "s3"
        oss << " --" << type;

        // optional
        // An option left out takes the server default (no description, unlimited quota), and so does the model: the
        // Validate stage compares the two.
        if (!v->description.empty()) {
            if (coin()) oss << " --" << randomAlias(std::vector<std::string>{"desc","d"}) << ' ' << quoted(v->description);
            else v->description.clear();
        }
        if (v->quota > 0) {
            if (coin()) oss << " --" << randomAlias(std::vector<std::string>{"quota","q"}) << ' ' << v->quotaStr();
            else v->quota = 0;
        }

        // if (type == "local") {
        //     const auto it = std::ranges::find_if(cmd->groups, [](const auto& g){ return g.title == "Local Vault Options"; });
        //     if (it == cmd->groups.end()) throw std::runtime_error("vault.create usage missing Local Vault Options group");
        //     const auto localOpts = *it;
        //     for (const auto& opt : localOpts.items) {
        //         if (coin()) {
        //             if (const auto option = std::get_if<Optional>(&opt)) {
        //                 oss << ' ' << randomAlias(option->option_tokens);
        //             } else if (const auto flag = std::get_if<Flag>(&opt)) {
        //                 oss << ' ' << randomFlagAlias(flag->aliases);
        //             } else {
        //                 throw std::runtime_error("vault.create Local Vault Options group has unsupported item type");
        //             }
        //         }
        //     }
        // }

        // s3 group (only if you start returning "s3" in chooseVaultType)
        // if (type == "s3") {
        //     if (coin()) oss << " --api-key " << (v->s3_api_key.empty() ? "default-key" : v->s3_api_key);
        //     if (coin()) oss << " --bucket "  << (v->s3_bucket.empty()  ? "default-bucket" : v->s3_bucket);
        //     if (coin()) oss << " --sync-strategy " << randomAlias(std::vector<std::string>{"cache","sync","mirror"});
        //     if (coin()) oss << " --on-sync-conflict " << randomAlias(std::vector<std::string>{"keep_local","keep_remote","ask"});
        //     // encryption toggles
        //     if (coin()) oss << " --encrypt";
        //     else if (coin()) oss << " --no-encrypt";
        //     if (coin()) oss << " --accept-overwrite-waiver";
        // } else {
        //     // local group
        //     if (coin()) oss << " --on-sync-conflict overwrite";
        // }

        // sometimes run interactive
        // if (coin(10000, 1500)) oss << " --interactive";

        return oss.str();
    }

    BuiltCommand VaultCommandBuilder::update(const std::shared_ptr<Vault>& v) {
        const auto cmd = root_->findSubcommand("update");
        if (!cmd) throw std::runtime_error("vault.update usage not found");
        const auto proposed = std::make_shared<Vault>(*v);

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases) << ' ';
        oss << randomizePrimaryPositional(v);

        for (const auto& opt : cmd->optional) {
            if (opt.label.contains("owner")) continue; // already handled above
            if (coin()) oss << ' ' << randomFlagAlias(opt.option_tokens) << ' ' << quoted(updateAndResolveVar(proposed, opt.label));
        }

        // s3-ish knobs (harmless on local if server ignores)
        // if (coin()) oss << " --sync-strategy " << randomAlias(std::vector<std::string>{"cache","sync","mirror"});
        // if (coin()) oss << " --on-sync-conflict " << randomAlias(std::vector<std::string>{"keep_local","keep_remote","ask"});
        // if (coin()) oss << (coin() ? " --encrypt" : " --no-encrypt");
        // if (coin()) oss << (coin() ? " --accept-overwrite-waiver" : " --accept-decryption-waiver");

        // if (coin(10000, 1200)) oss << " --interactive";

        return {oss.str(), [v, proposed] { *v = *proposed; }};
    }

    std::string VaultCommandBuilder::remove(const std::shared_ptr<Vault>& v) {
        const auto cmd = root_->findSubcommand("delete");
        if (!cmd) throw std::runtime_error("vault.delete usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases) << ' ';
        oss << randomizePrimaryPositional(v);
        // Deletion asks how to delete in a terminal (#162); the harness has none. A scheduled delete is the default.
        oss << " --yes";
        return oss.str();
    }

    std::string VaultCommandBuilder::info(const std::shared_ptr<Vault>& v) {
        const auto cmd = root_->findSubcommand("info");
        if (!cmd) throw std::runtime_error("vault.info usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases) << ' ';
        oss << randomizePrimaryPositional(v);
        return oss.str();
    }

    std::string VaultCommandBuilder::list() {
        const auto cmd = root_->findSubcommand("list");
        if (!cmd) throw std::runtime_error("vault.list usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        if (coin()) oss << " --local";
        // if (coin()) oss << " --s3";
        if (coin()) oss << " --limit " << (5 + (generateRandomIndex(1000) % 10));
        return oss.str();
    }

    static std::string manageRole(const std::shared_ptr<Vault>& vault, const std::shared_ptr<role::Vault>& role, const EntityType& entityType, const std::shared_ptr<void>& entity, const std::shared_ptr<protocols::shell::CommandUsage>& root, std::string action) {
        const auto cmdBase = root->findSubcommand("role");
        if (!cmdBase) throw std::runtime_error("vault.roles usage not found");
        const auto cmd = cmdBase->findSubcommand(action);
        if (!cmd) throw std::runtime_error("vault.roles.assign usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root->aliases) << ' ' << randomAlias(cmdBase->aliases) << ' ' << randomAlias(cmd->aliases);

        bool useVaultName = coin();
        for (const auto& pos : cmd->positionals) {
            if (pos.label.contains("vault")) oss << ' ' << (useVaultName ? vault->name : std::to_string(vault->id));
            else if (pos.label.contains("role")) oss << ' ' << role->id;
            else throw std::runtime_error("VaultCommandBuilder: unsupported positional in vault.roles.assign: " + pos.label);
        }

        if (useVaultName) oss << " --owner " << vault->owner_id;

        for (const auto& req : cmd->required) {
            if (req.label.contains("subject")) {
                if (!entity) throw std::runtime_error("VaultCommandBuilder: no entity provided for vault.roles.assign subject");
                if (entityType == EntityType::USER) {
                    const auto user = std::static_pointer_cast<User>(entity);
                    if (coin()) oss << " --user " << user->id;
                    else       oss << " --user " << user->name();
                } else if (entityType == EntityType::GROUP) {
                    const auto group = std::static_pointer_cast<Group>(entity);
                    if (coin()) oss << " --group " << group->id;
                    else       oss << " --group " << group->name();
                } else throw std::runtime_error("VaultCommandBuilder: unsupported entity type for vault.roles.assign subject");
            } else throw std::runtime_error("VaultCommandBuilder: unsupported required option in vault.roles.assign: " + req.label);
        }

        return oss.str();
    }

    std::string VaultCommandBuilder::assignVaultRole(const std::shared_ptr<Vault>& vault, const std::shared_ptr<role::Vault>& role, const EntityType& entityType, const std::shared_ptr<void>& entity) const {
        return manageRole(vault, role, entityType, entity, root_, "assign");
    }

    std::string VaultCommandBuilder::unassignVaultRole(const std::shared_ptr<Vault>& vault, const std::shared_ptr<role::Vault>& role, const EntityType& entityType, const std::shared_ptr<void>& entity) const {
        return manageRole(vault, role, entityType, entity, root_, "unassign");
    }


    // ---------------- extras ----------------

    std::string VaultCommandBuilder::sync_set(const std::shared_ptr<Vault>& v) {
        const auto sync = root_->findSubcommand("sync");     if (!sync) throw std::runtime_error("vault.sync not found");
        const auto set  = sync->findSubcommand("set");       if (!set)  throw std::runtime_error("vault.sync.set not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(sync->aliases) << ' ' << randomAlias(set->aliases) << ' ';
        oss << randomizePrimaryPositional(v);

        oss << " --sync-strategy " << randomAlias(std::vector<std::string>{"cache","sync","mirror"});
        oss << " --on-sync-conflict " << randomAlias(std::vector<std::string>{"keep_local","keep_remote","ask"});
        return oss.str();
    }

    std::string VaultCommandBuilder::sync_info(const std::shared_ptr<Vault>& v) {
        const auto sync = root_->findSubcommand("sync");     if (!sync) throw std::runtime_error("vault.sync not found");
        const auto info = sync->findSubcommand("info");      if (!info) throw std::runtime_error("vault.sync.info not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(sync->aliases) << ' ' << randomAlias(info->aliases) << ' ';
        oss << randomizePrimaryPositional(v);
        return oss.str();
    }

    std::string VaultCommandBuilder::sync_trigger(const std::shared_ptr<Vault>& v) {
        // the parent "sync" is also executable per your examples
        const auto sync = root_->findSubcommand("sync");     if (!sync) throw std::runtime_error("vault.sync not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(sync->aliases) << ' ';
        oss << randomizePrimaryPositional(v);
        return oss.str();
    }

    std::string VaultCommandBuilder::key_export(const std::shared_ptr<Vault>& v) {
        const auto key = root_->findSubcommand("key");       if (!key)  throw std::runtime_error("vault.key not found");
        const auto exp = key->findSubcommand("export");      if (!exp)  throw std::runtime_error("vault.key.export not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(key->aliases) << ' ' << randomAlias(exp->aliases) << ' ';
        oss << randomizePrimaryPositional(v);

        if (coin()) oss << " --output " << (v->name.empty() ? "vault_key.pem" : v->name + "_key.pem");
        if (coin()) oss << " --recipient " << "ABCDEF1234567890";
        return oss.str();
    }

    std::string VaultCommandBuilder::key_rotate(const std::shared_ptr<Vault>& v) {
        const auto key = root_->findSubcommand("key");       if (!key)  throw std::runtime_error("vault.key not found");
        const auto rot = key->findSubcommand("rotate");      if (!rot)  throw std::runtime_error("vault.key.rotate not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(key->aliases) << ' ' << randomAlias(rot->aliases) << ' ';
        oss << randomizePrimaryPositional(v);
        if (coin()) oss << " --sync-now";
        return oss.str();
    }
}
