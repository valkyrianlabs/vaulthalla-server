#include "protocols/shell/commands/vault.hpp"
#include "vault/model/Vault.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/APIKey.hpp"
#include "identities/User.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/permission/Override.hpp"
#include "db/query/vault/Vault.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/rbac/role/vault/Assignments.hpp"
#include "db/query/vault/APIKey.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/provider/Registry.hpp"
#include "CommandUsage.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "db/encoding/interval.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/fs/glob/Tokenizer.hpp"
#include "ops/Error.hpp"
#include "identities/Manager.hpp"

using namespace vh;

namespace vh::protocols::shell::commands::vault {

std::optional<unsigned int> parsePositiveUint(const std::string& s, const char* errLabel, std::string& errOut) {
    if (const auto v = parseUInt(s)) {
        if (*v <= 0) { errOut = std::string(errLabel) + " must be a positive integer"; return std::nullopt; }
        return static_cast<unsigned int>(*v);
    }
    errOut = std::string(errLabel) + " must be a positive integer";
    return std::nullopt;
}

std::shared_ptr<identities::User> resolveOwner(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage) {
    const auto ownerUsage = usage ? usage->resolveOptional("owner") : nullptr;
    if (ownerUsage) {
        if (const auto ownerOpt = optVal(call, ownerUsage->option_tokens)) {
            if (const auto idOpt = parseUInt(*ownerOpt)) {
                if (*idOpt <= 0) throw std::runtime_error("owner must be a positive integer");
                const auto user = vh::identities::manager().user(*idOpt);
                if (!user) throw std::runtime_error("owner id not found: " + *ownerOpt);
                return user;
            }
            const auto user = vh::identities::manager().userByName(*ownerOpt);
            if (!user) throw std::runtime_error("owner not found: " + *ownerOpt);
            return user;
        }
    }
    return call.user;
}

Lookup<identities::User> resolveOwnerRequired(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage, const std::string& errPrefix) {
    Lookup<identities::User> out;
    const auto ownerUsage = usage ? usage->resolveOptional("owner") : nullptr;
    if (!ownerUsage) {
        out.error = errPrefix + ": --owner is not supported by this command";
        return out;
    }
    const auto ownerOpt = optVal(call, ownerUsage->option_tokens);
    if (!ownerOpt || ownerOpt->empty()) {
        out.error = errPrefix + ": when using a vault name, you must specify --owner <id|name>";
        return out;
    }
    if (const auto idOpt = parseUInt(*ownerOpt)) {
        if (*idOpt <= 0) { out.error = errPrefix + ": --owner must be a positive integer"; return out; }
        out.ptr = vh::identities::manager().user(*idOpt);
        if (!out.ptr) out.error = errPrefix + ": owner id not found: " + *ownerOpt;
        return out;
    }
    out.ptr = vh::identities::manager().userByName(*ownerOpt);
    if (!out.ptr) out.error = errPrefix + ": owner not found: " + *ownerOpt;
    return out;
}

Lookup<::vh::vault::model::Vault> resolveVault(const CommandCall& call, const std::string& vaultArg, const std::shared_ptr<CommandUsage>& usage, const std::string& errPrefix) {
    Lookup<::vh::vault::model::Vault> out;
    if (const auto idOpt = parseUInt(vaultArg)) {
        if (*idOpt <= 0) { out.error = errPrefix + ": vault ID must be a positive integer"; return out; }
        out.ptr = db::query::vault::Vault::getVault(*idOpt);
        if (!out.ptr) out.error = errPrefix + ": vault with id " + std::to_string(*idOpt) + " not found";
        return out;
    }

    auto ownerLkp = resolveOwnerRequired(call, usage, errPrefix);
    if (!ownerLkp) { out.error = std::move(ownerLkp.error); return out; }
    out.ptr = db::query::vault::Vault::getVault(vaultArg, ownerLkp.ptr->id);
    if (!out.ptr) out.error = errPrefix + ": vault named '" + vaultArg + "' (owner id " + std::to_string(ownerLkp.ptr->id) + ") not found";
    return out;
}

Lookup<storage::Engine> resolveEngine(const CommandCall& call, const std::string& vaultArg, const std::shared_ptr<CommandUsage>& usage, const std::string& errPrefix) {
    Lookup<storage::Engine> out;

    const auto vLkp = resolveVault(call, vaultArg, usage, errPrefix);
    if (!vLkp || !vLkp.ptr) { out.error = vLkp.error; return out; }
    const auto vault = vLkp.ptr;

    out.ptr = runtime::Deps::get().storageManager->getEngine(vault->id);
    if (!out.ptr) out.error = errPrefix + ": no storage engine found for vault '" + vaultArg + "'";
    return out;
}

PatternParse parseGlobPatternOpt(const CommandCall& call, bool required, const std::string& errPrefix) {
    PatternParse out;
    auto p = optVal(call, "path");
    if (!p) p = optVal(call, "pattern");
    if (!p || p->empty()) {
        if (required) out.error = errPrefix + ": --path/--pattern is required";
        else { out.ok = true; }
        return out;
    }

    try {
        out.pattern = rbac::fs::glob::Tokenizer::parse(*p);
    } catch (const std::regex_error&) {
        out.error = errPrefix + ": invalid regex for --path/--pattern";
        out.pattern = std::nullopt;
        out.ok = false;
        return out;
    }
    out.ok = true;
    return out;
}

EnableParse parseEnableDisableOpt(const CommandCall& call, const std::string& errPrefix) {
    EnableParse out;
    const bool hasEnable  = hasFlag(call, "enable");
    const bool hasDisable = hasFlag(call, "disable");
    if (hasEnable && hasDisable) {
        out.error = errPrefix + ": cannot specify both --enable and --disable";
        return out;
    }
    if (hasEnable)  out.value = true;
    if (hasDisable) out.value = false;
    out.ok = true;
    return out;
}

EffectParse parseEffectChangeOpt(const CommandCall& call, const std::string& errPrefix) {
    EffectParse out;
    const bool allowFlag = hasFlag(call, "allow") || hasFlag(call, "allow-effect");
    const bool denyFlag  = hasFlag(call, "deny")  || hasFlag(call, "deny-effect");
    if (allowFlag && denyFlag) {
        out.error = errPrefix + ": cannot set both --allow and --deny";
        return out;
    }
    if (allowFlag) out.value = ::vh::rbac::permission::OverrideOpt::ALLOW;
    if (denyFlag)  out.value = ::vh::rbac::permission::OverrideOpt::DENY;
    out.ok = true;
    return out;
}

std::unique_ptr<::vh::vault::model::VaultType> parseVaultType(const CommandCall& call) {
    const bool local = hasFlag(call, "local");
    const bool s3    = hasFlag(call, "s3");
    if (local && s3) throw std::runtime_error("--local and --s3 are mutually exclusive");
    if (local) return std::make_unique<::vh::vault::model::VaultType>(::vh::vault::model::VaultType::Local);
    if (s3)    return std::make_unique<::vh::vault::model::VaultType>(::vh::vault::model::VaultType::S3);

    throw std::runtime_error("Vault type not specified: must provide either --local or --s3");
}

std::optional<uintmax_t> quotaFromOption(const CommandCall& call) {
    const auto quota = optVal(call, std::vector<std::string>{"quota", "q"});
    if (!quota) return std::nullopt;
    if (*quota == "none" || *quota == "unlimited") return 0;
    try {
        return parseSize(*quota);
    } catch (const std::exception& e) {
        throw ops::Invalid("invalid --quota '" + *quota + "': " + e.what());
    }
}

std::optional<unsigned int> apiKeyIdFromOption(const CommandCall& call) {
    const auto value = optVal(call, "api-key");
    if (!value) return std::nullopt;
    const auto key = parseUInt(*value) ? db::query::vault::APIKey::getAPIKey(*parseUInt(*value))
                                       : db::query::vault::APIKey::getAPIKey(*value);
    if (!key) throw ops::NotFound("API key not found: " + *value);
    return key->id;
}

std::optional<bool> encryptFromFlags(const CommandCall& call) {
    const bool on = hasFlag(call, "encrypt"), off = hasFlag(call, "no-encrypt");
    if (on && off) throw ops::Invalid("--encrypt and --no-encrypt are mutually exclusive");
    if (on) return true;
    if (off) return false;
    return std::nullopt;
}

static std::optional<std::optional<uint64_t>> budgetOption(const CommandCall& call, const std::string& key) {
    const auto value = optVal(call, key);
    if (!value) return std::nullopt;
    if (*value == "none" || *value == "null" || *value == "unlimited") return std::optional<uint64_t>{};
    const auto parsed = parseUInt(*value);
    if (!parsed) throw ops::Invalid("--" + key + " must be a non-negative integer or 'unlimited'");
    return std::optional<uint64_t>{*parsed};
}

ops::vaults::SyncPatch syncPatchFromOptions(const CommandCall& call) {
    ops::vaults::SyncPatch patch;
    try {
        if (const auto v = optVal(call, std::vector<std::string>{"interval", "sync-interval"}))
            patch.interval = db::encoding::parseSyncInterval(*v);
        if (const auto v = optVal(call, std::vector<std::string>{"max-remote-index-age", "remote-index-age"}))
            patch.max_remote_index_age = sync::model::remoteIndexAgeFromString(*v);
    } catch (const ops::Error&) {
        throw;
    } catch (const std::exception& e) {
        throw ops::Invalid(e.what());
    }
    patch.conflict_policy = optVal(call, std::vector<std::string>{"on-sync-conflict", "conflict"});
    patch.strategy = optVal(call, std::vector<std::string>{"sync-strategy", "strategy"});
    patch.s3_budget_preset = optVal(call, std::vector<std::string>{"s3-budget-preset", "budget-preset"});
    patch.s3_budget.list = budgetOption(call, "s3-budget-list");
    patch.s3_budget.head = budgetOption(call, "s3-budget-head");
    patch.s3_budget.get = budgetOption(call, "s3-budget-get");
    patch.s3_budget.put = budgetOption(call, "s3-budget-put");
    patch.s3_budget.copy = budgetOption(call, "s3-budget-copy");
    patch.s3_budget.del = budgetOption(call, "s3-budget-delete");
    patch.s3_budget.downloaded_bytes = budgetOption(call, "s3-budget-download-bytes");
    return patch;
}

}
