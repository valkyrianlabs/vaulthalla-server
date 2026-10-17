#pragma once

#include "protocols/shell/types.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "helpers.hpp"
#include "ops/Vaults.hpp"
#include "identities/Fwd.hpp"
#include "protocols/shell/Fwd.hpp"
#include "rbac/Fwd.hpp"
#include "storage/Fwd.hpp"
#include "sync/Fwd.hpp"
#include "vault/Fwd.hpp"

#include <functional>
#include <string_view>

#include <memory>
#include <optional>
#include <regex>
#include <string>

namespace vh::rbac::role {
    enum class OverrideOpt;
}

namespace vh::protocols::shell::commands::vault {
    // router.cpp
    void registerCommands(const std::shared_ptr<Router> &r);

    // waiver.cpp: runs an op that may need an encryption waiver (it throws ops::NeedsConfirmation); asks the
    // person at the terminal (or honours --accept-overwrite-waiver / --accept-decryption-waiver) and repeats it
    // accepted. `op` returns the command's output.
    CommandResult runWithWaiver(const CommandCall &call, std::string_view prefix,
                                const std::function<std::string(bool acceptWaiver)> &op);

    CommandResult runVaultChange(const CommandCall &call, std::string_view prefix,
                                 const std::function<ops::vaults::VaultPtr(bool acceptWaiver)> &op,
                                 const std::function<std::string(const ops::vaults::VaultPtr &)> &format);

    // create.cpp
    CommandResult handle_vault_create(const CommandCall &call);

    // lifecycle.cpp
    CommandResult handle_vault_update(const CommandCall &call);

    CommandResult handle_vault_delete(const CommandCall &call);

    // Safe deletion (#162): restore a pending deletion; list deletions.
    CommandResult handle_vault_restore(const CommandCall &call);

    CommandResult handle_vaults_deleted(const CommandCall &call);

    // listinfo.cpp
    CommandResult handle_vault_info(const CommandCall &call);

    CommandResult handle_vaults_list(const CommandCall &call);

    // role.cpp
    CommandResult handle_vault_role(const CommandCall &call);
    CommandResult handle_vault_role_override(const CommandCall& call);

    // keys.cpp
    CommandResult handle_vault_keys(const CommandCall &call);

    // sync.cpp
    CommandResult handle_sync(const CommandCall &call);

    // recovery.cpp: `vh vault recovery status|set|suspend|disclosure` (ops::recovery policy).
    CommandResult handle_vault_recovery(const CommandCall &call);

    // helpers.cpp
    std::optional<unsigned int> parsePositiveUint(const std::string &s, const char *errLabel, std::string &errOut);

    std::shared_ptr<identities::User> resolveOwner(const CommandCall &call, const std::shared_ptr<CommandUsage> &usage);

    Lookup<identities::User> resolveOwnerRequired(const CommandCall &call, const std::shared_ptr<CommandUsage> &usage,
                                                  const std::string &errPrefix);

    Lookup<vh::vault::model::Vault> resolveVault(const CommandCall &call, const std::string &vaultArg,
                                                 const std::shared_ptr<CommandUsage> &usage,
                                                 const std::string &errPrefix);

    Lookup<storage::Engine> resolveEngine(const CommandCall &call, const std::string &vaultArg,
                                          const std::shared_ptr<CommandUsage> &usage, const std::string &errPrefix);

    PatternParse parseGlobPatternOpt(const CommandCall &call, bool required, const std::string &errPrefix);

    EnableParse parseEnableDisableOpt(const CommandCall &call, const std::string &errPrefix);

    EffectParse parseEffectChangeOpt(const CommandCall &call, const std::string &errPrefix);

    std::unique_ptr<vh::vault::model::VaultType> parseVaultType(const CommandCall &call);

    // CLI options -> the ops::vaults request fields they set (absent options stay unset).
    ops::vaults::SyncPatch syncPatchFromOptions(const CommandCall &call);

    std::optional<uintmax_t> quotaFromOption(const CommandCall &call);

    // --api-key by name or id.
    std::optional<unsigned int> apiKeyIdFromOption(const CommandCall &call);

    // --encrypt / --no-encrypt (mutually exclusive).
    std::optional<bool> encryptFromFlags(const CommandCall &call);
}