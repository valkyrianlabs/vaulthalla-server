#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/SocketIO.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "ops/Error.hpp"
#include "vault/model/Vault.hpp"

#include <string>

namespace vh::protocols::shell::commands::vault {

CommandResult runWithWaiver(const CommandCall& call, const std::string_view prefix,
                            const std::function<std::string(bool acceptWaiver)>& op) {
    const auto refused = [&](const std::string& why) { return invalid(std::string(prefix) + ": " + why); };
    const bool acceptedByFlag = hasFlag(call, "accept-overwrite-waiver") || hasFlag(call, "accept-decryption-waiver");
    try {
        try {
            return ok(op(acceptedByFlag));
        } catch (const ops::NeedsConfirmation& e) {
            // The op found existing data the encryption change affects. A person has to accept the waiver.
            if (!call.io) {
                noteConfirmationNeeded(e.code, {"--accept-overwrite-waiver", "--accept-decryption-waiver"});
                return refused("this change requires accepting an encryption waiver: re-run in an interactive "
                               "terminal, or pass --accept-overwrite-waiver / --accept-decryption-waiver.\n" +
                               std::string(e.what()));
            }
            if (call.io->prompt(e.what(), "I DO NOT ACCEPT") != "I ACCEPT")
                return refused("the encryption waiver was not accepted; nothing was changed");
            return ok(op(true));
        }
    } catch (const ops::Error& e) {
        return refused(e.what());
    }
}

CommandResult runVaultChange(const CommandCall& call, const std::string_view prefix,
                             const std::function<ops::vaults::VaultPtr(bool acceptWaiver)>& op,
                             const std::function<std::string(const ops::vaults::VaultPtr&)>& format) {
    return runWithWaiver(call, prefix, [&](const bool accept) { return format(op(accept)); });
}

}
