#pragma once

#include <memory>
#include <nlohmann/json_fwd.hpp>
#include "protocols/ws/Fwd.hpp"

// vault.keys.* (ops::vault_keys): key backup status for any signed-in session; export, its confirmation and import
// only on a paired device's session (D4: never through the browser; MCP has no ws path at all).
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct VaultKeys {
    static json status(const json& payload, const std::shared_ptr<Session>& session);
    static json exportKeys(const json& payload, const std::shared_ptr<Session>& session);
    static json confirmExport(const json& payload, const std::shared_ptr<Session>& session);
    static json importKeys(const json& payload, const std::shared_ptr<Session>& session);
    // Recovery recipients (ops::recovery_recipients, #370): list for any session with the View permission; add and
    // revoke only on a paired device's session (D4; recipient_requires_device otherwise).
    static json listRecipients(const json& payload, const std::shared_ptr<Session>& session);
    static json addRecipient(const json& payload, const std::shared_ptr<Session>& session);
    static json revokeRecipient(const json& payload, const std::shared_ptr<Session>& session);
    // vault.recover (ops::vault_recover, #371): a vault rebuilt from its bucket and the customer's recovery material,
    // only on a paired device's session (recover_requires_device otherwise) with the keys step-up.
    static json recover(const json& payload, const std::shared_ptr<Session>& session);
};

}
