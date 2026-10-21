#include "protocols/ws/handler/vault/Keys.hpp"

#include "ops/Error.hpp"
#include "ops/VaultKeys.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

namespace {

namespace keys = ::vh::ops::vault_keys;

const ops::Actor& actorOf(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw ops::Denied("not authenticated");
    return session->user;
}

// Which transport this is, for D4: a paired device's session, or anything else (a browser session).
keys::Channel channelOf(const std::shared_ptr<Session>& session) {
    return session && session->isDeviceSession() && session->devicePeer() ? keys::Channel::Device
                                                                          : keys::Channel::Console;
}

unsigned int requiredVaultId(const json& payload) {
    if (!payload.is_object() || !payload.contains("vault_id") || !payload.at("vault_id").is_number_unsigned() ||
        payload.at("vault_id").get<uint64_t>() == 0 || payload.at("vault_id").get<uint64_t>() > UINT32_MAX)
        throw ops::Invalid("vault_id is required (a positive integer)");
    return payload.at("vault_id").get<unsigned int>();
}

}

json VaultKeys::status(const json& payload, const std::shared_ptr<Session>& session) {
    std::optional<unsigned int> vaultId;
    if (payload.is_object() && payload.contains("vault_id") && !payload.at("vault_id").is_null())
        vaultId = requiredVaultId(payload);
    json vaults = json::array();
    for (const auto& s : keys::status(actorOf(session), vaultId)) vaults.push_back(keys::toJson(s));
    return {{"vaults", std::move(vaults)}};
}

json VaultKeys::exportKeys(const json& payload, const std::shared_ptr<Session>& session) {
    const auto channel = channelOf(session);
    const auto vaultId = requiredVaultId(payload);
    const auto exported = keys::exportVault(actorOf(session), vaultId, channel);
    // Not marked exported here: the device confirms once it has stored the key (vault.keys.export.confirm).
    return keys::toJson(exported, session->user->name());
}

json VaultKeys::importKeys(const json& payload, const std::shared_ptr<Session>& session) {
    const auto channel = channelOf(session);
    const auto vaultId = requiredVaultId(payload);
    if (!payload.contains("keys") || !(payload.at("keys").is_object() || payload.at("keys").is_array()))
        throw ops::Invalid("keys is required: the key export (one vault object, or the array of an `all` export)");
    std::optional<std::string> confirmName;
    if (payload.contains("confirm_name") && payload.at("confirm_name").is_string())
        confirmName = payload.at("confirm_name").get<std::string>();
    auto mode = keys::ImportMode::Recover;
    if (payload.contains("mode") && !payload.at("mode").is_null()) {
        const auto& m = payload.at("mode");
        if (!m.is_string() || (m.get<std::string>() != "recover" && m.get<std::string>() != "salvage"))
            throw ops::Invalid("mode must be \"recover\" or \"salvage\"");
        if (m.get<std::string>() == "salvage") mode = keys::ImportMode::Salvage;
    }
    return keys::toJson(keys::importKeys(actorOf(session),
                                         {.vault_id = vaultId, .keys = &payload.at("keys"), .confirm_name = confirmName,
                                          .mode = mode},
                                         channel));
}

json VaultKeys::confirmExport(const json& payload, const std::shared_ptr<Session>& session) {
    const auto channel = channelOf(session);
    const auto vaultId = requiredVaultId(payload);
    if (!payload.contains("version") || !payload.at("version").is_number_unsigned())
        throw ops::Invalid("version is required (a positive integer)");
    if (!payload.contains("key_check") || !payload.at("key_check").is_string())
        throw ops::Invalid("key_check is required (32 lowercase hex digits)");
    const auto confirmed = keys::confirmExport(actorOf(session), vaultId, payload.at("version").get<unsigned int>(),
                                               payload.at("key_check").get<std::string>(), channel);
    return {{"vault_id", confirmed.vault_id},
            {"version", confirmed.version},
            {"exported_at", static_cast<int64_t>(confirmed.exported_at)}};
}

}
