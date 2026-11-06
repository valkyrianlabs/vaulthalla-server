#include "protocols/ws/handler/vault/Keys.hpp"

#include "ops/Error.hpp"
#include "ops/RecoveryRecipients.hpp"
#include "ops/VaultKeys.hpp"
#include "ops/VaultLayout.hpp"
#include "ops/VaultRecover.hpp"
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

json VaultKeys::listRecipients(const json& payload, const std::shared_ptr<Session>& session) {
    return ops::recovery_recipients::toJson(ops::recovery_recipients::list(actorOf(session), requiredVaultId(payload)));
}

json VaultKeys::addRecipient(const json& payload, const std::shared_ptr<Session>& session) {
    const auto channel = channelOf(session);
    const auto vaultId = requiredVaultId(payload);
    if (!payload.contains("public_key") || !payload.at("public_key").is_string())
        throw ops::Invalid("public_key is required (an X25519 public key: base64 or hex)");
    std::optional<std::string> label;
    if (payload.contains("label") && !payload.at("label").is_null()) {
        if (!payload.at("label").is_string()) throw ops::Invalid("label must be a string");
        label = payload.at("label").get<std::string>();
    }
    return ops::recovery_recipients::toJson(ops::recovery_recipients::add(
        actorOf(session), {.vault_id = vaultId, .public_key = payload.at("public_key").get<std::string>(), .label = label},
        channel));
}

json VaultKeys::revokeRecipient(const json& payload, const std::shared_ptr<Session>& session) {
    const auto channel = channelOf(session);
    const auto vaultId = requiredVaultId(payload);
    if (!payload.contains("grant_id") || !payload.at("grant_id").is_string())
        throw ops::Invalid("grant_id is required");
    return ops::recovery_recipients::toJson(ops::recovery_recipients::revoke(
        actorOf(session), vaultId, payload.at("grant_id").get<std::string>(), channel));
}

json VaultKeys::recover(const json& payload, const std::shared_ptr<Session>& session) {
    const auto channel = channelOf(session);
    if (!payload.is_object()) throw ops::Invalid("vault.recover takes an object");
    ops::vault_recover::Request req;
    const auto str = [&](const char* name) -> std::optional<std::string> {
        if (!payload.contains(name) || payload.at(name).is_null()) return std::nullopt;
        if (!payload.at(name).is_string()) throw ops::Invalid(std::string(name) + " must be a string");
        return payload.at(name).get<std::string>();
    };
    const auto flag = [&](const char* name) {
        if (!payload.contains(name) || payload.at(name).is_null()) return false;
        if (!payload.at(name).is_boolean()) throw ops::Invalid(std::string(name) + " must be a boolean");
        return payload.at(name).get<bool>();
    };
    if (!payload.contains("api_key_id") || !payload.at("api_key_id").is_number_unsigned() ||
        payload.at("api_key_id").get<uint64_t>() == 0 || payload.at("api_key_id").get<uint64_t>() > UINT32_MAX)
        throw ops::Invalid("api_key_id is required (a positive integer)");
    req.api_key_id = payload.at("api_key_id").get<unsigned int>();
    req.bucket = str("bucket").value_or("");
    if (payload.contains("kit") && !payload.at("kit").is_null()) {
        if (!payload.at("kit").is_object()) throw ops::Invalid("kit must be a recovery kit object");
        req.kit = &payload.at("kit");
    }
    if (payload.contains("export") && !payload.at("export").is_null()) {
        if (!(payload.at("export").is_object() || payload.at("export").is_array()))
            throw ops::Invalid("export must be a key export (one vault object, or the array of an `all` export)");
        req.exported = &payload.at("export");
    }
    req.into = str("into");
    req.vault_uid = str("vault_uid");
    if (payload.contains("owner_id") && !payload.at("owner_id").is_null()) {
        if (!payload.at("owner_id").is_number_unsigned() || payload.at("owner_id").get<uint64_t>() > UINT32_MAX)
            throw ops::Invalid("owner_id must be a positive integer");
        req.owner_id = payload.at("owner_id").get<unsigned int>();
    }
    req.accept_rollback = flag("accept_rollback");
    req.dry_run = flag("dry_run");
    req.salvage = flag("salvage");
    req.confirm_name = str("confirm_name");
    return ops::vault_recover::toJson(ops::vault_recover::recover(actorOf(session), req, channel));
}

json VaultKeys::layoutStatus(const json& payload, const std::shared_ptr<Session>& session) {
    return ops::vault_layout::toJson(ops::vault_layout::status(actorOf(session), requiredVaultId(payload)).front());
}

json VaultKeys::layoutMigrate(const json& payload, const std::shared_ptr<Session>& session) {
    bool acceptUnpriced = false;
    if (payload.contains("accept_unpriced") && !payload.at("accept_unpriced").is_null()) {
        if (!payload.at("accept_unpriced").is_boolean()) throw ops::Invalid("accept_unpriced must be a boolean");
        acceptUnpriced = payload.at("accept_unpriced").get<bool>();
    }
    return ops::vault_layout::toJson(ops::vault_layout::start(
        actorOf(session), {.vault_id = requiredVaultId(payload), .accept_unpriced = acceptUnpriced}));
}

json VaultKeys::layoutCleanup(const json& payload, const std::shared_ptr<Session>& session) {
    std::optional<std::string> confirm;
    if (payload.contains("confirm") && !payload.at("confirm").is_null()) {
        if (!payload.at("confirm").is_string()) throw ops::Invalid("confirm must be the vault's name");
        confirm = payload.at("confirm").get<std::string>();
    }
    return ops::vault_layout::toJson(
        ops::vault_layout::cleanup(actorOf(session), {.vault_id = requiredVaultId(payload), .confirm = confirm}));
}

}
