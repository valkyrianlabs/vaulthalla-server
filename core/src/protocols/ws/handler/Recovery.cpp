#include "protocols/ws/handler/Recovery.hpp"

#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Recovery.hpp"
#include "ops/RecoveryJson.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <limits>
#include <optional>
#include <string>

namespace vh::protocols::ws::handler {

namespace {

namespace wrec = vh::ops::recovery;

// Payload readers for the members the RecoveryJson readers don't cover: a wrong type is a refusal (`invalid`).
const json& wrObject(const json& payload) {
    static const json empty = json::object();
    if (payload.is_null()) return empty;
    if (!payload.is_object()) throw vh::ops::Invalid("payload must be an object");
    return payload;
}

uint64_t wrRequiredId(const json& payload, const char* name, const uint64_t max = static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    const auto& p = wrObject(payload);
    if (!p.contains(name) || !p.at(name).is_number_integer() || p.at(name).get<int64_t>() <= 0 ||
        static_cast<uint64_t>(p.at(name).get<int64_t>()) > max)
        throw vh::ops::Invalid(std::string(name) + " must be a positive integer");
    return static_cast<uint64_t>(p.at(name).get<int64_t>());
}

uint32_t wrVaultId(const json& payload) {
    return static_cast<uint32_t>(wrRequiredId(payload, "vault_id", std::numeric_limits<uint32_t>::max()));
}

std::string wrRequiredString(const json& payload, const char* name) {
    const auto& p = wrObject(payload);
    if (!p.contains(name) || !p.at(name).is_string() || p.at(name).get<std::string>().empty())
        throw vh::ops::Invalid(std::string(name) + " is required");
    return p.at(name).get<std::string>();
}

bool wrBool(const json& payload, const char* name) {
    const auto& p = wrObject(payload);
    if (!p.contains(name) || p.at(name).is_null()) return false;
    if (!p.at(name).is_boolean()) throw vh::ops::Invalid(std::string(name) + " must be a boolean");
    return p.at(name).get<bool>();
}

}

json Recovery::list(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"points", wrec::list(session->user, wrVaultId(payload), wrec::listQueryFromJson(wrObject(payload)))}};
}

json Recovery::inspect(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"detail", wrec::inspect(session->user, wrRequiredString(payload, "recovery_id"))}};
}

json Recovery::plan(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"plan", wrec::plan(session->user, wrec::planRequestFromJson(wrObject(payload)))}};
}

json Recovery::planGet(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"plan", wrec::getPlan(session->user, wrRequiredId(payload, "plan_id"))}};
}

json Recovery::restore(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"result", wrec::restore(session->user, wrec::restoreRequestFromJson(wrObject(payload)))}};
}

json Recovery::snapshotCreate(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"detail", wrec::createSnapshot(session->user, wrVaultId(payload),
                                            wrec::snapshotRequestFromJson(wrObject(payload)))}};
}

json Recovery::pointDelete(const json& payload, const std::shared_ptr<Session>& session) {
    const auto id = wrRequiredString(payload, "recovery_id");
    wrec::deletePoint(session->user, id, wrBool(payload, "confirm"));
    return {{"recovery_id", id}};
}

json Recovery::costs(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"costs", wrec::costs(session->user, wrVaultId(payload))}};
}

json Recovery::vaultStatus(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"status", wrec::status(session->user, wrVaultId(payload), wrBool(payload, "refresh_provider"))}};
}

json Recovery::vaultUpdate(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"status", wrec::update(session->user, wrVaultId(payload), wrec::updateFromJson(wrObject(payload)))}};
}

json Recovery::vaultDisclosure(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& p = wrObject(payload);
    std::optional<vh::recovery::ProviderRetention> retention;
    if (const auto it = p.find("provider_retention"); it != p.end() && !it->is_null())
        retention = wrec::providerRetentionFromJson(*it);
    return {{"disclosure", wrec::versioningDisclosure(session->user, wrVaultId(payload), retention)}};
}

json Recovery::vaultSuspend(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"status", wrec::suspendVersioning(session->user, wrVaultId(payload), wrBool(payload, "confirm"))}};
}

}
