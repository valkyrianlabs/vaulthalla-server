#include "protocols/ws/handler/vault/APIKeys.hpp"
#include "vault/model/APIKey.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Session.hpp"
#include "ops/APIKeys.hpp"
#include "ops/Error.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <stdexcept>
#include <string>

using namespace vh::protocols::ws::handler;
using json = nlohmann::json;

namespace {

std::optional<std::string> optionalApiKeyField(const json& payload, const char* field) {
    if (!payload.contains(field) || payload.at(field).is_null()) return std::nullopt;
    if (!payload.at(field).is_string()) throw vh::ops::Invalid(std::string(field) + " must be a string");
    return payload.at(field).get<std::string>();
}

}

json APIKeys::add(const json& payload, const std::shared_ptr<Session>& session) {
    // An unknown provider name is the caller's input: Invalid (data.code "invalid"), s3_provider_from_string's text.
    vh::vault::model::S3Provider provider{};
    try {
        provider = vh::vault::model::s3_provider_from_string(payload.at("provider").get<std::string>());
    } catch (const std::invalid_argument& e) {
        throw vh::ops::Invalid(e.what());
    }

    std::optional<vh::ops::api_keys::Ref> owner;
    if (payload.contains("owner_id") && !payload.at("owner_id").is_null()) owner = payload.at("owner_id").get<uint32_t>();

    const auto key = vh::ops::api_keys::create(session->user, {
        .name = payload.at("name").get<std::string>(),
        .provider = provider,
        .access_key = payload.at("access_key").get<std::string>(),
        .secret_access_key = payload.at("secret_access_key").get<std::string>(),
        .endpoint = payload.at("endpoint").get<std::string>(),
        .region = payload.value("region", "auto"),
        .owner = owner
    });
    return {{"api_key", key}};
}

json APIKeys::update(const json& payload, const std::shared_ptr<Session>& session) {
    vh::ops::api_keys::Update req{
        .name = optionalApiKeyField(payload, "name"),
        .provider = std::nullopt,
        .access_key = optionalApiKeyField(payload, "access_key"),
        // Omitted, null or "" keeps the sealed secret (the console never has it to send back).
        .secret_access_key = optionalApiKeyField(payload, "secret_access_key"),
        .endpoint = optionalApiKeyField(payload, "endpoint"),
        .region = optionalApiKeyField(payload, "region"),
    };
    if (const auto provider = optionalApiKeyField(payload, "provider")) {
        try {
            req.provider = vh::vault::model::s3_provider_from_string(*provider);
        } catch (const std::invalid_argument&) {
            throw vh::ops::Invalid("invalid provider '" + *provider + "'");
        }
    }
    return {{"api_key", vh::ops::api_keys::update(session->user, payload.at("id").get<unsigned int>(), req)}};
}

json APIKeys::remove(const json& payload, const std::shared_ptr<Session>& session) {
    (void)vh::ops::api_keys::remove(session->user, payload.at("id").get<unsigned int>());
    return {};
}

json APIKeys::list(const std::shared_ptr<Session>& session) {
    // A real array (it used to be the array JSON-encoded into a string).
    return {{"keys", json(vh::ops::api_keys::list(session->user))}};
}

json APIKeys::get(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"api_key", vh::ops::api_keys::get(session->user, payload.at("id").get<unsigned int>())}};
}
