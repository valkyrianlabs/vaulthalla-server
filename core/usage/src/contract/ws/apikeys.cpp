// ws book: storage.apiKey.* (core/src/protocols/ws/handler/vault/APIKeys.cpp → ops::api_keys).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

std::vector<std::string> apiKeyProviders() {
    return {"AWS", "Cloudflare R2", "Wasabi", "Backblaze B2", "DigitalOcean", "MinIO", "Ceph", "Storj", "Other"};
}

WsField apiKeyIdPayload() { return uinteger("id").gen(gen::ref("api_key", {"id"})).desc("API key id."); }

WsField apiKeyObject() { return object("api_key", "APIKey").desc("Metadata only: the secret is never returned."); }

}

std::vector<WsCommandUsage> apiKeyCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "storage.apiKey.add",
        .description = "Store an upstream S3 API key after checking the credentials against the provider (skipped in "
                       "test mode). owner_id defaults to the caller; creating one for someone else needs the users/"
                       "admins keys permission.",
        .payload = {str("name").gen(gen::freshName("key_")),
                    str("provider").oneOf(apiKeyProviders()).gen(gen::constant("AWS")),
                    str("access_key").gen(gen::pattern("AKIA{A}{A}{A}{A}{9}{9}{9}{9}")),
                    str("secret_access_key").gen(gen::bytes(32, 40)),
                    str("endpoint").gen(gen::constant("https://s3.us-east-2.amazonaws.com")),
                    str("region").opt().desc("Defaults to \"auto\"."),
                    uinteger("owner_id").opt().nullable().gen(gen::ref("user", {"id"}))},
        .response = {apiKeyObject()},
        .refusal_codes = opsRefusals(),
        .untyped_refusals = {"invalid"},
        .client_timeout = 60s,
    });

    out.push_back({
        .command = "storage.apiKey.update",
        .description = "Edit a key in place (same id, so bound vaults keep their binding; their engines are rebuilt). "
                       "Absent or null members keep their value; an empty secret_access_key keeps the sealed secret. "
                       "The resulting credentials are re-checked like add.",
        .payload = {apiKeyIdPayload(),
                    str("name").opt().nullable(),
                    str("provider").opt().nullable().oneOf(apiKeyProviders()),
                    str("access_key").opt().nullable(),
                    str("secret_access_key").opt().nullable(),
                    str("endpoint").opt().nullable(),
                    str("region").opt().nullable()},
        .response = {apiKeyObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = 60s,
    });

    out.push_back({
        .command = "storage.apiKey.remove",
        .description = "Delete a key. Refused (invalid, naming the vaults) while a vault uses it, and (conflict) while "
                       "it operates an event subscription. The answer carries no data.",
        .payload = {apiKeyIdPayload()},
        .response = {},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "storage.apiKey.list",
        .description = "The API keys the caller may view (metadata only).",
        .input = "none",
        .response = {objectArray("keys", "APIKey")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "storage.apiKey.get",
        .description = "One API key's metadata.",
        .payload = {apiKeyIdPayload()},
        .response = {apiKeyObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
