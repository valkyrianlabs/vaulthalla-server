// ws models: s3.gateway.* — the shapes S3GatewayJson builds (core/src/protocols/ws/handler/S3Gateway.cpp, declared
// in protocols/ws/handler/S3GatewayJson.hpp). Timestamps are epoch seconds (std::time_t). Budgets use the pricing
// serializers (PriceBudgetPolicy, PriceBudgetLedgerEntry, PriceBudgetTrendStats: admin area).

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField s3gwModelEpoch(std::string name) { return integer(std::move(name)).desc("Epoch seconds."); }

WsField s3gwModelCreatedBy() { return uinteger("created_by").nullable().desc("User id that created it."); }

std::vector<WsField> s3gwModelOverrideFields() {
    return {uinteger("id").desc("Override id."),
            uinteger("override_id").desc("Same as id."),
            uinteger("assignment_id").desc("The role assignment (or default role) the override belongs to."),
            uinteger("credential_id"),
            object("credential", "S3GatewayCredential"),
            uinteger("permission_id").desc("0 when the permission row id is not known."),
            str("permission_name").desc("Qualified permission name."),
            str("permission_qualified").desc("Same as permission_name."),
            object("permission", "Permission"),
            str("glob_path").desc("Path pattern the override applies to."),
            str("effect").oneOf({"allow", "deny"}),
            boolean("enabled")};
}

}

std::vector<WsModel> s3GatewayModels() {
    std::vector<WsModel> out;

    out.push_back(model(
        "S3GatewayCredential",
        "An S3 gateway credential (never its secret). S3GatewayJson::credential (ws/handler/S3Gateway.cpp).",
        {uinteger("id"),
         uinteger("user_id").desc("Owning user id."),
         uinteger("principal_user_id").desc("The user whose access the credential acts with."),
         object("principal_user", "", {uinteger("id"), str("name"), str("email").nullable()})
             .nullable()
             .desc("The principal, or null when that user no longer exists."),
         s3gwModelCreatedBy(),
         str("name"),
         str("access_key"),
         boolean("enabled"),
         str("scope_mode").oneOf({"user_access", "global", "vault_allowlist"}),
         boolean("enforce_budget_for_local_requests"),
         str("description").nullable(),
         s3gwModelEpoch("created_at"),
         s3gwModelEpoch("last_used_at").nullable(),
         s3gwModelEpoch("expires_at").nullable()}));

    out.push_back(model(
        "S3GatewayVaultRef",
        "A vault as s3.gateway.* names it. S3GatewayJson::vault (ws/handler/S3Gateway.cpp).",
        {uinteger("id"), str("name"), str("slug"), str("fuse_name").nullable(),
         str("effective_fuse_name").desc("fuse_name when set, else slug."), uinteger("owner_id")}));

    out.push_back(model(
        "S3GatewayRoleAssignment",
        "A vault role granted to a credential on one vault. S3GatewayJson::assignment (ws/handler/S3Gateway.cpp).",
        {uinteger("id"),
         uinteger("assignment_id").desc("Same as id."),
         uinteger("credential_id"),
         object("credential", "S3GatewayCredential").nullable(),
         uinteger("vault_id"),
         object("vault", "S3GatewayVaultRef").nullable(),
         uinteger("vault_role_id"),
         object("role", "VaultRole").nullable().desc("The vault role definition, or null when it is gone."),
         boolean("enabled"),
         s3gwModelCreatedBy(),
         s3gwModelEpoch("created_at"),
         s3gwModelEpoch("updated_at")}));

    out.push_back(model(
        "S3GatewayDefaultRole",
        "A credential's default vault role (global and vault-allowlist credentials). S3GatewayJson::defaultRole "
        "(ws/handler/S3Gateway.cpp).",
        {uinteger("id"),
         uinteger("default_role_id").desc("Same as id."),
         uinteger("credential_id"),
         object("credential", "S3GatewayCredential").nullable(),
         uinteger("vault_role_id"),
         object("role", "VaultRole").nullable().desc("The vault role definition, or null when it is gone."),
         boolean("enabled"),
         s3gwModelCreatedBy(),
         s3gwModelEpoch("created_at"),
         s3gwModelEpoch("updated_at")}));

    out.push_back(model(
        "S3GatewaySelectedVault",
        "A vault selected for a vault-allowlist credential. S3GatewayJson::selectedVault (ws/handler/S3Gateway.cpp).",
        {uinteger("credential_id"),
         uinteger("vault_id"),
         object("vault", "S3GatewayVaultRef").nullable(),
         boolean("enabled"),
         s3gwModelCreatedBy(),
         s3gwModelEpoch("created_at"),
         s3gwModelEpoch("updated_at")}));

    {
        auto fields = s3gwModelOverrideFields();
        fields.push_back(uinteger("vault_id").nullable());
        fields.push_back(object("vault", "S3GatewayVaultRef").nullable());
        out.push_back(model(
            "S3GatewayRoleOverride",
            "A permission override on a credential's role on one vault. S3GatewayJson::roleOverride "
            "(ws/handler/S3Gateway.cpp).",
            std::move(fields)));
    }

    {
        auto fields = s3gwModelOverrideFields();
        fields.push_back(uinteger("vault_id").nullable().desc("Always null: a default-role override has no vault."));
        fields.push_back(object("vault", "S3GatewayVaultRef").nullable()
                             .desc("Always null: a default-role override has no vault."));
        fields.push_back(uinteger("default_role_id").desc("The credential's default role row (= assignment_id)."));
        fields.push_back(uinteger("gateway_credential_default_role_id").desc("Same as default_role_id."));
        out.push_back(model(
            "S3GatewayDefaultRoleOverride",
            "A permission override on a credential's default vault role. S3GatewayJson::defaultRoleOverride "
            "(ws/handler/S3Gateway.cpp).",
            std::move(fields)));
    }

    out.push_back(model(
        "S3GatewayBucket",
        "A gateway bucket bound to a vault. S3GatewayJson::bucket (ws/handler/S3Gateway.cpp).",
        {str("bucket_name"),
         str("bucket").desc("Same as bucket_name."),
         uinteger("vault_id"),
         str("mode").oneOf({"local", "remote_cache", "remote_proxy"}),
         boolean("api_exclusive"),
         s3gwModelCreatedBy(),
         s3gwModelEpoch("created_at"),
         s3gwModelEpoch("updated_at")}));

    return out;
}

}
