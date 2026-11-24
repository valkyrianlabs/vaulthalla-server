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
         s3gwModelEpoch("expires_at").nullable(),
         object("upstream", "S3GatewayCredentialUpstream")
             .desc("What a CreateBucket made with this credential creates.")}));

    out.push_back(model(
        "S3GatewayUpstreamProfile",
        "An upstream profile: the API key and vault settings a gateway CreateBucket applies. "
        "S3GatewayJson::upstreamProfile (ws/handler/S3Gateway.cpp).",
        {uinteger("id"),
         str("name").desc("Region-shaped; S3 clients send it as LocationConstraint or sign with it to select the profile."),
         uinteger("api_key_id"),
         str("api_key_name").nullable().desc("Null when the key can no longer be read."),
         str("provider").nullable().desc("The key's provider label."),
         boolean("encrypt_upstream"),
         str("sync_strategy").oneOf({"cache", "sync", "mirror"}),
         str("conflict_policy").oneOf({"keep_local", "keep_remote", "keep_newest", "ask"}),
         str("bucket_prefix").desc("The upstream bucket is <bucket_prefix><gateway bucket>."),
         str("versioning").desc("What a bucket created through the profile keeps on the provider: off (only the latest "
                                "version), indefinite or <N>d. Anything but off is Backblaze B2 only."),
         str("description").nullable(),
         boolean("server_default").desc("This profile is s3_gateway.default_upstream_profile."),
         s3gwModelCreatedBy(),
         s3gwModelEpoch("created_at"),
         s3gwModelEpoch("updated_at")}));

    out.push_back(model(
        "S3GatewayCredentialUpstream",
        "What a credential's CreateBucket creates. S3GatewayJson::credentialUpstream (ws/handler/S3Gateway.cpp).",
        {str("source").oneOf({"local", "profile", "server_default"})
             .desc("local: a local vault. profile: the credential's own profile. server_default: the server's."),
         object("profile", "S3GatewayUpstreamProfile").nullable()
             .desc("The profile a CreateBucket would use now; null for local, or when `problem` says why."),
         str("problem").nullable().desc("Why there is no profile although the source asks for one."),
         boolean("reapply").nullable().desc("The credential's own choice; null follows the server's setting."),
         boolean("reapply_effective"),
         objectArray("allowed_profiles", "S3GatewayUpstreamProfile")
             .desc("The profiles a request made with this credential may name (LocationConstraint or signing "
                   "region) besides `profile`. Any other profile is refused.")}));

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
         s3gwModelEpoch("updated_at"),
         uinteger("created_by_credential_id").nullable()
             .desc("The gateway credential whose CreateBucket made the bucket through an upstream profile."),
         uinteger("upstream_profile_id").nullable().desc("The upstream profile the bucket was created from.")}));

    return out;
}

}
