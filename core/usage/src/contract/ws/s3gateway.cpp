// ws book: s3.gateway.* (core/src/protocols/ws/handler/S3Gateway.cpp → ops::s3_gateway). The handler shapes the JSON
// (credentialJson, assignmentJson, defaultRoleJson, selectedVaultJson, overrideJson, bucketJson, vaultJson); budgets
// are storage::s3::pricing serializers. No s3.gateway.* command reads a bare `id`: a payload carrying one is refused
// ('invalid') naming the explicit field to send instead.

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

// ---- payload members ------------------------------------------------------------------------------------------

// The credential a command acts on: credential_id first, then an access key or a name (any one is required; none →
// 'invalid').
std::vector<WsField> s3gwCredentialRef() {
    return {uinteger("credential_id").opt().gen(gen::ref("s3_credential", {"id"}))
                .desc("The credential. One of credential_id, access_key / credential_access_key or name / "
                      "credential_name / credential is required."),
            str("access_key").opt().desc("The credential's access key."),
            str("credential_access_key").opt().desc("Legacy spelling of access_key."),
            str("name").opt().desc("The credential's name."),
            str("credential_name").opt().desc("Legacy spelling of name."),
            str("credential").opt().desc("Legacy: the credential's access key or name.")};
}

// The vault a grant is about: vault_id, or a vault name (under owner_id when given; ambiguous names are refused).
std::vector<WsField> s3gwVaultRef() {
    return {uinteger("vault_id").opt().gen(gen::ref("vault", {"id"}))
                .desc("The vault. vault_id or vault_name (alias vault) is required."),
            str("vault_name").opt().desc("Vault name: the caller's own vault of that name, else the only one."),
            str("vault").opt().desc("Legacy spelling of vault_name."),
            uinteger("owner_id").opt().nullable().gen(gen::ref("user", {"id"}))
                .desc("With vault_name: the owner whose vault of that name is meant.")};
}

// A vault role by id or name (vault_role_id, role_id, vault_role_name, role_name, role; first present wins).
std::vector<WsField> s3gwRoleRef(const std::string& requirement) {
    return {uinteger("vault_role_id").opt().gen(gen::ref("role.vault", {"id"})).desc(requirement),
            uinteger("role_id").opt().desc("Legacy spelling of vault_role_id."),
            str("vault_role_name").opt().desc("The vault role by name."),
            str("role_name").opt().desc("Legacy spelling of vault_role_name."),
            str("role").opt().desc("Legacy spelling of vault_role_name.")};
}

std::vector<WsField> s3gwPermissionRef() {
    return {uinteger("permission_id").opt().gen(gen::ref("permission", {"id"}))
                .desc("The permission: permission_id, else permission_qualified / permission_name / permission (a "
                      "qualified name or a files/directories short name). Required."),
            str("permission_qualified").opt(),
            str("permission_name").opt(),
            str("permission").opt(),
            str("effect").opt().oneOf({"allow", "deny"}).desc("Required."),
            str("glob_path").opt().desc("Path pattern the override applies to (required; alias path)."),
            str("path").opt().desc("Legacy spelling of glob_path."),
            boolean("enabled").opt().desc("Defaults to true.")};
}

WsField s3gwOverrideId() {
    return uinteger("override_id").opt().gen(gen::ref("s3_credential_override", {"id"}))
        .desc("The override to remove (required; a bare id is refused).");
}

// Default vault role at create / scope update: default_vault_role_id, default_role_id, or any role reference.
std::vector<WsField> s3gwDefaultRoleRef() {
    auto out = std::vector<WsField>{
        uinteger("default_vault_role_id").opt().nullable().gen(gen::ref("role.vault", {"id"}))
            .desc("The credential's default vault role (global and vault-allowlist credentials)."),
        uinteger("default_role_id").opt().nullable().desc("Legacy spelling of default_vault_role_id.")};
    for (auto& f : s3gwRoleRef("Also names the default vault role when default_vault_role_id is absent.")) out.push_back(f);
    return out;
}

// Each element is a vault id; legacy clients send {vault_id} or {id} objects (anything else is skipped).
WsField s3gwSelectedVaultElement() {
    return alt({"integer", "object"})
        .alternatives({alt({"integer"}).min(0).desc("A vault id."),
                       WsField{.types = {"object"}, .fields = {uinteger("vault_id")}}.desc("Legacy: {vault_id}."),
                       WsField{.types = {"object"}, .fields = {uinteger("id")}}.desc("Legacy: {id} (a vault id).")});
}

std::vector<WsField> s3gwSelectedVaultIds() {
    return {arrayOf("selected_vault_ids", s3gwSelectedVaultElement()).opt()
                .desc("Vault ids selected for a vault-allowlist credential."),
            arrayOf("vault_ids", s3gwSelectedVaultElement()).opt().desc("Legacy spelling of selected_vault_ids.")};
}

WsField s3gwVaultScopes() {
    return objectArray("vault_scopes", "",
                       {uinteger("vault_id"), boolean("can_list").opt().desc("Defaults to true."),
                        boolean("can_read").opt().desc("Defaults to true."), boolean("can_write").opt(),
                        boolean("can_delete").opt(), boolean("can_admin").opt().desc("Admins only.")})
        .opt()
        .desc("Boolean shorthand per vault: each selects the vault and grants the vault role it maps to.");
}

WsField s3gwScopeMode(std::string name = "scope_mode") {
    return str(std::move(name)).opt().oneOf({"user_access", "global", "vault_allowlist"})
        .desc("Dashes and any letter case are accepted (user-access).");
}

WsField s3gwExpiresAt() { return uinteger("expires_at").opt().nullable().desc("Epoch seconds."); }

std::vector<WsField> s3gwWith(std::vector<WsField> base, const std::vector<WsField>& more) {
    for (const auto& f : more) base.push_back(f);
    return base;
}

// ---- budget payloads (gateway credential budgets only) --------------------------------------------------------

WsField s3gwBudgetScope() {
    return str("scope").oneOf({"gateway_credential", "gateway_credential_vault"})
        .desc("Any other scope is refused (pricing.budget.* manages the rest).");
}

WsField s3gwBudgetCredentialId(const bool required) {
    auto f = uinteger("gateway_credential_id").gen(gen::ref("s3_credential", {"id"})).desc("The gateway credential.");
    return required ? f : f.opt().nullable();
}

std::vector<WsField> s3gwBudgetFilter(const bool withLimit, const std::int64_t defaultLimit) {
    std::vector<WsField> out{s3gwBudgetCredentialId(false),
                             uinteger("vault_id").opt().nullable().gen(gen::ref("vault", {"id"})),
                             boolean("include_inactive").opt().desc("Defaults to true.")};
    if (withLimit)
        out.push_back(uinteger("limit").opt().desc("Clamped to 1..500, default " + std::to_string(defaultLimit) + "."));
    return out;
}

// ---- responses ------------------------------------------------------------------------------------------------

WsField s3gwCredential() { return object("credential", "S3GatewayCredential"); }

WsField s3gwVault() {
    return object("vault", "S3GatewayVaultRef").nullable().desc("The vault (id, name, slug, fuse names, owner_id).");
}

std::vector<std::string> s3gwRefusals() { return opsRefusals(); }

WsCommandUsage s3gwCommand(std::string name, std::string description, std::vector<WsField> payload,
                           std::vector<WsField> response, std::vector<std::string> untyped = {},
                           const std::chrono::milliseconds timeout = kDefaultTimeout) {
    return {.command = std::move(name),
            .description = std::move(description),
            .payload = std::move(payload),
            .response = std::move(response),
            .refusal_codes = s3gwRefusals(),
            .untyped_refusals = std::move(untyped),
            .client_timeout = timeout};
}

}

std::vector<WsCommandUsage> s3GatewayCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    // ---- service ----
    {
        auto status = s3gwCommand(
            "s3.gateway.status",
            "S3 gateway runtime status: running/configured/ready, the listen endpoint and request counters.",
            {},
            {object("status", "", {boolean("running"), boolean("configured"), boolean("ready"), str("host"),
                                   uinteger("port"), str("endpoint").desc("host:port"), uinteger("active_sessions"),
                                   uinteger("total_requests"), uinteger("failed_requests")})});
        status.input = "none";
        out.push_back(std::move(status));
    }

    // ---- credentials ----
    out.push_back(s3gwCommand(
        "s3.gateway.credentials.create",
        "Create a gateway credential for a principal (the caller unless principal_user_id / user_id names another). "
        "The secret is returned once. scope_mode defaults to vault_allowlist when vaults are given, else user_access; "
        "global needs an admin principal and a default vault role.",
        s3gwWith(s3gwWith({str("name").gen(gen::freshName("s3cred_")).desc("The credential's name."),
                           uinteger("principal_user_id").opt().nullable().gen(gen::ref("user", {"id"})),
                           uinteger("user_id").opt().nullable().desc("Legacy spelling of principal_user_id (wins)."),
                           s3gwScopeMode(), s3gwScopeMode("scope").desc("Legacy spelling of scope_mode."),
                           str("description").opt().nullable(), s3gwExpiresAt()},
                          s3gwDefaultRoleRef()),
                 s3gwWith(s3gwSelectedVaultIds(),
                          {s3gwVaultScopes(), boolean("enforce_budget_for_local_requests").opt()})),
        {s3gwCredential(), str("secret_access_key").desc("Shown once.")}));

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.list",
        "Every credential the caller may see (their own, or all with admin.s3_gateway.manage_credentials).",
        {boolean("include_disabled").opt().desc("Defaults to true.")},
        {objectArray("credentials", "S3GatewayCredential")}));

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.revoke",
        "Revoke a credential by access key or name.",
        {str("access_key").opt().desc("access_key or name is required."), str("name").opt()},
        {boolean("revoked")}));

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.scope.update",
        "Change a credential's scope and settings; absent members stay as they are. Nothing to change is 'invalid'.",
        s3gwWith(s3gwWith(s3gwCredentialRef(),
                          {s3gwScopeMode(), uinteger("principal_user_id").opt().nullable().gen(gen::ref("user", {"id"})),
                           str("description").opt().nullable().desc("null or \"\" clears it."), s3gwExpiresAt(),
                           boolean("enforce_budget_for_local_requests").opt(), s3gwVaultScopes()}),
                 s3gwWith(s3gwSelectedVaultIds(), s3gwDefaultRoleRef())),
        {s3gwCredential()}));

    // ---- default vault role ----
    out.push_back(s3gwCommand(
        "s3.gateway.credentials.defaultRole.get", "A credential's default vault role, or null.",
        s3gwCredentialRef(),
        {s3gwCredential(), object("default_role", "S3GatewayDefaultRole").nullable()}));

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.defaultRole.set",
        "Set a credential's default vault role (refused for user-access credentials).",
        s3gwWith(s3gwWith(s3gwCredentialRef(), s3gwRoleRef("The vault role (or one of its name members) is required.")),
                 {boolean("enabled").opt().desc("Defaults to true.")}),
        {s3gwCredential(), object("default_role", "S3GatewayDefaultRole")},
        {"invalid", "not_found"}));

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.defaultRole.clear", "Remove a credential's default vault role.",
        s3gwCredentialRef(),
        {boolean("cleared").desc("Whether there was one."), s3gwCredential()}));

    // ---- selected vaults (vault-allowlist credentials) ----
    {
        const std::vector<WsField> selectedResponse{
            s3gwCredential(), objectArray("selected_vaults", "S3GatewaySelectedVault"),
            objectArray("vaults", "S3GatewaySelectedVault").desc("The same rows as selected_vaults (legacy).")};
        out.push_back(s3gwCommand(
            "s3.gateway.credentials.selectedVaults.list", "The vaults selected for a credential.",
            s3gwCredentialRef(), selectedResponse));
        out.push_back(s3gwCommand(
            "s3.gateway.credentials.selectedVaults.replace",
            "Replace a vault-allowlist credential's selected vaults (an empty or absent list clears them).",
            s3gwWith(s3gwCredentialRef(), s3gwSelectedVaultIds()), selectedResponse));
    }

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.selectedVaults.add", "Select one more vault for a vault-allowlist credential.",
        s3gwWith(s3gwWith(s3gwCredentialRef(), s3gwVaultRef()), {boolean("enabled").opt().desc("Defaults to true.")}),
        {s3gwCredential(), object("selected_vault", "S3GatewaySelectedVault")},
        {"invalid"}));

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.selectedVaults.remove",
        "Drop a vault from a credential: its selection and any per-vault role.",
        s3gwWith(s3gwCredentialRef(), s3gwVaultRef()),
        {boolean("removed"), s3gwCredential(), s3gwVault()},
        {"invalid"}));

    // ---- default role overrides ----
    out.push_back(s3gwCommand(
        "s3.gateway.credentials.defaultRole.overrides.list",
        "Permission overrides on a credential's default vault role.",
        s3gwCredentialRef(),
        {s3gwCredential(), object("default_role", "S3GatewayDefaultRole").nullable(),
         objectArray("overrides", "S3GatewayDefaultRoleOverride")}));

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.defaultRole.overrides.add",
        "Add a permission override to a credential's default vault role (needs a default role).",
        s3gwWith(s3gwCredentialRef(), s3gwPermissionRef()),
        {object("override", "S3GatewayDefaultRoleOverride")}));

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.defaultRole.overrides.remove",
        "Remove a permission override from a credential's default vault role.",
        s3gwWith(s3gwCredentialRef(), {s3gwOverrideId()}),
        {boolean("removed"), s3gwCredential()}));

    // ---- per-vault roles ----
    {
        const std::vector<WsField> assignment{object("assignment", "S3GatewayRoleAssignment"),
                                              object("role", "S3GatewayRoleAssignment").desc("Same as assignment (legacy).")};
        out.push_back(s3gwCommand(
            "s3.gateway.credentials.roles.list",
            "A credential's per-vault role assignments the caller may see.",
            s3gwCredentialRef(),
            {s3gwCredential(), objectArray("roles", "S3GatewayRoleAssignment"),
             objectArray("assignments", "S3GatewayRoleAssignment").desc("The same rows as roles (legacy).")}));
        out.push_back(s3gwCommand(
            "s3.gateway.credentials.roles.assign",
            "Assign a vault role to a credential on a vault (not for user-access credentials; the role may not "
            "exceed what the principal can do).",
            s3gwWith(s3gwWith(s3gwWith(s3gwCredentialRef(), s3gwVaultRef()),
                              s3gwRoleRef("The vault role (or one of its name members) is required.")),
                     {boolean("enabled").opt().desc("Defaults to true.")}),
            assignment, {"invalid", "not_found"}));
    }

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.roles.revoke", "Remove a credential's role on a vault.",
        s3gwWith(s3gwCredentialRef(), s3gwVaultRef()),
        {boolean("revoked"), s3gwCredential(), s3gwVault()},
        {"invalid"}));

    // ---- per-vault role overrides ----
    out.push_back(s3gwCommand(
        "s3.gateway.credentials.roles.overrides.list", "Permission overrides on a credential's grant on one vault.",
        s3gwWith(s3gwCredentialRef(), s3gwVaultRef()),
        {s3gwCredential(), s3gwVault(), objectArray("overrides", "S3GatewayRoleOverride")},
        {"invalid"}));

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.roles.overrides.add",
        "Add a permission override to a credential's grant on a vault (the vault must be selected and a default role "
        "set).",
        s3gwWith(s3gwWith(s3gwCredentialRef(), s3gwVaultRef()), s3gwPermissionRef()),
        {object("override", "S3GatewayRoleOverride")},
        {"invalid"}));

    out.push_back(s3gwCommand(
        "s3.gateway.credentials.roles.overrides.remove", "Remove a permission override from a credential's vault grant.",
        s3gwWith(s3gwWith(s3gwCredentialRef(), s3gwVaultRef()), {s3gwOverrideId()}),
        {boolean("removed"), s3gwCredential(), s3gwVault()},
        {"invalid"}));

    // ---- buckets ----
    {
        auto list = s3gwCommand("s3.gateway.buckets.list", "Bucket bindings the caller may manage.", {},
                                {objectArray("buckets", "S3GatewayBucket")});
        list.input = "none";
        out.push_back(std::move(list));
    }

    out.push_back(s3gwCommand(
        "s3.gateway.buckets.bind",
        "Bind a vault to a gateway bucket name (default: the vault's slug). Local vaults use mode local, S3/R2 vaults "
        "remote_cache or remote_proxy.",
        s3gwWith(s3gwVaultRef(),
                 {str("bucket_name").opt(), str("mode").opt().oneOf({"local", "remote_cache", "remote_proxy"}),
                  boolean("api_exclusive").opt()}),
        {boolean("bound")},
        {"invalid"}));

    out.push_back(s3gwCommand(
        "s3.gateway.buckets.unbind", "Remove a bucket binding (the vault stays).",
        {str("bucket_name").gen(gen::ref("s3_bucket", {"name"}))},
        {boolean("unbound")}));

    out.push_back(s3gwCommand(
        "s3.gateway.buckets.createLocal",
        "Create a local vault and bind it as a bucket (bucket name defaults to the vault's slug).",
        {str("bucket_name").opt(), uinteger("owner_id").opt().nullable().gen(gen::ref("user", {"id"})),
         uinteger("quota_bytes").opt().desc("0 = unlimited (default)."), str("name").opt().nullable(),
         str("description").opt().nullable()},
        {object("bucket", "S3GatewayBucket")},
        {}, 60s));

    {
        auto remote = s3gwCommand(
            "s3.gateway.buckets.createRemoteCache",
            "Create an S3 vault (cache strategy) over an upstream bucket and bind it as an API-exclusive bucket. The "
            "key needs Consume; a refusal with data.code 'encryption_waiver' means the upstream bucket already holds "
            "data: resend with accept_encryption_waiver once the person accepts.",
            {str("bucket_name").opt(), uinteger("owner_id").opt().nullable().gen(gen::ref("user", {"id"})),
             uinteger("api_key_id").opt().nullable().gen(gen::ref("api_key", {"id"}))
                 .desc("The upstream API key: api_key_id or api_key (name) is required."),
             str("api_key").opt().nullable().desc("The upstream API key by name."),
             str("upstream_bucket").gen(gen::pattern("vh-test-{a}{a}{a}{9}{9}")),
             boolean("encrypt_upstream").opt().desc("Defaults to true."), str("name").opt().nullable(),
             str("description").opt().nullable(), boolean("accept_encryption_waiver").opt()},
            {object("bucket", "S3GatewayBucket")},
            {"not_found"}, 180s);
        remote.refusal_codes.emplace_back("encryption_waiver");
        out.push_back(std::move(remote));
    }

    // ---- credential budgets ----
    out.push_back(s3gwCommand(
        "s3.gateway.budget.policy.list", "Gateway credential budget policies the caller may see.",
        s3gwBudgetFilter(false, 0),
        {objectArray("policies", "PriceBudgetPolicy")}));

    out.push_back(s3gwCommand(
        "s3.gateway.budget.policy.upsert",
        "Create or replace a gateway credential (or credential + vault) budget policy. Limits are decimal strings.",
        {s3gwBudgetScope(), s3gwBudgetCredentialId(true),
         uinteger("vault_id").opt().nullable().gen(gen::ref("vault", {"id"}))
             .desc("Required for gateway_credential_vault."),
         str("mode").opt().nullable().oneOf({"off", "report", "warn", "enforce"})
             .desc("Default enforce (warning / enforced accepted)."),
         str("currency").opt().nullable().desc("Default USD."), str("max_run_cost").opt().nullable(),
         str("max_daily_cost").opt().nullable(), str("max_monthly_cost").opt().nullable(),
         boolean("require_verified_catalog").opt().desc("Default true."),
         boolean("allow_stale_catalog").opt().desc("Default false."),
         uinteger("max_catalog_age_seconds").opt().nullable().desc("Default 43200.")},
        {object("policy", "PriceBudgetPolicy")},
        {"invalid"}));

    out.push_back(s3gwCommand(
        "s3.gateway.budget.policy.disable", "Disable a gateway credential (or credential + vault) budget policy.",
        {s3gwBudgetScope(), s3gwBudgetCredentialId(true),
         uinteger("vault_id").opt().nullable().gen(gen::ref("vault", {"id"}))},
        {boolean("disabled").desc("Whether an active policy was disabled.")},
        {"invalid"}));

    out.push_back(s3gwCommand(
        "s3.gateway.budget.ledger.list", "Gateway credential budget ledger entries (newest first).",
        s3gwBudgetFilter(true, 50),
        {objectArray("ledger", "PriceBudgetLedgerEntry")}));

    out.push_back(s3gwCommand(
        "s3.gateway.budget.status", "Gateway credential budget policies, recent ledger entries and spend trends.",
        s3gwBudgetFilter(true, 20),
        {objectArray("policies", "PriceBudgetPolicy"), objectArray("ledger", "PriceBudgetLedgerEntry"),
         objectArray("trends", "PriceBudgetTrendStats")}));

    return out;
}

}
