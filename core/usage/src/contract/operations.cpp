// Operation catalog: one canonical description per operation and how it is spelled on each surface. The CLI
// bindings name CommandUsage entries by kind and label ("positional:username", "option:role", "optional:email",
// "flag:disable"); the unit test resolves every one against the books, so a renamed entry fails the build's tests.

#include "Contract.hpp"

#include <utility>

namespace vh::contract {

namespace {

using std::chrono::milliseconds;

FieldSpec opField(std::string name, std::string type, FieldGenPtr g = nullptr, const bool required = true) {
    return {.name = std::move(name), .type = std::move(type), .required = required, .generator = std::move(g)};
}

FieldSpec opRef(std::string name, std::string entity, std::vector<std::string> attrs = {"id"}, const bool required = true) {
    auto g = gen::ref(entity, std::move(attrs));
    return {.name = std::move(name), .type = "ref", .required = required, .ref = std::move(entity), .generator = std::move(g)};
}

FieldSpec opOptional(FieldSpec f) {
    f.required = false;
    return f;
}

// ops:: refusals: CLI exit 2 with "<command>: <reason>", ws ERROR with data.code.
std::map<std::string, Refusal> opsRefusalMap() {
    return {
        {"denied", {.cli_exit = 2, .ws_code = "denied", .errno_name = "EACCES", .http_status = 403}},
        {"not_found", {.cli_exit = 2, .ws_code = "not_found", .errno_name = "ENOENT", .http_status = 404}},
        {"invalid", {.cli_exit = 2, .ws_code = "invalid", .errno_name = "EINVAL", .http_status = 400}},
        {"conflict", {.cli_exit = 2, .ws_code = "conflict", .errno_name = "EEXIST", .http_status = 409}},
        // ws: the router refuses before the handler; CLI: the socket peer is not in the vaulthalla group (77).
        {"unauthorized", {.cli_exit = 77, .ws_status = "UNAUTHORIZED", .http_status = 401}},
    };
}

// Filesystem handlers refuse with plain runtime errors: no ws data.code (see WsCommandUsage::untyped_refusals).
std::map<std::string, Refusal> fsRefusalMap() {
    auto m = opsRefusalMap();
    for (auto& [kind, refusal] : m)
        if (kind != "unauthorized") refusal.ws_code.clear();
    return m;
}

FieldSpec opVault() { return opRef("vault", "vault", {"id"}); }

FieldSpec opPath(std::string name = "path") {
    return opField(std::move(name), "path", gen::path("/{a}{a}{a}{9}"));
}

}

std::vector<OperationSpec> operations() {
    using namespace std::chrono_literals;
    std::vector<OperationSpec> out;

    // ---- identities -------------------------------------------------------------------------------------------

    out.push_back({
        .id = "users.create",
        .description = "Create a user with an admin role.",
        .fields = {opField("name", "string", gen::freshName("user_")),
                   opRef("role", "role.admin", {"name", "id"}),
                   opOptional(opField("email", "string", gen::email())),
                   opOptional(opField("password", "string", gen::bytes(16, 24))),
                   opOptional(opField("linux_uid", "uint", gen::testLinuxId()))},
        .requires_any = {"admin.identities.users.add", "admin.identities.admins.add"},
        .effect = {.kind = "create", .entity = "user"},
        .cli = CliBinding{.usage_path = {"user", "create"},
                          .field_to_entry = {{"name", "positional:username"}, {"role", "option:role"},
                                             {"email", "optional:email"}, {"linux_uid", "optional:linux_uid"}}},
        .ws = WsBinding{.command = "auth.register",
                        .field_to_json = {{"name", "/name"}, {"role", "/role"}, {"email", "/email"},
                                          {"password", "/password"}},
                        .id_pointer = "/user/id"},
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "users.update",
        .description = "Rename a user, change the email or the admin role.",
        .fields = {opRef("user", "user", {"name", "id"}),
                   opOptional(opField("name", "string", gen::freshName("user_"))),
                   opOptional(opField("email", "string", gen::email())),
                   opOptional(opRef("role", "role.admin", {"name", "id"}))},
        .requires_any = {"admin.identities.users.edit", "admin.identities.admins.edit", "owner"},
        .effect = {.kind = "update", .entity = "user"},
        .cli = CliBinding{.usage_path = {"user", "update"},
                          .field_to_entry = {{"user", "positional:username"}, {"name", "optional:username"},
                                             {"email", "optional:email"}, {"role", "optional:role"}}},
        .ws = WsBinding{.command = "auth.user.update",
                        .field_to_json = {{"user", "/id"}, {"name", "/name"}, {"email", "/email"}, {"role", "/role"}},
                        .id_pointer = "/user/id"},
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "users.deactivate",
        .description = "Deactivate an account; its sessions end on their next request.",
        .fields = {opRef("user", "user", {"name", "id"})},
        .requires_any = {"admin.identities.users.edit", "admin.identities.admins.edit"},
        .effect = {.kind = "update", .entity = "user"},
        .cli = CliBinding{.usage_path = {"user", "update"},
                          .field_to_entry = {{"user", "positional:username"}},
                          .fixed = {{"flag:disable", ""}}},
        .ws = WsBinding{.command = "auth.user.update", .field_to_json = {{"user", "/id"}},
                        .fixed = {{"/is_active", "false"}}},
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "users.delete",
        .description = "Delete a user (confirmed). Its vaults are destroyed unless transfer_to names an heir.",
        .fields = {opRef("user", "user", {"name", "id"}), opOptional(opRef("transfer_to", "user", {"name", "id"}))},
        .requires_any = {"admin.identities.users.delete", "admin.identities.admins.delete"},
        .effect = {.kind = "delete", .entity = "user"},
        .cli = CliBinding{.usage_path = {"user", "delete"},
                          .field_to_entry = {{"user", "positional:username"}, {"transfer_to", "optional:transfer_to"}},
                          .fixed = {{"flag:yes", ""}}},
        .ws = WsBinding{.command = "auth.user.delete",
                        .field_to_json = {{"user", "/id"}, {"transfer_to", "/transfer_to"}},
                        .fixed = {{"/confirm", "true"}}},
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "groups.create",
        .description = "Create a group.",
        .fields = {opField("name", "string", gen::freshName("group_")),
                   opOptional(opField("description", "string", gen::pattern("group {a}{a}{a}{a}{a}"))),
                   opOptional(opField("linux_gid", "uint", gen::testLinuxId()))},
        .requires_any = {"admin.identities.groups.add"},
        .effect = {.kind = "create", .entity = "group"},
        .cli = CliBinding{.usage_path = {"group", "create"},
                          .field_to_entry = {{"name", "positional:group"}, {"description", "optional:description"},
                                             {"linux_gid", "optional:linux_group"}}},
        .ws = WsBinding{.command = "group.add",
                        .field_to_json = {{"name", "/name"}, {"description", "/description"},
                                          {"linux_gid", "/linux_gid"}},
                        .id_pointer = "/group/id"},
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "groups.delete",
        .description = "Delete a group.",
        .fields = {opRef("group", "group", {"name", "id"})},
        .requires_any = {"admin.identities.groups.delete"},
        .effect = {.kind = "delete", .entity = "group"},
        .cli = CliBinding{.usage_path = {"group", "delete"}, .field_to_entry = {{"group", "positional:group"}}},
        .ws = WsBinding{.command = "group.remove", .field_to_json = {{"group", "/id"}}},
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "groups.add_user",
        .description = "Add a user to a group.",
        .fields = {opRef("group", "group", {"name", "id"}), opRef("user", "user", {"name", "id"})},
        .requires_any = {"admin.identities.groups.edit"},
        .effect = {.kind = "update", .entity = "group_membership"},
        .cli = CliBinding{.usage_path = {"group", "user", "add"},
                          .field_to_entry = {{"group", "positional:group"}, {"user", "positional:user"}}},
        .ws = WsBinding{.command = "group.member.add", .field_to_json = {{"group", "/group_id"}, {"user", "/user_id"}}},
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "groups.remove_user",
        .description = "Remove a user from a group.",
        .fields = {opRef("group", "group", {"name", "id"}), opRef("user", "user", {"name", "id"})},
        .requires_any = {"admin.identities.groups.edit"},
        .effect = {.kind = "update", .entity = "group_membership"},
        .cli = CliBinding{.usage_path = {"group", "user", "remove"},
                          .field_to_entry = {{"group", "positional:group"}, {"user", "positional:user"}}},
        .ws = WsBinding{.command = "group.member.remove",
                        .field_to_json = {{"group", "/group_id"}, {"user", "/user_id"}}},
        .refusals = opsRefusalMap(),
    });

    // ---- vault roles ------------------------------------------------------------------------------------------

    const auto subjectType = FieldSpec{.name = "subject_type", .type = "enum", .enum_values = {"user", "group"},
                                       .generator = gen::oneOf({"user", "group"})};
    out.push_back({
        .id = "roles.vault.assign",
        .description = "Assign a vault role to a user or group on a vault.",
        .fields = {opVault(), opRef("role", "role.vault", {"id", "name"}), subjectType,
                   opRef("subject", "subject", {"id", "name"})},
        .requires_any = {"vault.roles.assign"},
        .effect = {.kind = "create", .entity = "vault_role_assignment"},
        .cli = CliBinding{.usage_path = {"vault", "role", "assign"},
                          .field_to_entry = {{"vault", "positional:vault"}, {"role", "positional:role_id"},
                                             {"subject_type", "token:subject"}, {"subject", "option:subject"}}},
        .ws = WsBinding{.command = "role.vault.assign",
                        .field_to_json = {{"vault", "/vault_id"}, {"role", "/id"}, {"subject_type", "/subject_type"},
                                          {"subject", "/subject_id"}}},
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "roles.vault.unassign",
        .description = "Remove a subject's vault role assignment (the CLI also names the role).",
        .fields = {opVault(), opOptional(opRef("role", "role.vault", {"id", "name"})), subjectType,
                   opRef("subject", "subject", {"id", "name"})},
        .requires_any = {"vault.roles.revoke"},
        .effect = {.kind = "delete", .entity = "vault_role_assignment"},
        .cli = CliBinding{.usage_path = {"vault", "role", "unassign"},
                          .field_to_entry = {{"vault", "positional:vault"}, {"role", "positional:role_id"},
                                             {"subject_type", "token:subject"}, {"subject", "option:subject"}}},
        .ws = WsBinding{.command = "role.vault.unassign",
                        .field_to_json = {{"vault", "/vault_id"}, {"subject_type", "/subject_type"},
                                          {"subject", "/subject_id"}}},
        .refusals = opsRefusalMap(),
    });

    // ---- vaults -----------------------------------------------------------------------------------------------

    out.push_back({
        .id = "vaults.create",
        .description = "Create a local vault (S3 vaults need credentials the engine doesn't hold).",
        .fields = {opField("name", "string", gen::freshName("vault_")),
                   opOptional(opField("description", "string", gen::pattern("vault {a}{a}{a}{a}{a}"))),
                   opOptional(opRef("owner", "user", {"id", "name"}))},
        .requires_any = {"admin.vaults.self.create", "admin.vaults.user.create", "admin.vaults.admin.create"},
        .effect = {.kind = "create", .entity = "vault"},
        .cli = CliBinding{.usage_path = {"vault", "create"},
                          .field_to_entry = {{"name", "positional:vault"}, {"description", "optional:description"},
                                             {"owner", "optional:owner"}},
                          .fixed = {{"flag:type", "local"}}},
        .ws = WsBinding{.command = "storage.vault.add",
                        .field_to_json = {{"name", "/name"}, {"description", "/description"}, {"owner", "/owner_id"}},
                        .fixed = {{"/type", "\"local\""}},
                        .id_pointer = "/vault/id"},
        .deadline = 60s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "vaults.delete",
        .description = "Delete a vault (restorable until the retention window ends).",
        .fields = {opVault()},
        .requires_any = {"admin.vaults.self.remove", "admin.vaults.user.remove", "admin.vaults.admin.remove"},
        .effect = {.kind = "delete", .entity = "vault"},
        .cli = CliBinding{.usage_path = {"vault", "delete"}, .field_to_entry = {{"vault", "positional:vault"}},
                          .fixed = {{"flag:yes", ""}}},
        .ws = WsBinding{.command = "storage.vault.remove", .field_to_json = {{"vault", "/id"}}},
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "vaults.accessible.list",
        .description = "Every vault the actor reaches (owner, vault role, group role, admin policy, super admin) with "
                       "browse and manage as the resolvers decide them.",
        .requires_any = {"owner", "vault.fs.directories.list", "admin.vaults.self.view", "admin.vaults.user.view",
                         "admin.vaults.admin.view"},
        .effect = {.kind = "read", .entity = "vault"},
        .cli = CliBinding{.usage_path = {"vault", "list"}, .fixed = {{"flag:accessible", ""}}},
        .ws = WsBinding{.command = "storage.vault.accessible.list"},
        .refusals = opsRefusalMap(),
    });

    // ---- filesystem -------------------------------------------------------------------------------------------

    out.push_back({
        .id = "fs.list",
        .description = "List a directory.",
        .fields = {opVault(), opPath()},
        .requires_any = {"vault.fs.directories.list"},
        .effect = {.kind = "read", .entity = "fs.entry"},
        .ws = WsBinding{.command = "fs.dir.list", .field_to_json = {{"vault", "/vault_id"}, {"path", "/path"}}},
        .fuse = FsBinding{.actor_op = "ls", .field_to_arg = {{"path", "path"}}},
        .deadline = 30s,
        .refusals = fsRefusalMap(),
    });

    out.push_back({
        .id = "fs.read",
        .description = "Read a whole file.",
        .fields = {opVault(), opPath()},
        .requires_any = {"vault.fs.files.download"},
        .effect = {.kind = "read", .entity = "fs.entry"},
        .fuse = FsBinding{.actor_op = "read", .field_to_arg = {{"path", "path"}}},
        .http = HttpBinding{.method = "GET", .path = "/download",
                            .field_to_param = {{"vault", "query:vault_id"}, {"path", "query:path"}}},
        .deadline = 30s,
        .refusals = fsRefusalMap(),
    });

    out.push_back({
        .id = "fs.write",
        .description = "Create or replace a file with the given bytes (Write; Overwrite when it exists).",
        .fields = {opVault(), opPath(), opField("data", "bytes", gen::bytes(0, 4096))},
        .requires_any = {"vault.fs.files.upload", "vault.fs.files.overwrite"},
        .effect = {.kind = "create", .entity = "fs.entry"},
        .ws = WsBinding{.command = "fs.upload.start",
                        .field_to_json = {{"vault", "/vault_id"}, {"path", "/path"}, {"data", "/size"}}},
        .fuse = FsBinding{.actor_op = "write", .field_to_arg = {{"path", "path"}, {"data", "data_b64"}}},
        .http = HttpBinding{.method = "POST", .path = "/upload/session",
                            .field_to_param = {{"vault", "json:vault_id"}, {"path", "json:path"}, {"data", "body"}}},
        .deadline = 60s,
        .refusals = fsRefusalMap(),
    });

    out.push_back({
        .id = "fs.mkdir",
        .description = "Create a directory.",
        .fields = {opVault(), opPath()},
        .requires_any = {"vault.fs.directories.touch"},
        .effect = {.kind = "create", .entity = "fs.entry"},
        .ws = WsBinding{.command = "fs.dir.create", .field_to_json = {{"vault", "/vault_id"}, {"path", "/path"}}},
        .fuse = FsBinding{.actor_op = "mkdir", .field_to_arg = {{"path", "path"}}},
        .refusals = fsRefusalMap(),
    });

    out.push_back({
        .id = "fs.rename",
        .description = "Rename an entry.",
        .fields = {opVault(), opPath(), opPath("to")},
        .requires_any = {"vault.fs.files.rename", "vault.fs.directories.rename"},
        .effect = {.kind = "update", .entity = "fs.entry"},
        .ws = WsBinding{.command = "fs.entry.rename",
                        .field_to_json = {{"vault", "/vault_id"}, {"path", "/from"}, {"to", "/to"}}},
        .fuse = FsBinding{.actor_op = "rename", .field_to_arg = {{"path", "path"}, {"to", "to"}}},
        .deadline = 60s,
        .refusals = fsRefusalMap(),
    });

    out.push_back({
        .id = "fs.delete",
        .description = "Delete a file or a directory tree.",
        .fields = {opVault(), opPath()},
        .requires_any = {"vault.fs.files.delete", "vault.fs.directories.delete"},
        .effect = {.kind = "delete", .entity = "fs.entry"},
        .ws = WsBinding{.command = "fs.entry.delete", .field_to_json = {{"vault", "/vault_id"}, {"path", "/path"}}},
        .fuse = FsBinding{.actor_op = "rm_rf", .field_to_arg = {{"path", "path"}}},
        .deadline = 180s,
        .refusals = fsRefusalMap(),
    });

    out.push_back({
        .id = "fs.copy",
        .description = "Copy an entry or tree.",
        .fields = {opVault(), opPath(), opPath("to")},
        .requires_any = {"vault.fs.files.copy", "vault.fs.directories.copy"},
        .effect = {.kind = "create", .entity = "fs.entry"},
        .ws = WsBinding{.command = "fs.entry.copy",
                        .field_to_json = {{"vault", "/vault_id"}, {"path", "/from"}, {"to", "/to"}}},
        .fuse = FsBinding{.actor_op = "cp_tree", .field_to_arg = {{"path", "path"}, {"to", "to"}}},
        .deadline = 180s,
        .refusals = fsRefusalMap(),
    });

    // ---- shares and sessions ----------------------------------------------------------------------------------

    out.push_back({
        .id = "shares.create",
        .description = "Create a public download link on an entry.",
        .fields = {opVault(), opRef("entry", "fs.entry", {"id"}), opRef("path", "fs.entry", {"path"}),
                   FieldSpec{.name = "target_type", .type = "enum", .enum_values = {"file", "directory"}},
                   FieldSpec{.name = "link_type", .type = "enum", .enum_values = {"download", "upload", "access"},
                             .generator = gen::constant("download")}},
        .requires_any = {"vault.fs.files.share.public", "vault.fs.directories.share.public"},
        .effect = {.kind = "create", .entity = "share"},
        .ws = WsBinding{.command = "share.link.create",
                        .field_to_json = {{"vault", "/vault_id"}, {"entry", "/root_entry_id"}, {"path", "/root_path"},
                                          {"target_type", "/target_type"}, {"link_type", "/link_type"}},
                        .fixed = {{"/access_mode", "\"public\""}, {"/allowed_ops", "[\"metadata\",\"list\",\"download\"]"}},
                        .id_pointer = "/share/id"},
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "shares.revoke",
        .description = "Revoke a share link.",
        .fields = {opRef("share", "share", {"id"})},
        .requires_any = {"owner", "vault.fs.files.share.public", "vault.fs.directories.share.public"},
        .effect = {.kind = "delete", .entity = "share"},
        .ws = WsBinding{.command = "share.link.revoke", .field_to_json = {{"share", "/id"}}},
        .refusals = opsRefusalMap(),
    });

    // ---- file recovery (ops::recovery; .claude/context/recovery.md) ------------------------------------------

    const auto recoveryPoint = [] { return opRef("point", "recovery_point", {"id"}); };
    out.push_back({
        .id = "recovery.status",
        .description = "A vault's recovery settings, store usage, upstream backlog and provider versioning state.",
        .fields = {opVault(), opOptional(opField("refresh", "bool", gen::boolean()))},
        .requires_any = {"owner", "vault.sync.config.view"},
        .effect = {.kind = "read", .entity = "vault_recovery_policy"},
        .cli = CliBinding{.usage_path = {"vault", "recovery", "status"},
                          .field_to_entry = {{"vault", "positional:vault"}, {"refresh", "flag:refresh"}}},
        .ws = WsBinding{.command = "vault.recovery.status",
                        .field_to_json = {{"vault", "/vault_id"}, {"refresh", "/refresh_provider"}}},
        .deadline = 60s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "recovery.update",
        .description = "Change a vault's recovery mode, snapshot quota or local versioning (provider versioning also "
                       "needs the cost disclosure's token).",
        .fields = {opVault(),
                   opOptional(FieldSpec{.name = "mode", .type = "enum", .enum_values = {"off", "local_snapshots"},
                                        .generator = gen::oneOf({"off", "local_snapshots"})}),
                   opOptional(opField("snapshot_quota", "uint", gen::intRange(0, 1073741824)))},
        .requires_any = {"owner", "vault.sync.config.edit"},
        .effect = {.kind = "update", .entity = "vault_recovery_policy"},
        .cli = CliBinding{.usage_path = {"vault", "recovery", "set"},
                          .field_to_entry = {{"vault", "positional:vault"}, {"mode", "optional:mode"},
                                             {"snapshot_quota", "optional:snapshot_quota"}}},
        .ws = WsBinding{.command = "vault.recovery.update",
                        .field_to_json = {{"vault", "/vault_id"}, {"mode", "/mode"},
                                          {"snapshot_quota", "/snapshot_quota_bytes"}}},
        .deadline = 180s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "recovery.disclosure",
        .description = "The cost disclosure (and its token) for enabling provider versioning. Read-only.",
        .fields = {opVault(), opOptional(FieldSpec{.name = "retention", .type = "enum",
                                                   .enum_values = {"30d", "90d", "365d", "indefinite"},
                                                   .generator = gen::oneOf({"30d", "90d", "365d", "indefinite"})})},
        .requires_any = {"admin.upstream.configure"},
        .effect = {.kind = "read", .entity = "vault_recovery_policy"},
        .cli = CliBinding{.usage_path = {"vault", "recovery", "disclosure"},
                          .field_to_entry = {{"vault", "positional:vault"}, {"retention", "optional:retention"}}},
        .ws = WsBinding{.command = "vault.recovery.disclosure",
                        .field_to_json = {{"vault", "/vault_id"}, {"retention", "/provider_retention"}}},
        .deadline = 60s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "recovery.suspend",
        .description = "Suspend versioning on the vault's bucket (confirmed). Nothing is deleted.",
        .fields = {opVault()},
        .requires_any = {"admin.upstream.configure"},
        .effect = {.kind = "update", .entity = "vault_recovery_policy"},
        .cli = CliBinding{.usage_path = {"vault", "recovery", "suspend"},
                          .field_to_entry = {{"vault", "positional:vault"}}, .fixed = {{"flag:yes", ""}}},
        .ws = WsBinding{.command = "vault.recovery.suspend", .field_to_json = {{"vault", "/vault_id"}},
                        .fixed = {{"/confirm", "true"}}},
        .deadline = 60s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "recovery.costs",
        .description = "The vault's recovery cost estimates (computed locally; unknown money is null).",
        .fields = {opVault()},
        .requires_any = {"owner", "admin.stats.view"},
        .effect = {.kind = "read", .entity = "vault_recovery_policy"},
        .cli = CliBinding{.usage_path = {"recovery", "costs"}, .field_to_entry = {{"vault", "positional:vault"}}},
        .ws = WsBinding{.command = "recovery.costs", .field_to_json = {{"vault", "/vault_id"}}},
        .deadline = 60s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "recovery.list",
        .description = "Recovery points of a vault or a path the actor can read.",
        .fields = {opVault(), opOptional(opPath())},
        .requires_any = {"vault.fs.files.download", "vault.fs.directories.list"},
        .effect = {.kind = "read", .entity = "recovery_point"},
        .cli = CliBinding{.usage_path = {"recovery", "list"},
                          .field_to_entry = {{"vault", "positional:vault"}, {"path", "positional:path"}}},
        .ws = WsBinding{.command = "recovery.list", .field_to_json = {{"vault", "/vault_id"}, {"path", "/path"}}},
        .deadline = 120s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "recovery.inspect",
        .description = "One recovery point (not_found when the actor can't read it).",
        .fields = {recoveryPoint()},
        .requires_any = {"vault.fs.files.download", "vault.fs.directories.list"},
        .effect = {.kind = "read", .entity = "recovery_point"},
        .cli = CliBinding{.usage_path = {"recovery", "inspect"}, .field_to_entry = {{"point", "positional:recovery_id"}}},
        .ws = WsBinding{.command = "recovery.inspect", .field_to_json = {{"point", "/recovery_id"}}},
        .deadline = 30s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "recovery.snapshot.create",
        .description = "Take a named local snapshot of a file or directory tree.",
        .fields = {opVault(), opPath(), opOptional(opField("name", "string", gen::pattern("snap {a}{a}{a}")))},
        .requires_any = {"vault.fs.files.copy", "vault.fs.directories.copy"},
        .effect = {.kind = "create", .entity = "recovery_point"},
        .cli = CliBinding{.usage_path = {"snapshot", "create"},
                          .field_to_entry = {{"vault", "positional:vault"}, {"path", "positional:path"},
                                             {"name", "optional:name"}}},
        .ws = WsBinding{.command = "recovery.snapshot.create",
                        .field_to_json = {{"vault", "/vault_id"}, {"path", "/path"}, {"name", "/name"}},
                        .id_pointer = "/detail/point/id"},
        .deadline = 300s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "recovery.point.delete",
        .description = "Delete a snapshot or a local version (confirmed).",
        .fields = {recoveryPoint()},
        .requires_any = {"vault.fs.files.delete", "vault.fs.directories.delete"},
        .effect = {.kind = "delete", .entity = "recovery_point"},
        .cli = CliBinding{.usage_path = {"recovery", "delete"}, .field_to_entry = {{"point", "positional:recovery_id"}},
                          .fixed = {{"flag:yes", ""}}},
        .ws = WsBinding{.command = "recovery.point.delete", .field_to_json = {{"point", "/recovery_id"}},
                        .fixed = {{"/confirm", "true"}}},
        .deadline = 60s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "recovery.plan",
        .description = "Plan restoring a recovery point (read-only; stored 30 minutes with a token).",
        .fields = {recoveryPoint(), opOptional(opPath("destination"))},
        .requires_any = {"vault.fs.files.download"},
        .effect = {.kind = "create", .entity = "recovery_plan"},
        .cli = CliBinding{.usage_path = {"recovery", "plan"},
                          .field_to_entry = {{"point", "positional:source"}, {"destination", "optional:to"}}},
        .ws = WsBinding{.command = "recovery.plan",
                        .field_to_json = {{"point", "/recovery_id"}, {"destination", "/destination"}},
                        .id_pointer = "/plan/id"},
        .deadline = 180s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "recovery.restore",
        .description = "Run a restore plan with its token; every item is authorized again.",
        .fields = {opRef("plan", "recovery_plan", {"id"}), opField("token", "string")},
        .requires_any = {"vault.fs.files.overwrite", "vault.fs.files.upload"},
        .effect = {.kind = "update", .entity = "fs.entry"},
        .cli = CliBinding{.usage_path = {"recovery", "restore"},
                          .field_to_entry = {{"plan", "positional:plan"}, {"token", "optional:token"}}},
        .ws = WsBinding{.command = "recovery.restore", .field_to_json = {{"plan", "/plan_id"}, {"token", "/token"}}},
        .deadline = 1800s,
        .refusals = opsRefusalMap(),
    });

    out.push_back({
        .id = "auth.login",
        .description = "Open an authenticated ws session.",
        .fields = {opRef("user", "user", {"name"}), opField("password", "string")},
        .effect = {.kind = "session", .entity = "session"},
        .ws = WsBinding{.command = "auth.login", .field_to_json = {{"user", "/name"}, {"password", "/password"}},
                        .id_pointer = "/user/id"},
        .deadline = 20s,
        .refusals = {{"denied", {.cli_exit = 2, .ws_code = "", .http_status = 401}}},
    });

    return out;
}

}
