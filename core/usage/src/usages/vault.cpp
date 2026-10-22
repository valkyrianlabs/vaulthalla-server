#include "usages.hpp"
#include "CommandUsage.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::vault {

static std::shared_ptr<CommandUsage> buildBaseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static const Positional vaultPos = Positional::WithAliases("vault", "Name or ID of the vault", {"name", "id"},
                                                          contract::gen::ref("vault", {"id", "name"}));

static const Optional localConflictOpt = Optional::Multi("local_conflict",
                                                         "Conflict resolution strategy for local vaults",
                                                         {"on-sync-conflict", "conflict"},
                                                         {"overwrite", "keep_both", "ask"}, "overwrite")
                                         .withLiteralValues();
static const Optional syncStrategyOpt = Optional::Multi("sync_strategy",
                                                        "Sync strategy for S3 vaults (new vaults default to "
                                                        "vaults.s3.default_remote_sync_strategy in config.yaml)",
                                                        {"sync-strategy", "strategy"}, {"cache", "sync", "mirror"})
                                        .withLiteralValues();
static const Optional s3ConflictOpt = Optional::Multi("s3_conflict",
                                                      "Conflict resolution strategy for S3 vaults (new vaults default "
                                                      "to vaults.s3.default_remote_conflict_policy in config.yaml)",
                                                      {"on-sync-conflict", "conflict"},
                                                      {"keep_local", "keep_remote", "keep_newest", "ask"})
                                      .withLiteralValues();

static const auto intervalOpt = Optional::ManyToOne("interval", "Sync interval in seconds (default 5m)", {"interval", "sync-interval"}, "interval")
                                    .withGen("interval", contract::gen::oneOf({"300", "5m", "30m", "1h"}));

static const auto s3BudgetListOpt = Optional::ManyToOne("s3_budget_list",
                                                        "Maximum LIST requests per S3 sync run; use 'unlimited' to clear.",
                                                        {"s3-budget-list"}, "count");
static const auto s3BudgetHeadOpt = Optional::ManyToOne("s3_budget_head",
                                                        "Maximum HEAD requests per S3 sync run; use 'unlimited' to clear.",
                                                        {"s3-budget-head"}, "count");
static const auto s3BudgetGetOpt = Optional::ManyToOne("s3_budget_get",
                                                       "Maximum GET requests per S3 sync run; use 'unlimited' to clear.",
                                                       {"s3-budget-get"}, "count");
static const auto s3BudgetPutOpt = Optional::ManyToOne("s3_budget_put",
                                                       "Maximum PUT requests per S3 sync run; use 'unlimited' to clear.",
                                                       {"s3-budget-put"}, "count");
static const auto s3BudgetCopyOpt = Optional::ManyToOne("s3_budget_copy",
                                                        "Maximum COPY requests per S3 sync run; use 'unlimited' to clear.",
                                                        {"s3-budget-copy"}, "count");
static const auto s3BudgetDeleteOpt = Optional::ManyToOne("s3_budget_delete",
                                                          "Maximum DELETE requests per S3 sync run; use 'unlimited' to clear.",
                                                          {"s3-budget-delete"}, "count");
static const auto s3BudgetDownloadBytesOpt = Optional::ManyToOne("s3_budget_download_bytes",
                                                                 "Maximum downloaded bytes per S3 sync run; use 'unlimited' to clear.",
                                                                 {"s3-budget-download-bytes"}, "bytes");
static const auto s3BudgetPresetOpt = Optional::Multi("s3_budget_preset",
                                                      "Apply an S3 budget preset. Individual budget flags override preset fields.",
                                                      {"s3-budget-preset", "budget-preset"},
                                                      {"conservative", "balanced", "bulk", "unlimited"});
static const auto maxRemoteIndexAgeOpt = Optional::ManyToOne("max_remote_index_age",
                                                             "Maximum age for trusting the local S3 remote index when manifest refresh fails; use 'unlimited' to clear.",
                                                             {"max-remote-index-age", "remote-index-age"}, "duration");

static const auto interactiveFlag = Flag::WithAliases("interactive_mode",
                                                      "Run in interactive mode, prompting for missing information",
                                                      {"interactive", "i"});

static const auto descriptionOpt = Optional::ManyToOne("description", "Description of the vault", {"description", "desc", "d"},
                                                       "description")
                                       .withGen("description", contract::gen::pattern("vault {a}{a}{a}{a}{a}"));

static const auto quotaOpt = Optional::Multi(
    "quota", "Storage quota (e.g. 10G, 500M). Use 'unlimited' to remove quota.", {"quota", "q"},
    {"size", "unlimited"})
                          .withGen("size", contract::gen::oneOf({"500M", "10G", "1T"}))
                          .withGen("unlimited", contract::gen::constant("unlimited"));

static const auto vaultType = Flag::WithAliases("type", "Type of vault to create", {"local", "s3"});

static const auto owner = Optional::Multi("owner", "User ID or username of the vault owner (required if using name)",
                                          {"owner", "o"},
                                          {"id", "name"})
                             .withGen("id", contract::gen::ref("user", {"id"}))
                             .withGen("name", contract::gen::ref("user", {"name"}));

static const auto vaultOrAll = Positional::WithAliases(
    "vault", "Single vault: ID or name of the vault or 'all' for all vaults",
    {"id", "name", "all"}, contract::gen::ref("vault", {"id", "name"}));

static const auto syncNowFlag = Flag::WithAliases("sync_now", "Immediately synchronize the vault after key rotation",
                                                  {"now", "sync-now", "sync"});

static const auto roleId = Positional::Alias("role_id", "ID of the role to override", "id",
                                             contract::gen::ref("role.vault", {"id", "name"}));

static const auto bitPosition = Positional::Same("bit_position", "Bit position of the permission override to update");
static const auto inventoryFileOpt = Option::Single("file", "Path to a local S3 Inventory CSV file.", "file", "path");
static const auto inventorySchemaOpt = Optional::ManyToOne("schema",
                                                           "Comma-separated CSV columns when the inventory file has no header.",
                                                           {"schema"}, "columns");
static const auto inventoryHeaderFlag = Flag::WithAliases("has_header",
                                                          "Treat the first inventory CSV row as a header row.",
                                                          {"has-header", "header"});
static const auto eventFileOpt = Option::Single("file", "Path to an S3 Event Notifications JSON file.", "file", "path");
static const auto allowListScanFlag = Flag::WithAliases("allow_list_scan",
                                                        "Allow a full S3 ListObjectsV2 scan when no LIST budget is configured.",
                                                        {"allow-list-scan"});
static const auto refreshIndexFlag = Flag::WithAliases("refresh_index",
                                                       "Refresh the remote index manifest before planning. Requires sync trigger permission and may issue S3 HEAD/GET requests.",
                                                       {"refresh-index", "refresh-remote-index"});
static const auto refreshPricingFlag = Flag::WithAliases("refresh_pricing",
                                                         "Refresh cached storage-rate profile and estimate data before pricing the dry-run.",
                                                         {"refresh-pricing"});
static const auto noPricingFlag = Flag::WithAliases("no_pricing",
                                                    "Skip storage-rate price estimates for this dry-run.",
                                                    {"no-pricing"});

static const auto enableFlag = Flag::Alias("enable", "Enable the override (default)", "enable");
static const auto disableFlag = Flag::Alias("disable", "Disable the override", "disable");
static const auto allowEffectFlag = Flag::Alias("allow", "Make the override an allow", "allow");
static const auto denyEffectFlag = Flag::Alias("deny", "Make the override a deny", "deny");

static const auto regexPattern = Optional::Single("regex_pattern",
                                                  "Regex pattern to scope the override to specific paths", "pattern",
                                                  "regex")
                                  .withGen("regex", contract::gen::path("/{a}{a}{a}{a}/**"));

static const auto localFlag = Flag::Alias("local_filter", "Show only local vaults", "local");
static const auto s3Flag = Flag::Alias("s3_filter", "Show only S3-backed vaults", "s3");
static const auto accessibleFlag = Flag::Alias("accessible",
                                               "Every vault you can reach (as owner, through a vault role of yours or "
                                               "a group's, or your admin role) with what you can do there: browse "
                                               "(open its files) and manage (its settings). Takes no filters or paging",
                                               "accessible");

static const auto apiKeyOpt = Optional::OneToMany("s3_api_key", "Name or ID of the API key to access the S3 bucket",
                                                  "api-key", {"name", "id"})
                                 .withGen("name", contract::gen::ref("api_key", {"name"}))
                                 .withGen("id", contract::gen::ref("api_key", {"id"}));

static const auto s3BucketOpt = Optional::Single("s3_bucket", "Name of the S3 bucket", "bucket", "name")
                                   .withGen("name", contract::gen::pattern("vh-test-{a}{a}{a}{9}{9}"));
static const auto s3StorageTierOpt = Optional::ManyToOne(
    "s3_storage_tier",
    "Provider-local S3 storage tier for new uploads; use 'none' or 'default' to clear.",
    {"storage-tier", "storage-class"},
    "tier");

static const auto enableS3Encryption = Flag::On("enable_s3_encrypt",
                                                "Enable upstream encryption for S3 vaults. This is the default.",
                                                {"encrypt"});
static const auto disableS3Encryption = Flag::Off("disable_s3_encrypt", "Disable upstream encryption for S3 vaults.",
                                                  {"no-encrypt"});
static const auto acceptOverwriteWaiver = Flag::Alias("accept_overwrite_waiver",
                                                      "Acknowledge the risks of enabling encryption on an upstream s3 bucket with existing files.",
                                                      "accept-overwrite-waiver");
static const auto acceptDecryptionWaiver = Flag::Alias("accept_decryption_waiver",
                                                       "Acknowledge the risks of disabling encryption on an upstream s3 bucket with existing encrypted files.",
                                                       "accept-decryption-waiver");

// Upstream bucket provisioning (#237), for keys with provider administration enabled (vh upstream admin enable).
static const auto bucketModeOpt = Optional::Single(
    "s3_bucket_mode",
    "existing (default: bind --bucket as named), create (a new managed bucket; never takes over an existing one) or "
    "adopt (associate an existing bucket after a read-only admission check)",
    "bucket-mode", "existing|create|adopt")
    .withGen("existing|create|adopt", contract::gen::constant("existing"));
static const auto generateBucketFlag = Flag::Alias(
    "s3_generate_bucket", "With --bucket-mode create: pick an available bucket name", "generate-bucket");
static const auto bucketRegionOpt = Optional::Single(
    "s3_bucket_region", "With --bucket-mode create: AWS region or R2 location hint (wnam, enam, weur, eeur, apac, oc)",
    "region", "region")
    .withGen("region", contract::gen::constant("us-east-2"));
static const auto eventsFlag = Flag::Alias(
    "s3_events", "With --bucket-mode create|adopt: turn on event-driven sync for the bucket", "events");
static const auto eventsPrefixOpt = Optional::Single(
    "s3_events_prefix", "With --events: only keys with this prefix", "events-prefix", "prefix")
    .withGen("prefix", contract::gen::pattern("{a}{a}{a}/"));
static const auto abortMultipartOpt = Optional::Single(
    "s3_abort_multipart_days", "With --bucket-mode create|adopt: abort incomplete multipart uploads after N days",
    "abort-multipart-days", "n")
    .withGen("n", contract::gen::intRange(1, 30));
static const auto acceptAdoptionFlag = Flag::Alias(
    "accept_adoption", "With --bucket-mode adopt: accept the admission report without being asked", "yes");

static const GroupedOptions localVaultOpts("Local Vault Options", {localConflictOpt});

static const GroupedOptions s3ProvisionOpts("S3 Bucket Provisioning (administrative keys)", {
                                                bucketModeOpt,
                                                generateBucketFlag,
                                                bucketRegionOpt,
                                                eventsFlag,
                                                eventsPrefixOpt,
                                                abortMultipartOpt,
                                                acceptAdoptionFlag
                                            });

static const GroupedOptions s3VaultOpts("S3 Vault Options", {
                                            apiKeyOpt,
                                            s3BucketOpt,
                                            s3StorageTierOpt,
                                            syncStrategyOpt,
                                            s3ConflictOpt,
                                            enableS3Encryption,
                                            disableS3Encryption,
                                            acceptOverwriteWaiver,
                                            acceptDecryptionWaiver
                                        });

static std::shared_ptr<CommandUsage> create(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"create", "new", "add", "mk"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Create a new vault. Supports local and S3-backed vaults.";
    cmd->positionals = {vaultPos.withGen(contract::gen::freshName("vault_"))};
    cmd->required_flags = {vaultType};
    cmd->optional_flags = {interactiveFlag};
    cmd->optional = {descriptionOpt, quotaOpt, intervalOpt,  owner};
    cmd->groups = {localVaultOpts, s3VaultOpts, s3ProvisionOpts};
    cmd->examples = {
        {"vh vault create myvault --local --desc \"My Local Vault\" --quota 10G",
         "Create a local vault with a 10GB quota."},
        {"vh vault create s3vault --s3 --api-key myapikey --bucket mybucket", "Create an S3-backed vault."},
        {"vh vault create media --s3 --api-key aws-admin --bucket-mode create --generate-bucket --region us-east-2",
         "Create the vault on a new managed bucket with a generated name."},
        {"vh vault create media --s3 --api-key r2-admin --bucket-mode create --bucket vh-media --events",
         "Create a managed R2 bucket with event-driven sync."},
        {"vh vault create archive --s3 --api-key aws-admin --bucket legacy-photos --bucket-mode adopt",
         "Adopt an existing bucket (shows the admission report and asks)."},
        {"vh vault create archive-ready --s3 --api-key aws-prod --bucket vaulthalla --storage-tier standard_ia",
         "Create an AWS S3 vault using the provider-local Standard-IA tier for new uploads."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> update(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"update", "set", "modify", "edit"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Update properties of an existing vault.";
    cmd->positionals = {vaultPos};
    cmd->optional = {descriptionOpt, quotaOpt, intervalOpt, owner};
    cmd->optional_flags = {interactiveFlag};
    cmd->groups = {localVaultOpts, s3VaultOpts};
    cmd->examples = {
        {"vh vault update 42 --desc \"Updated Description\" --quota 20G",
         "Update the description and quota of the vault with ID 42."},
        {"vh vault update myvault --owner alice --api-key newkey --bucket newbucket --sync-strategy mirror "
         "--on-sync-conflict keep_remote",
         "Update multiple properties of the vault named 'myvault' owned by 'alice'."},
        {"vh vault update 42 --owner bob",
         "Give the vault with ID 42 to 'bob' (needs permission to create vaults for him)."},
        {"vh vault update 42 --storage-tier none",
         "Clear an S3 vault storage tier so the provider default is used."}
    };
    return cmd;
}

static const auto deleteNowFlag = Flag::Alias(
    "delete_now",
    "Purge the vault's data right away instead of after vaults.retention_window. Asks once more (--yes confirms). "
    "On a vault already pending deletion, purges it now. The encryption key is still kept for the full key retention window.",
    "now");
static const auto deleteUpstreamFlag = Flag::Alias(
    "delete_upstream", "S3 vaults: also delete every object in the bucket when the vault is purged.", "delete-upstream");
static const auto keepUpstreamFlag = Flag::Alias(
    "keep_upstream", "S3 vaults: keep the bucket's objects (the default without a terminal).", "keep-upstream");
static const auto deleteYesFlag = Flag::Alias(
    "yes", "Don't ask: delete with the given flags (also confirms --now).", "yes");
static const auto acceptKeyLossFlag = Flag::Alias(
    "accept_key_loss",
    "Delete an S3 vault whose encrypted objects stay in the bucket although its key was never exported. Without the key "
    "that data can never be decrypted again: export it first (vh vault keys export).",
    "accept-key-loss");

static std::shared_ptr<CommandUsage> remove(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"delete", "remove", "del", "rm"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Delete a vault. It disappears at once and can be restored (vh vault restore) until "
                       "vaults.retention_window ends; then its data is purged. Its encryption key is kept for the key "
                       "retention window. In a terminal it asks how to delete; S3 vaults are asked about their upstream data.";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->optional_flags = {deleteNowFlag, deleteUpstreamFlag, keepUpstreamFlag, deleteYesFlag, acceptKeyLossFlag};
    cmd->examples = {
        {"vh vault delete 42", "Delete the vault with ID 42 (restorable until the retention window ends)."},
        {"vh vault delete myvault --owner alice", "Delete the vault named 'myvault' owned by user 'alice'."},
        {"vh vault delete 42 --now --yes", "Delete vault 42 and purge its data right away, without asking."},
        {"vh vault delete 7 --delete-upstream --yes", "Delete S3 vault 7 and the objects in its bucket when it is purged."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> restore(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"restore", "undelete"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Restore a deleted vault, exactly as it was, while it is pending deletion (until "
                       "vaults.retention_window ends and its purge starts).";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->examples = {
        {"vh vault restore 42", "Restore the deleted vault with ID 42."},
        {"vh vault restore myvault --owner alice", "Restore the deleted vault 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> deleted(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"deleted", "trash"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List deleted vaults: pending (restorable), being purged, and purged ones whose encryption key "
                       "is still kept. Warns about encrypted upstream data whose key was never exported.";
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {
        {"vh vault deleted", "List deleted vaults you could restore or purge."},
        {"vh vault deleted --json", "The same, as JSON."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> info(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"info", "show", "get"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Display detailed information about a vault.";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->examples = {
        {"vh vault info 42", "Show information for the vault with ID 42."},
        {"vh vault info myvault --owner alice", "Show information for the vault named 'myvault' owned by user 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> list(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"list", "ls"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List the vaults your admin role lets you view (--accessible: every vault you can reach).";
    cmd->required_flags = {localFlag, s3Flag, jsonFlag};
    cmd->optional_flags = {accessibleFlag};
    cmd->optional = listQueryOptions();
    cmd->examples = {
        {"vh vaults", "List the vaults your admin role lets you view."},
        {"vh vaults --local", "List only local vaults."},
        {"vh vaults --s3 --limit 5", "List up to 5 S3-backed vaults."},
        {"vh vault list --accessible", "Every vault you can reach, how, and whether you can browse or manage it."},
        {"vh vault list --accessible --json", "The same as JSON (storage.vault.accessible.list's rows)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> role_assign(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"assign"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Assign a role to a user or group for a specific vault.";
    cmd->positionals = {vaultPos, roleId};
    cmd->required = {subjectOption};
    cmd->optional = {owner};
    cmd->examples = {
        {"vh vault role assign 42 read-only -u bob", "Add user 'bob' to the 'read-only' role for the vault with ID 42."},
        {"vh vault role assign myvault read-write --group developers --owner alice",
         "Add group 'developers' to the 'read-write' role for the vault named 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> role_unassign(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"unassign", "remove", "rm-assn"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Remove a role assignment from a user or group for a specific vault.";
    cmd->positionals = {vaultPos, roleId};
    cmd->required = {subjectOption};
    cmd->optional = {owner};
    cmd->examples = {
        {"vh vault role unassign 42 read-only -u bob",
         "Remove user 'bob' from the 'read-only' role for the vault with ID 42."},
        {"vh vault role unassign myvault read-write --group developers --owner alice",
         "Remove group 'developers' from the 'read-write' role for the vault named 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> role_override_add(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"add", "new", "create", "mk"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Add path-scoped permission overrides (--allow-<perm> / --deny-<perm>, see 'vh permission vault') "
                       "to the vault role assigned to a user or group.";
    cmd->positionals = {vaultPos, roleId};
    cmd->required = {subjectOption};
    cmd->optional_flags = {enableFlag, disableFlag};
    cmd->optional = {regexPattern, owner};
    cmd->option_prefixes = {"allow-", "deny-"};
    cmd->examples = {
        {R"(vh vault role override add 42 read-only -u bob --allow-files-download --pattern "/reports/**")",
         "Allow user 'bob' to download files under /reports in the vault with ID 42."},
        {R"(vh vault role override add myvault read-write --group developers --deny-files-delete --pattern "/sensitive/**" --owner alice)",
         "Deny group 'developers' from deleting files under /sensitive in the vault 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> role_override_update(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"update", "set", "modify", "edit"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Update an override (by ID) on the vault role assigned to a user or group.";
    cmd->positionals = {vaultPos, roleId, bitPosition};
    cmd->required = {subjectOption};
    cmd->optional_flags = {allowEffectFlag, denyEffectFlag, enableFlag, disableFlag};
    cmd->optional = {regexPattern, owner};
    cmd->examples = {
        {R"(vh vault role override update 42 read-only 7 -u bob --deny --pattern "/reports/*.exe")",
         "Make override 7 for user 'bob' on vault 42 a deny for .exe files under /reports."},
        {R"(vh vault role override update myvault read-write 3 --group developers --disable --owner alice)",
         "Disable override 3 for group 'developers' on the vault 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> role_override_remove(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"remove", "del", "rm"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Remove a permission override (by bit position) from a user or group in a specific vault role.";
    cmd->positionals = {vaultPos, roleId, bitPosition};
    cmd->required = {
        Option::Multi("subject", "Specify the user or group whose override to remove", {"user", "u", "group", "g"},
                      {"id", "name"})
    };
    cmd->optional = {
        Optional::Multi("owner", "User ID or username of the vault owner (required if using name)", {"owner", "o"},
                        {"id", "name"})
    };
    cmd->examples = {
        {"vh vault role override remove 42 read-only 5 -u bob",
         "Remove the bit-5 override for user 'bob' in vault 42 on role 'read-only'."},
        {"vh vault role override rm myvault read-write 3 --group developers --owner alice",
         "Remove the bit-3 override for group 'developers' in 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> role_override_list(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"list", "ls"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List permission overrides for a user or group in a specific vault role.";
    cmd->positionals = {vaultPos, roleId};
    cmd->required = {subjectOption};
    cmd->optional = {owner};
    cmd->examples = {
        {"vh vault role override list 42 read-only -u bob",
         "List all overrides for user 'bob' in role 'read-only' on vault 42."},
        {"vh vault role override ls myvault read-write --group developers --owner alice",
         "List all overrides for group 'developers' in 'myvault' (owner 'alice') on role 'read-write'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> role_override(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"override", "o"};
    cmd->description = "Manage permission overrides for users or groups in a specific vault role.";
    cmd->examples = {
        {R"(vh vault role override add 42 read-only -u bob --allow-files-download --pattern "/reports/**")",
         "Allow user 'bob' to download files under /reports in vault 42, on top of 'read-only'."},
        {R"(vh vault role override add myvault read-write --group developers --deny-files-delete --pattern "/sensitive/**" --owner alice)",
         "Deny 'developers' from deleting files under /sensitive in 'myvault' (owner 'alice')."}
    };
    cmd->subcommands = {
        role_override_add(cmd->weak_from_this()),
        role_override_update(cmd->weak_from_this()),
        role_override_remove(cmd->weak_from_this()),
        role_override_list(cmd->weak_from_this())
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> role_list(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"list", "ls"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List all role assignments for a specific vault.";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->examples = {
        {"vh vault role list 42", "List all role assignments for the vault with ID 42."},
        {"vh vault role list myvault --owner alice",
         "List all role assignments for the vault named 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> vrole(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"role", "r"};
    cmd->pluralAliasImpliesList = true;
    cmd->description = "Manage vault role assignments and permission overrides.";
    cmd->examples = {
        {"vh vault role assign 42 read-only -u bob", "Add user 'bob' to the 'read-only' role for the vault with ID 42."},
        {"vh vault role remove myvault read-write --group developers --owner alice",
         "Remove group 'developers' from the 'read-write' role for the vault named 'myvault' owned by 'alice'."},
        {R"(vh vault role override add 42 read-only -u bob --allow-files-download --pattern "/reports/**")",
         "Allow user 'bob' to download PDF files in the vault with ID 42, overriding the 'read-only' role."},
        {"vh vault role list myvault --owner alice",
         "List all role assignments for the vault named 'myvault' owned by 'alice'."}
    };
    cmd->subcommands = {
        role_list(cmd->weak_from_this()),
        role_override(cmd->weak_from_this()),
        role_assign(cmd->weak_from_this()),
        role_unassign(cmd->weak_from_this())
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> key_export(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"export"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Export an encryption key for a specific vault. --output is written by the daemon, so it must "
                       "be an absolute path; the file is created with mode 0600. Retired key versions that recoverable "
                       "data (snapshots, local versions, provider object versions) still needs are included under "
                       "historical_keys.";
    cmd->positionals = {vaultOrAll};
    cmd->optional = {gpgRecipient, outputFile, owner};
    cmd->examples = {
        {"vh vault keys export 42 --output /var/lib/vaulthalla/keyfile.pem --recipient ABCDEF1234567890",
         "Export the encryption key for the vault with ID 42 to '/var/lib/vaulthalla/keyfile.pem', encrypted for the GPG recipient with fingerprint 'ABCDEF1234567890'."},
        {"vh vault keys export myvault --owner alice --output /var/lib/vaulthalla/myvault_key.pem",
         "Export the encryption key for the vault named 'myvault' owned by 'alice' to '/var/lib/vaulthalla/myvault_key.pem' (unencrypted)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> key_inspect(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"inspect", "info", "show"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show encryption key metadata (version, creation and rotation state) for a vault. "
                       "Never prints key material.";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->examples = {
        {"vh vault keys inspect 42", "Show key metadata for the vault with ID 42."},
        {"vh vault keys inspect myvault --owner alice", "Show key metadata for 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> key_status(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"status"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show each vault's key backup state: the current key version and its key check (a public "
                       "fingerprint, never key material), the last exported version, whether a rotation is under way, "
                       "and every key version the vault still needs (current, an unfinished rotation's outgoing key, "
                       "retired versions recovery data references). Deleted vaults within key retention are included.";
    cmd->positionals = {vaultOrAll};
    cmd->optional = {owner};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {
        {"vh vault keys status all", "Key backup state of every vault."},
        {"vh vault keys status 42 --json", "The same for the vault with ID 42, as JSON."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> key_import(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"import"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Recover a vault's keys from a key export (vh vault keys export, or a Vaulthalla Desktop backup) "
                       "when this host can no longer unseal them or no longer holds them: after the vault master was "
                       "lost or replaced, or a database restored from an older backup. Import is a recovery mechanism, "
                       "never a way to set a key: it restores only key versions the vault had, proven by this node's "
                       "signed attestation in the export (or a key this host still holds); a key this host can still "
                       "unseal is never replaced, and a version the vault has no record of is refused. A version that "
                       "can't be proven (an export from before attestations, another node's key) is reported as "
                       "needing salvage: --salvage re-encrypts every file the supplied key decrypts under a fresh key "
                       "this host creates and reports the rest as unrecoverable; the supplied key is never stored. The "
                       "file is read by vh on your side (--file -: standard input; decrypt a GPG export first). "
                       "Writing asks you to type the vault's name (--confirm-name without a terminal). Deleted vaults "
                       "that are still restorable can be recovered (not salvaged).";
    cmd->positionals = {vaultPos};
    cmd->required = {Option::Multi("key_file", "The key export to read (on your side; - for standard input)",
                                   {"file", "f"}, {"path"})
                         .withGen("path", contract::gen::constant("keys.json"))};
    cmd->optional = {owner,
                     Optional::ManyToOne("confirm_name", "The vault's name, confirming the import without a terminal",
                                         {"confirm-name"}, "name")};
    cmd->optional_flags = {jsonFlag,
                           Flag::Alias("salvage",
                                       "Best effort for versions that can't be proven: re-encrypt what their key "
                                       "decrypts under a fresh key; never store the supplied key",
                                       "salvage")};
    cmd->examples = {
        {"vh vault keys import 12 --file vault-12-keys.json", "Recover vault 12's keys from an export (asks to confirm)."},
        {"vh vault keys import archive --owner alice --file - --confirm-name archive",
         "Read the export from standard input (e.g. piped from gpg --decrypt, so the keys never touch disk)."},
        {"vh vault keys import 12 --file old-export.json --salvage",
         "Salvage vault 12's files with keys this node can't attest (asks to confirm; prints a report)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> key_rotate(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"rotate", "renew"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Start an encryption key rotation for a vault (or 'all'). Existing data is re-encrypted by "
                       "the next sync; a vault whose rotation is already pending is reported, not rotated again.";
    cmd->positionals = {vaultOrAll};
    cmd->optional = {owner};
    cmd->optional_flags = {syncNowFlag};
    cmd->examples = {
        {"vh vault keys rotate 42 --sync-now",
         "Rotate the encryption key for the vault with ID 42 and immediately sync."},
        {"vh vault keys rotate myvault --owner alice",
         "Rotate the encryption key for the vault named 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> key(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"key", "keys", "k"};
    cmd->pluralAliasImpliesList = true;
    cmd->description = "Manage encryption keys for vaults.";
    cmd->examples = {
        {"vh vault keys export 42 --output /var/lib/vaulthalla/keyfile.pem --recipient ABCDEF1234567890",
         "Export the encryption key for the vault with ID 42 to '/var/lib/vaulthalla/keyfile.pem', encrypted for the GPG recipient with fingerprint 'ABCDEF1234567890'."},
        {"vh vault keys rotate myvault --owner alice",
         "Rotate the encryption key for the vault named 'myvault' owned by 'alice'."}
    };
    cmd->subcommands = {
        key_status(cmd->weak_from_this()),
        key_export(cmd->weak_from_this()),
        key_import(cmd->weak_from_this()),
        key_rotate(cmd->weak_from_this()),
        key_inspect(cmd->weak_from_this())
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> sync_info(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"info", "show", "get"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Display the current synchronization settings for a specific vault.";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->examples = {
        {"vh vault sync info 42", "Show sync configuration for the vault with ID 42."},
        {"vh vault sync info myvault --owner alice",
         "Show sync configuration for the vault named 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> sync_set(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"set", "update", "modify", "edit"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Set or update synchronization settings for a specific vault.";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner, intervalOpt};
    cmd->groups = {
        {"Local Vault Options", {
             localConflictOpt
         }},
        {"S3 Vault Options", {
             syncStrategyOpt,
             s3ConflictOpt,
             s3BudgetPresetOpt,
             maxRemoteIndexAgeOpt,
             s3BudgetListOpt,
             s3BudgetHeadOpt,
             s3BudgetGetOpt,
             s3BudgetPutOpt,
             s3BudgetCopyOpt,
             s3BudgetDeleteOpt,
             s3BudgetDownloadBytesOpt
         }}
    };
    cmd->examples = {
        {"vh vault sync set 42 --sync-strategy mirror --on-sync-conflict keep_remote",
         "Set sync configuration for the vault with ID 42."},
        {"vh vault sync set myvault --sync-strategy cache --s3-budget-get 10 --owner alice",
         "Set sync configuration and a GET request budget for the vault named 'myvault' owned by 'alice'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> sync_reconcile(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"reconcile"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Refresh the remote S3 object index using an explicit ListObjectsV2 reconciliation pass.";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->optional_flags = {allowListScanFlag};
    cmd->examples = {
        {"vh vault sync reconcile 42",
         "Rebuild the remote object index for S3 vault 42. This can issue roughly one S3 LIST request per 1,000 objects."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> sync_dry_run(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"dry-run", "dryrun", "plan"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Estimate S3 request and byte pressure for the next sync plan without executing file changes using the local remote index.";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->optional_flags = {refreshIndexFlag, refreshPricingFlag, noPricingFlag};
    cmd->examples = {
        {"vh vault sync dry-run 42",
         "Estimate S3 request counts, upload bytes, and body-download bytes for S3 vault 42 using the local remote index."},
        {"vh vault sync dry-run 42 --refresh-index",
         "Refresh the remote index manifest before planning; this may issue S3 HEAD/GET requests and requires sync trigger permission."},
        {"vh vault sync dry-run 42 --refresh-pricing",
         "Refresh cached storage-rate profile data before showing the optional price estimate."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> sync_inventory(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"inventory", "import-inventory", "inventory-import"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Import a local S3 Inventory CSV into the remote object index without downloading object bodies.";
    cmd->positionals = {vaultPos};
    cmd->required = {inventoryFileOpt};
    cmd->optional = {owner, inventorySchemaOpt};
    cmd->optional_flags = {inventoryHeaderFlag};
    cmd->examples = {
        {"vh vault sync inventory 42 --file inventory.csv",
         "Replace the remote object index for S3 vault 42 using a local S3 Inventory CSV."},
        {"vh vault sync inventory 42 --file inventory.csv --schema bucket,key,size,last_modified_date,etag,storage_class",
         "Import an inventory CSV that has no header row."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> sync_events(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"events", "ingest-events", "event"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Feed saved S3 Event Notifications JSON (or an SQS message dump) through the event pipeline: "
                       "stored in the durable inbox, applied to the remote object index, then synced by a pass scoped "
                       "to the affected keys.";
    cmd->positionals = {vaultPos};
    cmd->required = {eventFileOpt};
    cmd->optional = {owner};
    cmd->examples = {
        {"vh vault sync events 42 --file s3-events.json",
         "Apply ObjectCreated and ObjectRemoved notifications to S3 vault 42 and sync just those keys."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> sync(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"sync", "s"};
    cmd->description = "Manage vault synchronization settings and operations.";
    cmd->positionals = {vaultPos};
    cmd->examples = {
        {"vh vault sync 42", "Manually trigger a sync for the vault with ID 42."},
        {"vh vault sync info 42", "Show sync configuration for the vault with ID 42."},
        {"vh vault sync dry-run 42", "Estimate the S3 request and byte pressure of the next sync using the local remote index."},
        {"vh vault sync reconcile 42", "Rebuild the S3 remote object index with an explicit LIST pass."},
        {"vh vault sync inventory 42 --file inventory.csv", "Import a local S3 Inventory CSV into the remote index."},
        {"vh vault sync events 42 --file s3-events.json", "Ingest S3 event notifications into the remote index."},
        {"vh vault sync set 42 --sync-strategy mirror --on-sync-conflict keep_remote",
         "Set sync configuration for the vault with ID 42."},
        {"vh vault sync update 42 --sync-strategy cache", "Update the sync strategy for the vault with ID 42."}
    };
    cmd->subcommands = {
        sync_info(cmd->weak_from_this()),
        sync_dry_run(cmd->weak_from_this()),
        sync_reconcile(cmd->weak_from_this()),
        sync_inventory(cmd->weak_from_this()),
        sync_events(cmd->weak_from_this()),
        sync_set(cmd->weak_from_this())
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"vault", "v"};
    cmd->description = "Manage a single vault.";
    cmd->pluralAliasImpliesList = true;

    // ---- build direct children first (we'll mine their subcommands next) ----
    const auto listCmd = list(cmd->weak_from_this());
    const auto createCmd = create(cmd->weak_from_this());
    const auto removeCmd = remove(cmd->weak_from_this());
    const auto restoreCmd = restore(cmd->weak_from_this());
    const auto deletedCmd = deleted(cmd->weak_from_this());
    const auto infoCmd = info(cmd->weak_from_this());
    const auto updateCmd = update(cmd->weak_from_this());

    const auto vroleCmd = vrole(cmd->weak_from_this());
    const auto keyCmd = key(cmd->weak_from_this());
    const auto syncCmd = sync(cmd->weak_from_this()); // executable (manual sync) + has subcommands
    const auto recoveryCmd = recovery_book::vaultRecovery(cmd->weak_from_this());

    // ---- helpers to pluck children by alias from a parent we just built ----
    auto findChild = [](const std::shared_ptr<CommandUsage>& parentCmd, std::string_view alias)
        -> std::shared_ptr<CommandUsage> {
        for (const auto& sc : parentCmd->subcommands) {
            if (sc && sc->matches(std::string(alias))) return sc;
        }
        return nullptr;
    };

    // ---- dig into vrole -> (list | override | assign | unassign) ----
    const auto roleListCmd = findChild(vroleCmd, "list");
    const auto roleOverrideCmd = findChild(vroleCmd, "override");
    const auto roleAssignCmd = findChild(vroleCmd, "assign");
    const auto roleUnassignCmd = findChild(vroleCmd, "unassign");

    // and into override -> (add | update | remove | list)
    std::shared_ptr<CommandUsage> ovAddCmd, ovUpdCmd, ovRmCmd, ovListCmd;
    if (roleOverrideCmd) {
        ovAddCmd = findChild(roleOverrideCmd, "add");
        ovUpdCmd = findChild(roleOverrideCmd, "update");
        ovRmCmd = findChild(roleOverrideCmd, "remove");
        ovListCmd = findChild(roleOverrideCmd, "list");
    }

    // ---- dig into key -> (export | rotate) ----
    const auto keyExportCmd = findChild(keyCmd, "export");
    const auto keyRotateCmd = findChild(keyCmd, "rotate");

    // ---- dig into sync -> (info | set) ----
    const auto syncInfoCmd = findChild(syncCmd, "info");
    const auto syncSetCmd = findChild(syncCmd, "set");

    // -- Define reusable TestCommandUsage handles
    const auto t_create = TestCommandUsage::Single(createCmd);
    const auto t_create_many = TestCommandUsage::Multiple(createCmd);
    const auto t_remove = TestCommandUsage::Single(removeCmd);
    const auto t_remove0 = TestCommandUsage::Multiple(removeCmd, 0, 0);

    const auto t_info = TestCommandUsage::Single(infoCmd);
    const auto t_update = TestCommandUsage::Single(updateCmd);

    const auto t_sync = TestCommandUsage::Single(syncCmd);
    const auto t_sync_info = TestCommandUsage::Single(syncInfoCmd);
    const auto t_sync_set = TestCommandUsage::Single(syncSetCmd);

    const auto t_key_export = TestCommandUsage::Single(keyExportCmd);
    const auto t_key_rotate = TestCommandUsage::Single(keyRotateCmd);

    const auto t_role_list = TestCommandUsage::Single(roleListCmd);
    const auto t_role_assign = TestCommandUsage::Single(roleAssignCmd);
    const auto t_role_assign_m = TestCommandUsage::Multiple(roleAssignCmd);
    const auto t_role_unassign = TestCommandUsage::Single(roleUnassignCmd);
    const auto t_role_unassign_m = TestCommandUsage::Multiple(roleUnassignCmd);

    const auto t_ov_add = TestCommandUsage::Single(ovAddCmd);
    const auto t_ov_add_m = TestCommandUsage::Multiple(ovAddCmd);
    const auto t_ov_upd = TestCommandUsage::Single(ovUpdCmd);
    const auto t_ov_rm = TestCommandUsage::Single(ovRmCmd);
    const auto t_ov_rm_m = TestCommandUsage::Multiple(ovRmCmd);
    const auto t_ov_list = TestCommandUsage::Single(ovListCmd);

    // -- Assign lifecycle tests
    listCmd->test_usage.setup = {t_create_many};
    listCmd->test_usage.teardown = {t_remove0};

    createCmd->test_usage.lifecycle = {
        t_info, t_update, t_sync_set, t_sync_info, t_key_export
    };
    createCmd->test_usage.teardown = {t_remove};

    removeCmd->test_usage.setup = {t_create};

    infoCmd->test_usage.setup = {t_create};
    infoCmd->test_usage.teardown = {t_remove};

    updateCmd->test_usage.setup = {t_create};
    updateCmd->test_usage.teardown = {t_remove};

    syncCmd->test_usage.setup = {t_create};
    syncCmd->test_usage.teardown = {t_remove};

    syncInfoCmd->test_usage.setup = {t_create};
    syncInfoCmd->test_usage.teardown = {t_remove};

    syncSetCmd->test_usage.setup = {t_create};
    syncSetCmd->test_usage.teardown = {t_remove};

    keyExportCmd->test_usage.setup = {t_create};
    keyExportCmd->test_usage.teardown = {t_remove};

    keyRotateCmd->test_usage.setup = {t_create};
    keyRotateCmd->test_usage.lifecycle = {t_key_export};
    keyRotateCmd->test_usage.teardown = {t_remove};

    roleAssignCmd->test_usage.setup = {t_create};
    roleAssignCmd->test_usage.lifecycle = {t_role_list};
    roleAssignCmd->test_usage.teardown = {t_role_unassign};

    roleUnassignCmd->test_usage.setup = {t_create, t_role_assign};
    roleUnassignCmd->test_usage.teardown = {t_remove};

    roleListCmd->test_usage.setup = {t_create, t_role_assign_m};
    roleListCmd->test_usage.teardown = {t_role_unassign_m, t_remove};

    ovAddCmd->test_usage.setup = {t_create, t_role_assign};
    ovAddCmd->test_usage.lifecycle = {t_ov_list};
    ovAddCmd->test_usage.teardown = {t_ov_rm, t_role_unassign, t_remove};

    ovUpdCmd->test_usage.setup = {t_create, t_role_assign, t_ov_add};
    ovUpdCmd->test_usage.lifecycle = {t_ov_list};
    ovUpdCmd->test_usage.teardown = {t_ov_rm, t_role_unassign, t_remove};

    ovRmCmd->test_usage.setup = {t_create, t_role_assign, t_ov_add};
    ovRmCmd->test_usage.teardown = {t_role_unassign, t_remove};

    ovListCmd->test_usage.setup = {t_create, t_role_assign, t_ov_add_m};
    ovListCmd->test_usage.teardown = {t_ov_rm_m, t_role_unassign, t_remove};

    // ---- examples (unchanged) ----
    cmd->examples = {
        {"vh vault create myvault --local --desc \"My Local Vault\" --quota 10G",
         "Create a local vault with a 10GB quota."},
        {"vh vault update 42 --desc \"Updated Description\" --quota 20G",
         "Update the description and quota of the vault with ID 42."},
        {"vh vault delete myvault --owner alice", "Delete the vault named 'myvault' owned by user 'alice'."},
        {"vh vault restore 42", "Restore the deleted vault with ID 42 while it is pending deletion."},
        {"vh vault info 42", "Show information for the vault with ID 42."},
        {"vh vaults", "List all vaults accessible to the current user."},
        {"vh vault role assign 42 read-only -u bob", "Add user 'bob' to the 'read-only' role for the vault with ID 42."},
        {"vh vault keys export 42 --output /var/lib/vaulthalla/keyfile.pem --recipient ABCDEF1234567890",
         "Export the encryption key for the vault with ID 42 to '/var/lib/vaulthalla/keyfile.pem', encrypted for the GPG recipient with fingerprint 'ABCDEF1234567890'."},
        {"vh vault sync 42", "Manually trigger a sync for the vault with ID 42."},
        {"vh vault recovery status 42", "Show file recovery settings (snapshots, versioning) for the vault with ID 42."}
    };

    // ---- finalize tree ----
    cmd->subcommands = {
        listCmd,
        createCmd,
        removeCmd,
        restoreCmd,
        deletedCmd,
        infoCmd,
        updateCmd,
        vroleCmd,
        keyCmd,
        syncCmd,
        recoveryCmd
    };

    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandBook>();
    cmd->title = "Vault Commands";
    cmd->root = base(parent);
    return cmd;
}

}
