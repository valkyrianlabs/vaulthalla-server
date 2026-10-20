#include "usages.hpp"
#include "ArgsGenerator.hpp"

// File recovery: `vh snapshot …`, `vh recovery …` and the `vh vault recovery …` subtree (the vault book adds it).
// Handlers: core/src/protocols/shell/commands/{snapshot,recovery}.cpp and vault/recovery.cpp (ops::recovery, the same
// checks as the ws recovery.* / vault.recovery.* commands). See .claude/context/recovery.md.
namespace vh::protocols::shell::recovery_book {

namespace {

std::shared_ptr<CommandUsage> rbNode(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

const auto rbVaultPos = Positional::WithAliases("vault", "Vault name or ID", {"name", "id"},
                                                contract::gen::ref("vault", {"name", "id"}));
const auto rbPathPos = Positional::Same("path", "Vault path of a file or directory (\"/docs/report.pdf\")",
                                        contract::gen::path("/{a}{a}{a}{9}"));
const auto rbRecoveryIdPos = Positional::WithAliases(
    "recovery_id", "Recovery point: snap-<id> (snapshot), lv-<id> (local version) or pv-<id> (provider version)",
    {"recovery-id", "id"}, contract::gen::ref("recovery_point", {"id"}));
const auto rbOwner = Optional::Multi("owner", "User ID or username of the vault owner (required if using a name)",
                                     {"owner", "o"}, {"id", "name"});
const auto rbYes = Flag::Alias("yes", "Don't ask: confirm the action (for scripts)", "yes");
const auto rbJson = Flag::Alias("json_output", "Print the result as JSON (the ws shapes)", "json");
const auto rbTo = Optional::Single("to", "Restore under this vault path instead of the original paths", "to", "path")
                      .withGen("path", contract::gen::path("/restored-{a}{a}{9}"));

}

// ---- vh snapshot ------------------------------------------------------------------------------------------------

namespace {

std::shared_ptr<CommandUsage> snapshotCreate(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"create", "new", "take"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Take a named local snapshot of a file or directory tree. Needs the vault's recovery mode "
                       "local-snapshots; counts against the snapshot quota and the vault quota (deduplicated bytes).";
    cmd->positionals = {rbVaultPos, rbPathPos};
    cmd->optional = {rbOwner, Optional::Single("name", "A name for the snapshot", "name", "name")
                                  .withGen("name", contract::gen::pattern("before-{a}{a}{a}"))};
    cmd->optional_flags = {rbJson};
    cmd->examples = {
        {"vh snapshot create 42 /finance --name \"before audit\"", "Snapshot the /finance tree of vault 42."},
        {"vh snapshot create photos /2026/trip.jpg --owner alice", "Snapshot one file of alice's vault 'photos'."}};
    return cmd;
}

std::shared_ptr<CommandUsage> snapshotList(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"list", "ls"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List a vault's snapshots, or those taken of a path (the path is optional).";
    cmd->positionals = {rbVaultPos, rbPathPos};
    cmd->optional = {rbOwner};
    cmd->optional_flags = {rbJson};
    cmd->examples = {{"vh snapshot list 42", "Every snapshot in vault 42 you can read."},
                     {"vh snapshot list 42 /finance --json", "Snapshots of /finance, as JSON."}};
    return cmd;
}

std::shared_ptr<CommandUsage> snapshotDelete(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"delete", "remove", "rm"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Delete a snapshot (filesystem Delete on its path). Asks for confirmation. Generations a local "
                       "version or another snapshot still uses are kept.";
    cmd->positionals = {Positional::WithAliases("snapshot_id", "Snapshot id (snap-<id>)", {"snapshot-id", "id"},
                                                contract::gen::ref("recovery_point", {"id"}))};
    cmd->optional_flags = {rbYes};
    cmd->examples = {{"vh snapshot delete snap-12", "Delete snapshot 12 after confirming."},
                     {"vh snapshot delete snap-12 --yes", "Delete it without a prompt (scripts)."}};
    return cmd;
}

std::shared_ptr<CommandUsage> snapshotBase(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"snapshot", "snapshots"};
    cmd->description = "Explicit, named local recovery points of files and directory trees. Restore them with "
                       "'vh recovery restore'.";
    cmd->examples = {{"vh snapshot create 42 /finance --name \"before audit\"", "Take a snapshot."},
                     {"vh snapshot list 42", "List vault 42's snapshots."}};
    cmd->subcommands = {snapshotCreate(cmd->weak_from_this()), snapshotList(cmd->weak_from_this()),
                        snapshotDelete(cmd->weak_from_this())};
    return cmd;
}

}

std::shared_ptr<CommandBook> getSnapshot(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Snapshot Commands";
    book->root = snapshotBase(parent);
    return book;
}

// ---- vh recovery ------------------------------------------------------------------------------------------------

namespace {

std::shared_ptr<CommandUsage> recoveryList(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"list", "ls", "history"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Recovery points of a vault, or of one path (a file's history, or the points under a "
                       "directory): snapshots, local versions and provider versions. Points you can't read are left "
                       "out.";
    cmd->positionals = {rbVaultPos, rbPathPos};
    cmd->optional = {rbOwner, Optional::Single("limit", "At most N points (default 200)", "limit", "n")
                                  .withGen("n", contract::gen::intRange(1, 50))};
    cmd->optional_flags = {
        Flag::Alias("refresh", "List the provider's versions of the path first (metadata only, request-budgeted)",
                    "refresh"),
        Flag::Alias("snapshots_only", "Only local snapshots", "snapshots-only"),
        Flag::Alias("versions_only", "Only local versions", "versions-only"),
        Flag::Alias("provider_only", "Only provider versions", "provider-only"), rbJson};
    cmd->examples = {{"vh recovery list 42 /finance/q3.xlsx", "Every recoverable version of one file."},
                     {"vh recovery list 42 /finance --refresh --provider-only",
                      "Provider versions under /finance, listed from the bucket first."}};
    return cmd;
}

std::shared_ptr<CommandUsage> recoveryInspect(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"inspect", "info", "show"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Details of one recovery point: what it holds, its key version, retention and whether it can "
                       "be restored (and why not). A snapshot lists its members.";
    cmd->positionals = {rbRecoveryIdPos};
    cmd->optional_flags = {rbJson};
    cmd->examples = {{"vh recovery inspect snap-12", "Show snapshot 12 and its files."},
                     {"vh recovery inspect pv-40 --json", "Provider version 40, as JSON."}};
    return cmd;
}

std::shared_ptr<CommandUsage> recoveryPlan(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"plan", "preview"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Plan a restore without changing anything: per item create, overwrite, skip, conflict, remove "
                       "or unavailable, the method, a request/cost estimate, warnings and blockers. Give a recovery id, "
                       "or a vault, a path and --at for a point-in-time restore (a timestamp-based reconstruction, not "
                       "an atomic snapshot). Prints the plan id and token 'vh recovery restore' takes (valid 30 minutes).";
    cmd->positionals = {Positional::WithAliases("source", "A recovery id, or the vault (then <path> and --at)",
                                                {"recovery-id", "vault"}, contract::gen::ref("recovery_point", {"id"})),
                        Positional::WithAliases("path", "Point in time: the vault path to reconstruct", {"path"},
                                                contract::gen::path("/{a}{a}{a}{9}"))};
    cmd->optional = {rbOwner, rbTo,
                     Optional::Single("at", "Point in time: restore the state as of this ISO-8601 UTC time", "at",
                                      "time")
                         .withGen("time", contract::gen::constant("2026-10-01T12:00:00Z"))};
    cmd->optional_flags = {
        Flag::Alias("prune", "Point in time: also remove files that did not exist at that time", "prune"), rbJson};
    cmd->examples = {{"vh recovery plan snap-12", "Preview restoring snapshot 12 over the original paths."},
                     {"vh recovery plan lv-81 --to /restored", "Preview restoring a local version under /restored."},
                     {"vh recovery plan 42 /finance --at 2026-10-01T12:00:00Z --prune",
                      "Preview /finance as it was at noon UTC on 1 October."}};
    return cmd;
}

std::shared_ptr<CommandUsage> recoveryRestore(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"restore", "apply"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Run a restore plan, or plan and run one for a recovery id. Shows the plan and asks first (type "
                       "RESTORE when anything is overwritten or removed); without a terminal it needs --yes or the "
                       "plan's --token. Every item is authorized again; a destination that changed since the plan is "
                       "a conflict and is never overwritten. Exit 1 when anything was not restored; run it again to "
                       "resume.";
    cmd->positionals = {Positional::WithAliases("plan", "A plan id from 'vh recovery plan', or a recovery id",
                                                {"plan-id", "recovery-id"}, contract::gen::ref("recovery_plan", {"id"}))};
    cmd->optional = {Optional::Single("token", "The plan's token (from 'vh recovery plan'); confirms without a prompt",
                                      "token", "token"),
                     rbTo};
    cmd->optional_flags = {
        rbYes,
        Flag::Alias("accept_unverified", "Also restore provider versions Vaulthalla did not write", "accept-unverified"),
        rbJson};
    cmd->examples = {{"vh recovery restore snap-12", "Plan, review and restore snapshot 12."},
                     {"vh recovery restore lv-81 --to /restored", "Restore a local version under /restored."},
                     {"vh recovery restore 7 --token 3f9c2a7d", "Run plan 7 from a script."}};
    return cmd;
}

std::shared_ptr<CommandUsage> recoveryDelete(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"delete", "remove", "rm"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Delete a snapshot or a local version (filesystem Delete on its path). Provider versions belong "
                       "to the bucket's retention. A version still waiting to be sent upstream can't be deleted.";
    cmd->positionals = {rbRecoveryIdPos};
    cmd->optional_flags = {rbYes};
    cmd->examples = {{"vh recovery delete lv-81", "Delete local version 81 after confirming."}};
    return cmd;
}

std::shared_ptr<CommandUsage> recoveryCosts(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"costs", "cost"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Estimated recovery costs for a vault: the provider versioning surcharge (separate from the "
                       "current object storage), recovery operations and what is not modelled, with ranges, basis and "
                       "catalog freshness. Computed on this host; estimates, not provider invoices.";
    cmd->positionals = {rbVaultPos};
    cmd->optional = {rbOwner};
    cmd->optional_flags = {rbJson};
    cmd->examples = {{"vh recovery costs 42", "The versioning cost panel for vault 42."}};
    return cmd;
}

std::shared_ptr<CommandUsage> recoveryBase(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"recovery"};
    cmd->description = "Find and restore earlier versions of files: local snapshots, local versions and provider "
                       "(S3) object versions. Vault settings live under 'vh vault recovery'.";
    cmd->examples = {{"vh recovery list 42 /finance/q3.xlsx", "A file's recoverable versions."},
                     {"vh recovery restore lv-81", "Restore one of them."},
                     {"vh vault recovery status 42", "Vault 42's recovery settings."}};
    cmd->subcommands = {recoveryList(cmd->weak_from_this()),    recoveryInspect(cmd->weak_from_this()),
                        recoveryPlan(cmd->weak_from_this()),    recoveryRestore(cmd->weak_from_this()),
                        recoveryDelete(cmd->weak_from_this()),  recoveryCosts(cmd->weak_from_this())};
    return cmd;
}

}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Recovery Commands";
    book->root = recoveryBase(parent);
    return book;
}

// ---- vh vault recovery ------------------------------------------------------------------------------------------

namespace {

const auto rbRetention = Optional::Single("retention", "How long provider versioning keeps old versions",
                                          "retention", "30d|90d|365d|indefinite")
                             .withGen("30d|90d|365d|indefinite", contract::gen::oneOf({"30d", "90d", "365d", "indefinite"}));

std::shared_ptr<CommandUsage> vaultRecoveryStatus(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"status", "info", "show"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "A vault's recovery mode, local versioning, snapshot and version storage, the upstream backlog "
                       "and the bucket's versioning state.";
    cmd->positionals = {rbVaultPos};
    cmd->optional = {rbOwner};
    cmd->optional_flags = {
        Flag::Alias("refresh", "Read the bucket's versioning, lifecycle and object lock again (one admin call)",
                    "refresh"),
        rbJson};
    cmd->examples = {{"vh vault recovery status 42", "Recovery settings of vault 42."},
                     {"vh vault recovery status photos --owner alice --refresh", "Re-read the bucket state first."}};
    return cmd;
}

std::shared_ptr<CommandUsage> vaultRecoverySet(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"set", "update"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Change a vault's recovery settings. Turning on provider versioning first shows the cost "
                       "disclosure and asks you to type ENABLE VERSIONING (and to accept separately when the cost "
                       "can't be estimated). Without a terminal it needs --yes, plus --accept-unpriced when unpriced. "
                       "Shortening retention deletes history sooner and is asked separately.";
    cmd->positionals = {rbVaultPos};
    cmd->optional = {rbOwner};
    cmd->groups = {
        {"Recovery mode",
         {Optional::Single("mode", "Vault recovery mode", "mode", "off|local-snapshots|provider-versioning")
              .withGen("off|local-snapshots|provider-versioning",
                       contract::gen::oneOf({"off", "local-snapshots"})),
          Optional::Single("snapshot_quota", "Snapshot storage quota (0 = none)", "snapshot-quota", "size")
              .withGen("size", contract::gen::constant("1G")),
          Optional::Single("cost_alert", "Notify when the projected monthly versioning cost exceeds this amount "
                                         "(catalog currency; 'none' clears it)", "cost-alert", "amount")
              .withGen("amount", contract::gen::constant("25.00"))}},
        {"Provider versioning",
         {rbRetention,
          Flag::Alias("accept_unpriced", "Accept recurring charges that can't be estimated", "accept-unpriced"),
          Flag::Alias("accept_retention_shortening", "Accept that a shorter retention deletes history sooner",
                      "accept-retention-shortening"),
          Flag::Alias("adopt_bucket", "Adopt the vault's own unmanaged bucket in the same step", "adopt-bucket")}},
        {"Local versioning",
         {Optional::Single("local_versioning", "Keep the prior generation of every changed file", "local-versioning",
                           "on|off")
              .withGen("on|off", contract::gen::oneOf({"on", "off"})),
          Optional::Single("keep_last", "Keep at most N versions per file", "keep-last", "n")
              .withGen("n", contract::gen::intRange(1, 20)),
          Optional::Single("max_age_days", "Drop versions older than N days", "max-age-days", "n")
              .withGen("n", contract::gen::intRange(1, 365)),
          Optional::Single("version_quota", "Storage quota for local versions", "version-quota", "size")
              .withGen("size", contract::gen::constant("10G"))}}};
    cmd->optional_flags = {rbYes, rbJson};
    cmd->examples = {
        {"vh vault recovery set 42 --mode local-snapshots --snapshot-quota 50G", "Allow snapshots, up to 50 GB."},
        {"vh vault recovery set 42 --local-versioning on --keep-last 10 --max-age-days 90",
         "Keep the last 10 versions of every file for up to 90 days."},
        {"vh vault recovery set 42 --mode provider-versioning --retention 90d",
         "Review the cost disclosure and turn on S3 versioning with 90-day retention."},
        {"vh vault recovery set 42 --mode provider-versioning --retention 30d --yes --accept-unpriced",
         "The same from a script (the disclosure is still fetched and printed)."}};
    return cmd;
}

std::shared_ptr<CommandUsage> vaultRecoverySuspend(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"suspend"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Suspend versioning on the vault's bucket. Existing versions are kept and nothing is deleted; "
                       "a bucket can never return to unversioned. Asks for confirmation.";
    cmd->positionals = {rbVaultPos};
    cmd->optional = {rbOwner};
    cmd->optional_flags = {rbYes};
    cmd->examples = {{"vh vault recovery suspend 42", "Stop new versions on vault 42's bucket."}};
    return cmd;
}

std::shared_ptr<CommandUsage> vaultRecoveryDisclosure(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"disclosure", "estimate"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show the cost disclosure for turning on provider versioning (read-only: at most one admin "
                       "call, no object requests).";
    cmd->positionals = {rbVaultPos};
    cmd->optional = {rbOwner, rbRetention};
    cmd->optional_flags = {rbJson};
    cmd->examples = {{"vh vault recovery disclosure 42 --retention 90d", "What 90-day versioning would cost."}};
    return cmd;
}

}

std::shared_ptr<CommandUsage> vaultRecovery(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = rbNode(parent);
    cmd->aliases = {"recovery"};
    cmd->description = "File recovery settings of a vault: local snapshots, local versioning and provider (S3) "
                       "versioning with its cost disclosure. (Undeleting a vault is 'vh vault restore'.)";
    cmd->examples = {{"vh vault recovery status 42", "Recovery settings of vault 42."},
                     {"vh vault recovery set 42 --mode local-snapshots", "Allow snapshots in vault 42."}};
    cmd->subcommands = {vaultRecoveryStatus(cmd->weak_from_this()), vaultRecoverySet(cmd->weak_from_this()),
                        vaultRecoverySuspend(cmd->weak_from_this()), vaultRecoveryDisclosure(cmd->weak_from_this())};
    return cmd;
}

}
