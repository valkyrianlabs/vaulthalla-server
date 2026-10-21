#include "usages.hpp"
#include "ArgsGenerator.hpp"

// `vh upstream …`: provider administration of upstream S3/R2 accounts (#237) and event-driven sync (#96). Handlers:
// core/src/protocols/shell/commands/upstream.cpp (ops::upstream, same checks as the ws upstream.* commands).
namespace vh::protocols::shell::upstream_book {

static std::shared_ptr<CommandUsage> node(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static const auto apiKeyPos = Positional::WithAliases("api_key", "Name or ID of the upstream API key", {"api_key", "id"},
                                                      contract::gen::ref("api_key", {"name", "id"}));
static const auto bucketPos = Positional::Same("bucket", "Bucket name in the key's provider account",
                                               contract::gen::pattern("vh-test-{a}{a}{a}{9}{9}"));
static const auto vaultPos = Positional::WithAliases("vault", "Vault name or ID", {"name", "id"},
                                                     contract::gen::ref("vault", {"name", "id"}));
static const auto owner = Optional::Multi("owner", "User ID or username of the vault owner (required if using a name)",
                                          {"owner", "o"}, {"id", "name"});
static const auto yesFlag = Flag::Alias("yes", "Don't ask: confirm the action (for scripts)", "yes");

// ---- admin ------------------------------------------------------------------------------------------------------

static std::shared_ptr<CommandUsage> adminEnable(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"enable", "on"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Turn on provider administration (AWS S3, Cloudflare R2) for an upstream API key. Probes what the "
                       "credential can do first. Run again to store or clear the Cloudflare API token.";
    cmd->positionals = {apiKeyPos};
    cmd->optional_flags = {
        Flag::Alias("provider_token", "Cloudflare R2: ask for the account API token (Queues Edit + Workers R2 Storage "
                                      "Edit) at a hidden prompt and store it sealed", "provider-token"),
        Flag::Alias("clear_provider_token", "Remove the stored Cloudflare API token", "clear-provider-token")};
    cmd->examples = {
        {"vh upstream admin enable aws-admin", "Let Vaulthalla administer the AWS account of key 'aws-admin'."},
        {"vh upstream admin enable r2-admin --provider-token",
         "Enable R2 administration and store the Cloudflare API token event-driven sync needs."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> adminDisable(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"disable", "off"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Turn provider administration off (refused while an event subscription runs through the key).";
    cmd->positionals = {apiKeyPos};
    cmd->examples = {{"vh upstream admin disable aws-admin", "Use 'aws-admin' as a plain storage credential again."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> adminStatus(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"status", "info", "show"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show administration status and the credential's capabilities.";
    cmd->positionals = {apiKeyPos};
    cmd->optional_flags = {Flag::Alias("probe", "Check the credential against the provider again", "probe"), jsonFlag};
    cmd->examples = {{"vh upstream admin status aws-admin --probe", "Re-check what 'aws-admin' may do."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> admin(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"admin"};
    cmd->description = "Provider administration on an upstream API key.";
    cmd->examples = {{"vh upstream admin status aws-admin", "Show administration status for 'aws-admin'."}};
    cmd->subcommands = {adminEnable(cmd->weak_from_this()), adminDisable(cmd->weak_from_this()),
                        adminStatus(cmd->weak_from_this())};
    return cmd;
}

// ---- buckets ----------------------------------------------------------------------------------------------------

static std::shared_ptr<CommandUsage> buckets(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"buckets", "inventory", "bucket-list"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List the account's buckets with what Vaulthalla knows about them (managed, adopted, unmanaged, "
                       "protected). Account-level listing only: no bucket or object calls.";
    cmd->positionals = {apiKeyPos};
    cmd->optional = {
        Optional::Single("state", "Only buckets in this state", "state", "managed|adopted|unmanaged|protected")
            .withGen("managed|adopted|unmanaged|protected", contract::gen::oneOf({"managed", "adopted", "unmanaged", "protected"})),
        Optional::Single("filter", "Only bucket names containing this text", "filter", "text")
            .withGen("text", contract::gen::pattern("{a}{a}")),
        Optional::Single("limit", "At most this many buckets (default 1000)", "limit", "n")
            .withGen("n", contract::gen::intRange(1, 50)),
        Optional::Single("page_token", "Continue a listing", "page-token", "token")};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {
        {"vh upstream buckets aws-admin", "List the AWS account's buckets."},
        {"vh upstream buckets r2-admin --state unmanaged", "Buckets Vaulthalla doesn't manage yet."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> protect(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"protect", "lock"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Lock a bucket: Vaulthalla will never probe, adopt, bind, configure, sync, empty or delete it. "
                       "The lock belongs to the bucket (provider, account, name), not to the key. Audited.";
    cmd->positionals = {apiKeyPos, bucketPos};
    cmd->required = {Option::Single("reason", "Why the bucket is protected (shown to everyone who sees it)", "reason", "text")
                         .withGen("text", contract::gen::pattern("test lock {a}{a}{a}"))};
    cmd->examples = {{"vh upstream protect aws-admin prod-backups --reason \"production backups\"",
                      "Exclude 'prod-backups' from everything Vaulthalla does."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> unprotect(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"unprotect", "unlock"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Remove a bucket lock (admin.upstream.unprotect). Asks for confirmation; audited.";
    cmd->positionals = {apiKeyPos, bucketPos};
    cmd->optional_flags = {yesFlag};
    cmd->examples = {{"vh upstream unprotect aws-admin old-backups", "Remove the lock on 'old-backups'."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> inspect(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"inspect", "describe"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show a bucket's region, versioning, object lock, lifecycle and event rules (Vaulthalla's and "
                       "other applications').";
    cmd->positionals = {apiKeyPos, bucketPos};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh upstream inspect aws-admin vh-media-3k2j", "Inspect the bucket's configuration."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> lifecycle(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"lifecycle"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Set or clear Vaulthalla's lifecycle rule on a managed or adopted bucket; other rules are kept. "
                       "0 removes a setting. Expiration deletes data and asks for confirmation.";
    cmd->positionals = {apiKeyPos, bucketPos};
    cmd->optional = {
        Optional::Single("abort_multipart_days", "Abort incomplete multipart uploads after N days", "abort-multipart-days", "n")
            .withGen("n", contract::gen::intRange(1, 30)),
        Optional::Single("expire_days", "Delete current objects N days after creation (destructive)", "expire-days", "n")
            .withGen("n", contract::gen::intRange(1, 30)),
        Optional::Single("expire_noncurrent_days", "AWS: delete old object versions after N days (destructive)",
                         "expire-noncurrent-days", "n")
            .withGen("n", contract::gen::intRange(1, 30)),
        Optional::Single("prefix", "Apply the rule to keys with this prefix only", "prefix", "prefix")};
    cmd->optional_flags = {Flag::Alias("clear", "Remove Vaulthalla's lifecycle rule", "clear"), yesFlag, jsonFlag};
    cmd->examples = {
        {"vh upstream lifecycle aws-admin vh-media-3k2j --abort-multipart-days 7",
         "Clean up incomplete uploads after a week."},
        {"vh upstream lifecycle aws-admin vh-media-3k2j --clear", "Remove Vaulthalla's lifecycle rule."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> adoptCheck(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"adopt-check", "admission"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Read-only admission check of an existing bucket before adopting it into a vault: object counts, "
                       "encryption of a sample, versioning, object lock, blockers.";
    cmd->positionals = {apiKeyPos, bucketPos};
    cmd->optional = {
        Optional::Single("max_objects", "List at most N keys (default 10000)", "max-objects", "n")
            .withGen("n", contract::gen::intRange(1, 1000)),
        Optional::Single("sample", "Read metadata of at most N sample objects (default 16)", "sample", "n")
            .withGen("n", contract::gen::intRange(0, 16))};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh upstream adopt-check aws-admin legacy-photos", "Check 'legacy-photos' before adopting it."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> detach(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"detach"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Give a managed or adopted bucket that no vault uses back: Vaulthalla removes its own rules and "
                       "stops managing it. Data is untouched.";
    cmd->positionals = {apiKeyPos, bucketPos};
    cmd->examples = {{"vh upstream detach aws-admin vh-media-3k2j", "Stop managing the bucket."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> cleanup(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"cleanup"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Delete a bucket Vaulthalla created and every object version in it. Prints a preflight first and "
                       "asks for the bucket name; --confirm-token (from a preflight, valid 10 minutes) runs it without a "
                       "prompt. Refused for protected, adopted, unmanaged or bound buckets.";
    cmd->positionals = {apiKeyPos, bucketPos};
    cmd->optional = {Optional::Single("confirm_token", "Run the cleanup a preflight planned", "confirm-token", "token")};
    cmd->optional_flags = {
        Flag::Alias("keep_bucket", "Delete the objects but keep the (empty) bucket", "keep-bucket"),
        Flag::Alias("preflight", "Only print the preflight", "preflight"), jsonFlag};
    cmd->examples = {
        {"vh upstream cleanup aws-admin vh-media-3k2j", "Show what would be deleted, then confirm."},
        {"vh upstream cleanup aws-admin vh-media-3k2j --preflight --json", "Plan only, as JSON (with confirm_token)."}};
    return cmd;
}

// ---- events -----------------------------------------------------------------------------------------------------

static std::shared_ptr<CommandUsage> eventsEnable(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"enable", "on"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Subscribe an S3 vault's bucket for event-driven sync (AWS S3 → SQS, Cloudflare R2 → Queues).";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner,
                     Optional::Single("prefix", "Only keys with this prefix", "prefix", "prefix"),
                     Optional::Single("foreign_objects",
                                      "Objects other tools uploaded (no Vaulthalla metadata): import (default) or ignore",
                                      "foreign-objects", "import|ignore")
                         .withGen("import|ignore", contract::gen::oneOf({"import", "ignore"}))};
    cmd->examples = {{"vh upstream events enable 42", "Sync vault 42 from its bucket's event notifications."},
                     {"vh upstream events enable photos --owner alice --prefix camera/ --foreign-objects import",
                      "Only camera/ uploads, imported as vault files."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> eventsDisable(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"disable", "off"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Remove the vault's event subscription (Vaulthalla's rule, and the queue when unused).";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->examples = {{"vh upstream events disable 42", "Stop event-driven sync for vault 42."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> eventsRepair(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"repair"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Re-create whatever is missing for the vault's subscription and re-arm it. Safe to repeat.";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->examples = {{"vh upstream events repair 42", "Repair vault 42's event subscription."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> eventsStatus(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"status", "info"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Event subscription, queue health and inbox counts for one vault, or for every S3 vault you may "
                       "view when no vault is given.";
    cmd->positionals = {vaultPos};
    cmd->optional = {owner};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh upstream events status", "Status of every S3 vault."},
                     {"vh upstream events status 42", "Status of vault 42."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> events(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"events"};
    cmd->description = "Event-driven sync of S3 vaults.";
    cmd->examples = {{"vh upstream events status", "Status of every S3 vault's event subscription."}};
    cmd->subcommands = {eventsEnable(cmd->weak_from_this()), eventsDisable(cmd->weak_from_this()),
                        eventsRepair(cmd->weak_from_this()), eventsStatus(cmd->weak_from_this())};
    return cmd;
}

// ---- audit ------------------------------------------------------------------------------------------------------

static std::shared_ptr<CommandUsage> audit(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"audit"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "The upstream control-plane audit log, newest first.";
    cmd->optional = {Optional::Single("bucket", "Only entries for this bucket", "bucket", "name"),
                     Optional::Single("limit", "At most N entries (default 100)", "limit", "n")
                         .withGen("n", contract::gen::intRange(1, 50))};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh upstream audit", "Recent upstream control-plane actions."},
                     {"vh upstream audit --bucket prod-backups", "Everything recorded for 'prod-backups'."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"upstream"};
    cmd->description = "Administer upstream S3/R2 accounts: bucket inventory, protection locks, lifecycle, adoption "
                       "checks, cleanup and event-driven sync.";
    cmd->examples = {{"vh upstream buckets aws-admin", "List the account's buckets."},
                     {"vh upstream events status", "Event-driven sync status of every S3 vault."}};
    cmd->subcommands = {admin(cmd->weak_from_this()),     buckets(cmd->weak_from_this()),
                        protect(cmd->weak_from_this()),   unprotect(cmd->weak_from_this()),
                        inspect(cmd->weak_from_this()),   lifecycle(cmd->weak_from_this()),
                        adoptCheck(cmd->weak_from_this()), detach(cmd->weak_from_this()),
                        cleanup(cmd->weak_from_this()),   events(cmd->weak_from_this()),
                        audit(cmd->weak_from_this())};
    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Upstream Account Commands";
    book->root = base(parent);
    return book;
}

}
