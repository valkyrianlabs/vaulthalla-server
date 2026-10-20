#include "usages.hpp"
#include "CommandUsage.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::pricing {

static std::shared_ptr<CommandUsage> baseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static const auto providerPos = Positional::WithAliases("provider", "S3 pricing provider key", {"provider_key"});
static const auto vaultPos = Positional::WithAliases("vault", "Vault ID or name", {"vault_id", "name"});
static const auto modeOpt = Optional::Multi("mode", "Budget policy mode", {"mode"}, {"off", "report", "warn", "enforce"});
static const auto currencyOpt = Optional::ManyToOne("currency", "Budget currency", {"currency"}, "currency");
static const auto maxRunOpt = Optional::ManyToOne("max_run", "Maximum per-run budget-safe S3 cost", {"max-run"}, "amount");
static const auto maxDailyOpt = Optional::ManyToOne("max_daily", "Maximum daily budget-safe S3 cost", {"max-daily"}, "amount");
static const auto maxMonthlyOpt = Optional::ManyToOne("max_monthly", "Maximum monthly budget-safe S3 cost", {"max-monthly"}, "amount");
static const auto allowStaleFlag = Flag::WithAliases("allow_stale_catalog", "Allow stale verified pricing catalog cache", {"allow-stale-catalog"});
static const auto noRequireVerifiedFlag = Flag::WithAliases("no_require_verified_catalog", "Do not require a strictly verified pricing catalog", {"no-require-verified-catalog"});
static const auto maxCatalogAgeOpt = Optional::ManyToOne("max_catalog_age", "Maximum stale catalog age in seconds", {"max-catalog-age"}, "seconds");
static const auto limitOpt = Optional::ManyToOne("limit", "Limit ledger rows", {"limit", "n"}, "limit");

static std::shared_ptr<CommandUsage> budgetList(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = baseUsage(parent);
    cmd->aliases = {"list", "ls"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List S3 price budget policies.";
    cmd->examples = {{"vh pricing budget list", "List configured S3 price budget policies."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> budgetSetGlobal(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = baseUsage(parent);
    cmd->aliases = {"set-global"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Set the global S3 price budget policy.";
    cmd->optional = {modeOpt, currencyOpt, maxRunOpt, maxDailyOpt, maxMonthlyOpt, maxCatalogAgeOpt};
    cmd->optional_flags = {allowStaleFlag, noRequireVerifiedFlag};
    cmd->examples = {{"vh pricing budget set-global --mode warn --max-monthly 100 --currency USD", "Warn when the combined S3 monthly budget would exceed 100 USD."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> budgetSetProvider(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = baseUsage(parent);
    cmd->aliases = {"set-provider"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Set a provider-scoped S3 price budget policy.";
    cmd->positionals = {providerPos};
    cmd->optional = {modeOpt, currencyOpt, maxRunOpt, maxDailyOpt, maxMonthlyOpt, maxCatalogAgeOpt};
    cmd->optional_flags = {allowStaleFlag, noRequireVerifiedFlag};
    cmd->examples = {{"vh pricing budget set-provider cloudflare-r2 --mode enforce --max-monthly 25 --max-run 5", "Enforce Cloudflare R2 S3 price budgets."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> budgetSetVault(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = baseUsage(parent);
    cmd->aliases = {"set-vault"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Set a vault-scoped S3 price budget policy.";
    cmd->positionals = {vaultPos};
    cmd->optional = {modeOpt, currencyOpt, maxRunOpt, maxDailyOpt, maxMonthlyOpt, maxCatalogAgeOpt};
    cmd->optional_flags = {allowStaleFlag, noRequireVerifiedFlag};
    cmd->examples = {{"vh pricing budget set-vault 42 --mode enforce --max-run 1 --max-monthly 10", "Enforce S3 price budgets for vault 42."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> budgetDisableGlobal(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = baseUsage(parent);
    cmd->aliases = {"disable-global"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Disable the global S3 price budget policy.";
    return cmd;
}

static std::shared_ptr<CommandUsage> budgetDisableProvider(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = baseUsage(parent);
    cmd->aliases = {"disable-provider"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Disable a provider-scoped S3 price budget policy.";
    cmd->positionals = {providerPos};
    return cmd;
}

static std::shared_ptr<CommandUsage> budgetDisableVault(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = baseUsage(parent);
    cmd->aliases = {"disable-vault"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Disable a vault-scoped S3 price budget policy.";
    cmd->positionals = {vaultPos};
    return cmd;
}

static std::shared_ptr<CommandUsage> budgetStatus(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = baseUsage(parent);
    cmd->aliases = {"status"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show S3 price budget policy and ledger status.";
    return cmd;
}

static std::shared_ptr<CommandUsage> budgetLedger(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = baseUsage(parent);
    cmd->aliases = {"ledger"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List recent S3 price budget ledger rows.";
    cmd->optional = {limitOpt};
    cmd->examples = {{"vh pricing budget ledger --limit 50", "Show the 50 most recent budget ledger rows."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> budget(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = baseUsage(parent);
    cmd->aliases = {"budget", "budgets"};
    cmd->description = "Manage opt-in S3 price budget policies.";
    cmd->subcommands = {
        budgetList(cmd->weak_from_this()),
        budgetSetGlobal(cmd->weak_from_this()),
        budgetSetProvider(cmd->weak_from_this()),
        budgetSetVault(cmd->weak_from_this()),
        budgetDisableGlobal(cmd->weak_from_this()),
        budgetDisableProvider(cmd->weak_from_this()),
        budgetDisableVault(cmd->weak_from_this()),
        budgetStatus(cmd->weak_from_this()),
        budgetLedger(cmd->weak_from_this())
    };
    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Pricing Commands";
    book->root = baseUsage(parent);
    book->root->aliases = {"pricing", "price"};
    book->root->description = "Manage S3 pricing estimates and price budget policies.";
    book->root->subcommands = {budget(book->root->weak_from_this())};
    book->root->examples = {
        {"vh pricing budget list", "List S3 price budget policies."},
        {"vh pricing budget set-provider cloudflare-r2 --mode enforce --max-monthly 25", "Set a provider S3 price budget."}
    };
    return book;
}

} // namespace vh::protocols::shell::pricing
