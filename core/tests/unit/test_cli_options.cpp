// The CLI rejects undeclared options (they used to be silently discarded). Options are declared by the usage
// definitions, so the definitions must cover what the commands read and what the help documents.

#include "CommandUsage.hpp"
#include "UsageManager.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "runtime/Deps.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_cli_options {

std::shared_ptr<protocols::shell::Router> fullRouter() {
    if (!runtime::Deps::get().shellUsageManager)
        runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
    auto router = std::make_shared<protocols::shell::Router>();
    protocols::shell::commands::registerAllCommands(router);
    return router;
}

TEST(CliOptions, EveryDocumentedExamplePassesOptionValidation) {
    const auto router = fullRouter();
    const auto root = runtime::Deps::get().shellUsageManager->root();
    ASSERT_TRUE(root);

    std::size_t checked = 0;
    std::function<void(const std::shared_ptr<protocols::shell::CommandUsage>&)> walk =
        [&](const std::shared_ptr<protocols::shell::CommandUsage>& node) {
            for (const auto& example : node->examples) {
                auto line = example.cmd;
                if (line.starts_with("sudo ")) line = line.substr(5);
                if (line.starts_with("vh ")) line = line.substr(3);
                else if (line == "vh") continue;
                ++checked;
                const auto err = router->optionError(line);
                EXPECT_FALSE(err.has_value()) << "documented example rejected: vh " << line << "\n  " << err.value_or("");
            }
            for (const auto& child : node->subcommands) walk(child);
        };
    walk(root);
    EXPECT_GT(checked, 100u) << "expected the usage tree's examples";
}

TEST(CliOptions, UndeclaredOptionsAreRejectedNotIgnored) {
    const auto router = fullRouter();
    EXPECT_TRUE(router->optionError("group create devs --description x").has_value()) << "--desc is the declared spelling";
    EXPECT_FALSE(router->optionError("group create devs --desc x").has_value());
    EXPECT_TRUE(router->optionError("vault list --no-such-flag").has_value());
    EXPECT_TRUE(router->optionError("user create bob --role admin --typo").has_value());
    // Help is accepted everywhere; declared permission-flag families stay open for the command to validate.
    EXPECT_FALSE(router->optionError("group create --help").has_value());
    EXPECT_FALSE(router->optionError("role admin create r --allow-users-view").has_value());
    EXPECT_TRUE(router->optionError("role admin info r --allow-users-view").has_value()) << "info declares no permission flags";
}

}

namespace vh::test_cli_options {

// Handlers dispatch subcommands with isCommandMatch(path, word), which only matches the aliases of the usage node
// `path` resolves to. A handler name the definition doesn't carry makes the subcommand unreachable (`vh vault keys`
// and `vh vault role remove` were). These are the dispatch paths the handlers use, harvested from their source.
TEST(CliOptions, EveryHandlerDispatchNameIsADefinedSubcommand) {
    (void)fullRouter();
    const auto usage = runtime::Deps::get().shellUsageManager;
    const std::vector<std::vector<std::string>> paths{
        {"api-key", "create"},
        {"api-key", "delete"},
        {"api-key", "info"},
        {"api-key", "list"},
        {"email", "alerting"},
        {"email", "doctor"},
        {"email", "history"},
        {"email", "provider"},
        {"email", "provider", "resend"},
        {"email", "provider", "resend", "set"},
        {"email", "provider", "ses"},
        {"email", "provider", "ses", "set"},
        {"email", "provider", "use"},
        {"email", "recipients"},
        {"email", "security"},
        {"email", "set"},
        {"email", "test"},
        {"email", "weekly"},
        {"fs", "get"},
        {"fs", "ls"},
        {"fs", "put"},
        {"group", "create"},
        {"group", "delete"},
        {"group", "info"},
        {"group", "list"},
        {"group", "update"},
        {"group", "user"},
        {"group", "user", "add"},
        {"group", "user", "list"},
        {"group", "user", "remove"},
        {"pricing", "budget"},
        {"pricing", "budget", "disable-global"},
        {"pricing", "budget", "disable-provider"},
        {"pricing", "budget", "disable-vault"},
        {"pricing", "budget", "ledger"},
        {"pricing", "budget", "list"},
        {"pricing", "budget", "set-global"},
        {"pricing", "budget", "set-provider"},
        {"pricing", "budget", "set-vault"},
        {"pricing", "budget", "status"},
        {"role", "admin"},
        {"role", "admin", "create"},
        {"role", "admin", "delete"},
        {"role", "admin", "info"},
        {"role", "admin", "list"},
        {"role", "admin", "update"},
        {"role", "vault"},
        {"role", "vault", "create"},
        {"role", "vault", "delete"},
        {"role", "vault", "info"},
        {"role", "vault", "list"},
        {"role", "vault", "update"},
        {"s3-gateway", "bucket"},
        {"s3-gateway", "bucket", "backfill"},
        {"s3-gateway", "bucket", "bind"},
        {"s3-gateway", "bucket", "create-local"},
        {"s3-gateway", "bucket", "create-remote-cache"},
        {"s3-gateway", "bucket", "list"},
        {"s3-gateway", "bucket", "unbind"},
        {"s3-gateway", "budget"},
        {"s3-gateway", "budget", "disable-key"},
        {"s3-gateway", "budget", "disable-key-vault"},
        {"s3-gateway", "budget", "ledger"},
        {"s3-gateway", "budget", "list"},
        {"s3-gateway", "budget", "set-key"},
        {"s3-gateway", "budget", "set-key-vault"},
        {"s3-gateway", "budget", "status"},
        {"s3-gateway", "creds"},
        {"s3-gateway", "creds", "create"},
        {"s3-gateway", "creds", "list"},
        {"s3-gateway", "creds", "revoke"},
        {"s3-gateway", "creds", "role"},
        {"s3-gateway", "creds", "role", "assign"},
        {"s3-gateway", "creds", "role", "list"},
        {"s3-gateway", "creds", "role", "override"},
        {"s3-gateway", "creds", "role", "override", "add"},
        {"s3-gateway", "creds", "role", "override", "list"},
        {"s3-gateway", "creds", "role", "override", "remove"},
        {"s3-gateway", "creds", "role", "revoke"},
        {"s3-gateway", "creds", "scope"},
        {"s3-gateway", "disable"},
        {"s3-gateway", "enable"},
        {"s3-gateway", "status"},
        {"sync", "resolve"},
        {"secrets", "export"},
        {"secrets", "set"},
        {"setup", "assign-admin"},
        {"setup", "db"},
        {"setup", "nginx"},
        {"setup", "remote-db"},
        {"teardown", "db"},
        {"teardown", "nginx"},
        {"user", "create"},
        {"user", "delete"},
        {"user", "info"},
        {"user", "list"},
        {"user", "ls"},
        {"user", "update"},
        {"vault", "create"},
        {"vault", "delete"},
        {"vault", "deleted"},
        {"vault", "info"},
        {"vault", "keys"},
        {"vault", "keys", "export"},
        {"vault", "keys", "inspect"},
        {"vault", "keys", "rotate"},
        {"vault", "list"},
        {"vault", "restore"},
        {"vault", "role"},
        {"vault", "role", "assign"},
        {"vault", "role", "list"},
        {"vault", "role", "override"},
        {"vault", "role", "override", "add"},
        {"vault", "role", "override", "list"},
        {"vault", "role", "override", "remove"},
        {"vault", "role", "override", "update"},
        {"vault", "role", "remove"},
        {"vault", "sync"},
        {"vault", "sync", "dry-run"},
        {"vault", "sync", "dryrun"},
        {"vault", "sync", "events"},
        {"vault", "sync", "info"},
        {"vault", "sync", "inventory"},
        {"vault", "sync", "plan"},
        {"vault", "sync", "reconcile"},
        {"vault", "sync", "update"},
        {"vault", "update"}
    };
    for (const auto& path : paths) {
        const auto node = usage->resolve(path);
        ASSERT_TRUE(node) << path.front();
        std::string joined;
        for (const auto& p : path) joined += p + " ";
        EXPECT_TRUE(std::ranges::find(node->aliases, path.back()) != node->aliases.end())
            << "'vh " << joined << "' is dispatched by a handler but not defined (resolves to '" << node->primary() << "')";
    }
}

}
