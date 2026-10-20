#include "usages.hpp"
#include "CommandUsage.hpp"

namespace vh::protocols::shell::sync_book {

static const auto keepLocalFlag = Flag::WithAliases("keep_local", "Keep the local copy: upload it over the remote object",
                                                    {"keep-local", "local"});
static const auto keepRemoteFlag = Flag::WithAliases("keep_remote", "Keep the remote copy: download it over the local copy",
                                                     {"keep-remote", "remote"});
static const auto listFlag = Flag::WithAliases("list", "List open conflicts and exit", {"list", "l"});
static const auto allFlag = Flag::WithAliases("all", "Every open conflict in --vault (needs --vault and a decision)", {"all"});
static const auto yesFlag = Flag::WithAliases("yes", "Do not ask before resolving with --all", {"yes", "y"});
static const auto jsonOutFlag = Flag::WithAliases("json_output", "Print JSON (the ws sync.conflicts.* shapes)", {"json", "j"});
static const auto vaultOpt = Optional::ManyToOne("vault", "Only this vault (ID or name)", {"vault", "v"}, "vault");

static void describeResolve(const std::shared_ptr<CommandUsage>& cmd) {
    cmd->synopsis = "vh sync resolve [<conflict-id>...] [--keep-local | --keep-remote] [--list] [--vault <vault>] "
                    "[--all] [--yes] [--json]";
    cmd->optional_flags = {keepLocalFlag, keepRemoteFlag, listFlag, allFlag, yesFlag, jsonOutFlag};
    cmd->optional = {vaultOpt};
    cmd->examples = {
        {"vh sync resolve", "In a terminal: walk through open conflicts, compare both sides, keep local or remote."},
        {"vh sync resolve --list", "List open conflicts you can resolve, grouped by vault."},
        {"vh sync resolve --list --vault photos --json", "Open conflicts in vault 'photos' as JSON."},
        {"vh sync resolve 12 13 --keep-local", "Upload the local copy of conflicts 12 and 13 over the remote objects."},
        {"vh sync resolve 7 --keep-remote", "Replace the local copy of conflict 7 with the remote version."},
        {"vh sync resolve --vault photos --all --keep-remote --yes",
         "Keep the remote version of every open conflict in vault 'photos' without asking."}
    };
}

static std::shared_ptr<CommandUsage> resolve(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    cmd->aliases = {"resolve"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description =
        "Resolve sync conflicts recorded under the 'ask' conflict policy (S3/R2 vaults). A conflict is a file that "
        "changed on both sides since they last agreed; it waits, while everything else keeps syncing, until you keep "
        "the local copy (uploaded over the remote object) or the remote copy (downloaded over the local one). Needs "
        "the vault's vault.sync.action.resolve_conflicts permission and Overwrite on the file. A decision is refused "
        "when either side changed since the conflict was recorded; transfers count against the vault's S3 request "
        "and price budgets. With a terminal and no arguments, opens an interactive session.";
    describeResolve(cmd);
    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Sync Commands";
    book->root = std::make_shared<CommandUsage>();
    book->root->parent = parent;
    book->root->aliases = {"sync"};
    book->root->description =
        "Resolve sync conflicts. A vault's sync settings and runs live under 'vh vault sync'.";
    book->root->subcommands = {resolve(book->root->weak_from_this())};
    book->root->examples = {
        {"vh sync resolve", "Walk through open sync conflicts interactively."},
        {"vh sync resolve --list", "List open sync conflicts."}
    };
    return book;
}

}

namespace vh::protocols::shell::resolve_book {

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Resolve Command";
    book->root = std::make_shared<CommandUsage>();
    book->root->parent = parent;
    book->root->aliases = {"resolve"};
    book->root->effect = CommandEffect::Destructive;
    book->root->description = "Shortcut for 'vh sync resolve': resolve sync conflicts recorded under the 'ask' policy.";
    sync_book::describeResolve(book->root);
    book->root->synopsis = "vh resolve [<conflict-id>...] [--keep-local | --keep-remote] [--list] [--vault <vault>] "
                           "[--all] [--yes] [--json]";
    for (auto& example : book->root->examples)
        if (example.cmd.starts_with("vh sync resolve")) example.cmd.replace(0, std::string("vh sync resolve").size(), "vh resolve");
    return book;
}

}
