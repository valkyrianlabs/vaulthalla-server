#include "usages.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell {

static std::shared_ptr<CommandUsage> help_base(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    cmd->aliases = {"help", "-h", "--h", "--help"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Explicitly show help about a command or namespace (optional).";
    cmd->examples = {
        {"vh help", "Show general help information."},
        {"vh help api-keys", "Show detailed help for the 'api-keys' command."},
        {"vh vault", "Call a command namespace with no args to show its help."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> version_base(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    cmd->aliases = {"version", "-v", "--v", "--version"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show version information about Vaulthalla.";
    cmd->examples.push_back({"vh version", "Show the current version of Vaulthalla."});
    return cmd;
}

static std::shared_ptr<CommandUsage> status_base(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    cmd->aliases = {"status"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show a concise Vaulthalla runtime status snapshot, including a live database round trip. "
                       "Exit status: 0 healthy, 1 degraded, 2 critical (e.g. database unreachable); "
                       "69 daemon not running, 75 daemon not responding, 77 not permitted to use the control socket.";
    cmd->examples = {
        {"vh status", "Show runtime service state, database reachability, protocol readiness, deps sanity, and a systemd summary when elevated."},
        {"vh status >/dev/null || echo unhealthy", "Use the exit status in scripts and health checks."}
    };
    return cmd;
}

std::shared_ptr<CommandBook> help::get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Help Command";
    book->root = help_base(parent);
    return book;
}

std::shared_ptr<CommandBook> version::get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Version Command";
    book->root = version_base(parent);
    return book;
}

std::shared_ptr<CommandBook> status::get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Status Command";
    book->root = status_base(parent);
    return book;
}

}
