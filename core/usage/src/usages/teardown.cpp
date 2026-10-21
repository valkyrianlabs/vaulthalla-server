#include "usages.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::teardown {

static std::shared_ptr<CommandUsage> buildBaseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static std::shared_ptr<CommandUsage> nginx(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"nginx", "proxy"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Disable/remove Vaulthalla-managed nginx site integration only. Requires sudo.";
    cmd->examples = {
        {"sudo vh teardown nginx", "Disable Vaulthalla nginx site integration without touching unrelated nginx config."}
    };
    return cmd;
}

static const auto caddyPurgeFlag = Flag::WithAliases("purge", "Also delete the certificates, the ACME account and Vaulthalla's internal CA (clients that trusted it keep trusting it until removed there)", {"purge"});

static std::shared_ptr<CommandUsage> caddy(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"caddy", "https"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "macOS: stop and remove Vaulthalla's Caddy HTTPS front end. Keeps certificates and the internal CA "
                       "unless --purge. Requires sudo.";
    cmd->optional_flags = {caddyPurgeFlag};
    cmd->examples = {
        {"sudo vh teardown caddy", "Stop serving HTTPS; keep certificates for a later `vh setup caddy`."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> db(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"db", "database", "postgres"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Disable/remove Vaulthalla local PostgreSQL integration (role/database). Requires sudo.";
    cmd->examples = {
        {"sudo vh teardown db", "Drop Vaulthalla local PostgreSQL role/database integration."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"teardown"};
    cmd->description = "Perform explicit Vaulthalla integration teardown tasks.";
    cmd->examples = {
        {"sudo vh teardown nginx", "Disable/remove Vaulthalla-managed nginx site integration."},
        {"sudo vh teardown db", "Disable/remove Vaulthalla local PostgreSQL integration."}
    };
    cmd->subcommands = {
        nginx(cmd->weak_from_this()),
        caddy(cmd->weak_from_this()),
        db(cmd->weak_from_this())
    };
    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Teardown Commands";
    book->root = base(parent);
    return book;
}

}
