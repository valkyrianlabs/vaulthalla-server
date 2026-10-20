#include "usages.hpp"
#include "CommandBook.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::permissions {

static const auto typeFilter = Optional::OneToMany(
    "type_filter",
    "Filter permissions by type",
    "type",
    {"user", "vault"},
    "both"
    );

static const auto userFlag = Flag::WithAliases("user_filter", "Filter permissions for user roles", {"user", "u"});
static const auto vaultFlag = Flag::WithAliases("vault_filter", "Filter permissions for vault roles", {"vault", "v"});

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    cmd->aliases = {"permission", "perm"};
    cmd->effect = CommandEffect::Read;
    cmd->optional = { typeFilter };
    cmd->optional_flags = { userFlag, vaultFlag };
    cmd->description = "Display available permission flags for user and vault roles.";
    cmd->examples.push_back({"vh permission", "Show all available permission flags."});
    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = base(parent);
    const auto book = std::make_shared<CommandBook>();
    book->title = "Permission Commands";
    book->root = cmd;
    return book;
}

}
