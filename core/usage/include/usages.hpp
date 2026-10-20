#pragma once

#include "CommandUsage.hpp"
#include "CommandBook.hpp"
#include "permsUtil.hpp"

namespace vh::protocols::shell {

struct CommandCall;

namespace aku { [[nodiscard]] std::string usage_cloud_provider(); }

namespace vault { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace user { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace group { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace secrets { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace email { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace pricing { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace sync_book { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace resolve_book { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace s3gateway { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace aku { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace role { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace permissions { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace setup { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace teardown { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace status { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace help { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace version { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace fs_book { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
// `vh mcp`, `vh skill`: run in the vh client (usages/agents.cpp).
namespace mcp_book { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace skill_book { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
namespace upstream_book { std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent); }
// File recovery: `vh recovery …` (get), `vh snapshot …` (getSnapshot) and the `vh vault recovery …` subtree.
namespace recovery_book {
std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent);
std::shared_ptr<CommandBook> getSnapshot(const std::weak_ptr<CommandUsage>& parent);
std::shared_ptr<CommandUsage> vaultRecovery(const std::weak_ptr<CommandUsage>& parent);
}

const auto gpgRecipient = Optional::ManyToOne("gpg_recipient", "GPG fingerprint to encrypt the exported key (if blank will not encrypt)",
                            {"recipient", "r"}, "gpg-fingerprint");

const auto outputFile = Optional::ManyToOne("output", "Output file for the exported key (if blank will print to stdout)",
                            {"output", "o"}, "file");

const auto subjectOption = Option::Multi("subject", "Specify the user or group the command is targeting", {"user", "u", "group", "g"},
                      {"id", "name"})
                              .withGen("id", contract::gen::ref("subject", {"id"}))
                              .withGen("name", contract::gen::ref("subject", {"name"}));

const auto permissionsFlags = Flag::WithAliases("permissions", "Permission flags to set for the new role (see 'vh permissions') min=1",
                          ALL_SHELL_PERMS_STR);

const auto jsonFlag = Flag::WithAliases("json_output", "Output the list in JSON format", {"json", "j"});

const auto limitOpt = Optional::ManyToOne("limit", "Limit the number of vaults displayed", {"limit", "n"}, "limit")
                         .withGen("limit", contract::gen::intRange(1, 50));

const auto pageOpt = Optional::ManyToOne("page", "Specify the page number when using --limit for pagination", {"page", "p"}, "page")
                        .withGen("page", contract::gen::intRange(1, 3));

const auto sortOpt = Optional::ManyToOne("sort", "Sort by this field", {"sort"}, "field");

const auto directionOpt = Optional::ManyToOne("direction", "Sort direction: asc or desc", {"direction"}, "asc|desc")
                             .withGen("asc|desc", contract::gen::oneOf({"asc", "desc"}));

const auto filterOpt = Optional::ManyToOne("filter", "Only show entries matching this text", {"filter"}, "text")
                          .withGen("text", contract::gen::pattern("{a}{a}"));

// Every option parseListQuery() reads; list commands that use it declare all of these.
inline std::vector<Optional> listQueryOptions() { return {limitOpt, pageOpt, sortOpt, directionOpt, filterOpt}; }

const auto userPos = Positional::WithAliases("user", "Username or ID of the user", {"name", "id"},
                                             contract::gen::ref("user", {"name", "id"}));

}
