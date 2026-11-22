#include "usages.hpp"

// `vh connector ...`: remote connectors (design/core/mcp-remote-signin.md): hosted AI clients (Claude, ChatGPT) and
// CLIs on other machines signing in to this node's MCP tools with OAuth. Never available to agents (an MCP exclusion).
namespace vh::protocols::shell::connector_book {

namespace {

std::shared_ptr<CommandUsage> build(const std::weak_ptr<CommandUsage>& parent, const CommandEffect effect,
                                    std::vector<std::string> aliases, std::string description) {
    auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    cmd->effect = effect;
    cmd->aliases = std::move(aliases);
    cmd->description = std::move(description);
    return cmd;
}

std::shared_ptr<CommandUsage> group(const std::weak_ptr<CommandUsage>& parent, std::vector<std::string> aliases,
                                    std::string description) {
    auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    cmd->aliases = std::move(aliases);
    cmd->description = std::move(description);
    return cmd;
}

const auto grantPos = Positional::WithAliases(
    "grant", "The grant: its id from `vh connector list`, or the first 8+ characters of it", {"grant", "id"});

const auto clientPos = Positional::WithAliases(
    "client", "The client: its id from `vh connector client list`, or the first 8+ characters of it", {"client", "id"});

std::shared_ptr<CommandUsage> client(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = group(parent, {"client", "clients"},
                     "Clients registered by hand, for apps that can't publish a client-id metadata document (super "
                     "admins). Claude and ChatGPT need none: they identify themselves.");
    auto list = build(cmd->weak_from_this(), CommandEffect::Read, {"list", "ls"},
                      "List the clients this server knows (registered, fetched metadata documents, dynamic ones).");
    list->optional_flags = {jsonFlag};
    list->examples = {{"vh connector client list", "Every client."}};

    auto add = build(cmd->weak_from_this(), CommandEffect::Write, {"add"},
                     "Register a client: a name and its exact redirect URI (https, or http to 127.0.0.1, [::1] or "
                     "localhost, any port). Prints the client id to configure the app with.");
    add->required = {Option::Multi("name", "The client's name (1-64 characters)", {"name", "n"}, {"name"}),
                     Option::Multi("redirect", "The exact redirect URI", {"redirect", "r"}, {"uri"})};
    add->optional_flags = {jsonFlag};
    add->examples = {{"vh connector client add --name \"Codex on laptop\" --redirect http://127.0.0.1/callback",
                      "Register a CLI that receives its sign-in on this computer's loopback."}};

    auto remove = build(cmd->weak_from_this(), CommandEffect::Destructive, {"remove", "rm"},
                        "Remove a client: it can't sign in again, and every grant it holds ends now.");
    remove->positionals = {clientPos};
    remove->examples = {{"vh connector client remove 5cd252fb", "Remove the client whose id starts with 5cd252fb."}};

    cmd->subcommands = {list, add, remove};
    cmd->examples = {{"vh connector client list", "Every client."}};
    return cmd;
}

}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Remote Connector Commands";
    auto root = group(parent, {"connector"},
                      "Remote connectors: let hosted AI apps (Claude, ChatGPT) and AI tools on other computers use this "
                      "server's tools as your account, read-only unless you choose more. Off by default. Whoever runs "
                      "the app then holds a key that acts within that access until it is revoked.");
    root->pluralAliasImpliesList = true;

    auto status = build(root->weak_from_this(), CommandEffect::Read, {"status"},
                        "Show the switch, the public address, the policy and how many grants and clients are live "
                        "(super admins).");
    status->optional_flags = {jsonFlag};
    status->examples = {{"vh connector status", "Is it on, and at which address."}};

    auto enable = build(root->weak_from_this(), CommandEffect::Write, {"enable", "on"},
                        "Switch remote connectors on at this server's public https address (a host name with a "
                        "publicly trusted certificate, port 443) (super admins).");
    enable->required = {Option::Multi("url", "The public origin, https://<host>", {"url", "u"}, {"origin"})};
    enable->optional_flags = {jsonFlag};
    enable->examples = {{"vh connector enable --url https://vault.example.com", "Switch it on at that address."}};

    auto disable = build(root->weak_from_this(), CommandEffect::Destructive, {"disable", "off"},
                         "Switch remote connectors off: every connected app is disconnected now (super admins).");
    disable->optional_flags = {jsonFlag};
    disable->examples = {{"vh connector disable", "Switch it off and end every grant."}};

    auto set = build(root->weak_from_this(), CommandEffect::Write, {"set"},
                     "Change what may be granted (super admins): the widest scope (read, write or destructive; write "
                     "by default), dynamic client registration (off by default), and which hosts may identify "
                     "clients (any, or a comma-separated list).");
    set->optional = {Optional::ManyToOne("max_scope", "The widest scope a grant may have", {"max-scope"}, "scope"),
                     Optional::ManyToOne("dcr", "Dynamic client registration: on or off", {"dcr"}, "on|off"),
                     Optional::ManyToOne("client_hosts", "any, or host names separated by commas", {"client-hosts"},
                                         "hosts")};
    set->optional_flags = {jsonFlag};
    set->examples = {{"vh connector set --max-scope read", "Only read-only grants from now on (wider ones end)."},
                     {"vh connector set --client-hosts claude.ai,chatgpt.com", "Only clients those hosts publish."}};

    auto list = build(root->weak_from_this(), CommandEffect::Read, {"list", "ls"},
                      "List your connected apps (grants), live first; --all lists every user's (super admins).");
    list->optional_flags = {Flag::WithAliases("all", "Every user's grants (super admins only)", {"all", "a"}), jsonFlag};
    list->examples = {{"vh connector list", "Your connected apps."}, {"vh connectors", "The same (plural alias)."}};

    auto revoke = build(root->weak_from_this(), CommandEffect::Destructive, {"revoke"},
                        "Disconnect an app now (your own, or anyone's for a super admin): its tokens stop working at "
                        "once.");
    revoke->positionals = {grantPos};
    revoke->examples = {{"vh connector revoke 5cd252fb", "Disconnect the app whose grant id starts with 5cd252fb."}};

    auto revokeAll = build(root->weak_from_this(), CommandEffect::Destructive, {"revoke-all"},
                           "Disconnect every app now (super admins), or only one user's with --user (that user, or a "
                           "super admin).");
    revokeAll->optional = {Optional::ManyToOne("user", "Only this user's grants", {"user"}, "name")};
    revokeAll->examples = {{"vh connector revoke-all", "Disconnect every app."},
                           {"vh connector revoke-all --user alice", "Disconnect alice's apps."}};

    root->subcommands = {status, enable, disable, set, list, revoke, revokeAll, client(root->weak_from_this())};
    root->examples = {{"vh connector status", "Is it on, and at which address."},
                      {"vh connector list", "Your connected apps."},
                      {"vh connector revoke 5cd252fb", "Disconnect one."}};
    book->root = root;
    return book;
}

}
