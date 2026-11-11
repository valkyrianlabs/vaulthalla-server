#include "usages.hpp"

using namespace vh::protocols::shell;

// `vh cloud ...`: this server's optional link to a vaulthalla.cloud account (design/cloud/server-link.md).
namespace vh::protocols::shell::cloud_book {

namespace {

std::shared_ptr<CommandUsage> build(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

std::shared_ptr<CommandUsage> link(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"link"};
    cmd->description = "Link this server to your vaulthalla.cloud account. Prints a code to enter on vaulthalla.cloud "
                       "and this server's key fingerprint to compare there; interactively, waits until you approve "
                       "it. Linking is never required. Super admins only.";
    cmd->optional = {Optional::ManyToOne("name", "What vaulthalla.cloud calls this server (default: its host name)",
                                         {"name"}, "name")};
    cmd->optional_flags = {
        Flag::WithAliases("finish", "Check a pending request instead of making a new one (after --json or Ctrl-C)",
                          {"finish"}),
        Flag::WithAliases("json_output", "Print the request (or, with --finish, its status) as JSON without waiting",
                          {"json", "j"})};
    cmd->examples = {
        {"vh cloud link", "Ask to link this server, then approve it on vaulthalla.cloud with the code shown."},
        {"vh cloud link --name \"home server\"", "The same, with the name vaulthalla.cloud shows for it."},
        {"vh cloud link --json", "Make the request and print its code and fingerprint as JSON."},
        {"vh cloud link --finish", "Check whether the pending request was approved, denied or expired."},
    };
    return cmd;
}

std::shared_ptr<CommandUsage> status(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"status"};
    cmd->description = "Whether this server is linked to Vaulthalla Cloud, as what, and whether the cloud still "
                       "accepts it.";
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh cloud status", "Show this server's Vaulthalla Cloud link."},
                     {"vh cloud status --json", "The same as JSON."}};
    return cmd;
}

const auto vaultPos = Positional::WithAliases("vault", "Name or ID of the vault", {"name", "id"},
                                              contract::gen::ref("vault", {"id"}));
const auto owner = Optional::Multi("owner", "User ID or username of the vault owner (required if using name)",
                                   {"owner", "o"}, {"id", "name"})
                       .withGen("id", contract::gen::ref("user", {"id"}));

std::shared_ptr<CommandUsage> recovery(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->aliases = {"recovery"};
    cmd->description = "Cloud recovery of vault keys (customer-key-controlled): keep a copy of a vault's recovery "
                       "envelopes in your Vaulthalla Cloud account. They are wrapped to your own recovery recipients, "
                       "so the cloud can't open them. Explicit per vault; self-managed recovery is unchanged.";
    const auto self = cmd->weak_from_this();

    auto enroll = build(self);
    enroll->effect = CommandEffect::Write;
    enroll->aliases = {"enroll"};
    enroll->description = "Send a vault's recovery envelopes (from its bucket), key checks, attestations and checkpoint "
                          "to your Vaulthalla Cloud account; run again after a key rotation. Never a key, seed or "
                          "export. Needs a linked server and a recovery recipient covering every needed key version.";
    enroll->positionals = {vaultPos};
    enroll->optional = {owner};
    enroll->examples = {{"vh cloud recovery enroll 12", "Enroll vault 12 in cloud recovery (or update its records)."},
                        {"vh cloud recovery enroll photos --owner alice", "The same, by name."}};

    auto status = build(self);
    status->effect = CommandEffect::Read;
    status->aliases = {"status"};
    status->description = "The enrolled vaults, and whether the cloud covers every key version each one needs.";
    status->optional = {Optional::ManyToOne("vault", "Only this vault (name or ID)", {"vault"}, "vault"), owner};
    status->optional_flags = {jsonFlag};
    status->examples = {{"vh cloud recovery status", "Every vault enrolled from this server."},
                        {"vh cloud recovery status --vault 12 --json", "One vault, as JSON."}};

    auto unenroll = build(self);
    unenroll->effect = CommandEffect::Destructive;
    unenroll->aliases = {"unenroll"};
    unenroll->description = "Delete the cloud's records of a vault and stop enrolling it. Your own recovery kit or "
                            "export still recovers it.";
    unenroll->positionals = {vaultPos};
    unenroll->optional = {owner};
    unenroll->examples = {{"vh cloud recovery unenroll 12", "Remove vault 12 from cloud recovery."}};

    cmd->subcommands = {enroll, status, unenroll};
    cmd->examples = {{"vh cloud recovery enroll 12", "Enroll vault 12."}, {"vh cloud recovery status", "Coverage."}};
    return cmd;
}

std::shared_ptr<CommandUsage> unlink(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Destructive;
    cmd->aliases = {"unlink"};
    cmd->description = "Revoke this server's link in Vaulthalla Cloud and forget it here, with its identity key. A "
                       "pending request is discarded.";
    cmd->optional_flags = {Flag::WithAliases("force", "Forget the link here even when the cloud can't confirm it "
                                                      "(then revoke this server on vaulthalla.cloud)",
                                             {"force"})};
    cmd->examples = {{"vh cloud unlink", "Unlink this server from its Vaulthalla Cloud account."},
                     {"vh cloud unlink --force", "Forget the link here although the cloud can't be reached."}};
    return cmd;
}

}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Cloud Commands";
    auto root = build(parent);
    root->aliases = {"cloud"};
    root->description = "Link this server to a vaulthalla.cloud account (optional; Vaulthalla never needs it). "
                        "vaulthalla.cloud isn't open yet.";
    root->subcommands = {link(root->weak_from_this()), status(root->weak_from_this()), unlink(root->weak_from_this()),
                         recovery(root->weak_from_this())};
    root->examples = {
        {"vh cloud link", "Link this server to your vaulthalla.cloud account."},
        {"vh cloud status", "Show the link."},
        {"vh cloud unlink", "Remove the link."},
    };
    book->root = root;
    return book;
}

}
