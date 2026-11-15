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
                       "it, then asks you to confirm the account recovery key's fingerprint (`vh cloud key confirm` "
                       "later otherwise). Linking is never required. Super admins only.";
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
    enroll->description = "Send a vault's recovery envelopes (from its bucket, or for a local vault from this server's "
                          "database), key checks, attestations and checkpoint to your Vaulthalla Cloud account; run "
                          "again after a key rotation. Never a key, seed or export. Needs a linked server and a recovery "
                          "recipient covering every needed key version.";
    enroll->positionals = {vaultPos};
    enroll->optional = {owner};
    enroll->optional_flags = {Flag::WithAliases("account_key", "Add the account recovery key this server pinned as a "
                                                               "recovery recipient first", {"account-key"})};
    enroll->examples = {{"vh cloud recovery enroll 12", "Enroll vault 12 in cloud recovery (or update its records)."},
                        {"vh cloud recovery enroll photos --owner alice", "The same, by name."},
                        {"vh cloud recovery enroll 12 --account-key",
                         "Wrap vault 12's keys to the pinned account recovery key, then enroll it."}};

    auto status = build(self);
    status->effect = CommandEffect::Read;
    status->aliases = {"status"};
    status->description = "The enrolled vaults, and whether the cloud covers every key version each one needs.";
    status->optional = {Optional::ManyToOne("vault", "Only this vault (name or ID)", {"vault"}, "vault"), owner};
    status->optional_flags = {jsonFlag,
                              Flag::WithAliases("verify", "Also compare the account-key envelopes the cloud holds with "
                                                          "this server's records", {"verify"})};
    status->examples = {{"vh cloud recovery status", "Every vault enrolled from this server."},
                        {"vh cloud recovery status --vault 12 --json", "One vault, as JSON."},
                        {"vh cloud recovery status --verify", "Check the cloud's envelopes against this server's."}};

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

// `vh cloud key ...`: the linked account's recovery key as this server pinned it (design/cloud/key-manager.md).
std::shared_ptr<CommandUsage> key(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->aliases = {"key", "keys"};
    cmd->description = "The account recovery key this server pinned: the key vault keys are wrapped to when you add "
                       "it as a recovery recipient. Its fingerprint is confirmed once, by a super admin, against the one "
                       "Vaulthalla Desktop or the account page shows.";
    const auto self = cmd->weak_from_this();

    auto status = build(self);
    status->effect = CommandEffect::Read;
    status->aliases = {"status"};
    status->description = "The pinned key (generation, fingerprint, who confirmed it), a key waiting for confirmation, "
                          "the accepted recovery policy and the vaults it covers, and the last check. Public values only.";
    status->optional_flags = {jsonFlag};
    status->examples = {{"vh cloud key status", "Show the account recovery key."},
                        {"vh cloud key status --json", "The same as JSON."}};

    auto confirm = build(self);
    confirm->effect = CommandEffect::Write;
    confirm->aliases = {"confirm"};
    confirm->description = "Pin the waiting account recovery key after comparing its fingerprint with the one Vaulthalla "
                           "Desktop or your account page shows: the first key after linking, or a replacement. A "
                           "mismatch pins nothing. Super admins only.";
    confirm->positionals = {Positional::Same("fingerprint", "The fingerprint you compared (eight groups of four hex "
                                                            "digits)")};
    confirm->optional_flags = {jsonFlag};
    confirm->examples = {{"vh cloud key confirm 3f2a-91c0-77d4-0b1e-5c6d-8e9f-a0b1-c2d3",
                          "Pin the account recovery key with this fingerprint."}};

    auto refresh = build(self);
    refresh->effect = CommandEffect::Write;
    refresh->aliases = {"refresh", "check"};
    refresh->description = "Fetch and verify the account recovery key and recovery policy now (the server also checks "
                           "daily). Signed rotations are followed; anything else waits for a confirmation.";
    refresh->optional_flags = {jsonFlag};
    refresh->examples = {{"vh cloud key refresh", "Check the account recovery key now."}};

    auto forget = build(self);
    forget->effect = CommandEffect::Destructive;
    forget->aliases = {"forget"};
    forget->description = "Forget the pinned account recovery key on this server, so the next link asks for a "
                          "confirmation again. Refused while a vault holds a recovery grant that rests on it.";
    forget->examples = {{"vh cloud key forget", "Forget the pin."}};

    cmd->subcommands = {status, confirm, refresh, forget};
    cmd->examples = {{"vh cloud key status", "Show the pinned key."}};
    return cmd;
}

// `vh cloud storage ...`: managed storage (design/cloud/managed-remotes.md).
std::shared_ptr<CommandUsage> storage(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->aliases = {"storage"};
    cmd->description = "Managed storage: on a linked server whose account includes storage, each vault can be kept in "
                       "a bucket of its own that the account provides. The vault stays encrypted on this server, which "
                       "holds its keys; nothing unencrypted leaves it. Per vault, with a switch.";
    const auto self = cmd->weak_from_this();

    auto status = build(self);
    status->effect = CommandEffect::Read;
    status->aliases = {"status"};
    status->description = "The account's plan state, usage against the quota, the vaults waiting for a decision (with "
                          "their sizes) and every vault's switch and state.";
    status->optional_flags = {jsonFlag};
    status->examples = {{"vh cloud storage status", "Show managed storage."},
                        {"vh cloud storage status --json", "The same as JSON."}};

    auto enable = build(self);
    enable->effect = CommandEffect::Write;
    enable->aliases = {"enable", "on"};
    enable->description = "Switch managed storage on for a vault: it is uploaded once its bucket is ready (an empty "
                          "vault waits for its first file). Its account recovery key becomes a recovery recipient.";
    enable->positionals = {vaultPos};
    enable->optional = {owner};
    enable->examples = {{"vh cloud storage enable 12", "Keep vault 12 in managed storage."}};

    auto disable = build(self);
    disable->effect = CommandEffect::Destructive;
    disable->aliases = {"disable", "off"};
    disable->description = "Switch managed storage off for a vault: every file is fetched and verified here, then the "
                           "vault is a local vault again. Its bucket is left in place (deleting it is the account "
                           "holder's step). A vault restored onto another server is kept here as a local vault.";
    disable->positionals = {vaultPos};
    disable->optional = {owner, Optional::ManyToOne("confirm", "The vault's name, typed", {"confirm"}, "name")};
    disable->examples = {{"vh cloud storage disable 12 --confirm photos", "Make vault 12 (photos) local again."}};

    auto accept = build(self);
    accept->effect = CommandEffect::Write;
    accept->aliases = {"accept"};
    accept->description = "Accept the offer for vaults that existed when managed storage became available: the named "
                          "ones, or every offered vault with --all. Nothing is uploaded before this.";
    accept->optional = {Optional::ManyToOne("vaults", "Vault IDs, comma-separated", {"vaults"}, "ids")};
    accept->optional_flags = {Flag::WithAliases("all", "Every offered vault", {"all"})};
    accept->examples = {{"vh cloud storage accept --all", "Keep every offered vault in managed storage."},
                        {"vh cloud storage accept --vaults 3,7", "Only vaults 3 and 7."}};

    auto decline = build(self);
    decline->effect = CommandEffect::Write;
    decline->aliases = {"decline"};
    decline->description = "Decline the offer for the vaults still offered: they stay local (each can be switched on "
                           "later).";
    decline->examples = {{"vh cloud storage decline", "Keep the remaining offered vaults local."}};

    auto rotate = build(self);
    rotate->effect = CommandEffect::Write;
    rotate->aliases = {"rotate"};
    rotate->description = "Ask for a new bucket key for a vault in managed storage; the old one is revoked once the new "
                          "one works.";
    rotate->positionals = {vaultPos};
    rotate->optional = {owner};
    rotate->examples = {{"vh cloud storage rotate 12", "Replace vault 12's bucket key."}};

    auto newVaults = build(self);
    newVaults->effect = CommandEffect::Write;
    newVaults->aliases = {"new-vaults"};
    newVaults->description = "Whether vaults created from now on use managed storage by default (on unless turned "
                             "off). Each vault keeps its own switch.";
    newVaults->positionals = {Positional::Same("setting", "on or off")};
    newVaults->examples = {{"vh cloud storage new-vaults off", "Keep new vaults local unless switched on."}};

    auto billing = build(self);
    billing->effect = CommandEffect::Write;
    billing->aliases = {"billing"};
    billing->description = "Print the address of the account's billing page (checkout to choose a plan, portal to "
                           "manage it), to open in a browser. Nothing of it is stored.";
    billing->optional = {Optional::ManyToOne("kind", "checkout or portal (default: portal)", {"kind"}, "kind"),
                         Optional::ManyToOne("plan", "The plan to check out", {"plan"}, "plan")};
    billing->examples = {{"vh cloud storage billing", "The billing portal's address."},
                         {"vh cloud storage billing --kind checkout --plan storage-1tb", "Choose a plan."}};

    cmd->subcommands = {status, enable, disable, accept, decline, rotate, newVaults, billing};
    cmd->examples = {{"vh cloud storage status", "Show managed storage."}};
    return cmd;
}

std::shared_ptr<CommandUsage> unlink(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Destructive;
    cmd->aliases = {"unlink"};
    cmd->description = "Revoke this server's link in Vaulthalla Cloud and forget it here, with its identity key. A "
                       "pending request is discarded.";
    cmd->optional_flags = {Flag::WithAliases("force", "Forget the link here even when the cloud can't confirm it "
                                                      "(then revoke this server on vaulthalla.cloud), or while vaults "
                                                      "are in managed storage (their bucket keys are revoked)",
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
                         recovery(root->weak_from_this()), key(root->weak_from_this()),
                         storage(root->weak_from_this())};
    root->examples = {
        {"vh cloud link", "Link this server to your vaulthalla.cloud account."},
        {"vh cloud status", "Show the link."},
        {"vh cloud unlink", "Remove the link."},
    };
    book->root = root;
    return book;
}

}
