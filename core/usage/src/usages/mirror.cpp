#include "usages.hpp"

using namespace vh::protocols::shell;

// `vh mirror ...`: mirrored vaults between linked servers (design/peers/mirror.md). Experimental and off by default
// (peers.experimental). The minimal set for starting and cancelling a mirror; the polished CLI comes later.
namespace vh::protocols::shell::mirror_book {

namespace {

std::shared_ptr<CommandUsage> build(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

const auto vaultPos = Positional::WithAliases("vault", "The vault's number on this server (vh vault list)",
                                              {"vault", "vault_id"}, contract::gen::pattern("{9}"));

const auto offerPos = Positional::WithAliases("offer", "The offer's number here (vh mirror pending) or its uid",
                                              {"offer"}, contract::gen::pattern("{9}"));

const auto peerPos = Positional::WithAliases(
    "peer", "The linked server: its number from `vh peer list`, its node id, its name, or 8+ hex digits of its key",
    {"peer", "id"}, contract::gen::pattern("{9}"));

std::shared_ptr<CommandUsage> add(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"add", "start"};
    cmd->description = "Start mirroring one of this server's vaults to a linked server: this server stays the vault's "
                       "core, the other gets a copy and the vault's keys. Checks first that the vault can be mirrored "
                       "(each refusal says why), then offers it; the other server accepts (a super admin there, or "
                       "its link is set to accept every vault from here). Super admins, or someone who may edit the "
                       "vault and assign its vault roles.";
    cmd->positionals = {vaultPos};
    cmd->required = {Option::Single("to", "The linked server to mirror it to", "to", "server")};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror add 3 --to vps", "Offer vault 3 to the linked server \"vps\"."}};
    return cmd;
}

std::shared_ptr<CommandUsage> pending(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"pending", "offers"};
    cmd->description = "List the vaults linked servers offer this server that wait for a super admin's answer.";
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror pending", "Offers waiting here."}};
    return cmd;
}

std::shared_ptr<CommandUsage> accept(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"accept"};
    cmd->description = "Accept an offer: the other server then sends the vault's keys, this server proves each against "
                       "the key it pinned when the servers were linked, and creates the vault (empty until its tree "
                       "is copied). Super admins only.";
    cmd->positionals = {offerPos};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror accept 4", "Accept offer 4."}};
    return cmd;
}

std::shared_ptr<CommandUsage> decline(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"decline"};
    cmd->description = "Decline an offer; the other server is told. Super admins only.";
    cmd->positionals = {offerPos};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror decline 4", "Decline offer 4."}};
    return cmd;
}

std::shared_ptr<CommandUsage> cancel(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Destructive;
    cmd->aliases = {"cancel", "remove"};
    cmd->description = "End a vault's mirror, at any step. On the core: the mirror is ended here at once and the other "
                       "server is told when it is reachable; it keeps its copy as an orphaned copy, or removes it with "
                       "--remove-copy (unless it keeps the vaults this server removes; an unfinished copy is removed "
                       "anyway). On the mirror: a start that has not completed is removed here and the core is told; "
                       "a completed mirror is refused (leaving with the copy is a later version's detach); an orphaned "
                       "copy is removed with its keys. --offer names a start whose vault does not exist here yet.";
    cmd->positionals = {Positional::WithAliases("vault", "The vault's number here (or 0 with --offer)", {"vault"},
                                                contract::gen::pattern("{9}"))};
    cmd->optional = {Optional::ManyToOne("offer", "The offer's number or uid instead of a vault", {"offer"}, "offer")};
    cmd->optional_flags = {Flag::WithAliases("remove_copy", "On the core: ask the mirror to remove its copy (it keeps "
                                                            "it, orphaned, without this or when it keeps removed vaults)",
                                             {"remove-copy"}),
                           jsonFlag};
    cmd->examples = {{"vh mirror cancel 3", "End vault 3's mirror; the other server keeps its copy, orphaned."},
                     {"vh mirror cancel 3 --remove-copy", "End it and ask the other server to remove its copy."},
                     {"vh mirror cancel 0 --offer 4", "Cancel offer 4 before its vault exists here."}};
    return cmd;
}

std::shared_ptr<CommandUsage> list(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"list", "ls"};
    cmd->description = "List the mirrored vaults here (this server's role, the linked server, the grant) and the starts "
                       "in progress. Super admins only.";
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror list", "Mirrored vaults and starts."}, {"vh mirrors", "The same (plural alias)."}};
    return cmd;
}

std::shared_ptr<CommandUsage> info(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"info", "status", "show"};
    cmd->description = "Show one vault's mirror: this server's role, the linked server, the state, the grant and what "
                       "step a start is at.";
    cmd->positionals = {vaultPos};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror info 3", "Vault 3's mirror."}};
    return cmd;
}

std::shared_ptr<CommandUsage> keep(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"keep-removed"};
    cmd->description = "Whether this server keeps the vaults a linked server (their core) removes: with it on, a "
                       "removal the core asks for leaves the copy here as an orphaned copy (off by default). Super "
                       "admins only; audited.";
    cmd->positionals = {peerPos, Positional::Alias("state", "on or off", "state", contract::gen::constant("off"))};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror keep-removed vps on", "Keep every vault \"vps\" removes, orphaned."}};
    return cmd;
}

const auto heldPos = Positional::WithAliases("held", "The held change's number (vh mirror held)", {"held", "id"},
                                             contract::gen::pattern("{9}"));

std::shared_ptr<CommandUsage> held(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"held"};
    cmd->description = "List the changes made here to a vault this server mirrors that its core refused (held: the "
                       "entry went back to the core's state and the change is kept, with the reason) or turned into a "
                       "conflict copy. Super admins only.";
    cmd->optional = {Optional::ManyToOne("vault", "One vault only (its number here)", {"vault"}, "vault")};
    cmd->optional_flags = {Flag::WithAliases("all", "Include the ones discarded or retried", {"all"}), jsonFlag};
    cmd->examples = {{"vh mirror held", "Held changes and conflict copies."}};
    return cmd;
}

std::shared_ptr<CommandUsage> discard(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Destructive;
    cmd->aliases = {"discard"};
    cmd->description = "Drop a held change (or dismiss a conflict copy's record); nothing in the vault changes. Super "
                       "admins only; audited.";
    cmd->positionals = {heldPos};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror discard 7", "Drop held change 7."}};
    return cmd;
}

std::shared_ptr<CommandUsage> retry(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"retry"};
    cmd->description = "Send a held change to the vault's core again, as the person who made it (after the core's "
                       "grant changed, say); it comes back in the log, or is held again. Super admins only; audited.";
    cmd->positionals = {heldPos};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror retry 7", "Submit held change 7 again."}};
    return cmd;
}

std::shared_ptr<CommandUsage> acceptAll(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"accept-all"};
    cmd->description = "Whether this server accepts every vault a linked server offers without asking (off by "
                       "default). Super admins only; audited.";
    cmd->positionals = {peerPos, Positional::Alias("state", "on or off", "state", contract::gen::constant("off"))};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror accept-all vps on", "Accept every vault \"vps\" offers."}};
    return cmd;
}

}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Mirrored Vault Commands";
    auto root = build(parent);
    root->aliases = {"mirror"};
    root->pluralAliasImpliesList = true;
    root->description = "Mirror a vault between this server and a linked one (experimental; peers.experimental in "
                        "config.yaml). One server is the vault's core; the other holds a copy and the vault's keys.";
    root->subcommands = {add(root->weak_from_this()),    pending(root->weak_from_this()), accept(root->weak_from_this()),
                         decline(root->weak_from_this()), cancel(root->weak_from_this()), list(root->weak_from_this()),
                         info(root->weak_from_this()),    acceptAll(root->weak_from_this()),
                         keep(root->weak_from_this()),    held(root->weak_from_this()),    discard(root->weak_from_this()),
                         retry(root->weak_from_this())};
    root->examples = {
        {"vh mirror add <vault> --to <server>", "On the core: offer a vault."},
        {"vh mirror pending", "On the other server: offers waiting."},
        {"vh mirror accept <offer>", "Accept one."},
    };
    book->root = root;
    return book;
}

}
