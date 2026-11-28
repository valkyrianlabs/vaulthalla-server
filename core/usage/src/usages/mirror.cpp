#include "usages.hpp"

using namespace vh::protocols::shell;

// `vh mirror ...`: mirrored vaults between linked servers (design/peers/mirror.md).
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
    cmd->description = "List the vaults linked servers offer this server that wait for a super admin's answer, and the "
                       "relinks they ask of this server's vaults (vh mirror relink <vault> --accept | --decline | "
                       "--approve): who asks, which vault, what accepting lets them see, the outcome to approve.";
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror pending", "Offers and relink requests waiting here."}};
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
                       "a completed mirror is refused (leave with the copy instead: vh mirror detach); an orphaned "
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
    cmd->description = "List the mirrored vaults here (this server's role, the linked server, the grant), the starts "
                       "in progress, and the vaults detached here (standalone now; the re-key pass is recommended). An "
                       "orphaned copy is one whose core ended the mirror while this server kept it, read-only: detach "
                       "it to keep it as this server's vault, or remove it with vh mirror cancel. Super admins only.";
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

std::shared_ptr<CommandUsage> save(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"save"};
    cmd->description = "Save the person's version of a held write (decrypted) to a local file; nothing in the vault "
                       "changes. Super admins only.";
    cmd->positionals = {heldPos, Positional::Alias("dest", "The local file to write, or - for stdout", "dest",
                                                   contract::gen::constant("-"))};
    cmd->examples = {{"vh mirror save 7 ./mine.txt", "Save held change 7's version as ./mine.txt."}};
    return cmd;
}

std::shared_ptr<CommandUsage> held(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"held"};
    cmd->description = "List the changes made here to a vault this server mirrors that its core refused (held: the "
                       "entry went back to the core's state and the change is kept, with the reason) or turned into a "
                       "conflict copy. Super admins only.";
    cmd->optional = {Optional::ManyToOne("vault", "One vault only (its number here)", {"vault"}, "vault")};
    cmd->optional_flags = {Flag::WithAliases("all", "Include the ones discarded or retried", {"all"}), jsonFlag};
    cmd->examples = {{"vh mirror held", "Held changes and conflict copies."},
                     {"vh mirror save 7 ./mine.txt", "Save the person's version of held write 7."}};
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

std::shared_ptr<CommandUsage> detach(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"detach"};
    cmd->description = "Leave a mirror with its files: a copy of another server's vault held here (live, stopped, "
                       "diverged, expired or orphaned; link up, down or gone) becomes a standalone vault on this server, "
                       "without asking the core, which is told when it is reachable. Nothing is deleted on either "
                       "server and no bucket is touched; changes made here and not yet confirmed become ordinary "
                       "changes; files whose contents never arrived stay listed, marked missing. --dry-run shows all of "
                       "that first (with --json, the list to export). The vault keeps the original's uid and keys "
                       "until the re-key pass runs. With --copy the held copy stays what it is (still a mirror, or "
                       "orphaned) and a new, separate vault is written from it in the background: a new uid, new "
                       "entry uids and its own new key, owned by --owner, with every folder, file and symlink, their "
                       "modes and modification times, and none of the trash, versions, shares or access rules; files "
                       "whose contents never arrived here are left out and listed. --copy --status shows its progress, "
                       "--copy --cancel stops it (the partial vault is removed). Super admins, or holders of "
                       "admin.mirror.detach; audited.";
    cmd->positionals = {vaultPos};
    cmd->optional = {Optional::ManyToOne("owner", "The new owner: a sign-in account here (default: you)", {"owner"},
                                         "user"),
                     Optional::ManyToOne("name", "With --copy: the new vault's name (default: \"<name> copy\")",
                                         {"name"}, "name")};
    cmd->optional_flags = {Flag::WithAliases("dry_run", "Show what detaching would give, and change nothing",
                                             {"dry-run", "preview"}),
                           Flag::WithAliases("copy", "Write a new, separate vault from the held copy instead, which "
                                                     "stays as it is", {"copy"}),
                           Flag::WithAliases("status", "With --copy: the newest copy's progress", {"status"}),
                           Flag::WithAliases("cancel", "With --copy: stop the running copy and remove its partial vault",
                                             {"cancel"}),
                           jsonFlag};
    cmd->examples = {{"vh mirror detach 5 --dry-run", "What detaching vault 5 would give, missing files included."},
                     {"vh mirror detach 5 --owner alice", "Detach vault 5; alice owns it here."},
                     {"vh mirror detach 5 --copy --name archive", "Write vault 5 into a new vault named archive."},
                     {"vh mirror detach 5 --copy --status", "How far the copy of vault 5 is."}};
    return cmd;
}

std::shared_ptr<CommandUsage> versions(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"versions"};
    cmd->description = "Whether this server keeps versions of what a vault's core replaces or deletes (a vault held "
                       "here as another server's mirror; off by default): before the core's change is applied here, "
                       "the file's prior version is kept, bounded by the limits (when turning it on, unset ones default "
                       "to the last 10 versions per file for 30 days; 0 is no limit of that kind). Read them with vh "
                       "recovery list|inspect. Super admins only; audited.";
    cmd->positionals = {vaultPos, Positional::Alias("state", "on or off", "state", contract::gen::constant("off"))};
    cmd->optional = {Optional::ManyToOne("keep_last", "Versions kept per file", {"keep-last"}, "n"),
                     Optional::ManyToOne("max_age_days", "Days a version is kept", {"max-age-days"}, "days"),
                     Optional::ManyToOne("quota_bytes", "Bytes the vault's versions may take", {"quota-bytes"}, "bytes")};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror versions 5 on", "Keep the last 10 versions of each file for 30 days."},
                     {"vh mirror versions 5 on --keep-last 3 --max-age-days 0", "Keep the last 3, however old."}};
    return cmd;
}

std::shared_ptr<CommandUsage> resync(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"resync"};
    cmd->description = "Start a copy that stopped (diverged, expired or stopped) over from its core's tree, without "
                       "making it again: files whose bytes are here already are not fetched; changes still pending, "
                       "this server's version of a file the core's replaces and anything the core's tree does not hold "
                       "are kept as held changes (vh mirror held). The link must be up. Super admins only; audited.";
    cmd->positionals = {vaultPos};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror resync 4", "Start vault 4's copy over from its core."}};
    return cmd;
}

std::shared_ptr<CommandUsage> switchCore(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"switch"};
    cmd->description = "Move a mirrored vault's core role to the other server by agreement, asked on either server: "
                       "the core stops taking changes (the vault is read-only on both servers for moments), the mirror "
                       "applies its last change with the same digest and nothing pending, then the roles swap in the "
                       "next term. The old core keeps the vault only through the new core's role for it (its link "
                       "policy or a per-vault role there): with none, the switch is refused unless --accept-no-access. "
                       "A switch that does not complete in time, or is refused, changes nothing and says why. Local "
                       "vaults only. Super admins only; audited.";
    cmd->positionals = {vaultPos};
    cmd->optional_flags = {Flag::WithAliases("accept_no_access", "Go ahead even though the old core would hold no role "
                                                                 "on the vault on its new core (its people could not "
                                                                 "read it there until one is set)",
                                             {"accept-no-access"}),
                           jsonFlag};
    cmd->examples = {{"vh mirror switch 4", "Swap vault 4's core and mirror; prints the role the old core keeps."},
                     {"vh mirror switch 4 --accept-no-access", "Swap them even though the old core keeps no role."}};
    return cmd;
}

std::shared_ptr<CommandUsage> takeover(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"takeover"};
    cmd->description = "On a mirror whose core is gone or cannot be reached: take over as the vault's core. This server "
                       "records the next term with itself as the core, the last change it applied from the old core as "
                       "the fork point and its tree then as the fork base; changes made here and still pending become "
                       "ordinary changes, held ones stay listed. The old core may hold changes this server never "
                       "received; they are merged when it returns. Refused while the core answers (use vh mirror "
                       "switch). Also the way out of a planned switch whose core never came back. Type the vault's name "
                       "with --confirm. Super admins, or holders of admin.mirror.takeover (Take over as core); audited.";
    cmd->positionals = {vaultPos};
    cmd->required = {Option::Single("confirm", "The vault's name, typed exactly", "confirm", "name")};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror takeover 4 --confirm photos", "Make this server vault 4's core while its core is gone."}};
    return cmd;
}

std::shared_ptr<CommandUsage> relink(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"relink", "reconnect"};
    cmd->description = "Mirror a vault again with a linked server that holds it too since a mirror between them ended "
                       "(detached, the core ended it or the servers were unlinked, an old core rejoining or forked after a "
                       "take over), and resolve how the two trees drifted. With --with alone: compare both trees by entry "
                       "and keep the result as a plan (counts, what refuses it, what each server gains and loses). "
                       "--keep this|theirs: the hard override, that server's tree wins everywhere. --review: compare and "
                       "list every drifted entry by path; --choose sets choices (uid=this|theirs|both|default, "
                       "kind:<kind>=..., all=...), --core and --default the rest, --apply carries the plan out. Nothing "
                       "is dropped: the losing versions are kept as held changes (vh mirror held) or conflict copies. "
                       "Type the vault's name with --confirm to apply. Both servers agree, each by a super admin: "
                       "comparing first asks the other server, whose super admin accepts (or declines) before anything "
                       "of its tree is shown (run the command again once they have); applying proposes the outcome "
                       "(which server becomes the core, the mode, what their vault gains and loses), which they approve "
                       "before anything changes on either server (it is then carried out on its own). On the other "
                       "server: --accept or --decline the request, --approve --confirm <name> the outcome (vh mirror "
                       "pending lists them). A request expires in a day; --discard cancels it. Super admins only; "
                       "audited on both servers.";
    cmd->positionals = {vaultPos};
    cmd->optional = {
        Optional::ManyToOne("with", "The linked server holding the vault too", {"with"}, "server"),
        Optional::ManyToOne("keep", "The hard override: this or theirs, whose tree wins everywhere", {"keep"}, "side")
            .withLiteralValues(),
        Optional::ManyToOne("choose", "Choices: uid=this|theirs|both|default, kind:<kind>=..., all=... (comma-separated)",
                            {"choose"}, "choices"),
        Optional::ManyToOne("core", "Which server becomes the core: this or theirs", {"core"}, "side"),
        Optional::ManyToOne("default", "The choice for entries left unset: this, theirs, both or core", {"default"},
                            "choice"),
        Optional::ManyToOne("show", "List the drifted entries of one kind (or all)", {"show"}, "kind"),
        Optional::ManyToOne("offset", "With --show or --review: skip this many entries", {"offset"}, "n"),
        Optional::ManyToOne("confirm", "The vault's name, typed exactly (to apply)", {"confirm"}, "name")};
    cmd->optional_flags = {Flag::WithAliases("review", "Compare and list the drifted entries to choose for each", {"review"}),
                           Flag::WithAliases("apply", "Carry the saved plan out", {"apply"}),
                           Flag::WithAliases("status", "The plan or the relink running, without comparing again",
                                             {"status"}),
                           Flag::WithAliases("discard", "End the relink here: the plan, or the request (the other "
                                             "server is told)", {"discard"}),
                           Flag::WithAliases("accept", "Asked by a linked server: let it compare its copy with this "
                                             "vault (names, places, hashes; no contents)", {"accept"}),
                           Flag::WithAliases("decline", "Asked by a linked server: decline its request or its outcome "
                                             "(nothing changes on either server)", {"decline"}),
                           Flag::WithAliases("approve", "Asked by a linked server: approve the outcome it proposes "
                                             "(with --confirm <name>)", {"approve"}),
                           jsonFlag};
    cmd->examples = {{"vh mirror relink 4 --with vps", "Compare vault 4 with vps's and keep the plan."},
                     {"vh mirror relink 4 --with vps --keep this --confirm photos", "This server's tree wins."},
                     {"vh mirror relink 4 --with vps --review", "Compare and list each drifted entry."},
                     {"vh mirror relink 4 --choose kind:changed_theirs=theirs,all=both", "Set choices in bulk."},
                     {"vh mirror relink 4 --apply --confirm photos", "Propose the plan; carried out once approved."},
                     {"vh mirror relink 7 --accept", "Asked by a linked server: let it compare."},
                     {"vh mirror relink 7 --approve --confirm photos", "Asked by a linked server: approve its outcome."}};
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


std::shared_ptr<CommandUsage> mirrorAll(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"mirror-all"};
    cmd->description = "On the core: whether this server mirrors every vault it owns to a linked server, new ones "
                       "included (off by default). Each vault that is not mirrored yet is offered, and each new one as "
                       "it is created; an offer that server declined is not made again. With accept-all on there it is "
                       "fully automatic. Super admins only; audited.";
    cmd->positionals = {peerPos, Positional::Alias("state", "on or off", "state", contract::gen::constant("off"))};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh mirror mirror-all vps on", "Mirror every vault of this server to \"vps\"."}};
    return cmd;
}

}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Mirrored Vault Commands";
    auto root = build(parent);
    root->aliases = {"mirror"};
    root->pluralAliasImpliesList = true;
    root->description = "Mirror a vault between this server and a linked one. One server is the vault's core; the other holds a copy and the vault's keys.";
    root->subcommands = {add(root->weak_from_this()),    pending(root->weak_from_this()), accept(root->weak_from_this()),
                         decline(root->weak_from_this()), cancel(root->weak_from_this()), list(root->weak_from_this()),
                         info(root->weak_from_this()),    acceptAll(root->weak_from_this()),
                         mirrorAll(root->weak_from_this()),
                         keep(root->weak_from_this()),    held(root->weak_from_this()),    discard(root->weak_from_this()),
                         retry(root->weak_from_this()), save(root->weak_from_this()), detach(root->weak_from_this()),
                         versions(root->weak_from_this()), resync(root->weak_from_this()),
                         switchCore(root->weak_from_this()), takeover(root->weak_from_this()),
                         relink(root->weak_from_this())};
    root->examples = {
        {"vh mirror add <vault> --to <server>", "On the core: offer a vault."},
        {"vh mirror pending", "On the other server: offers waiting."},
        {"vh mirror accept <offer>", "Accept one."},
    };
    book->root = root;
    return book;
}

}
