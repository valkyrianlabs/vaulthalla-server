#include "usages.hpp"

using namespace vh::protocols::shell;

// `vh peer ...`: linked servers (design/peers/link.md). Experimental and off by default (peers.experimental).
namespace vh::protocols::shell::peer_book {

namespace {

std::shared_ptr<CommandUsage> build(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

const auto peerPos = Positional::WithAliases(
    "peer", "The linked server: its number from `vh peer list`, its node id, its name, or 8+ hex digits of its key",
    {"peer", "id"}, contract::gen::pattern("{9}"));

const auto requestPos = Positional::WithAliases("request", "The link request id (from `vh peer pending`)",
                                                {"request", "request_id"}, contract::gen::pattern("{a}{a}{a}{a}{9}{9}"));

const auto fingerprintOpt = Optional::ManyToOne(
    "fingerprint", "The other server's key (its SPKI SHA-256, 64 hex digits): refuse any other", {"fingerprint"},
    "hex");

std::shared_ptr<CommandUsage> pair(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"pair"};
    cmd->description = "Open a 10-minute window for linking another server to this one, and print this server's "
                       "address, node id and key. Interactively, wait for the other server (`vh peer link` there) and "
                       "pick the code it shows; otherwise approve with `vh peer approve`. Super admins only.";
    cmd->optional_flags = {Flag::WithAliases("close", "Close your window instead", {"close"}),
                           Flag::WithAliases("json_output", "Open the window without waiting and print it as JSON",
                                             {"json", "j"})};
    cmd->examples = {
        {"vh peer pair", "Open a window, then pick the code the other server shows when it asks to link."},
        {"vh peer pair --json", "Open the window and print its expiry, endpoints, node id and key as JSON."},
        {"vh peer pair --close", "Close your window; its requests expire."},
    };
    return cmd;
}

std::shared_ptr<CommandUsage> pending(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"pending", "requests"};
    cmd->description = "List the servers waiting in your window to be linked, each with three codes to choose from.";
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh peer pending", "Show link requests waiting for your approval."}};
    return cmd;
}

std::shared_ptr<CommandUsage> approve(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"approve"};
    cmd->description = "Approve a link request with the code the other server shows. Asks which of the three codes it "
                       "is; --code answers without asking. A wrong code denies the request. --fingerprint also "
                       "requires the requesting server's key to be that one.";
    cmd->positionals = {requestPos};
    cmd->optional = {Optional::ManyToOne("code", "The six-digit code the other server shows", {"code"}, "code"),
                     fingerprintOpt};
    cmd->examples = {{"vh peer approve 7f3a9c1d2e4b6a80 --code 482913", "Approve non-interactively."}};
    return cmd;
}

std::shared_ptr<CommandUsage> deny(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"deny"};
    cmd->description = "Decline a link request.";
    cmd->positionals = {requestPos};
    cmd->examples = {{"vh peer deny 7f3a9c1d2e4b6a80", "Decline a link request."}};
    return cmd;
}

std::shared_ptr<CommandUsage> link(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"link"};
    cmd->description = "Link this server with the one at <address> (host, host:port or [v6]:port; the device port "
                       "36972 by default), whose super admin has run `vh peer pair`. Shows a six-digit code to pick "
                       "there and waits for the decision; with --json it prints the code and returns while the link "
                       "waits (`vh peer list` shows it once approved). --fingerprint refuses any key but that one.";
    cmd->positionals = {Positional::Alias("address", "Where the other server's device listener is", "address",
                                          contract::gen::constant("127.0.0.1:36972"))};
    cmd->optional = {fingerprintOpt};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {
        {"vh peer link vps.example.net", "Link with the server at vps.example.net (port 36972)."},
        {"vh peer link 10.0.0.5:36972 --fingerprint 5cd2...", "The same, refusing any key but the given one."},
    };
    return cmd;
}

std::shared_ptr<CommandUsage> list(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"list", "ls"};
    cmd->description = "List the linked servers and each link's health; --all includes unlinked ones.";
    cmd->optional_flags = {Flag::WithAliases("all", "Unlinked servers too", {"all", "a"}), jsonFlag};
    cmd->examples = {{"vh peer list", "Linked servers, connected or not."},
                     {"vh peers", "The same (plural alias)."}};
    return cmd;
}

std::shared_ptr<CommandUsage> info(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"info", "show"};
    cmd->description = "Show one linked server: its key, keys, endpoints and the link's health.";
    cmd->positionals = {peerPos};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh peer info 1", "Show linked server 1."}};
    return cmd;
}

std::shared_ptr<CommandUsage> rename(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"rename"};
    cmd->description = "Rename a linked server here (the other server keeps its own name for this one).";
    cmd->positionals = {peerPos, Positional::Alias("name", "The new name (1-64 characters)", "name",
                                                   contract::gen::pattern("vps-{a}{a}{a}"))};
    cmd->examples = {{"vh peer rename 1 vps", "Call linked server 1 \"vps\"."}};
    return cmd;
}

std::shared_ptr<CommandUsage> unlink(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Destructive;
    cmd->aliases = {"unlink"};
    cmd->description = "Unlink a server: its key is refused from now on, its connections close, and it is told if it "
                       "is connected. Linking it again needs a new pairing.";
    cmd->positionals = {peerPos};
    cmd->examples = {{"vh peer unlink 1", "Unlink server 1."}};
    return cmd;
}

}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Linked Server Commands";
    auto root = build(parent);
    root->aliases = {"peer"};
    root->pluralAliasImpliesList = true;
    root->description = "Link this server with other Vaulthalla servers (experimental; peers.experimental in "
                        "config.yaml). A linked server is its own kind of principal: it never acts as a user.";
    root->subcommands = {pair(root->weak_from_this()),   pending(root->weak_from_this()), approve(root->weak_from_this()),
                         deny(root->weak_from_this()),   link(root->weak_from_this()),    list(root->weak_from_this()),
                         info(root->weak_from_this()),   rename(root->weak_from_this()),  unlink(root->weak_from_this())};
    root->examples = {
        {"vh peer pair", "On one server: open a window for the other."},
        {"vh peer link <address>", "On the other: link with it, then compare the codes."},
        {"vh peer list", "Linked servers and their health."},
    };
    book->root = root;
    return book;
}

}
