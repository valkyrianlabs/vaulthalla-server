#include "usages.hpp"

using namespace vh::protocols::shell;

// `vh device ...`: paired devices (Vaulthalla Desktop) and the device listener's exposure.
namespace vh::protocols::shell::device_book {

namespace {

std::shared_ptr<CommandUsage> build(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

const auto devicePos = Positional::WithAliases(
    "device", "The device: its number from `vh device list`, its id, or the first 8+ characters of the id",
    {"device", "id"}, contract::gen::ref("device", {"id"}));

const auto requestPos = Positional::WithAliases("request", "The pairing request id (from `vh device pending`)",
                                                {"request", "request_id"},
                                                contract::gen::ref("device.pairing_request", {"request_id"}));

const auto codeOpt = Optional::ManyToOne("code", "The six-digit code the device shows (number matching)", {"code"},
                                         "code")
                         .withGen("code", contract::gen::ref("device.pairing_request", {"code"}));

std::shared_ptr<CommandUsage> pair(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"pair"};
    cmd->description = "Open a 10-minute pairing window for your account. Interactively, wait for a device and approve "
                       "it by the code it shows; otherwise approve with `vh device approve`. With --json, only open it "
                       "and print what a Desktop on this machine needs to pair (device port, node id, server key).";
    cmd->optional_flags = {Flag::WithAliases("close", "Close your pairing window instead", {"close"}),
                           Flag::WithAliases("any", "With --close: close whoever's window is open (super admins)",
                                             {"any"}),
                           Flag::WithAliases("json_output", "Open the window without waiting and print it as JSON",
                                             {"json", "j"})};
    cmd->examples = {
        {"vh device pair", "Open a pairing window, then pick the code your Mac shows when it asks to pair."},
        {"vh device pair --json", "Open the window without waiting and print its expiry, port, node id and server key "
                                  "as JSON (what Vaulthalla Desktop on this Mac reads to pair itself)."},
        {"vh device pair --close", "Close your pairing window; its requests expire."},
        {"vh device pair --close --any", "Close another user's pairing window (super admins)."},
    };
    return cmd;
}

std::shared_ptr<CommandUsage> pending(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"pending", "requests"};
    cmd->description = "List the devices waiting in your pairing window, each with three codes to choose from.";
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {{"vh device pending", "Show pairing requests waiting for your approval."},
                     {"vh device pending --json", "The same as JSON."}};
    return cmd;
}

std::shared_ptr<CommandUsage> approve(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"approve"};
    cmd->description = "Approve a pairing request with the code the device shows. Asks which of the three codes it "
                       "is; --code answers without asking. A wrong code denies the request.";
    cmd->positionals = {requestPos};
    cmd->optional = {codeOpt};
    cmd->examples = {{"vh device approve 7f3a9c1d2e4b6a80", "Approve after picking the code your Mac shows."},
                     {"vh device approve 7f3a9c1d2e4b6a80 --code 482913", "Approve non-interactively."}};
    return cmd;
}

std::shared_ptr<CommandUsage> deny(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"deny"};
    cmd->description = "Deny a pairing request; the device is told it was declined.";
    cmd->positionals = {requestPos};
    cmd->examples = {{"vh device deny 7f3a9c1d2e4b6a80", "Decline a pairing request."}};
    return cmd;
}

std::shared_ptr<CommandUsage> list(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Read;
    cmd->aliases = {"list", "ls"};
    cmd->description = "List your paired devices (revoked ones included); --all lists every user's (super admins).";
    cmd->optional_flags = {Flag::WithAliases("all", "Every user's devices (super admins only)", {"all", "a"}), jsonFlag};
    cmd->examples = {{"vh device list", "Your devices."},
                     {"vh devices", "The same (plural alias)."},
                     {"vh device list --all --json", "Every device on this node, as JSON."}};
    return cmd;
}

std::shared_ptr<CommandUsage> rename(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Write;
    cmd->aliases = {"rename"};
    cmd->description = "Rename a device.";
    cmd->positionals = {devicePos, Positional::Alias("name", "The new name (1-64 characters)", "name",
                                                     contract::gen::pattern("Mac {a}{a}{a}"))};
    cmd->examples = {{"vh device rename 3 \"Studio Mac\"", "Rename device 3."}};
    return cmd;
}

std::shared_ptr<CommandUsage> revoke(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->effect = CommandEffect::Destructive;
    cmd->aliases = {"revoke", "unpair"};
    cmd->description = "Unpair a device. Final: its open connections close now, and it has to pair again with a new "
                       "key.";
    cmd->positionals = {devicePos};
    cmd->examples = {{"vh device revoke 3", "Unpair device 3."},
                     {"vh device revoke 5cd252fb", "Unpair the device whose id starts with 5cd252fb."}};
    return cmd;
}

std::shared_ptr<CommandUsage> remote(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = build(parent);
    cmd->aliases = {"remote"};
    cmd->description = "Whether devices on other hosts may connect (super admins). Off by default: the device "
                       "listener then answers on loopback only.";

    auto status = build(cmd->weak_from_this());
    status->effect = CommandEffect::Read;
    status->aliases = {"status"};
    status->description = "Show where the device listener listens and the server key's pin.";
    status->optional_flags = {jsonFlag};
    status->examples = {{"vh device remote status", "Loopback only or every interface, and whether it listens."}};

    auto enable = build(cmd->weak_from_this());
    enable->effect = CommandEffect::Write;
    enable->aliases = {"enable", "on"};
    enable->description = "Let devices on other hosts connect: the listener rebinds to every interface now and stays "
                          "that way across restarts and upgrades.";
    enable->examples = {{"vh device remote enable", "Open the device listener (port 36972) to the network."}};

    auto disable = build(cmd->weak_from_this());
    disable->effect = CommandEffect::Destructive;
    disable->aliases = {"disable", "off"};
    disable->description = "Back to loopback only; device sessions from other hosts close.";
    disable->examples = {{"vh device remote disable", "Close the device listener to the network."}};

    cmd->subcommands = {status, enable, disable};
    cmd->examples = {{"vh device remote status", "Show the device listener's exposure."}};
    return cmd;
}

}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Device Commands";
    auto root = build(parent);
    root->aliases = {"device"};
    root->pluralAliasImpliesList = true;
    root->description = "Pair and manage devices (Vaulthalla Desktop). A paired device acts as your account, with "
                        "your permissions.";
    root->subcommands = {pair(root->weak_from_this()),    pending(root->weak_from_this()), approve(root->weak_from_this()),
                         deny(root->weak_from_this()),    list(root->weak_from_this()),    rename(root->weak_from_this()),
                         revoke(root->weak_from_this()),  remote(root->weak_from_this())};
    root->examples = {
        {"vh device pair", "Pair a Mac running Vaulthalla Desktop with your account."},
        {"vh device list", "Your paired devices."},
        {"vh device revoke 3", "Unpair device 3."},
        {"vh device remote enable", "Let devices on other hosts connect."},
    };
    book->root = root;
    return book;
}

}
