#include "usages.hpp"

using namespace vh::protocols::shell;

// `vh fs`: vault file access over the CLI socket (#229), for hosts where the vault isn't mounted (macOS: the server
// never mounts there, #262) or a script wants one file. The client moves the bytes (protocols/shell/Transfer.hpp);
// the daemon authorizes every path with the same evaluator as the web console's HTTP lanes. Finder access on macOS is
// Vaulthalla Desktop's (vaulthalla/desktop#1), not this command's; don't grow it into a second file API.
namespace vh::protocols::shell::fs_book {

static std::shared_ptr<CommandUsage> buildBaseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static const auto vaultPos = Positional::WithAliases("vault", "Vault ID, or name with --owner", {"id", "name"},
                                                     contract::gen::ref("vault", {"id", "name"}));
static const auto pathPos = Positional::Alias("path", "Path inside the vault (starting at /)", "path");
static const auto localPos = Positional::Alias(
    "local", "Local file to upload, read by vh (not the daemon); - reads standard input", "file");

static const auto owner = Optional::Multi("owner", "User ID or username of the vault owner (required if using name)",
                                          {"owner"}, {"id", "name"})
                             .withGen("id", contract::gen::ref("user", {"id"}))
                             .withGen("name", contract::gen::ref("user", {"name"}));
static const auto output = Optional::ManyToOne(
    "output", "Write to this local file (written by vh, atomically, only if the whole file arrived intact); - for stdout",
    {"output", "o"}, "file");
static const auto overwriteFlag = Flag::WithAliases(
    "overwrite", "Replace the file if it exists (needs the Overwrite permission on it)", {"overwrite"});

static std::shared_ptr<CommandUsage> lsCmd(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"ls", "list"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List a directory in a vault (or show one file). Needs the List permission on the path.";
    cmd->positionals = {vaultPos, pathPos};
    cmd->optional = {owner};
    cmd->examples = {
        {"vh fs ls 42 /", "List the top of vault 42."},
        {"vh fs ls photos /2026 --owner alice", "List /2026 in alice's vault named 'photos'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> getCmd(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"get", "download"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Download a file from a vault. Needs the Read permission on it. Without --output the bytes go "
                       "to stdout (not to a terminal unless you pass -o -). Exit status: 0 only if every byte "
                       "arrived and authenticated; 66 not found, 77 permission denied, 75 busy, 65 a damaged transfer.";
    cmd->positionals = {vaultPos, pathPos};
    cmd->optional = {owner, output};
    cmd->examples = {
        {"vh fs get 42 /reports/q3.pdf -o q3.pdf", "Download /reports/q3.pdf from vault 42 into ./q3.pdf."},
        {"vh fs get 42 /notes.txt -o -", "Print /notes.txt to stdout."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> putCmd(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"put", "upload"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Upload a local file into a vault, encrypted like a web upload. Needs the Write permission on "
                       "the path (missing folders are created); replacing an existing file needs --overwrite and the "
                       "Overwrite permission, and fails if the file changes meanwhile. Nothing is stored unless every "
                       "byte arrives. Put options after the positionals. Exit status: 73 if the path exists, 77 "
                       "permission denied, 66 the local file is missing, 75 busy.";
    cmd->positionals = {vaultPos, localPos, pathPos};
    cmd->optional = {owner};
    cmd->optional_flags = {overwriteFlag};
    cmd->examples = {
        {"vh fs put 42 ./q3.pdf /reports/q3.pdf", "Upload ./q3.pdf to /reports/q3.pdf in vault 42."},
        {"vh fs put 42 ./q3.pdf /reports/q3.pdf --overwrite", "Replace /reports/q3.pdf with ./q3.pdf."},
        {"vh fs put 42 - /logs/today.log", "Upload standard input."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"fs", "files"};
    cmd->description = "Read and write vault files without a mount (bytes travel over the vh socket): the CLI file "
                       "path on macOS, where the server never mounts vaults.";
    cmd->subcommands = {lsCmd(cmd->weak_from_this()), getCmd(cmd->weak_from_this()), putCmd(cmd->weak_from_this())};
    cmd->examples = {
        {"vh fs ls 42 /", "List the top of vault 42."},
        {"vh fs get 42 /a.txt -o a.txt", "Download a file."},
        {"vh fs put 42 ./a.txt /a.txt", "Upload a file."}
    };
    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "File Commands";
    book->root = base(parent);
    return book;
}

}
