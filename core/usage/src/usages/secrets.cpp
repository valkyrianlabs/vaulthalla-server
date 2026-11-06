#include "usages.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::secrets {

static std::shared_ptr<CommandUsage> buildBaseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static const auto secretPos = Positional::WithAliases("secret", "Name of the secret (jwt-secret, db-password)", {"db-password", "jwt-secret"});
static const auto filePos = Positional::Alias("file", "Absolute path to a file containing the secret value (read by the daemon)", "path");

static std::shared_ptr<CommandUsage> set(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"update", "set", "modify", "edit"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Set or update an internal secret. db-password is refused: the PostgreSQL role password and the "
                       "sealed copy must change together (the command prints the rotation procedure).";
    cmd->positionals = { secretPos, filePos };
    cmd->examples = {
        {"vh secret set jwt-secret /var/lib/vaulthalla/jwt_secret.txt", "Set the JWT secret from the specified file."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> secret_export(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"export", "get", "download"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Export an internal secret (to stdout, or to an --output file the daemon writes: absolute path, mode 0600)";
    cmd->positionals = { secretPos };
    cmd->optional = { gpgRecipient, outputFile };
    cmd->examples = {
        {"vh secret export db-password --output /var/lib/vaulthalla/db_password.gpg --recipient ABCDEF1234567890",
         "Export the database password, GPG-encrypted, to the specified file."},
        {"vh secret export jwt-secret", "Print the JWT secret to stdout."}
    };
    return cmd;
}

// ---- vh secret master (#352): the versioned vault_master rewrap -------------------------------------------------

static const auto yesFlag = Flag::Alias("yes", "Don't ask for confirmation", "yes");

static std::shared_ptr<CommandUsage> master_status(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"status", "show"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show the vault master: its version, how it is sealed, and any rotation in progress (the version "
                       "being staged and how many key rows are staged) or recovery window (the previous version, until "
                       "when it is kept, how many rows still hold a retained wrap). Never shows key material.";
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {
        {"vh secret master status", "Show the vault master version and any rotation or recovery window."},
        {"vh secret master status --json", "The same, as JSON."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> master_rotate(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"rotate"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Replace the vault master that wraps every vault key, without re-encrypting any file. The new "
                       "master is sealed beside the current one, every key row (live, retired and deleted vaults' "
                       "retained keys) is rewrapped under it in batches and verified against its key check, then all "
                       "rows switch in one transaction. An interrupted rotation resumes where it stopped when run "
                       "again. The previous master is kept for a recovery window (default 7 days; vh secret master "
                       "rollback returns to it), then deleted. Super admins only; asks to confirm (--yes without a "
                       "terminal).";
    cmd->optional = {
        Optional::ManyToOne("window_hours", "Recovery window in hours (1 to 2160; default 168)",
                            {"window-hours", "window"}, "hours")
            .withGen("hours", contract::gen::intRange(1, 2160)),
        Optional::ManyToOne("batch", "Key rows per staging transaction (1 to 10000; default 200)", {"batch"}, "rows")
            .withGen("rows", contract::gen::intRange(1, 10000))};
    cmd->optional_flags = {yesFlag, jsonFlag};
    cmd->examples = {
        {"sudo vh secret master rotate", "Rotate the vault master with the default 7-day recovery window."},
        {"vh secret master rotate --window-hours 48 --yes", "Rotate with a 48-hour window, without asking."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> master_finalize(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"finalize"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "End the recovery window now: verify every key row under the current vault master, then delete "
                       "the previous master and the retained wraps. Irreversible; a rollback is no longer possible. "
                       "The window also ends by itself when it expires. Super admins only; asks to confirm.";
    cmd->optional_flags = {yesFlag, jsonFlag};
    cmd->examples = {{"vh secret master finalize", "Close the recovery window of the last rotation (asks to confirm)."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> master_rollback(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"rollback"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Inside the recovery window: return every vault key to the previous vault master (from the "
                       "retained wraps, verified first) and delete the newer one. While a rotation is still staging: "
                       "abandon it. Super admins only; asks to confirm.";
    cmd->optional_flags = {yesFlag, jsonFlag};
    cmd->examples = {{"vh secret master rollback", "Undo the last vault master rotation (asks to confirm)."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> master(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"master"};
    cmd->description = "Rotate the vault master: the installation secret that wraps every vault key (never file "
                       "contents). Super admins only.";
    cmd->examples = {
        {"vh secret master status", "Show the vault master version and any rotation in progress."},
        {"vh secret master rotate", "Rotate it (asks to confirm)."}
    };
    cmd->subcommands = {
        master_status(cmd->weak_from_this()),
        master_rotate(cmd->weak_from_this()),
        master_finalize(cmd->weak_from_this()),
        master_rollback(cmd->weak_from_this())
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"secrets", "secret"};
    cmd->description = "Manage internal secrets used by Vaulthalla.";

    // --- subcommands (define pointers) ---
    const auto setCmd       = set(cmd->weak_from_this());
    const auto exportCmd    = secret_export(cmd->weak_from_this());
    const auto masterCmd    = master(cmd->weak_from_this());

    const auto exportSingle = TestCommandUsage::Single(exportCmd);
    const auto setSingle    = TestCommandUsage::Single(setCmd);

    // --- examples ---
    cmd->examples = {
        {"vh secret set jwt-secret /var/lib/vaulthalla/jwt_secret.txt", "Set the JWT secret from the specified file."},
        {"vh secret export jwt-secret --output /var/lib/vaulthalla/jwt_secret.json", "Export the JWT secret to a 0600 file."}
    };

    // --- lifecycles ---
    setCmd->test_usage.lifecycle = { exportSingle };
    exportCmd->test_usage.setup = { setSingle };

    // --- finalize subcommands ---
    cmd->subcommands = {
        setCmd,
        exportCmd,
        masterCmd
    };

    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Secrets Commands";
    book->root = base(parent);
    return book;
}

}
