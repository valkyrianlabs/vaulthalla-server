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

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"secrets", "secret"};
    cmd->description = "Manage internal secrets used by Vaulthalla.";

    // --- subcommands (define pointers) ---
    const auto setCmd       = set(cmd->weak_from_this());
    const auto exportCmd    = secret_export(cmd->weak_from_this());

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
        exportCmd
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
