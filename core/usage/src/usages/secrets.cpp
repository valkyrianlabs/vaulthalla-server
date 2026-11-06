#include "usages.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::secrets {

static std::shared_ptr<CommandUsage> buildBaseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static const auto secretPos = Positional::WithAliases("secret", "Name of the secret (jwt-secret, db-password, mfa-seal, mfa-pepper)",
                                                      {"db-password", "jwt-secret", "mfa-seal", "mfa-pepper"});
static const auto exportSecretPos = Positional::WithAliases(
    "secret", "Name of the secret (jwt-secret, db-password, mfa-seal, mfa-pepper, all)",
    {"db-password", "jwt-secret", "mfa-seal", "mfa-pepper", "all"});
static const auto filePos = Positional::Alias("file", "Absolute path to a file containing the secret value (read by the daemon)", "path");

static const auto mfaRecoveryCode = Optional::Single(
    "code", "mfa-pepper only: one of your own recovery codes (used or unused, it is not spent); the imported key must "
            "reproduce its stored hash", "code", "recovery-code");
static const auto yesFlag = Flag::Alias("yes", "Don't ask for confirmation", "yes");

static std::shared_ptr<CommandUsage> set(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"update", "set", "modify", "edit"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Set or update an internal secret. db-password is refused: the PostgreSQL role password and the "
                       "sealed copy must change together (the command prints the rotation procedure). mfa-seal and "
                       "mfa-pepper import the file `vh secret export` wrote, on a host restored from a database backup "
                       "without its old state (super admins only, confirmed, audited): the key is checked against stored "
                       "TOTP seeds (mfa-seal) or against a recovery code of yours (mfa-pepper, --code), a key that does "
                       "not match or a host that already has a working key is refused, and the key is never printed.";
    cmd->positionals = { secretPos, filePos };
    cmd->optional = { mfaRecoveryCode };
    cmd->optional_flags = { yesFlag };
    cmd->examples = {
        {"vh secret set jwt-secret /var/lib/vaulthalla/jwt_secret.txt", "Set the JWT secret from the specified file."},
        {"vh secret set mfa-seal /root/mfa-seal.json", "Import the exported TOTP sealing key after a restore."},
        {"vh secret set mfa-pepper /root/mfa-pepper.json --code ABCDE-FGHJK",
         "Import the exported recovery code key, verified against one of your own recovery codes."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> secret_export(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"export", "get", "download"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Export an internal secret (to stdout, or to an --output file the daemon writes: absolute path, mode 0600). "
                       "mfa-seal (the key that seals TOTP seeds) and mfa-pepper (the key that hashes recovery codes) "
                       "are exported base64 once they exist; all exports every secret that exists";
    cmd->positionals = { exportSecretPos };
    cmd->optional = { gpgRecipient, outputFile };
    cmd->examples = {
        {"vh secret export db-password --output /var/lib/vaulthalla/db_password.gpg --recipient ABCDEF1234567890",
         "Export the database password, GPG-encrypted, to the specified file."},
        {"vh secret export jwt-secret", "Print the JWT secret to stdout."}
    };
    return cmd;
}

// ---- vh secret master (#352, #353): the versioned rewrap of the data-wrapping masters ---------------------------


static Optional slotOption(const bool allowAll) {
    return Optional::Single("slot",
                            allowAll ? "Which master: vault (vault_master, the default), api-keys (ak_master), "
                                       "s3-gateway (s3gw_master), or all"
                                     : "Which master: vault (vault_master, the default), api-keys (ak_master: provider "
                                       "API key secrets), s3-gateway (s3gw_master: S3 gateway credential secrets)",
                            "slot", "slot", "vault")
        .withGen("slot", allowAll ? contract::gen::oneOf({"vault", "api-keys", "s3-gateway", "all"})
                                  : contract::gen::oneOf({"vault", "api-keys", "s3-gateway"}));
}

static std::shared_ptr<CommandUsage> master_status(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"status", "show"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show a master secret (the vault master unless --slot says otherwise): its version, how it is "
                       "sealed, and any rotation in progress (the version being staged and how many rows are staged) "
                       "or recovery window (the previous version, until when it is kept, how many rows still hold a "
                       "retained wrap). Never shows key material.";
    cmd->optional = {slotOption(true)};
    cmd->optional_flags = {jsonFlag};
    cmd->examples = {
        {"vh secret master status", "Show the vault master version and any rotation or recovery window."},
        {"vh secret master status --slot all --json", "Every data-wrapping master, as JSON."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> master_rotate(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"rotate"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Replace a data-wrapping master without changing what it protects. --slot vault (default): the "
                       "vault master that wraps every vault key (no file is re-encrypted; every key row, live, retired "
                       "and deleted vaults' retained keys, is verified against its key check). --slot api-keys: the "
                       "master that wraps provider API key secrets and provider tokens. --slot s3-gateway: the master "
                       "that wraps S3 gateway credential secrets. The new master is sealed beside the current one, "
                       "every row is rewrapped under it in batches and verified, then all rows switch in one "
                       "transaction. An interrupted rotation resumes where it stopped when run again. The previous "
                       "master is kept for a recovery window (default 7 days; vh secret master rollback returns to it), "
                       "then deleted. Super admins only; asks to confirm (--yes without a terminal).";
    cmd->optional = {
        slotOption(false),
        Optional::ManyToOne("window_hours", "Recovery window in hours (1 to 2160; default 168)",
                            {"window-hours", "window"}, "hours")
            .withGen("hours", contract::gen::intRange(1, 2160)),
        Optional::ManyToOne("batch", "Key rows per staging transaction (1 to 10000; default 200)", {"batch"}, "rows")
            .withGen("rows", contract::gen::intRange(1, 10000))};
    cmd->optional_flags = {yesFlag, jsonFlag};
    cmd->examples = {
        {"sudo vh secret master rotate", "Rotate the vault master with the default 7-day recovery window."},
        {"vh secret master rotate --window-hours 48 --yes", "Rotate with a 48-hour window, without asking."},
        {"vh secret master rotate --slot api-keys", "Rotate the master that wraps provider API key secrets."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> master_finalize(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"finalize"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "End the recovery window now: verify every row under the current master (--slot, default vault), "
                       "then delete the previous master and the retained wraps. Irreversible; a rollback is no longer "
                       "possible. The window also ends by itself when it expires. Super admins only; asks to confirm.";
    cmd->optional = {slotOption(false)};
    cmd->optional_flags = {yesFlag, jsonFlag};
    cmd->examples = {{"vh secret master finalize", "Close the recovery window of the last rotation (asks to confirm)."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> master_rollback(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"rollback"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Inside the recovery window: return every row to the previous master (--slot, default vault; from "
                       "the retained wraps, verified first) and delete the newer one. While a rotation is still "
                       "staging: abandon it. Super admins only; asks to confirm.";
    cmd->optional = {slotOption(false)};
    cmd->optional_flags = {yesFlag, jsonFlag};
    cmd->examples = {{"vh secret master rollback", "Undo the last vault master rotation (asks to confirm)."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> master(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"master"};
    cmd->description = "Rotate a data-wrapping master: the vault master (every vault key; never file contents), the API "
                       "key master (provider API key secrets) or the S3 gateway master (gateway credential secrets). "
                       "Super admins only.";
    cmd->examples = {
        {"vh secret master status", "Show the vault master version and any rotation in progress."},
        {"vh secret master rotate", "Rotate the vault master (asks to confirm)."},
        {"vh secret master rotate --slot s3-gateway", "Rotate the S3 gateway master (asks to confirm)."}
    };
    cmd->subcommands = {
        master_status(cmd->weak_from_this()),
        master_rotate(cmd->weak_from_this()),
        master_finalize(cmd->weak_from_this()),
        master_rollback(cmd->weak_from_this())
    };
    return cmd;
}

// ---- vh secret jwt rotate, vh secret device-identity rotate (#353): rotation by regeneration ---------------------

static std::shared_ptr<CommandUsage> jwt_rotate(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"rotate"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Replace the JWT secret that signs every session with a fresh one. Everyone is signed out: every "
                       "refresh token is revoked and every live console connection closed, so every user signs in "
                       "again. Paired devices reconnect by themselves; share-link visitors keep their share sessions. "
                       "No rollback. Super admins only; asks to confirm (--yes without a terminal).";
    cmd->optional_flags = {yesFlag, jsonFlag};
    cmd->examples = {{"vh secret jwt rotate", "Sign everyone out with a fresh JWT secret (asks to confirm)."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> jwt(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"jwt"};
    cmd->description = "The JWT secret that signs sessions. Super admins only.";
    cmd->examples = {{"vh secret jwt rotate", "Rotate it: everyone signs in again (asks to confirm)."}};
    cmd->subcommands = {jwt_rotate(cmd->weak_from_this())};
    return cmd;
}

static std::shared_ptr<CommandUsage> device_identity_rotate(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"rotate"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Replace the device listener's identity (the TLS key every paired Desktop pins) with a fresh one. "
                       "Every paired device is revoked and disconnected and has to pair again with a new pairing code; "
                       "pairing requests in progress are dropped. No rollback: the old key is deleted. Super admins "
                       "only; asks to confirm (--yes without a terminal).";
    cmd->optional_flags = {yesFlag, jsonFlag};
    cmd->examples = {{"vh secret device-identity rotate", "Rotate it: every device pairs again (asks to confirm)."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> device_identity(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"device-identity"};
    cmd->description = "The device listener's identity (device_tls), pinned by every paired Desktop. Super admins only.";
    cmd->examples = {{"vh secret device-identity rotate", "Rotate it: every device pairs again (asks to confirm)."}};
    cmd->subcommands = {device_identity_rotate(cmd->weak_from_this())};
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
    const auto jwtCmd       = jwt(cmd->weak_from_this());
    const auto deviceCmd    = device_identity(cmd->weak_from_this());

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
        masterCmd,
        jwtCmd,
        deviceCmd
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
