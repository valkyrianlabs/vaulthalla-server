#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "identities/User.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/secrets/Manager.hpp"
#include "fs/ops/file.hpp"
#include <nlohmann/json.hpp>
#include "crypto/encryptors/GPG.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"

#include <fstream>
#include <paths.h>

using namespace vh;
using namespace vh::protocols::shell;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::fs::ops;

static std::vector<uint8_t> trimSecret(const std::vector<uint8_t>& secret) {
    auto start = secret.begin();
    while (start != secret.end() && std::isspace(*start)) ++start;
    auto end = secret.end();
    while (end != start && std::isspace(*(end - 1))) --end; // empty/all-whitespace input yields {} (no UB)
    return {start, end};
}

static CommandResult handle_secrets_set(const CommandCall& call) {
    const auto usage = resolveUsage({"secrets", "set"});
    validatePositionals(call, usage);

    const auto secretArg = call.positionals[0];
    const auto fileArg = call.positionals[1];

    if (secretArg == "db-password") {
        // Resealing alone only changed what the daemon *sends*; the PostgreSQL role kept its old password, so the
        // next daemon restart or pool reconnect failed authentication. The role password and the sealed copy have
        // to change together, and the running pool's connection string only changes on restart, so this is an
        // operator procedure, not an in-daemon operation.
        return invalid(
            "secrets set db-password: refusing to change only the sealed copy of the database password; the "
            "PostgreSQL role password must change with it or the daemon can no longer connect.\n"
            "To rotate the database password:\n"
            "  1. Set the new password on the role, e.g.  sudo -u postgres psql -c '\\password vaulthalla'\n"
            "  2. Hand the same password to the daemon:   write it to " VH_DB_PASSWORD_SEED_PATH "\n"
            "     (owner " VH_SERVICE_ACCOUNT ", mode 0600, single line)\n"
            "  3. Restart the daemon:                     sudo systemctl restart vaulthalla\n"
            "The daemon reseals the handed-off password with the TPM on startup and deletes the file.");
    }

    if (!std::filesystem::path(fileArg).is_absolute())
        return invalid("secrets set: the secret file path must be absolute (it is read by the vaulthalla daemon, "
                       "not in your current directory): " + fileArg);
    if (!std::filesystem::exists(fileArg)) return invalid("secrets set: file does not exist: " + fileArg);

    const auto secret = trimSecret(readFileToVector(fileArg));
    if (secret.empty()) return invalid("secrets set: secret file is empty: " + fileArg);

    if (secretArg == "jwt-secret") {
        runtime::Deps::get().secretsManager->setJWTSecret({secret.begin(), secret.end()});
        return ok("Successfully updated JWT secret");
    }

    return invalid("secrets set: unknown secret '" + std::string(secretArg) + "'. Valid secrets are: db-password, jwt-secret");
}

static CommandResult handle_secret_encrypt_and_response(const CommandCall& call,
                                                     const nlohmann::json& output,
                                                     const std::shared_ptr<CommandUsage>& usage) {
    const auto outputOpt = optVal(call, usage->resolveOptional("output")->option_tokens);

    if (const auto recipientOpt = optVal(call, usage->resolveOptional("recipient")->option_tokens)) {
        if (recipientOpt->empty()) return invalid("secrets export: --recipient requires a value");
        if (!outputOpt) return invalid("secrets export: --recipient requires --output to specify the output file");

        if (const auto pathError = secretOutputPathError(*outputOpt)) return invalid("secrets export: " + *pathError);

        try {
            writePrivateFile(*outputOpt, ""); // pre-create 0600 so gpg's output never exists with a looser mode
            vh::crypto::encryptors::GPG::encryptToFile(output, *recipientOpt, *outputOpt);
            restrictToOwner(*outputOpt);
            return ok("Secret successfully encrypted and saved to " + *outputOpt);
        } catch (const std::exception& e) {
            return invalid("secrets export: failed to encrypt secret: " + std::string(e.what()));
        }
    }

    if (outputOpt) {
        if (const auto pathError = secretOutputPathError(*outputOpt)) return invalid("secrets export: " + *pathError);
        log::Registry::audit()->warn(
            "[shell::handle_secret_encrypt_and_response] No recipient specified, saving unencrypted key(s) to " + *outputOpt);
        try {
            writePrivateFile(*outputOpt, output.dump(4)); // mode 0600, symlinks refused
            return {0, "secret(s) successfully saved to " + *outputOpt,
                    "\nWARNING: No recipient specified, key(s) are unencrypted.\n"
                    "\nConsider using --recipient with a GPG fingerprint to encrypt the key(s) before saving."};
        } catch (const std::exception& e) {
            return invalid("secrets export: failed to write to output file: " + std::string(e.what()));
        }
    }

    log::Registry::audit()->warn(
        "[shell::handle_secret_encrypt_and_response] No recipient specified, returning unencrypted key(s)");
    return {0, output.dump(4),
            "\nWARNING: No recipient specified, key(s) are unencrypted.\n"
            "\nConsider using --recipient with a GPG fingerprint along with --output\nto securely encrypt the key(s) to an output file."};
}

static nlohmann::json generateSecretOutput(const std::string& name, const std::vector<uint8_t>& secret) {
    return {
            {"name", name},
            {"secret", std::string(secret.begin(), secret.end())}
    };
}

static nlohmann::json generateSecretOutput(const std::string& name, const std::string& secret) {
    return {
            {"name", name},
            {"secret", secret}
    };
}

static nlohmann::json getDBPassword() {
    vh::crypto::secrets::KeyProvider tpm(vh::paths::testMode ? "test_psql" : "psql");
    tpm.init();
    return generateSecretOutput("db-password", tpm.getMasterKey());
}

static nlohmann::json getJWTSecret() {
    return generateSecretOutput("jwt-secret", runtime::Deps::get().secretsManager->jwtSecret());
}

static CommandResult handle_secrets_export(const CommandCall& call) {
    const auto usage = resolveUsage({"secrets", "export"});
    validatePositionals(call, usage);

    const auto secretArg = call.positionals[0];

    nlohmann::json out = nlohmann::json::array();

    if (secretArg == "db-password" || secretArg == "all") out.push_back(getDBPassword());
    if (secretArg == "jwt-secret" || secretArg == "all") out.push_back(getJWTSecret());

    if (out.empty()) return invalid("secrets export: unknown secret '" + std::string(secretArg) + "'. Valid secrets are: db-password, jwt-secret, all");
    return handle_secret_encrypt_and_response(call, out, usage);
}

static bool isSecretsMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"secrets", cmd}, input);
}

static CommandResult handle_secrets(const CommandCall& call) {
    if (!call.user->encryptionKeysPerms().canExport())
        return invalid("secrets export: insufficient permissions to export secrets. Requires encryption keys export permission.");

    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());

    const auto [sub, subcall] = descend(call);

    if (isSecretsMatch("set", sub)) return handle_secrets_set(subcall);
    if (isSecretsMatch("export", sub)) return handle_secrets_export(subcall);

    return invalid(call.constructFullArgs(), "Unknown secrets subcommand: '" + std::string(sub) + "'");
}

void commands::registerSecretsCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("secrets"), handle_secrets);
}
