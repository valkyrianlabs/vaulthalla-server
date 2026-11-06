#include "protocols/shell/commands/all.hpp"
#include "auth/stepup/StepUp.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "identities/User.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/secrets/Manager.hpp"
#include "auth/mfa/Keys.hpp"
#include "crypto/SecretBytes.hpp"
#include "crypto/util/encrypt.hpp"
#include "fs/ops/file.hpp"
#include <nlohmann/json.hpp>
#include <span>
#include "crypto/encryptors/GPG.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "ops/MasterSecrets.hpp"
#include "crypto/secrets/Versioned.hpp"
#include "protocols/shell/types.hpp"

#include <fmt/format.h>

#include <cctype>
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
        vh::auth::stepup::require(vh::auth::stepup::Family::Secrets);  // #359: host-exempt, never an agent
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

static nlohmann::json generateSecretOutput(const std::string& name, const std::span<const uint8_t> secret) {
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

// The MFA keys (#356) are raw bytes, exported base64. nullopt when the key was never created (no TOTP factor or
// recovery code batch yet). A stored key the master can't open throws: the export fails, nothing is replaced.
static std::optional<nlohmann::json> getMfaKey(const std::string& name, const char* key) {
    const auto& secrets = runtime::Deps::get().secretsManager;
    if (!secrets->hasSecret(key)) return std::nullopt;
    auto value = secrets->getSecret(key);
    if (!value) return std::nullopt;
    std::vector<uint8_t> bytes(value->begin(), value->end());
    vh::crypto::wipeSecret(*value);
    auto encoded = vh::crypto::util::b64_encode(bytes);
    vh::crypto::wipeSecret(bytes);
    nlohmann::json out{{"name", name}, {"encoding", "base64"}, {"secret", encoded}};
    vh::crypto::wipeSecret(encoded);
    return out;
}

static CommandResult handle_secrets_export(const CommandCall& call) {
    const auto usage = resolveUsage({"secrets", "export"});
    validatePositionals(call, usage);

    const auto secretArg = call.positionals[0];

    nlohmann::json out = nlohmann::json::array();

    if (secretArg == "db-password" || secretArg == "all") out.push_back(getDBPassword());
    if (secretArg == "jwt-secret" || secretArg == "all") out.push_back(getJWTSecret());
    for (const auto& [name, key] : {std::pair{"mfa-seal", vh::auth::mfa::keys::kSealName},
                                    std::pair{"mfa-pepper", vh::auth::mfa::keys::kPepperName}}) {
        if (secretArg != name && secretArg != "all") continue;
        if (auto mfaKey = getMfaKey(name, key)) out.push_back(std::move(*mfaKey));
        else if (secretArg == name)
            return invalid("secrets export: " + std::string(name) + " does not exist yet (it is created with the "
                           "first TOTP factor or recovery code batch)");
    }

    if (out.empty()) return invalid("secrets export: unknown secret '" + std::string(secretArg) + "'. Valid secrets are: db-password, jwt-secret, mfa-seal, mfa-pepper, all");
    vh::auth::stepup::require(vh::auth::stepup::Family::Secrets);  // #359: host-exempt, never an agent
    return handle_secret_encrypt_and_response(call, out, usage);
}

// ---- vh secret master (#352, #353) ----------------------------------------------------------------------------

namespace master_ops = vh::ops::master_secrets;
namespace master_slots = vh::crypto::secrets::versioned;

static bool isMasterMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"secrets", "master", cmd}, input);
}

static std::string iso(const std::optional<std::time_t>& t) {
    if (!t) return "-";
    std::tm tm{};
    gmtime_r(&*t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S UTC", &tm);
    return buf;
}

static std::string capitalized(std::string_view text) {
    std::string out(text);
    if (!out.empty()) out[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(out[0])));
    return out;
}

static std::string master_status_text(const crypto::secrets::rewrap::Status& s) {
    std::string out = fmt::format("{}: version {} ('{}'), {} sealing ({}){}\n", capitalized(master_slots::noun(s.slot)),
                                  s.state.version, master_slots::slotName(s.slot, s.state.version),
                                  crypto::secrets::KeyProvider::posture(), crypto::secrets::KeyProvider::backend(),
                                  s.current_sealed ? "" : " [NOT SEALED ON THIS HOST]");
    out += fmt::format("  rows:         {}", s.rows);
    for (const auto& [v, n] : s.by_master) out += fmt::format("  (version {}: {})", v, n);
    out += "\n";
    if (s.state.staging_version)
        out += fmt::format("  staging:      version {} since {}: {} of {} row(s) staged{}\n", *s.state.staging_version,
                           iso(s.state.staging_started_at), s.staged, s.rows,
                           s.staging_sealed ? "" : " (its master is not sealed yet)");
    if (s.state.previous_version)
        out += fmt::format("  recovery:     version {} kept until {} ({} row(s) with a retained wrap{}); "
                           "rollback or finalize\n",
                           *s.state.previous_version, iso(s.state.window_until), s.retained,
                           s.previous_sealed ? "" : "; ITS MASTER IS NO LONGER ON THIS HOST");
    if (!s.state.staging_version && !s.state.previous_version) out += "  rotation:     none in progress\n";
    if (!s.state.discard_versions.empty())
        out += fmt::format("  pending:      {} retired master slot(s) still to delete\n", s.state.discard_versions.size());
    return out;
}

// Runs a confirmable operation: asks in a terminal, else needs --yes.
template <class Fn>
static CommandResult runConfirmable(const CommandCall& call, const std::string& err, Fn&& fn) {
    const bool yes = hasFlag(call, "yes");
    try {
        try {
            return fn(yes);
        } catch (const ops::NeedsConfirmation& e) {
            if (!call.io) {
                noteConfirmationNeeded(e.code, {"--yes"});
                return invalid(err + ": " + e.what() + "\nRe-run in a terminal, or with --yes.");
            }
            if (!call.io->confirm(std::string(e.what()) + " [no]", true)) return invalid(err + ": cancelled; nothing was changed");
            return fn(true);
        }
    } catch (const ops::Error& e) {
        return invalid(err + ": " + e.what());
    } catch (const std::exception& e) {
        return {1, "", err + ": " + e.what()};
    }
}

// --slot vault|api-keys|s3-gateway (default vault); `all` only where allowAll (status).
static std::optional<std::vector<master_slots::Slot>> slotsOf(const CommandCall& call, const bool allowAll) {
    const auto value = optVal(call, "slot");
    if (!value) return std::vector{master_slots::Slot::VaultMaster};
    if (allowAll && *value == "all") return std::vector<master_slots::Slot>(master_slots::kSlots.begin(), master_slots::kSlots.end());
    if (const auto slot = master_slots::parse(*value)) return std::vector{*slot};
    return std::nullopt;
}

static CommandResult handle_secrets_master(const CommandCall& call) {
    // Changing which master wraps stored secrets is never an agent's decision (also excluded from MCP).
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const bool json = hasFlag(subcall, "json") || hasFlag(subcall, "j");
    const bool isStatus = isMasterMatch("status", sub);
    const auto slots = slotsOf(subcall, isStatus);
    if (!slots)
        return invalid(std::string("secret master: --slot is one of vault, api-keys, s3-gateway") +
                       (isStatus ? ", all" : ""));
    const auto slot = slots->front();

    if (isStatus) {
        try {
            if (slots->size() > 1) {
                nlohmann::json all = nlohmann::json::object();
                std::string text;
                for (const auto s : *slots) {
                    const auto st = master_ops::status(subcall.user, s);
                    all[std::string(master_slots::id(s))] = master_ops::toJson(st);
                    text += master_status_text(st);
                }
                return ok(json ? all.dump(4) : text);
            }
            const auto s = master_ops::status(subcall.user, slot);
            return ok(json ? master_ops::toJson(s).dump(4) : master_status_text(s));
        } catch (const ops::Error& e) {
            return invalid(std::string("secret master status: ") + e.what());
        }
    }
    const bool mutating = isMasterMatch("rotate", sub) || isMasterMatch("finalize", sub) || isMasterMatch("rollback", sub);
    if (mutating && AgentCallScope::active())
        return invalid("secret master: master secrets are rotated by a human at the terminal, never by an agent");

    const auto noun = std::string(master_slots::noun(slot));
    const auto slotFlag = slot == master_slots::Slot::VaultMaster ? std::string{} : " --slot " + std::string(master_slots::cliName(slot));
    if (isMasterMatch("rotate", sub)) {
        master_ops::RotateRequest req{.slot = slot};
        try {
            if (const auto h = optVal(subcall, "window-hours")) req.window = std::chrono::hours(std::stoul(*h));
            else if (const auto w = optVal(subcall, "window")) req.window = std::chrono::hours(std::stoul(*w));
            if (const auto b = optVal(subcall, "batch")) req.batch = static_cast<unsigned int>(std::stoul(*b));
        } catch (const std::exception&) {
            return invalid("secret master rotate: --window-hours and --batch take whole numbers");
        }
        return runConfirmable(subcall, "secret master rotate", [&](const bool yes) {
            req.confirmed = yes;
            const auto r = master_ops::rotate(subcall.user, req);
            if (json) return ok(master_ops::toJson(r).dump(4));
            return ok(fmt::format("{} rotated from version {} to {}: {} row(s) rewrapped and verified ({} staged now "
                                  "in {} batch(es){}, {} caught up at the switch). No protected value changed.\nThe "
                                  "previous master is kept until {}: `vh secret master rollback{}` returns to it, "
                                  "`vh secret master finalize{}` deletes it sooner.",
                                  capitalized(noun), r.from, r.to, r.rows, r.staged_now, r.batches,
                                  r.resumed ? ", resuming an interrupted rotation" : "", r.caught_up,
                                  iso(r.window_until), slotFlag, slotFlag));
        });
    }
    if (isMasterMatch("finalize", sub))
        return runConfirmable(subcall, "secret master finalize", [&](const bool yes) {
            const auto r = master_ops::finalize(subcall.user, slot, yes);
            if (json) return ok(master_ops::toJson(r).dump(4));
            if (!r.finalized)
                return ok(r.deleted.empty() ? std::string("No recovery window is open; nothing to finalize.")
                                            : fmt::format("No recovery window is open; deleted {} leftover retired "
                                                          "master slot(s).", r.deleted.size()));
            return ok(fmt::format("Finalized: {} row(s) verified under the current {}; version {} deleted.", r.rows,
                                  noun, *r.previous));
        });
    if (isMasterMatch("rollback", sub))
        return runConfirmable(subcall, "secret master rollback", [&](const bool yes) {
            const auto r = master_ops::rollback(subcall.user, slot, yes);
            if (json) return ok(master_ops::toJson(r).dump(4));
            if (r.kind == crypto::secrets::rewrap::RollbackResult::Kind::AbandonedStaging)
                return ok(fmt::format("Abandoned the staged {} version {}; version {} stays.", noun, r.from, r.to));
            return ok(fmt::format("Rolled back to {} version {}: {} row(s) restored from their retained wrap, {} "
                                  "rewrapped; version {} deleted.", noun, r.to, r.rows, r.rewrapped, r.from));
        });
    return invalid("secret master: unknown subcommand '" + std::string(sub) + "'. Use: status | rotate | finalize | rollback");
}

// ---- vh secret jwt rotate, vh secret device-identity rotate (#353) --------------------------------------------

static CommandResult handle_secrets_jwt(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (!isCommandMatch({"secrets", "jwt", "rotate"}, sub))
        return invalid("secret jwt: unknown subcommand '" + std::string(sub) + "'. Use: rotate");
    if (AgentCallScope::active())
        return invalid("secret jwt rotate: the JWT secret is rotated by a human at the terminal, never by an agent");
    const bool json = hasFlag(subcall, "json") || hasFlag(subcall, "j");
    return runConfirmable(subcall, "secret jwt rotate", [&](const bool yes) {
        const auto r = master_ops::rotateJwtSecret(subcall.user, yes);
        if (json) return ok(master_ops::toJson(r).dump(4));
        return ok(fmt::format("JWT secret rotated: {} refresh token(s) revoked, {} live session(s) ended. Everyone "
                              "signs in again.", r.refresh_tokens_revoked, r.sessions_ended));
    });
}

static CommandResult handle_secrets_device_identity(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (!isCommandMatch({"secrets", "device-identity", "rotate"}, sub))
        return invalid("secret device-identity: unknown subcommand '" + std::string(sub) + "'. Use: rotate");
    if (AgentCallScope::active())
        return invalid("secret device-identity rotate: the device identity is rotated by a human at the terminal, "
                       "never by an agent");
    const bool json = hasFlag(subcall, "json") || hasFlag(subcall, "j");
    return runConfirmable(subcall, "secret device-identity rotate", [&](const bool yes) {
        const auto r = master_ops::rotateDeviceIdentity(subcall.user, yes);
        if (json) return ok(master_ops::toJson(r).dump(4));
        return ok(fmt::format("Device identity rotated (version {} to {}); the new pin is SPKI sha256 {}.\n{} paired "
                              "device(s) revoked and {} connection(s) closed: each device pairs again with a new "
                              "pairing code.{}",
                              r.from, r.to, r.spki_sha256, r.devices_revoked, r.sessions_closed,
                              r.listener_updated ? "" : " The device listener presents the new identity when it starts."));
    });
}

static bool isSecretsMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"secrets", cmd}, input);
}

static CommandResult handle_secrets(const CommandCall& call) {
    // The master secret rotations have their own gate (super admins only, ops::master_secrets), checked there.
    if (!call.positionals.empty() && isSecretsMatch("master", call.positionals[0])) {
        const auto [_, subcall] = descend(call);
        return handle_secrets_master(subcall);
    }
    if (!call.positionals.empty() && isSecretsMatch("jwt", call.positionals[0])) {
        const auto [_, subcall] = descend(call);
        return handle_secrets_jwt(subcall);
    }
    if (!call.positionals.empty() && isSecretsMatch("device-identity", call.positionals[0])) {
        const auto [_, subcall] = descend(call);
        return handle_secrets_device_identity(subcall);
    }
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
