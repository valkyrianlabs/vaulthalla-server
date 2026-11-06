#include "ops/MfaKeys.hpp"

#include "audit/Trail.hpp"
#include "auth/mfa/Keys.hpp"
#include "auth/mfa/RecoveryCodes.hpp"
#include "auth/stepup/StepUp.hpp"
#include "crypto/SecretBytes.hpp"
#include "crypto/secrets/Dependents.hpp"
#include "crypto/secrets/Manager.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "identities/User.hpp"
#include "runtime/Deps.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <algorithm>
#include <string>
#include <vector>

namespace vh::ops::mfa_keys {

namespace {

namespace mk = vh::auth::mfa::keys;

const char* rowName(const Key key) { return key == Key::Seal ? mk::kSealName : mk::kPepperName; }
std::string action() { return "secrets.mfa_key.import"; }

void auditAs(const Actor& actor, const Key key, const vh::audit::Outcome outcome, nlohmann::json details,
             const std::string& message, const spdlog::level::level_enum level = spdlog::level::info) {
    details["key"] = std::string(cliName(key));
    vh::audit::record({.action = action(), .outcome = outcome,
                       .actor_id = actor ? std::optional<uint32_t>(actor->id) : std::nullopt,
                       .actor = actor ? actor->name() : std::string{}, .details = std::move(details)},
                      "[ops::mfa_keys] " + (actor ? actor->name() : std::string("?")) + " " + message, level);
}

// Never replace a key that works: a readable stored row (the right length) is the host's current key.
bool currentKeyReadable(const crypto::secrets::Manager& secrets, const Key key) {
    if (!secrets.hasSecret(rowName(key))) return false;
    try {
        auto stored = secrets.getSecret(rowName(key));
        if (!stored) return false;
        const bool usable = stored->size() == mk::kKeyBytes;
        crypto::wipeSecret(*stored);
        return usable;
    } catch (const std::exception&) {
        return false;
    }
}

struct SealCheck {
    std::size_t rows{}, opened{};
};

SealCheck checkSeal(const std::span<const uint8_t> key) {
    struct Row {
        uint32_t user{};
        std::string uuid;
        mk::SealedSecret sealed;
    };
    const auto rows = db::Transactions::exec("ops::mfa_keys::loadTotp", [](pqxx::work& txn) {
        std::vector<Row> out;
        for (const auto& r : txn.exec("SELECT user_id, factor_uuid::text, secret_sealed, secret_iv FROM totp_factors "
                                      "ORDER BY id"))
            out.push_back({r[0].as<uint32_t>(), r[1].as<std::string>(),
                           {db::encoding::from_hex_bytea(r[2].as<std::string>()),
                            db::encoding::from_hex_bytea(r[3].as<std::string>())}});
        return out;
    });
    SealCheck out{.rows = rows.size()};
    for (const auto& row : rows) {
        try {
            (void)mk::openTotpSecret(key, row.user, row.uuid, row.sealed);
            ++out.opened;
        } catch (const std::exception&) {
        }
    }
    return out;
}

struct PepperCheck {
    std::size_t rows{}, matched{};
};

PepperCheck checkPepper(const std::span<const uint8_t> key, const uint32_t userId, const std::string_view code) {
    const auto rows = db::Transactions::exec("ops::mfa_keys::countHashes", [](pqxx::work& txn) {
        return static_cast<std::size_t>(txn.exec("SELECT COUNT(*) FROM recovery_codes").one_field().as<long long>());
    });
    auto normalized = auth::mfa::recovery::normalize(code);
    if (!normalized)
        throw Invalid("--code is not a recovery code (ten letters and digits, like XXXXX-XXXXX)");
    const auto h = auth::mfa::recovery::hash(key, userId, *normalized);
    std::fill(normalized->begin(), normalized->end(), '\0');
    const auto matched = db::Transactions::exec("ops::mfa_keys::matchHash", [&](pqxx::work& txn) {
        return static_cast<std::size_t>(
            txn.exec("SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1 AND code_hash = $2",
                     pqxx::params{userId, db::encoding::to_hex_bytea(std::vector<uint8_t>(h.begin(), h.end()))})
                .one_field()
                .as<long long>());
    });
    return {rows, matched};
}

}

std::string_view cliName(const Key key) { return key == Key::Seal ? "mfa-seal" : "mfa-pepper"; }

ImportResult import(const Actor& actor, const Key which, const std::span<const uint8_t> key,
                    const std::string_view recoveryCode, const bool confirmed) {
    requireActor(actor);
    if (!actor->isSuperAdmin()) {
        auditAs(actor, which, vh::audit::Outcome::Denied, nlohmann::json::object(),
                "was refused " + action() + ": super admins only", spdlog::level::warn);
        throw Denied("only super admins can import the MFA keys");
    }

    const auto fail = [&](const std::string& code, const std::string& text) -> void {
        auditAs(actor, which, vh::audit::Outcome::Failure, {{"code", code}}, action() + " refused: " + text,
                spdlog::level::warn);
        throw Refused(code, text);
    };

    try {
        const auto name = std::string(cliName(which));
        if (key.size() != mk::kKeyBytes)
            throw Invalid(name + " must be exactly 32 bytes (the export's base64 secret)");
        const auto& deps = runtime::Deps::get();
        if (!deps.secretsManager) throw std::runtime_error("the secrets manager is not running");
        const auto& secrets = *deps.secretsManager;

        const auto dependents = which == Key::Seal ? crypto::secrets::dependents::mfaSeal()
                                                   : crypto::secrets::dependents::mfaPepper();
        const auto what = dependents();
        if (!what)
            fail("nothing_to_protect", "nothing is stored that " + name + " would protect (no " +
                                           (which == Key::Seal ? "TOTP factor" : "recovery code") +
                                           "); the key is created when it is first needed");
        if (currentKeyReadable(secrets, which))
            fail("key_already_works", "this host already has a readable " + name + "; a working key is never "
                                      "replaced. Export it with `vh secret export " + name + "` if you need a copy");

        std::size_t verified = 0, rows = 0;
        if (which == Key::Seal) {
            const auto c = checkSeal(key);
            rows = c.rows;
            verified = c.opened;
            if (verified == 0)
                fail("key_mismatch", "that key opens none of the " + std::to_string(rows) +
                                         " stored TOTP seed(s): it is not this database's mfa-seal. Nothing was changed");
        } else {
            if (recoveryCode.empty())
                throw Invalid("mfa-pepper is verified against a recovery code of yours: pass one with --code "
                              "(used or unused; it is not spent)");
            const auto c = checkPepper(key, actor->id, recoveryCode);
            rows = c.rows;
            verified = c.matched;
            if (verified == 0)
                fail("key_mismatch", "that key does not reproduce the stored hash of the recovery code you gave "
                                     "(wrong key, or not one of your codes). Nothing was changed");
        }

        if (!confirmed)
            throw NeedsConfirmation(
                (which == Key::Seal ? "mfa_seal_import" : "mfa_pepper_import"),
                fmt::format("{} verified against this database ({}). Adopting it seals it under this host's master "
                            "and makes {} usable again; it is only ever adopted while this host has no working {}. "
                            "Continue?",
                            name, which == Key::Seal ? fmt::format("{} of {} TOTP seed(s) open", verified, rows)
                                                     : std::string("a stored recovery code hash reproduced"),
                            which == Key::Seal ? "TOTP" : "recovery codes", name));
        auth::stepup::require(auth::stepup::Family::Secrets);  // #359: host-exempt, never an agent

        const bool replacedUnreadable = secrets.hasSecret(rowName(which));
        std::string text(key.begin(), key.end());
        try {
            secrets.setSecret(rowName(which), text);
        } catch (...) {
            crypto::wipeSecret(text);
            throw;
        }
        crypto::wipeSecret(text);
        auto back = secrets.getSecret(rowName(which));
        const bool same = back && back->size() == key.size() &&
                          std::equal(back->begin(), back->end(), key.begin(),
                                     [](const char a, const uint8_t b) { return static_cast<uint8_t>(a) == b; });
        if (back) crypto::wipeSecret(*back);
        if (!same) throw std::runtime_error(name + " did not read back identically after sealing");
        mk::resetForTesting();  // drop the cached (failed or older) state; the next use reads the adopted row

        auditAs(actor, which, vh::audit::Outcome::Success,
                {{"verified", verified}, {"rows", rows}, {"replaced_unreadable", replacedUnreadable}},
                fmt::format("imported {} ({} of {} verified)", name, verified, rows), spdlog::level::warn);
        return {.key = which, .verified = verified, .rows = rows, .replaced_unreadable = replacedUnreadable};
    } catch (const NeedsConfirmation&) {
        throw;
    } catch (const Refused&) {
        throw;
    } catch (const Error& e) {
        auditAs(actor, which, vh::audit::Outcome::Failure, {{"code", "invalid"}}, action() + " refused: " + e.what(),
                spdlog::level::warn);
        throw;
    } catch (const std::exception& e) {
        auditAs(actor, which, vh::audit::Outcome::Failure, {{"code", "fault"}}, action() + " failed: " + e.what(),
                spdlog::level::err);
        throw;
    }
}

}
