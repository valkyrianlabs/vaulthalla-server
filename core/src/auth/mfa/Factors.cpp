#include "auth/mfa/Factors.hpp"

#include "audit/Trail.hpp"
#include "auth/mfa/Keys.hpp"
#include "auth/mfa/RecoveryCodes.hpp"
#include "auth/mfa/Totp.hpp"
#include "auth/session/Assurance.hpp"
#include "crypto/SecretBytes.hpp"
#include "crypto/util/uuid.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "log/Registry.hpp"
#include "notifications/AccountSecurity.hpp"
#include "ops/Error.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdint>
#include <format>
#include <string>

namespace vh::auth::mfa {

namespace {

using db::encoding::from_hex_bytea;
using db::encoding::to_hex_bytea;

constexpr std::size_t kMfaLabelMaxChars = 64;
constexpr const char* kTotpEnrollmentLive = "created_at > NOW() - interval '10 minutes'";
static_assert(kTotpEnrollmentTtl == std::chrono::minutes(10), "kTotpEnrollmentLive spells the TTL out in SQL");

constexpr const char* kCredentialColumns =
    "id, user_id, credential_id, public_key_cose, cose_alg, rp_id, aaguid::text, sign_count, backup_eligible, "
    "backup_state, discoverable, array_to_string(transports, ','), attestation_fmt, label, created_during_recovery, "
    "EXTRACT(EPOCH FROM created_at)::BIGINT, EXTRACT(EPOCH FROM last_used_at)::BIGINT, "
    "EXTRACT(EPOCH FROM suspended_at)::BIGINT, suspended_reason, EXTRACT(EPOCH FROM disabled_at)::BIGINT";

// 1..64 characters (code points), no control characters.
std::string mfaLabel(const std::string_view label) {
    std::size_t chars = 0;
    for (const unsigned char c : label) {
        if (c < 0x20 || c == 0x7f) throw ops::Invalid("a factor label can't contain control characters");
        if ((c & 0xc0) != 0x80) ++chars;
    }
    if (chars == 0 || chars > kMfaLabelMaxChars) throw ops::Invalid("a factor label is 1 to 64 characters");
    return std::string(label);
}

bool mfaCanonicalUuid(const std::string_view s) {
    if (s.size() != 36) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? s[i] != '-' : !(std::isdigit(static_cast<unsigned char>(s[i])) || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    }
    return true;
}

std::vector<std::string> mfaSplitList(const std::string& joined) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start < joined.size()) {
        const auto comma = joined.find(',', start);
        const auto end = comma == std::string::npos ? joined.size() : comma;
        if (end > start) out.emplace_back(joined.substr(start, end - start));
        start = end + 1;
    }
    return out;
}

void recordMfa(const char* action, const vh::audit::Outcome outcome, const uint32_t userId, nlohmann::json details,
               const std::string& message) {
    vh::audit::record({.action = action, .outcome = outcome, .actor_id = userId, .details = std::move(details)},
                      "[auth::mfa] user " + std::to_string(userId) + " " + message,
                      outcome == vh::audit::Outcome::Success || outcome == vh::audit::Outcome::Info ? spdlog::level::info
                                                                                            : spdlog::level::warn);
}

// Design 7.2: every factor change notifies the account (a suspension, a possible clone, the security recipients too).
void noticeFactor(const uint32_t userId, const char* event, std::string title, std::string summary,
                  const bool toSecurity = false) {
    notifications::account::send({.event = event, .title = std::move(title), .summary = std::move(summary),
                                  .user_id = userId,
                                  .advice = "If this wasn't you, sign in and review Account > Security now, or ask an "
                                            "administrator to reset this account's MFA.",
                                  .severity = toSecurity ? "warning" : "info", .to_security = toSecurity});
}

const char* factorTable(const FactorKind kind) {
    return kind == FactorKind::WebAuthn ? "webauthn_credentials" : "totp_factors";
}

WebAuthnCredential credentialFrom(const pqxx::row_ref r) {
    WebAuthnCredential c;
    c.id = r[0].as<uint32_t>();
    c.user_id = r[1].as<uint32_t>();
    c.credential_id = from_hex_bytea(r[2].as<std::string>());
    c.public_key_cose = from_hex_bytea(r[3].as<std::string>());
    c.cose_alg = r[4].as<int>();
    c.rp_id = r[5].as<std::string>();
    c.aaguid = r[6].as<std::optional<std::string>>();
    c.sign_count = r[7].as<int64_t>();
    c.backup_eligible = r[8].as<bool>();
    c.backup_state = r[9].as<bool>();
    c.discoverable = r[10].as<std::optional<bool>>();
    c.transports = mfaSplitList(r[11].as<std::string>());
    c.attestation_fmt = r[12].as<std::string>();
    c.label = r[13].as<std::string>();
    c.created_during_recovery = r[14].as<bool>();
    c.created_at = r[15].as<int64_t>();
    c.last_used_at = r[16].as<std::optional<int64_t>>();
    c.suspended_at = r[17].as<std::optional<int64_t>>();
    c.suspended_reason = r[18].as<std::optional<std::string>>();
    c.disabled_at = r[19].as<std::optional<int64_t>>();
    return c;
}

Factor factorFrom(const WebAuthnCredential& c) {
    return {.id = c.id,
            .kind = FactorKind::WebAuthn,
            .label = c.label,
            .created_at = c.created_at,
            .last_used_at = c.last_used_at,
            .backup_eligible = c.backup_eligible,
            .backup_state = c.backup_state,
            .transports = c.transports,
            .aaguid = c.aaguid,
            .suspended = c.suspended_at.has_value(),
            .created_during_recovery = c.created_during_recovery};
}

// id, label, created_at, last_used_at, created_during_recovery
Factor totpFactorFrom(const pqxx::row_ref r) {
    return {.id = r[0].as<uint32_t>(),
            .kind = FactorKind::Totp,
            .label = r[1].as<std::string>(),
            .created_at = r[2].as<int64_t>(),
            .last_used_at = r[3].as<std::optional<int64_t>>(),
            .created_during_recovery = r[4].as<bool>()};
}

struct SealedTotpRow {
    uint32_t id{};
    std::string factor_uuid{};
    keys::SealedSecret sealed{};
    int64_t last_step{};
};

// id, factor_uuid, secret_sealed, secret_iv, last_step
SealedTotpRow sealedTotpFrom(const pqxx::row_ref r) {
    return {.id = r[0].as<uint32_t>(),
            .factor_uuid = r[1].as<std::string>(),
            .sealed = {.ciphertext = from_hex_bytea(r[2].as<std::string>()),
                       .iv = from_hex_bytea(r[3].as<std::string>())},
            .last_step = r[4].as<int64_t>()};
}

// The factor's seed, or nullopt when its row doesn't open under mfa_seal (logged: a tampered or moved row).
std::optional<crypto::SecretBytes> openTotpRow(const keys::Key& key, const uint32_t userId, const SealedTotpRow& row) {
    try {
        return keys::openTotpSecret(key->bytes(), userId, row.factor_uuid, row.sealed);
    } catch (const std::exception& e) {
        log::Registry::crypto()->error("[auth::mfa] TOTP factor {} of user {} does not open: {}", row.id, userId,
                                       e.what());
        return std::nullopt;
    }
}

std::size_t unusedCodes(pqxx::work& txn, const std::string& batchId) {
    return txn.exec("SELECT COUNT(*) FROM recovery_codes WHERE batch_id = $1::uuid AND used_at IS NULL",
                    pqxx::params{batchId}).one_field().as<std::size_t>();
}

void wipeString(std::string& s) noexcept { crypto::wipeSecret(s); }

}

std::string_view to_string(const FactorKind kind) noexcept {
    return kind == FactorKind::WebAuthn ? "webauthn" : "totp";
}

void to_json(nlohmann::json& j, const Factor& f) {
    j = {{"id", f.id},
         {"kind", to_string(f.kind)},
         {"label", f.label},
         {"created_at", f.created_at},
         {"last_used_at", f.last_used_at ? nlohmann::json(*f.last_used_at) : nlohmann::json(nullptr)},
         {"suspended", f.suspended},
         {"created_during_recovery", f.created_during_recovery}};
    if (f.kind == FactorKind::WebAuthn) {
        j["backup_eligible"] = f.backup_eligible.value_or(false);
        j["backup_state"] = f.backup_state.value_or(false);
        j["transports"] = f.transports;
        j["aaguid"] = f.aaguid ? nlohmann::json(*f.aaguid) : nlohmann::json(nullptr);
    }
}

TotpEnrollment::~TotpEnrollment() {
    wipeString(secret_base32);
    wipeString(otpauth_uri);
}

RecoveryBatch::~RecoveryBatch() {
    for (auto& code : codes) wipeString(code);
}

// ---- the account's MFA row

UserMfa ensureUser(const uint32_t userId) {
    const auto handle = crypto::SecretBytes::random(32);
    const std::vector<uint8_t> handleBytes(handle.bytes().begin(), handle.bytes().end());
    db::Transactions::exec("auth::mfa::ensureUser", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO user_mfa (user_id, webauthn_user_handle) VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING",
                 pqxx::params{userId, to_hex_bytea(handleBytes)});
    });
    auto state = userState(userId);
    if (!state) throw std::runtime_error("user_mfa row missing after insert");
    return std::move(*state);
}

std::optional<UserMfa> userState(const uint32_t userId) {
    return db::Transactions::exec("auth::mfa::userState", [&](pqxx::work& txn) -> std::optional<UserMfa> {
        const auto res = txn.exec("SELECT webauthn_user_handle, required, "
                                  "EXTRACT(EPOCH FROM recovery_cooldown_until)::BIGINT, "
                                  "EXTRACT(EPOCH FROM reset_at)::BIGINT FROM user_mfa WHERE user_id = $1",
                                  pqxx::params{userId});
        if (res.empty()) return std::nullopt;
        const auto r = res.one_row();
        return UserMfa{.user_id = userId,
                       .webauthn_user_handle = from_hex_bytea(r[0].as<std::string>()),
                       .required = r[1].as<bool>(),
                       .recovery_cooldown_until = r[2].as<std::optional<int64_t>>(),
                       .reset_at = r[3].as<std::optional<int64_t>>()};
    });
}

int64_t startRecoveryCooldown(const uint32_t userId, const std::chrono::hours duration) {
    (void)ensureUser(userId);
    return db::Transactions::exec("auth::mfa::startRecoveryCooldown", [&](pqxx::work& txn) {
        return txn.exec("UPDATE user_mfa SET recovery_cooldown_until = GREATEST(COALESCE(recovery_cooldown_until, "
                        "NOW()), NOW() + make_interval(hours => $2)) WHERE user_id = $1 "
                        "RETURNING EXTRACT(EPOCH FROM recovery_cooldown_until)::BIGINT",
                        pqxx::params{userId, static_cast<int>(duration.count())}).one_field().as<int64_t>();
    });
}

void setRequired(const uint32_t userId, const bool required) {
    (void)ensureUser(userId);
    db::Transactions::exec("auth::mfa::setRequired", [&](pqxx::work& txn) {
        txn.exec("UPDATE user_mfa SET required = $2 WHERE user_id = $1", pqxx::params{userId, required});
    });
    session::assurance::policyChanged();
}

std::vector<Factor> factors(const uint32_t userId) {
    std::vector<Factor> out;
    for (const auto& c : webAuthnCredentials(userId)) out.push_back(factorFrom(c));
    db::Transactions::exec("auth::mfa::factors", [&](pqxx::work& txn) {
        for (const auto& r : txn.exec("SELECT id, label, EXTRACT(EPOCH FROM created_at)::BIGINT, "
                                      "EXTRACT(EPOCH FROM last_used_at)::BIGINT, created_during_recovery "
                                      "FROM totp_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL "
                                      "AND disabled_at IS NULL ORDER BY created_at, id",
                                      pqxx::params{userId}))
            out.push_back(totpFactorFrom(r));
    });
    std::ranges::stable_sort(out, [](const Factor& a, const Factor& b) { return a.created_at < b.created_at; });
    return out;
}

bool hasUsableFactor(const uint32_t userId) {
    return db::Transactions::exec("auth::mfa::hasUsableFactor", [&](pqxx::work& txn) {
        return txn.exec("SELECT EXISTS (SELECT 1 FROM totp_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL "
                        "AND disabled_at IS NULL) OR EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id = $1 "
                        "AND suspended_at IS NULL AND disabled_at IS NULL)",
                        pqxx::params{userId}).one_field().as<bool>();
    });
}

bool renameFactor(const uint32_t userId, const FactorKind kind, const uint32_t id, const std::string_view label) {
    const auto clean = mfaLabel(label);
    const auto confirmed = kind == FactorKind::Totp ? " AND confirmed_at IS NOT NULL" : "";
    const bool renamed = db::Transactions::exec("auth::mfa::renameFactor", [&](pqxx::work& txn) {
        return txn.exec(std::string("UPDATE ") + factorTable(kind) + " SET label = $3 WHERE id = $2 AND user_id = $1 "
                        "AND disabled_at IS NULL" + confirmed,
                        pqxx::params{userId, id, clean}).affected_rows() == 1;
    });
    if (renamed)
        recordMfa("auth.mfa.factor.rename", vh::audit::Outcome::Success, userId,
                  {{"factor_id", id}, {"kind", to_string(kind)}},
                  "renamed " + std::string(to_string(kind)) + " factor " + std::to_string(id));
    if (renamed) noticeFactor(userId, "mfa.factor.rename", "Sign-in factor renamed",
                              "A passkey or authenticator app on this account was renamed.");
    return renamed;
}

bool removeFactor(const uint32_t userId, const FactorKind kind, const uint32_t id) {
    const bool removed = db::Transactions::exec("auth::mfa::removeFactor", [&](pqxx::work& txn) {
        return txn.exec(std::string("UPDATE ") + factorTable(kind) + " SET disabled_at = NOW() WHERE id = $2 "
                        "AND user_id = $1 AND disabled_at IS NULL",
                        pqxx::params{userId, id}).affected_rows() == 1;
    });
    if (removed) {
        session::assurance::policyChanged();
        recordMfa("auth.mfa.factor.remove", vh::audit::Outcome::Success, userId,
                  {{"factor_id", id}, {"kind", to_string(kind)}},
                  "removed " + std::string(to_string(kind)) + " factor " + std::to_string(id));
        noticeFactor(userId, "mfa.factor.remove", "Sign-in factor removed",
                     "A passkey or authenticator app was removed from this account; it can't sign in any more.");
    }
    return removed;
}

// ---- TOTP

TotpEnrollment startTotp(const uint32_t userId, const TotpStart& request) {
    const auto label = mfaLabel(request.label);
    if (request.account.empty() || request.issuer.empty()) throw ops::Invalid("TOTP enrollment needs an account name");

    const auto key = keys::seal();
    const auto secret = totp::generateSecret();
    const auto factorUuid = crypto::util::uuid4_hex();
    const auto sealed = keys::sealTotpSecret(key->bytes(), userId, factorUuid, secret.bytes());

    TotpEnrollment out;
    db::Transactions::exec("auth::mfa::startTotp", [&](pqxx::work& txn) {
        // One enrollment in flight per account: a new start replaces the unconfirmed one.
        txn.exec("DELETE FROM totp_factors WHERE user_id = $1 AND confirmed_at IS NULL", pqxx::params{userId});
        const auto r = txn.exec("INSERT INTO totp_factors (factor_uuid, user_id, label, secret_sealed, secret_iv, "
                                "created_during_recovery) VALUES ($1::uuid, $2, $3, $4, $5, $6) "
                                "RETURNING id, EXTRACT(EPOCH FROM created_at + interval '10 minutes')::BIGINT",
                                pqxx::params{factorUuid, userId, label, to_hex_bytea(sealed.ciphertext),
                                             to_hex_bytea(sealed.iv), request.during_recovery})
                            .one_row();
        out.factor_id = r[0].as<uint32_t>();
        out.expires_at = r[1].as<int64_t>();
    });
    out.secret_base32 = totp::base32(secret.bytes());
    out.otpauth_uri = totp::otpauthUri(request.issuer, request.account, out.secret_base32);
    log::Registry::auth()->info("[auth::mfa] user {} started TOTP enrollment (factor {})", userId, out.factor_id);
    return out;
}

std::optional<Factor> confirmTotp(const uint32_t userId, const uint32_t factorId, const std::string_view code,
                                  const std::chrono::system_clock::time_point now) {
    const auto row = db::Transactions::exec("auth::mfa::confirmTotp.load", [&](pqxx::work& txn) {
        const auto res = txn.exec(std::string("SELECT id, factor_uuid::text, secret_sealed, secret_iv, last_step "
                                              "FROM totp_factors WHERE id = $2 AND user_id = $1 "
                                              "AND confirmed_at IS NULL AND disabled_at IS NULL AND ") +
                                      kTotpEnrollmentLive,
                                  pqxx::params{userId, factorId});
        if (res.empty()) throw ops::NotFound("no such TOTP enrollment (it may have expired: start again)");
        return sealedTotpFrom(res.one_row_ref());
    });

    const auto key = keys::seal();
    const auto secret = openTotpRow(key, userId, row);
    if (!secret) throw keys::Unavailable("TOTP factor unavailable");
    const auto step = totp::match(secret->bytes(), code, totp::stepAt(now), row.last_step);
    if (!step) return std::nullopt;

    auto factor = db::Transactions::exec("auth::mfa::confirmTotp", [&](pqxx::work& txn) -> std::optional<Factor> {
        const auto res = txn.exec(std::string("UPDATE totp_factors SET confirmed_at = NOW(), last_step = $3 "
                                              "WHERE id = $2 AND user_id = $1 AND confirmed_at IS NULL "
                                              "AND disabled_at IS NULL AND last_step < $3 AND ") +
                                      kTotpEnrollmentLive +
                                      " RETURNING id, label, EXTRACT(EPOCH FROM created_at)::BIGINT, "
                                      "EXTRACT(EPOCH FROM last_used_at)::BIGINT, created_during_recovery",
                                  pqxx::params{userId, factorId, *step});
        if (res.empty()) return std::nullopt;
        return totpFactorFrom(res.one_row_ref());
    });
    if (!factor) return std::nullopt;

    session::assurance::policyChanged();
    recordMfa("auth.mfa.factor.enroll", vh::audit::Outcome::Success, userId,
              {{"factor_id", factor->id}, {"kind", "totp"}, {"during_recovery", factor->created_during_recovery}},
              "enrolled TOTP factor " + std::to_string(factor->id));
    noticeFactor(userId, "mfa.factor.enroll", "Authenticator app added",
                 "An authenticator app was set up as a sign-in factor on this account.");
    return factor;
}

std::optional<uint32_t> verifyTotp(const uint32_t userId, const std::string_view code,
                                   const std::chrono::system_clock::time_point now) {
    if (!totp::normalizeCode(code)) return std::nullopt;

    const auto rows = db::Transactions::exec("auth::mfa::verifyTotp.load", [&](pqxx::work& txn) {
        std::vector<SealedTotpRow> out;
        for (const auto& r : txn.exec("SELECT id, factor_uuid::text, secret_sealed, secret_iv, last_step "
                                      "FROM totp_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL "
                                      "AND disabled_at IS NULL ORDER BY id",
                                      pqxx::params{userId}))
            out.push_back(sealedTotpFrom(r));
        return out;
    });
    if (rows.empty()) return std::nullopt;

    const auto key = keys::seal();
    const auto current = totp::stepAt(now);
    for (const auto& row : rows) {
        const auto secret = openTotpRow(key, userId, row);
        if (!secret) continue;
        const auto step = totp::match(secret->bytes(), code, current, row.last_step);
        if (!step) continue;
        // The claim: of a replay, or of two concurrent uses of one code, only one raises last_step.
        const bool claimed = db::Transactions::exec("auth::mfa::verifyTotp", [&](pqxx::work& txn) {
            return txn.exec("UPDATE totp_factors SET last_step = $3, last_used_at = NOW() WHERE id = $2 "
                            "AND user_id = $1 AND confirmed_at IS NOT NULL AND disabled_at IS NULL AND last_step < $3",
                            pqxx::params{userId, row.id, *step}).affected_rows() == 1;
        });
        if (claimed) return row.id;
    }
    return std::nullopt;
}

std::size_t purgeExpiredTotpEnrollments() {
    return db::Transactions::exec("auth::mfa::purgeExpiredTotpEnrollments", [](pqxx::work& txn) {
        return static_cast<std::size_t>(
            txn.exec("DELETE FROM totp_factors WHERE confirmed_at IS NULL "
                     "AND created_at <= NOW() - interval '10 minutes'").affected_rows());
    });
}

// ---- recovery codes

RecoveryBatch generateRecoveryCodes(const uint32_t userId) {
    const auto pepper = keys::pepper();
    RecoveryBatch out;
    out.batch_id = crypto::util::uuid4_hex();
    std::vector<recovery::Hash> hashes;
    for (std::size_t i = 0; i < recovery::kCodesPerBatch; ++i) {
        out.codes.push_back(recovery::generateCode());
        auto normalized = recovery::normalize(out.codes.back());
        if (!normalized) throw std::logic_error("generated recovery code does not normalize");
        hashes.push_back(recovery::hash(pepper->bytes(), userId, *normalized));
        wipeString(*normalized);
    }

    db::Transactions::exec("auth::mfa::generateRecoveryCodes", [&](pqxx::work& txn) {
        // A batch nobody acknowledged is dropped (its codes go with it): only the newest one can be activated.
        txn.exec("DELETE FROM recovery_code_batches WHERE user_id = $1 AND acknowledged_at IS NULL",
                 pqxx::params{userId});
        txn.exec("INSERT INTO recovery_code_batches (id, user_id) VALUES ($1::uuid, $2)",
                 pqxx::params{out.batch_id, userId});
        for (const auto& h : hashes)
            txn.exec("INSERT INTO recovery_codes (batch_id, user_id, code_hash) VALUES ($1::uuid, $2, $3)",
                     pqxx::params{out.batch_id, userId, to_hex_bytea(std::vector<uint8_t>(h.begin(), h.end()))});
    });
    recordMfa("auth.mfa.recovery.generate", vh::audit::Outcome::Success, userId,
              {{"batch_id", out.batch_id}, {"remaining", out.codes.size()}},
              "generated recovery code batch " + out.batch_id);
    return out;
}

std::size_t acknowledgeRecoveryCodes(const uint32_t userId, const std::string& batchId) {
    if (!mfaCanonicalUuid(batchId)) throw ops::NotFound("no such pending recovery code batch");
    const auto remaining = db::Transactions::exec("auth::mfa::acknowledgeRecoveryCodes", [&](pqxx::work& txn) {
        // Serializes with any other acknowledgement or generation of this account.
        txn.exec("SELECT id FROM recovery_code_batches WHERE user_id = $1 FOR UPDATE", pqxx::params{userId});
        if (txn.exec("SELECT 1 FROM recovery_code_batches WHERE id = $2::uuid AND user_id = $1 "
                     "AND acknowledged_at IS NULL AND superseded_at IS NULL",
                     pqxx::params{userId, batchId}).empty())
            throw ops::NotFound("no such pending recovery code batch");
        txn.exec("UPDATE recovery_code_batches SET superseded_at = NOW() WHERE user_id = $1 "
                 "AND acknowledged_at IS NOT NULL AND superseded_at IS NULL",
                 pqxx::params{userId});
        txn.exec("UPDATE recovery_code_batches SET acknowledged_at = NOW() WHERE id = $2::uuid AND user_id = $1",
                 pqxx::params{userId, batchId});
        return unusedCodes(txn, batchId);
    });
    recordMfa("auth.mfa.recovery.acknowledge", vh::audit::Outcome::Success, userId,
              {{"batch_id", batchId}, {"remaining", remaining}}, "acknowledged recovery code batch " + batchId);
    noticeFactor(userId, "mfa.recovery.renew", "New recovery codes",
                 "New recovery codes were saved for this account; the previous ones no longer work.");
    return remaining;
}

std::optional<RecoveryUse> useRecoveryCode(const uint32_t userId, const std::string_view code, const std::string& ip) {
    auto normalized = recovery::normalize(code);
    if (!normalized) {
        recordMfa("auth.mfa.recovery.use", vh::audit::Outcome::Failure, userId, nlohmann::json::object(),
                  "presented a malformed recovery code");
        return std::nullopt;
    }
    const auto pepper = keys::pepper();
    const auto h = recovery::hash(pepper->bytes(), userId, *normalized);
    wipeString(*normalized);

    auto used = db::Transactions::exec("auth::mfa::useRecoveryCode", [&](pqxx::work& txn) -> std::optional<RecoveryUse> {
        const auto res = txn.exec(
            "UPDATE recovery_codes c SET used_at = NOW(), used_ip = NULLIF($3, '') FROM recovery_code_batches b "
            "WHERE c.batch_id = b.id AND c.user_id = $1 AND b.user_id = $1 AND c.code_hash = $2 AND c.used_at IS NULL "
            "AND b.acknowledged_at IS NOT NULL AND b.superseded_at IS NULL RETURNING c.batch_id::text",
            pqxx::params{userId, to_hex_bytea(std::vector<uint8_t>(h.begin(), h.end())), ip});
        if (res.empty()) return std::nullopt;
        RecoveryUse use{.batch_id = res.one_field().as<std::string>()};
        use.remaining = unusedCodes(txn, use.batch_id);
        return use;
    });

    if (!used) {
        recordMfa("auth.mfa.recovery.use", vh::audit::Outcome::Failure, userId, nlohmann::json::object(),
                  "presented a recovery code that is not valid");
        return std::nullopt;
    }
    recordMfa("auth.mfa.recovery.use", vh::audit::Outcome::Success, userId,
              {{"batch_id", used->batch_id}, {"remaining", used->remaining}},
              "used a recovery code of batch " + used->batch_id + " (" + std::to_string(used->remaining) + " left)");
    return used;
}

RecoveryStatus recoveryStatus(const uint32_t userId) {
    return db::Transactions::exec("auth::mfa::recoveryStatus", [&](pqxx::work& txn) {
        RecoveryStatus status;
        for (const auto& r : txn.exec("SELECT id::text, acknowledged_at IS NOT NULL FROM recovery_code_batches "
                                      "WHERE user_id = $1 AND superseded_at IS NULL ORDER BY created_at",
                                      pqxx::params{userId})) {
            if (r[1].as<bool>()) status.active_batch = r[0].as<std::string>();
            else status.pending_batch = r[0].as<std::string>();
        }
        if (status.active_batch) status.remaining = unusedCodes(txn, *status.active_batch);
        return status;
    });
}

// ---- passkeys

WebAuthnCredential addWebAuthnCredential(const uint32_t userId, const NewWebAuthnCredential& c) {
    if (c.credential_id.size() < 16 || c.credential_id.size() > 1023)
        throw ops::Invalid("a credential id is 16 to 1023 bytes");
    if (c.public_key_cose.empty()) throw ops::Invalid("a credential needs its public key");
    if (c.cose_alg != -8 && c.cose_alg != -7 && c.cose_alg != -257) throw ops::Invalid("unsupported COSE algorithm");
    if (c.rp_id.empty()) throw ops::Invalid("a credential needs its RP ID");
    if (c.aaguid && !mfaCanonicalUuid(*c.aaguid)) throw ops::Invalid("an AAGUID is a canonical lower-case UUID");
    if (c.sign_count < 0) throw ops::Invalid("signCount is never negative");
    if (c.attestation_fmt.empty() || c.attestation_fmt.size() > 32) throw ops::Invalid("bad attestation format");
    std::string transports;
    for (const auto& t : c.transports) {
        if (t.empty() || t.size() > 32 ||
            !std::ranges::all_of(t, [](const unsigned char ch) { return std::islower(ch) || ch == '-'; }))
            throw ops::Invalid("a transport is a lower-case token");
        if (!transports.empty()) transports += ',';
        transports += t;
    }
    const auto label = mfaLabel(c.label);

    auto stored = db::Transactions::exec("auth::mfa::addWebAuthnCredential", [&](pqxx::work& txn) {
        try {
            const auto id = txn.exec("INSERT INTO webauthn_credentials (user_id, credential_id, public_key_cose, "
                                     "cose_alg, rp_id, aaguid, sign_count, backup_eligible, backup_state, discoverable, "
                                     "transports, attestation_fmt, label, created_during_recovery) VALUES ($1, $2, $3, "
                                     "$4, $5, $6::uuid, $7, $8, $9, $10, string_to_array($11, ','), $12, $13, $14) "
                                     "RETURNING id",
                                     pqxx::params{userId, to_hex_bytea(c.credential_id), to_hex_bytea(c.public_key_cose),
                                                  c.cose_alg, c.rp_id, c.aaguid, c.sign_count, c.backup_eligible,
                                                  c.backup_state, c.discoverable, transports, c.attestation_fmt, label,
                                                  c.created_during_recovery})
                                .one_field()
                                .as<uint32_t>();
            const auto res = txn.exec(std::string("SELECT ") + kCredentialColumns +
                                          " FROM webauthn_credentials WHERE id = $1",
                                      pqxx::params{id});
            return credentialFrom(res.one_row_ref());
        } catch (const pqxx::unique_violation&) {
            throw ops::Conflict("this credential is registered already");
        }
    });
    session::assurance::policyChanged();
    recordMfa("auth.mfa.factor.enroll", vh::audit::Outcome::Success, userId,
              {{"factor_id", stored.id}, {"kind", "webauthn"}, {"during_recovery", stored.created_during_recovery}},
              "enrolled passkey " + std::to_string(stored.id));
    noticeFactor(userId, "mfa.factor.enroll", "Passkey added", "A passkey was added as a sign-in factor on this account.");
    return stored;
}

std::optional<WebAuthnCredential> webAuthnCredential(const std::span<const uint8_t> credentialId) {
    if (credentialId.empty() || credentialId.size() > 1023) return std::nullopt;
    const std::vector<uint8_t> id(credentialId.begin(), credentialId.end());
    return db::Transactions::exec("auth::mfa::webAuthnCredential", [&](pqxx::work& txn) -> std::optional<WebAuthnCredential> {
        const auto res = txn.exec(std::string("SELECT ") + kCredentialColumns +
                                      " FROM webauthn_credentials WHERE credential_id = $1 AND disabled_at IS NULL",
                                  pqxx::params{to_hex_bytea(id)});
        if (res.empty()) return std::nullopt;
        return credentialFrom(res.one_row_ref());
    });
}

std::vector<WebAuthnCredential> webAuthnCredentials(const uint32_t userId) {
    return db::Transactions::exec("auth::mfa::webAuthnCredentials", [&](pqxx::work& txn) {
        std::vector<WebAuthnCredential> out;
        for (const auto& r : txn.exec(std::string("SELECT ") + kCredentialColumns +
                                          " FROM webauthn_credentials WHERE user_id = $1 AND disabled_at IS NULL "
                                          "ORDER BY created_at, id",
                                      pqxx::params{userId}))
            out.push_back(credentialFrom(r));
        return out;
    });
}

bool recordWebAuthnUse(const uint32_t id, const int64_t expectedSignCount, const int64_t signCount,
                       const bool backupState) {
    if (signCount < 0) throw ops::Invalid("signCount is never negative");
    return db::Transactions::exec("auth::mfa::recordWebAuthnUse", [&](pqxx::work& txn) {
        return txn.exec("UPDATE webauthn_credentials SET sign_count = $3, backup_state = $4, last_used_at = NOW() "
                        "WHERE id = $1 AND sign_count = $2 AND suspended_at IS NULL AND disabled_at IS NULL",
                        pqxx::params{id, expectedSignCount, signCount, backupState}).affected_rows() == 1;
    });
}

bool suspendWebAuthnCredential(const uint32_t userId, const uint32_t id, const std::string_view reason) {
    if (reason.empty() || reason.size() > 64) throw ops::Invalid("a suspension reason is 1 to 64 characters");
    const bool suspended = db::Transactions::exec("auth::mfa::suspendWebAuthnCredential", [&](pqxx::work& txn) {
        return txn.exec("UPDATE webauthn_credentials SET suspended_at = NOW(), suspended_reason = $3 WHERE id = $2 "
                        "AND user_id = $1 AND suspended_at IS NULL AND disabled_at IS NULL",
                        pqxx::params{userId, id, std::string(reason)}).affected_rows() == 1;
    });
    if (suspended) {
        session::assurance::policyChanged();
        recordMfa("auth.mfa.factor.suspend", vh::audit::Outcome::Success, userId,
                  {{"factor_id", id}, {"kind", "webauthn"}, {"reason", std::string(reason)}},
                  "suspended passkey " + std::to_string(id));
        noticeFactor(userId, "mfa.factor.suspend", "Passkey suspended",
                     "A passkey on this account reported a signature counter that went backwards, which can mean it "
                     "was copied. It was suspended and can't sign in.",
                     true);
    }
    return suspended;
}

// ---- the verifier's side

NewWebAuthnCredential fromVerified(const webauthn::NewCredential& verified, const RegistrationDetails& details) {
    NewWebAuthnCredential out{.credential_id = verified.id,
                              .public_key_cose = verified.publicKeyCose,
                              .cose_alg = static_cast<int>(verified.algorithm),
                              .rp_id = verified.rpId,
                              .sign_count = verified.signCount,
                              .backup_eligible = verified.backupEligible,
                              .backup_state = verified.backupState,
                              .discoverable = details.discoverable,
                              .attestation_fmt = verified.attestationFormat,
                              .label = details.label,
                              .created_during_recovery = details.during_recovery};
    if (std::ranges::any_of(verified.aaguid, [](const uint8_t b) { return b != 0; })) {
        std::string uuid;
        for (std::size_t i = 0; i < verified.aaguid.size(); ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10) uuid += '-';
            uuid += std::format("{:02x}", verified.aaguid[i]);
        }
        out.aaguid = std::move(uuid);
    }
    for (const auto& t : details.transports) {
        if (out.transports.size() >= 8) break;
        if (!t.empty() && t.size() <= 32 &&
            std::ranges::all_of(t, [](const unsigned char ch) { return std::islower(ch) || ch == '-'; }) &&
            std::ranges::find(out.transports, t) == out.transports.end())
            out.transports.push_back(t);
    }
    return out;
}

std::optional<webauthn::StoredCredential> CredentialStore::find(const webauthn::ByteView credentialId) const {
    if (credentialId.empty() || credentialId.size() > 1023) return std::nullopt;
    const std::vector<uint8_t> id(credentialId.begin(), credentialId.end());
    return db::Transactions::exec("auth::mfa::CredentialStore::find",
                                  [&](pqxx::work& txn) -> std::optional<webauthn::StoredCredential> {
        const auto res = txn.exec(
            "SELECT c.credential_id, c.user_id, m.webauthn_user_handle, c.public_key_cose, c.rp_id, c.sign_count, "
            "c.backup_eligible, c.backup_state, c.disabled_at IS NOT NULL, c.suspended_at IS NOT NULL "
            "FROM webauthn_credentials c LEFT JOIN user_mfa m ON m.user_id = c.user_id WHERE c.credential_id = $1",
            pqxx::params{to_hex_bytea(id)});
        if (res.empty()) return std::nullopt;
        const auto r = res.one_row();
        const auto signCount = r[5].as<int64_t>();
        return webauthn::StoredCredential{
            .id = from_hex_bytea(r[0].as<std::string>()),
            .userId = r[1].as<int64_t>(),
            .userHandle = r[2].is_null() ? webauthn::Bytes{} : from_hex_bytea(r[2].as<std::string>()),
            .publicKeyCose = from_hex_bytea(r[3].as<std::string>()),
            .rpId = r[4].as<std::string>(),
            .signCount = static_cast<uint32_t>(std::clamp<int64_t>(signCount, 0, UINT32_MAX)),
            .backupEligible = r[6].as<bool>(),
            .backupState = r[7].as<bool>(),
            .disabled = r[8].as<bool>(),
            .suspended = r[9].as<bool>()};
    });
}

bool recordAssertion(const webauthn::VerifiedAssertion& assertion, const uint32_t expectedSignCount) {
    if (assertion.credentialId.empty() || assertion.credentialId.size() > 1023) return false;
    const int64_t next = assertion.storeSignCount ? assertion.signCount : expectedSignCount;
    return db::Transactions::exec("auth::mfa::recordAssertion", [&](pqxx::work& txn) {
        return txn.exec("UPDATE webauthn_credentials SET sign_count = $4, backup_state = $5, last_used_at = NOW() "
                        "WHERE credential_id = $1 AND user_id = $2 AND sign_count = $3 AND suspended_at IS NULL "
                        "AND disabled_at IS NULL",
                        pqxx::params{to_hex_bytea(assertion.credentialId), assertion.userId,
                                     static_cast<int64_t>(expectedSignCount), next, assertion.backupState})
                   .affected_rows() == 1;
    });
}

}
