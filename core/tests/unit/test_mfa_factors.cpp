// vh-test-tier: db-only
// MFA factor storage (#356; MFA design note sections 4.2, 4.3 and 9, migration 120): TOTP enrollment, confirmation,
// the window and the replay guard in the database (a replay and concurrent double use both fail), drift refused,
// seeds sealed per account; recovery code batches that are inactive until acknowledged, superseded on
// acknowledgement and single use under concurrency; passkey storage; and a missing or unreadable mfa_seal / mfa_pepper
// that refuses its own factor without ever being regenerated, while passkeys keep working. No code, seed or URI
// reaches the audit trail.
#include "../helpers/db_suite.hpp"
#include "../helpers/web_session.hpp"
#include "audit/Trail.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Keys.hpp"
#include "auth/mfa/Totp.hpp"
#include "crypto/model/Secret.hpp"
#include "crypto/secrets/Manager.hpp"
#include "db/Transactions.hpp"
#include "db/query/crypto/Secret.hpp"
#include "ops/Error.hpp"
#include "runtime/Deps.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <format>
#include <latch>
#include <string>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

namespace vh::auth::mfa::test_factors {

namespace q = db::query::crypto;
using Clock = std::chrono::system_clock;

using vh::test::web::fromBase32;

class MfaFactorsDb : public vh::test::db::Suite {
protected:
    inline static int counter = 0;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("mfa_factors")) return;
        audit::Trail::instance()->resetForTesting();
    }

    static void TearDownTestSuite() { tearDownDbSuite(); }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        keys::resetForTesting();
    }

    void TearDown() override {
        if (skipTests) return;
        keys::resetForTesting();
    }

    static void exec(const std::string& sql) {
        db::Transactions::exec("mfa test", [&](pqxx::work& txn) { txn.exec(sql); });
    }

    template <typename T>
    static T scalar(const std::string& sql) {
        return db::Transactions::exec("mfa test", [&](pqxx::work& txn) { return txn.exec(sql).one_field().as<T>(); });
    }

    static uint32_t newUser() {
        const auto name = "mfa_user_" + std::to_string(::getpid()) + "_" + std::to_string(++counter);
        return db::Transactions::exec("mfa test", [&](pqxx::work& txn) {
            return txn.exec("INSERT INTO users (name, password_hash) VALUES ($1, 'x') RETURNING id",
                            pqxx::params{name}).one_field().as<uint32_t>();
        });
    }

    struct Enrolled {
        uint32_t factor{};
        std::vector<uint8_t> seed{};
        int64_t step{};  // the step the confirmation spent
    };

    static Enrolled enrollTotp(const uint32_t user, const Clock::time_point now = Clock::now()) {
        auto started = startTotp(user, {.label = "Phone", .account = "user" + std::to_string(user)});
        Enrolled e{.factor = started.factor_id, .seed = fromBase32(started.secret_base32), .step = totp::stepAt(now)};
        const auto factor = confirmTotp(user, started.factor_id, totp::code(e.seed, e.step), now);
        if (!factor) throw std::runtime_error("confirmation failed");
        return e;
    }

    static NewWebAuthnCredential credential(const uint8_t fill) {
        return {.credential_id = std::vector<uint8_t>(32, fill),
                .public_key_cose = std::vector<uint8_t>{0xa5, 0x01, 0x02},
                .cose_alg = -7,
                .rp_id = "vault.example.com",
                .aaguid = "08987058-cadc-4b81-b6e1-30de50dcbe96",
                .backup_eligible = true,
                .backup_state = true,
                .discoverable = true,
                .transports = {"internal", "hybrid"},
                .attestation_fmt = "none",
                .label = "1Password"};
    }

    // Writes an unreadable mfa_* row: what a row sealed under another host's master looks like.
    static void corrupt(const char* name) {
        auto row = std::make_shared<crypto::model::Secret>();
        row->key = name;
        row->value = std::vector<uint8_t>(48, 0x7e);
        row->iv = std::vector<uint8_t>(12, 0x09);
        q::Secret::upsertSecret(row);
        keys::resetForTesting();
    }
};

// ── TOTP ────────────────────────────────────────────────────────────────────────────────────────────────────────────

TEST_F(MfaFactorsDb, TotpIsUnusableUntilConfirmedAndTheSeedIsStoredSealed) {
    const auto user = newUser();
    auto started = startTotp(user, {.label = "Phone", .account = "alice"});
    EXPECT_EQ(started.secret_base32.size(), 32u);
    EXPECT_TRUE(started.otpauth_uri.starts_with("otpauth://totp/Vaulthalla:alice?secret=" + started.secret_base32));
    EXPECT_GT(started.expires_at, std::chrono::duration_cast<std::chrono::seconds>(
                                      Clock::now().time_since_epoch()).count());
    const auto seed = fromBase32(started.secret_base32);
    ASSERT_EQ(seed.size(), 20u);

    const auto sealed = scalar<std::string>("SELECT encode(secret_sealed, 'hex') FROM totp_factors WHERE id = " +
                                            std::to_string(started.factor_id));
    std::string seedHex;
    for (const auto b : seed) seedHex += std::format("{:02x}", b);
    EXPECT_EQ(sealed.find(seedHex), std::string::npos) << "the seed is never stored in the clear";

    const auto now = Clock::now();
    const auto step = totp::stepAt(now);
    EXPECT_FALSE(verifyTotp(user, totp::code(seed, step), now)) << "unconfirmed: unusable";
    EXPECT_FALSE(hasUsableFactor(user));
    EXPECT_TRUE(factors(user).empty());

    const auto wrong = (std::stoi(totp::code(seed, step)) + 1) % 1'000'000;
    EXPECT_FALSE(confirmTotp(user, started.factor_id, std::format("{:06}", wrong), now));
    const auto factor = confirmTotp(user, started.factor_id, totp::code(seed, step), now);
    ASSERT_TRUE(factor);
    EXPECT_EQ(factor->kind, FactorKind::Totp);
    EXPECT_EQ(factor->label, "Phone");
    EXPECT_TRUE(hasUsableFactor(user));
    ASSERT_EQ(factors(user).size(), 1u);
    EXPECT_THROW((void)confirmTotp(user, started.factor_id, totp::code(seed, step + 1), now), ops::NotFound)
        << "confirmed once";
    EXPECT_FALSE(verifyTotp(user, totp::code(seed, step), now)) << "the confirming code is spent";
}

TEST_F(MfaFactorsDb, AnEnrollmentNotConfirmedWithinTenMinutesIsGone) {
    const auto user = newUser();
    auto started = startTotp(user, {.label = "Phone", .account = "bob"});
    const auto seed = fromBase32(started.secret_base32);
    exec("UPDATE totp_factors SET created_at = NOW() - interval '11 minutes' WHERE id = " +
         std::to_string(started.factor_id));
    const auto now = Clock::now();
    EXPECT_THROW((void)confirmTotp(user, started.factor_id, totp::code(seed, totp::stepAt(now)), now), ops::NotFound);
    EXPECT_GE(purgeExpiredTotpEnrollments(), 1u);
    EXPECT_EQ(scalar<int>("SELECT COUNT(*) FROM totp_factors WHERE id = " + std::to_string(started.factor_id)), 0);

    // A new start replaces an enrollment still in flight.
    auto first = startTotp(user, {.label = "A", .account = "bob"});
    auto second = startTotp(user, {.label = "B", .account = "bob"});
    EXPECT_EQ(scalar<int>("SELECT COUNT(*) FROM totp_factors WHERE user_id = " + std::to_string(user)), 1);
    EXPECT_THROW((void)startTotp(user, {.label = "", .account = "bob"}), ops::Invalid);
    EXPECT_THROW((void)startTotp(user, {.label = std::string(65, 'x'), .account = "bob"}), ops::Invalid);
}

TEST_F(MfaFactorsDb, WindowOfOneStepReplayRefusedAndDriftOfTwoRefused) {
    const auto user = newUser();
    const auto t0 = Clock::now();
    const auto e = enrollTotp(user, t0);
    const auto s = e.step;

    EXPECT_FALSE(verifyTotp(user, totp::code(e.seed, s), t0)) << "replay of the spent step";
    EXPECT_EQ(verifyTotp(user, totp::code(e.seed, s + 1), t0), e.factor) << "one step ahead is accepted";
    EXPECT_FALSE(verifyTotp(user, totp::code(e.seed, s + 1), t0)) << "and spent";
    EXPECT_FALSE(verifyTotp(user, totp::code(e.seed, s - 1), t0)) << "older than the last used step";

    const auto t1 = t0 + std::chrono::seconds(30 * 3);  // current step s+3
    EXPECT_EQ(verifyTotp(user, totp::code(e.seed, s + 2), t1), e.factor) << "one step behind is accepted";

    const auto t2 = t0 + std::chrono::seconds(30 * 10);  // current step s+10
    EXPECT_FALSE(verifyTotp(user, totp::code(e.seed, s + 8), t2)) << "two steps behind is drift";
    EXPECT_FALSE(verifyTotp(user, totp::code(e.seed, s + 12), t2)) << "two steps ahead is drift";
    EXPECT_EQ(verifyTotp(user, totp::code(e.seed, s + 10), t2), e.factor);

    EXPECT_FALSE(verifyTotp(user, "12345", t2));
    EXPECT_FALSE(verifyTotp(user, "abcdef", t2));
    EXPECT_GT(scalar<int64_t>("SELECT last_step FROM totp_factors WHERE id = " + std::to_string(e.factor)), s);
}

TEST_F(MfaFactorsDb, ConcurrentUseOfOneCodeSucceedsExactlyOnce) {
    const auto user = newUser();
    const auto t0 = Clock::now();
    const auto e = enrollTotp(user, t0);
    const auto later = t0 + std::chrono::seconds(30 * 20);
    const auto code = totp::code(e.seed, totp::stepAt(later));

    constexpr int kThreads = 8;
    std::latch start(kThreads);
    std::atomic<int> accepted{0}, failed{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i)
        threads.emplace_back([&] {
            start.arrive_and_wait();
            try {
                if (verifyTotp(user, code, later)) ++accepted;
            } catch (...) {
                ++failed;
            }
        });
    for (auto& t : threads) t.join();
    EXPECT_EQ(accepted.load(), 1);
    EXPECT_EQ(failed.load(), 0);
}

TEST_F(MfaFactorsDb, ASealedSeedMovedToAnotherAccountDoesNotOpen) {
    const auto alice = newUser();
    const auto mallory = newUser();
    const auto t0 = Clock::now();
    const auto e = enrollTotp(alice, t0);
    exec("UPDATE totp_factors SET user_id = " + std::to_string(mallory) + " WHERE id = " + std::to_string(e.factor));
    const auto later = t0 + std::chrono::seconds(30 * 5);
    EXPECT_FALSE(verifyTotp(mallory, totp::code(e.seed, totp::stepAt(later)), later))
        << "the AAD binds the seed to its account";
}

TEST_F(MfaFactorsDb, RemovedFactorsAreKeptButNeverUsable) {
    const auto user = newUser();
    const auto t0 = Clock::now();
    const auto e = enrollTotp(user, t0);
    EXPECT_TRUE(renameFactor(user, FactorKind::Totp, e.factor, "Work phone"));
    EXPECT_EQ(factors(user).at(0).label, "Work phone");
    EXPECT_FALSE(renameFactor(newUser(), FactorKind::Totp, e.factor, "theirs")) << "another account's factor";
    EXPECT_TRUE(removeFactor(user, FactorKind::Totp, e.factor));
    EXPECT_FALSE(removeFactor(user, FactorKind::Totp, e.factor));
    const auto later = t0 + std::chrono::seconds(30 * 5);
    EXPECT_FALSE(verifyTotp(user, totp::code(e.seed, totp::stepAt(later)), later));
    EXPECT_FALSE(hasUsableFactor(user));
    EXPECT_EQ(scalar<int>("SELECT COUNT(*) FROM totp_factors WHERE disabled_at IS NOT NULL AND id = " +
                          std::to_string(e.factor)), 1) << "kept for the audit trail";
}

// ── keys: fail closed, never regenerated ────────────────────────────────────────────────────────────────────────────

TEST_F(MfaFactorsDb, AnUnreadableMfaSealRefusesTotpButPasskeysKeepWorking) {
    const auto user = newUser();
    const auto t0 = Clock::now();
    const auto e = enrollTotp(user, t0);
    const auto stored = q::Secret::getSecret(keys::kSealName);
    ASSERT_TRUE(stored);

    corrupt(keys::kSealName);
    const auto corrupted = q::Secret::getSecret(keys::kSealName)->value;
    const auto later = t0 + std::chrono::seconds(30 * 5);
    EXPECT_THROW((void)verifyTotp(user, totp::code(e.seed, totp::stepAt(later)), later), keys::Unavailable);
    EXPECT_THROW((void)verifyTotp(user, totp::code(e.seed, totp::stepAt(later)), later), keys::Unavailable)
        << "every attempt: a failure is not cached";
    EXPECT_THROW((void)startTotp(user, {.label = "New", .account = "u"}), keys::Unavailable);
    EXPECT_EQ(q::Secret::getSecret(keys::kSealName)->value, corrupted) << "never regenerated";

    // Passkeys don't depend on it.
    const auto passkey = addWebAuthnCredential(user, credential(0x31));
    EXPECT_TRUE(webAuthnCredential(passkey.credential_id));
    EXPECT_TRUE(hasUsableFactor(user));

    // Restoring the row brings TOTP back with the same seeds.
    q::Secret::upsertSecret(stored);
    keys::resetForTesting();
    EXPECT_EQ(verifyTotp(user, totp::code(e.seed, totp::stepAt(later)), later), e.factor);

    // A missing row while sealed factors exist is not regenerated either.
    exec("DELETE FROM internal_secrets WHERE key = 'mfa_seal'");
    keys::resetForTesting();
    EXPECT_THROW((void)keys::seal(), keys::Unavailable);
    EXPECT_FALSE(q::Secret::secretExists(keys::kSealName));
    q::Secret::upsertSecret(stored);
}

TEST_F(MfaFactorsDb, AMissingMfaPepperWithCodesOnRecordIsNotRegenerated) {
    const auto user = newUser();
    auto batch = generateRecoveryCodes(user);
    (void)acknowledgeRecoveryCodes(user, batch.batch_id);
    const auto stored = q::Secret::getSecret(keys::kPepperName);
    ASSERT_TRUE(stored);
    exec("DELETE FROM internal_secrets WHERE key = 'mfa_pepper'");
    keys::resetForTesting();
    EXPECT_THROW((void)useRecoveryCode(user, batch.codes[0]), keys::Unavailable);
    EXPECT_THROW((void)generateRecoveryCodes(user), keys::Unavailable);
    EXPECT_FALSE(q::Secret::secretExists(keys::kPepperName)) << "nothing generated in its place";

    q::Secret::upsertSecret(stored);
    keys::resetForTesting();
    EXPECT_TRUE(useRecoveryCode(user, batch.codes[0])) << "restoring the row restores the codes";
}

// ── recovery codes ──────────────────────────────────────────────────────────────────────────────────────────────────

TEST_F(MfaFactorsDb, ABatchIsInactiveUntilAcknowledgedAndEachCodeWorksOnce) {
    const auto user = newUser();
    auto batch = generateRecoveryCodes(user);
    ASSERT_EQ(batch.codes.size(), 10u);
    auto status = recoveryStatus(user);
    EXPECT_FALSE(status.active_batch);
    EXPECT_EQ(status.pending_batch, batch.batch_id);

    EXPECT_FALSE(useRecoveryCode(user, batch.codes[0])) << "unacknowledged: refused";
    EXPECT_EQ(acknowledgeRecoveryCodes(user, batch.batch_id), 10u);
    EXPECT_THROW((void)acknowledgeRecoveryCodes(user, batch.batch_id), ops::NotFound) << "only a pending batch";
    EXPECT_THROW((void)acknowledgeRecoveryCodes(user, "not-a-uuid"), ops::NotFound);

    const auto used = useRecoveryCode(user, batch.codes[0], "203.0.113.7");
    ASSERT_TRUE(used);
    EXPECT_EQ(used->batch_id, batch.batch_id);
    EXPECT_EQ(used->remaining, 9u);
    EXPECT_FALSE(useRecoveryCode(user, batch.codes[0])) << "single use";

    // Typed loosely: lower case, no hyphen.
    std::string loose = batch.codes[1];
    std::erase(loose, '-');
    std::ranges::transform(loose, loose.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    EXPECT_TRUE(useRecoveryCode(user, loose));
    EXPECT_EQ(recoveryStatus(user).remaining, 8u);

    EXPECT_FALSE(useRecoveryCode(newUser(), batch.codes[2])) << "another account can't use it";
    EXPECT_FALSE(useRecoveryCode(user, "AAAAA-AAAAA"));
    EXPECT_FALSE(useRecoveryCode(user, "not a code"));
}

TEST_F(MfaFactorsDb, ANewBatchSupersedesTheOldOneOnlyWhenAcknowledged) {
    const auto user = newUser();
    auto first = generateRecoveryCodes(user);
    (void)acknowledgeRecoveryCodes(user, first.batch_id);

    auto second = generateRecoveryCodes(user);
    EXPECT_TRUE(useRecoveryCode(user, first.codes[0])) << "the active batch works until the new one is acknowledged";
    EXPECT_FALSE(useRecoveryCode(user, second.codes[0]));

    auto third = generateRecoveryCodes(user);  // drops the unacknowledged second batch
    EXPECT_THROW((void)acknowledgeRecoveryCodes(user, second.batch_id), ops::NotFound);
    EXPECT_EQ(acknowledgeRecoveryCodes(user, third.batch_id), 10u);

    EXPECT_FALSE(useRecoveryCode(user, first.codes[1])) << "superseded: refused";
    EXPECT_FALSE(useRecoveryCode(user, second.codes[1])) << "dropped: refused";
    EXPECT_TRUE(useRecoveryCode(user, third.codes[0]));
    const auto status = recoveryStatus(user);
    EXPECT_EQ(status.active_batch, third.batch_id);
    EXPECT_FALSE(status.pending_batch);
    EXPECT_EQ(scalar<int>("SELECT COUNT(*) FROM recovery_code_batches WHERE user_id = " + std::to_string(user) +
                          " AND acknowledged_at IS NOT NULL AND superseded_at IS NULL"), 1);
}

TEST_F(MfaFactorsDb, ConcurrentUseOfOneRecoveryCodeSucceedsExactlyOnce) {
    const auto user = newUser();
    auto batch = generateRecoveryCodes(user);
    (void)acknowledgeRecoveryCodes(user, batch.batch_id);

    constexpr int kThreads = 8;
    std::latch start(kThreads);
    std::atomic<int> accepted{0}, failed{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i)
        threads.emplace_back([&] {
            start.arrive_and_wait();
            try {
                if (useRecoveryCode(user, batch.codes[3])) ++accepted;
            } catch (...) {
                ++failed;
            }
        });
    for (auto& t : threads) t.join();
    EXPECT_EQ(accepted.load(), 1);
    EXPECT_EQ(failed.load(), 0);
    EXPECT_EQ(recoveryStatus(user).remaining, 9u);
}

// ── passkeys and the account row ────────────────────────────────────────────────────────────────────────────────────

TEST_F(MfaFactorsDb, PasskeysAreStoredWithTheirFlagsAndCountersMoveOnlyByCompareAndSet) {
    const auto user = newUser();
    const auto stored = addWebAuthnCredential(user, credential(0x41));
    EXPECT_EQ(stored.user_id, user);
    EXPECT_EQ(stored.cose_alg, -7);
    EXPECT_EQ(stored.transports, (std::vector<std::string>{"internal", "hybrid"}));
    EXPECT_EQ(stored.aaguid, "08987058-cadc-4b81-b6e1-30de50dcbe96");
    EXPECT_TRUE(stored.backup_eligible);
    EXPECT_THROW((void)addWebAuthnCredential(newUser(), credential(0x41)), ops::Conflict) << "one owner per id";

    auto bad = credential(0x42);
    bad.cose_alg = -35;
    EXPECT_THROW((void)addWebAuthnCredential(user, bad), ops::Invalid);
    bad = credential(0x42);
    bad.credential_id.resize(8);
    EXPECT_THROW((void)addWebAuthnCredential(user, bad), ops::Invalid);

    EXPECT_TRUE(recordWebAuthnUse(stored.id, 0, 5, false));
    EXPECT_FALSE(recordWebAuthnUse(stored.id, 0, 6, false)) << "the count moved under it";
    const auto after = webAuthnCredential(stored.credential_id);
    ASSERT_TRUE(after);
    EXPECT_EQ(after->sign_count, 5);
    EXPECT_FALSE(after->backup_state);
    EXPECT_TRUE(after->last_used_at);

    EXPECT_TRUE(suspendWebAuthnCredential(user, stored.id, "counter_regression"));
    EXPECT_FALSE(recordWebAuthnUse(stored.id, 5, 6, false)) << "suspended";
    EXPECT_FALSE(hasUsableFactor(user));
    const auto listed = factors(user);
    ASSERT_EQ(listed.size(), 1u);
    EXPECT_TRUE(listed[0].suspended);
    nlohmann::json j = listed[0];
    EXPECT_EQ(j["kind"], "webauthn");
    EXPECT_FALSE(j.contains("credential_id")) << "the model never carries the credential id";

    EXPECT_TRUE(removeFactor(user, FactorKind::WebAuthn, stored.id));
    EXPECT_FALSE(webAuthnCredential(stored.credential_id));
    EXPECT_TRUE(webAuthnCredentials(user).empty());
}

// The adapters the verifier (#355) plugs into: a verified registration becomes a row, the row answers check 11's
// lookup with the owner's user handle, and a verified assertion is written back compare-and-set.
TEST_F(MfaFactorsDb, AVerifiedRegistrationIsStoredAndServesTheVerifiersLookup) {
    const auto user = newUser();
    const auto account = ensureUser(user);
    vl::webauthn::NewCredential verified{.id = std::vector<uint8_t>(20, 0x51),
                                     .publicKeyCose = {0xa5, 0x01, 0x02},
                                     .algorithm = vl::webauthn::Algorithm::EdDSA,
                                     .aaguid = {0xad, 0xce, 0x00, 0x02, 0x35, 0xbc, 0xc6, 0x0a, 0x64, 0x8b, 0x0b, 0x25,
                                                0xf1, 0xf0, 0x55, 0x03},
                                     .signCount = 0,
                                     .backupEligible = false,
                                     .attestationFormat = "packed",
                                     .rpId = "vault.example.com"};
    const auto row = fromVerified(verified, {.label = "YubiKey", .transports = {"usb", "NFC!", "usb", "nfc"},
                                             .discoverable = true});
    EXPECT_EQ(row.cose_alg, -8);
    EXPECT_EQ(row.aaguid, "adce0002-35bc-c60a-648b-0b25f1f05503");
    EXPECT_EQ(row.transports, (std::vector<std::string>{"usb", "nfc"})) << "hints only: bad and repeated ones dropped";
    verified.aaguid = {};
    EXPECT_FALSE(fromVerified(verified, {.label = "x"}).aaguid) << "an all-zero AAGUID is none";

    const auto stored = addWebAuthnCredential(user, row);
    const CredentialStore store;
    const vl::webauthn::CredentialLookup& lookup = store;
    auto found = lookup.find(stored.credential_id);
    ASSERT_TRUE(found);
    EXPECT_EQ(found->userId, user);
    EXPECT_EQ(found->userHandle, account.webauthn_user_handle);
    EXPECT_EQ(found->rpId, "vault.example.com");
    EXPECT_FALSE(found->backupEligible);
    EXPECT_FALSE(found->disabled || found->suspended);
    EXPECT_FALSE(lookup.find(std::vector<uint8_t>(20, 0x52)));

    vl::webauthn::VerifiedAssertion signedIn{.userId = user, .credentialId = stored.credential_id, .signCount = 7,
                                         .storeSignCount = true, .userVerified = true};
    EXPECT_TRUE(recordAssertion(signedIn, found->signCount));
    EXPECT_FALSE(recordAssertion(signedIn, found->signCount)) << "the count moved under a second writer";
    EXPECT_EQ(lookup.find(stored.credential_id)->signCount, 7u);
    signedIn.storeSignCount = false;
    signedIn.signCount = 3;
    EXPECT_TRUE(recordAssertion(signedIn, 7));
    EXPECT_EQ(lookup.find(stored.credential_id)->signCount, 7u) << "not stored unless the verifier says so";
    signedIn.userId = newUser();
    EXPECT_FALSE(recordAssertion(signedIn, 7)) << "another owner";

    ASSERT_TRUE(suspendWebAuthnCredential(user, stored.id, "counter_regression"));
    EXPECT_TRUE(lookup.find(stored.credential_id)->suspended) << "returned flagged, for the verifier to refuse";
    ASSERT_TRUE(removeFactor(user, FactorKind::WebAuthn, stored.id));
    EXPECT_TRUE(lookup.find(stored.credential_id)->disabled);
}

TEST_F(MfaFactorsDb, TheAccountRowHasAStableRandomUserHandle) {
    const auto user = newUser();
    EXPECT_FALSE(userState(user));
    const auto first = ensureUser(user);
    EXPECT_EQ(first.webauthn_user_handle.size(), 32u);
    EXPECT_FALSE(first.required);
    EXPECT_EQ(ensureUser(user).webauthn_user_handle, first.webauthn_user_handle);
    EXPECT_NE(ensureUser(newUser()).webauthn_user_handle, first.webauthn_user_handle);
}

// ── audit ───────────────────────────────────────────────────────────────────────────────────────────────────────────

TEST_F(MfaFactorsDb, TheTrailRecordsMfaEventsWithoutAnyCodeOrSeed) {
    const auto user = newUser();
    auto started = startTotp(user, {.label = "Phone", .account = "auditee"});
    const auto seed = fromBase32(started.secret_base32);
    const auto now = Clock::now();
    const auto code = totp::code(seed, totp::stepAt(now));
    ASSERT_TRUE(confirmTotp(user, started.factor_id, code, now));
    auto batch = generateRecoveryCodes(user);
    (void)acknowledgeRecoveryCodes(user, batch.batch_id);
    ASSERT_TRUE(useRecoveryCode(user, batch.codes[0]));
    EXPECT_FALSE(useRecoveryCode(user, batch.codes[0]));
    ASSERT_TRUE(audit::Trail::instance()->flushNow());

    const auto rows = db::Transactions::exec("mfa audit", [&](pqxx::work& txn) {
        std::vector<std::tuple<std::string, std::string, std::string, std::string>> out;
        for (const auto& r : txn.exec("SELECT action, outcome, message, details FROM audit_event WHERE actor_id = $1 "
                                      "AND action LIKE 'auth.mfa.%' ORDER BY seq",
                                      pqxx::params{user}))
            out.emplace_back(r[0].as<std::string>(), r[1].as<std::string>(), r[2].as<std::string>(),
                             r[3].as<std::string>());
        return out;
    });
    std::vector<std::string> actions;
    for (const auto& [action, outcome, message, details] : rows) {
        actions.push_back(action + "/" + outcome);
        for (const auto& secret : std::vector<std::string>{started.secret_base32, code, batch.codes[0], batch.codes[1],
                                                           batch.codes[0].substr(0, 5) + batch.codes[0].substr(6)}) {
            EXPECT_EQ(message.find(secret), std::string::npos) << action;
            EXPECT_EQ(details.find(secret), std::string::npos) << action;
        }
        EXPECT_EQ(message.find("otpauth"), std::string::npos);
        EXPECT_EQ(details.find("auditee"), std::string::npos) << "no names in details";
    }
    EXPECT_EQ(actions, (std::vector<std::string>{"auth.mfa.factor.enroll/success", "auth.mfa.recovery.generate/success",
                                                 "auth.mfa.recovery.acknowledge/success",
                                                 "auth.mfa.recovery.use/success", "auth.mfa.recovery.use/failure"}));
}

}
