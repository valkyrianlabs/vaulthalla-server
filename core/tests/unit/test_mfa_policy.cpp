// MFA policy and lockout, DB-free (#360; MFA design note sections 7.1, 7.3 and 7.4).
//
//   - the per-account backoff: 5 failures, then 1, 2, 4, 8 minutes and 15 at most, never a lock; a streak ends 15
//     quiet minutes after its last delay; the 10th failure notifies once per streak;
//   - auth.mfa.* configuration: policy names, the cooldown and step-up ranges, the default `admins` when the key is
//     absent (D2), admin flags only with passkeys configured;
//   - what counts as weakening the policy;
//   - the recovery cooldown's families, the step-up table's #360 entries, and the recovery_cooldown refusal shape.
#include "Contract.hpp"
#include "auth/mfa/Policy.hpp"
#include "auth/mfa/SignIn.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Config.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/core/Refusal.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>

namespace vh::auth::mfa::test_policy {

using namespace std::chrono_literals;
using Backoff = signin::AccountBackoff;

TEST(MfaBackoff, FiveFailuresThenADoublingDelayCappedAtFifteenMinutes) {
    EXPECT_EQ(Backoff::delayFor(1), 0s);
    EXPECT_EQ(Backoff::delayFor(4), 0s);
    EXPECT_EQ(Backoff::delayFor(5), 1min);
    EXPECT_EQ(Backoff::delayFor(6), 2min);
    EXPECT_EQ(Backoff::delayFor(7), 4min);
    EXPECT_EQ(Backoff::delayFor(8), 8min);
    EXPECT_EQ(Backoff::delayFor(9), 15min);
    EXPECT_EQ(Backoff::delayFor(10), 15min);
    EXPECT_EQ(Backoff::delayFor(1000), 15min) << "never a permanent lock";

    Backoff b;
    auto now = Backoff::Clock::now();
    for (int i = 1; i <= 4; ++i) {
        const auto f = b.fail(now);
        EXPECT_EQ(f.failures, i);
        EXPECT_EQ(f.delay, 0s);
        EXPECT_EQ(b.retryAfter(now), 0s);
        now += 10s;
    }
    const auto fifth = b.fail(now);
    EXPECT_EQ(fifth.delay, 1min);
    EXPECT_EQ(b.retryAfter(now), 60s);
    EXPECT_EQ(b.retryAfter(now + 30s), 30s);
    EXPECT_EQ(b.retryAfter(now + 60s), 0s) << "the delay is all there is";
    now += 61s;
    EXPECT_EQ(b.fail(now).delay, 2min);
    now += 2min + 1s;
    EXPECT_EQ(b.fail(now).delay, 4min);
}

TEST(MfaBackoff, AStreakEndsAfterFifteenQuietMinutesCountedFromItsLastDelay) {
    Backoff b;
    auto now = Backoff::Clock::now();
    for (int i = 0; i < 9; ++i) {
        now += b.retryAfter(now) + 1s;
        (void)b.fail(now);
    }
    // 15 minutes of delay after the 9th: waiting it out, then failing again within the window keeps the streak.
    now += 15min + 1s;
    EXPECT_FALSE(b.expired(now));
    EXPECT_EQ(b.fail(now).failures, 10);
    // 15 quiet minutes after that delay ends: a new streak.
    now += 15min + 15min;
    EXPECT_TRUE(b.expired(now));
    const auto fresh = b.fail(now);
    EXPECT_EQ(fresh.failures, 1);
    EXPECT_EQ(fresh.delay, 0s);
}

TEST(MfaBackoff, TheTenthFailureNotifiesOncePerStreak) {
    Backoff b;
    auto now = Backoff::Clock::now();
    int notified = 0;
    for (int i = 1; i <= 14; ++i) {
        now += b.retryAfter(now) + 1s;
        const auto f = b.fail(now);
        if (f.notify) {
            ++notified;
            EXPECT_EQ(f.failures, signin::kAccountNotifyAt);
        }
    }
    EXPECT_EQ(notified, 1);
    now += 1h;
    for (int i = 1; i <= 10; ++i) {
        now += b.retryAfter(now) + 1s;
        if (b.fail(now).notify) ++notified;
    }
    EXPECT_EQ(notified, 2) << "a new streak notifies again";
}

TEST(MfaPolicyConfig, DefaultsRangesAndNames) {
    const config::MfaConfig d;
    EXPECT_EQ(d.policy, "admins") << "D2: new and upgraded installs";
    EXPECT_EQ(d.recovery_cooldown_hours, 24u);
    EXPECT_FALSE(d.admin_webauthn_only);
    EXPECT_FALSE(d.admin_device_bound_only);

    // A config without the keys (an upgraded config.yaml) reads the defaults.
    const auto absent = nlohmann::json::object().get<config::MfaConfig>();
    EXPECT_EQ(absent.policy, "admins");
    EXPECT_EQ(absent.step_up_ttl_seconds, 300u);

    for (const auto* name : {"optional", "admins", "all"})
        EXPECT_EQ(nlohmann::json({{"policy", name}}).get<config::MfaConfig>().policy, name);
    for (const auto& bad : {nlohmann::json{{"policy", "none"}}, nlohmann::json{{"policy", 1}},
                            nlohmann::json{{"recovery_cooldown_hours", 0}},
                            nlohmann::json{{"recovery_cooldown_hours", 169}},
                            nlohmann::json{{"recovery_cooldown_hours", "24"}},
                            nlohmann::json{{"admin_webauthn_only", "yes"}},
                            nlohmann::json{{"step_up_ttl_seconds", 30}}})
        EXPECT_THROW((void)bad.get<config::MfaConfig>(), std::invalid_argument) << bad.dump();

    // Holding admins to passkeys needs passkeys, or no admin could sign in.
    config::AuthConfig a;
    a.mfa.admin_webauthn_only = true;
    EXPECT_THROW(config::validateAuth(a), std::invalid_argument);
    a.mfa.admin_webauthn_only = false;
    a.mfa.admin_device_bound_only = true;
    EXPECT_THROW(config::validateAuth(a), std::invalid_argument);
    a.webauthn.rp_id = "vault.example.test";
    a.webauthn.origins = {"https://vault.example.test"};
    EXPECT_NO_THROW(config::validateAuth(a));

    // The JSON form round-trips (settings.get / settings.update).
    const auto j = nlohmann::json(a.mfa);
    EXPECT_EQ(j.at("policy"), "admins");
    EXPECT_TRUE(j.at("admin_device_bound_only").get<bool>());
    EXPECT_EQ(j.get<config::MfaConfig>().admin_device_bound_only, true);
}

TEST(MfaPolicyLevels, NamesAndWeakening) {
    for (const auto l : {policy::Level::Optional, policy::Level::Admins, policy::Level::All})
        EXPECT_EQ(policy::parseLevel(policy::to_string(l)), l);
    EXPECT_FALSE(policy::parseLevel("none"));

    config::AuthConfig from, to;
    from.webauthn.rp_id = to.webauthn.rp_id = "vault.example.test";
    EXPECT_TRUE(policy::weakenings(from, to).empty());
    EXPECT_FALSE(policy::policyChanged(from, to));

    to.mfa.policy = "all";
    EXPECT_TRUE(policy::weakenings(from, to).empty()) << "a raise is not a weakening";
    EXPECT_TRUE(policy::policyChanged(from, to));
    to.mfa.policy = "optional";
    EXPECT_EQ(policy::weakenings(from, to), std::vector<std::string>{"policy"});

    to = from;
    from.mfa.admin_webauthn_only = from.mfa.admin_device_bound_only = true;
    EXPECT_EQ(policy::weakenings(from, to), (std::vector<std::string>{"admin_webauthn_only", "admin_device_bound_only"}));
    EXPECT_TRUE(policy::weakenings(to, from).empty()) << "turning them on strengthens";

    from = to;
    to.webauthn.rp_id = "other.example.test";
    EXPECT_EQ(policy::weakenings(from, to), std::vector<std::string>{"webauthn.rp_id"});
    from.webauthn.rp_id.clear();
    EXPECT_TRUE(policy::weakenings(from, to).empty()) << "turning passkeys on for the first time weakens nothing";
    EXPECT_TRUE(policy::policyChanged(from, to));
}

TEST(MfaRecoveryCooldown, ItsFamiliesAndItsRefusal) {
    using stepup::Family;
    for (const auto f : stepup::kFamilies) {
        const bool expected = f == Family::Keys || f == Family::DeviceTrust || f == Family::IdentityAdmin ||
                              f == Family::Secrets || f == Family::Settings;
        EXPECT_EQ(stepup::cooldownFamily(f), expected) << stepup::to_string(f);
    }
    try {
        throw ops::RecoveryCooldown("settings", 1'800'000'000, "wait");
    } catch (...) {
        const auto reply = protocols::ws::core::describeCurrentError();
        EXPECT_EQ(reply.data.at("code"), "recovery_cooldown");
        EXPECT_EQ(reply.data.at("family"), "settings");
        EXPECT_EQ(reply.data.at("cooldown_until"), 1'800'000'000);
    }
}

TEST(MfaPolicyContract, AdminCommandsAreSteppedUpAndCooldownFamiliesSayTheyRefuse) {
    const auto table = contract::stepUpTable();
    const auto family = [&](const std::string& command) {
        const auto it = std::ranges::find(table, command, &contract::WsStepUp::command);
        return it == table.end() ? std::string{} : it->family;
    };
    EXPECT_EQ(family("auth.mfa.admin.reset"), "account.credentials");
    EXPECT_EQ(family("auth.mfa.admin.require"), "identity.admin");
    EXPECT_EQ(family("auth.mfa.admin.status"), "") << "a read";

    for (const auto& c : contract::ws::commands()) {
        if (!c.step_up) continue;
        const bool cooldown = *c.step_up == "keys" || *c.step_up == "device.trust" || *c.step_up == "identity.admin" ||
                              *c.step_up == "secrets" || *c.step_up == "settings";
        const bool listed =
            std::ranges::find(c.refusal_codes, "recovery_cooldown") != c.refusal_codes.end();
        EXPECT_EQ(listed, cooldown) << c.command;
    }
}

}
