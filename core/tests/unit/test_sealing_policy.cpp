// The refusals and warnings around the PCR 7 policy (#351), without a TPM: the gate `vh secret reseal --pcr7` applies,
// the health warning and the policy names. The sealing itself (binding, fail-closed unseal, staged reseal, crash points,
// the recovery drill) runs on swtpm in test_tpm_sealer.cpp.

#include "ops/MasterSecrets.hpp"
#include "platform/Sealer.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <ctime>
#include <string>

namespace vh::test_sealing_policy {

namespace ms = ops::master_secrets;
using ops::vault_keys::KeyStatus;

KeyStatus vault(const unsigned int id, const std::string& name) {
    KeyStatus v;
    v.vault_id = id;
    v.vault_name = name;
    v.version = 3;
    return v;
}

ms::ResealGate readyGate(const std::time_t now) {
    ms::ResealGate g;
    g.supported = true;
    g.posture = "hardware";
    g.now = now;
    g.last_export_at = now - 3600;
    auto exported = vault(1, "docs");
    exported.exported_version = 3;
    g.vaults = {exported};
    return g;
}

TEST(SealingPolicyGate, PassesWithHardwareFreshExportAndBackedUpVaults) {
    EXPECT_TRUE(ms::resealRefusals(readyGate(1'800'000'000)).empty());
}

TEST(SealingPolicyGate, RefusesWithoutHardware) {
    auto g = readyGate(1'800'000'000);
    g.posture = "software";
    const auto problems = ms::resealRefusals(g);
    ASSERT_EQ(problems.size(), 1u);
    EXPECT_NE(problems[0].find("no hardware TPM"), std::string::npos);
    g.posture = "unknown";
    EXPECT_EQ(ms::resealRefusals(g).size(), 1u);
}

TEST(SealingPolicyGate, RefusesWhereThePlatformHasNoPcrs) {
    auto g = readyGate(1'800'000'000);
    g.supported = false;
    g.posture = "hardware";  // the Secure Enclave
    const auto problems = ms::resealRefusals(g);
    ASSERT_EQ(problems.size(), 1u);
    EXPECT_NE(problems[0].find("Secure Enclave"), std::string::npos);
}

TEST(SealingPolicyGate, RefusesWithoutAnExportOrWithAnOldOne) {
    const std::time_t now = 1'800'000'000;
    auto g = readyGate(now);
    g.last_export_at.reset();
    auto problems = ms::resealRefusals(g);
    ASSERT_EQ(problems.size(), 1u);
    EXPECT_NE(problems[0].find("vh secret export all"), std::string::npos);

    g.last_export_at = now - 24 * 3600 - 1;
    problems = ms::resealRefusals(g);
    ASSERT_EQ(problems.size(), 1u);
    EXPECT_NE(problems[0].find("24 hours at most"), std::string::npos);

    g.last_export_at = now - 24 * 3600;  // exactly 24 hours still counts
    EXPECT_TRUE(ms::resealRefusals(g).empty());
}

TEST(SealingPolicyGate, RefusesVaultsWhoseKeysAreNotBackedUpAndNamesThem) {
    auto g = readyGate(1'800'000'000);
    auto stale = vault(2, "photos");
    stale.exported_version = 2;  // a rotation made the export stale
    auto never = vault(3, "ledger");
    auto gone = vault(4, "lost");
    gone.exported_version = 3;
    gone.key_available = false;
    auto gap = vault(5, "gap");
    gap.exported_version = 3;
    gap.missing_versions = {1};
    g.vaults.insert(g.vaults.end(), {stale, never, gone, gap});
    const auto problems = ms::resealRefusals(g);
    ASSERT_EQ(problems.size(), 1u);
    for (const auto* name : {"'photos' (ID 2)", "'ledger' (ID 3)", "'lost' (ID 4)", "'gap' (ID 5)"})
        EXPECT_NE(problems[0].find(name), std::string::npos) << name;
    EXPECT_EQ(problems[0].find("'docs'"), std::string::npos) << "a backed-up vault is not listed";
}

TEST(SealingPolicyGate, RecoveryRecipientsCoverAVaultToo) {
    auto v = vault(7, "team");
    v.recovery.required = true;
    v.recovery.state = "recipient";
    v.recovery.recipients = 2;
    EXPECT_TRUE(ms::keysBackedUp(v));
    v.recovery.uncovered_versions = {2};
    EXPECT_FALSE(ms::keysBackedUp(v));
    v.recovery.uncovered_versions.clear();
    v.recovery.rotation_needed = true;
    EXPECT_FALSE(ms::keysBackedUp(v));
}

TEST(SealingPolicyGate, EveryProblemIsReportedAtOnce) {
    ms::ResealGate g;
    g.supported = true;
    g.posture = "software";
    g.now = 1'800'000'000;
    g.vaults = {vault(1, "a")};
    EXPECT_EQ(ms::resealRefusals(g).size(), 3u);
}

TEST(SealingPolicyHealth, WarnsOnlyWhenPcrBoundWithoutAnExportInThirtyDays) {
    const std::time_t now = 1'800'000'000;
    const auto day = 24 * 3600;
    EXPECT_FALSE(ms::pcrExportWarning(0, std::nullopt, now)) << "nothing bound: nothing to warn about";
    EXPECT_FALSE(ms::pcrExportWarning(0, now - 400 * day, now));
    const auto never = ms::pcrExportWarning(4, std::nullopt, now);
    ASSERT_TRUE(never);
    EXPECT_NE(never->find("4 sealed secret(s)"), std::string::npos);
    EXPECT_NE(never->find("vh secret export all"), std::string::npos);
    EXPECT_FALSE(ms::pcrExportWarning(4, now - 29 * day, now));
    EXPECT_FALSE(ms::pcrExportWarning(4, now - 30 * day, now));
    const auto old = ms::pcrExportWarning(4, now - 31 * day, now);
    ASSERT_TRUE(old);
    EXPECT_NE(old->find("31 day(s)"), std::string::npos);
}

TEST(SealingPolicyNames, RoundTrip) {
    using platform::sealer::Policy;
    EXPECT_EQ(platform::sealer::parsePolicy("none"), Policy::None);
    EXPECT_EQ(platform::sealer::parsePolicy("pcr7"), Policy::Pcr7);
    EXPECT_FALSE(platform::sealer::parsePolicy("pcr0"));
    EXPECT_FALSE(platform::sealer::parsePolicy(""));
    EXPECT_EQ(platform::sealer::policyName(Policy::Pcr7), "pcr7");
    EXPECT_EQ(platform::sealer::policyName(Policy::None), "none");
}

}
