// Every named ws model (core/usage/src/contract/models) against the serializer that produces it: seeded instances
// per area (models_*.cpp), checked field by field (core/tests/helpers/contract_model_check.hpp). DB-free.

#include "model_suites.hpp"

#include <gtest/gtest.h>

#include <set>
#include <string>
#include <vector>

namespace vh::test_contract_models {

using test::contract_models::Checker;

std::string lines(const std::vector<std::string>& items) {
    std::string out;
    for (const auto& i : items) out += "\n  " + i;
    return out;
}

void runSuite(void (*suite)(Checker&)) {
    Checker c;
    suite(c);
    EXPECT_TRUE(c.problems().empty()) << "serializer output disagrees with the declared model:" << lines(c.problems());
    EXPECT_TRUE(c.unseen(true).empty()) << "declared fields no seeded instance produced (seed them, or allowUnseen "
                                           "with the reason):" << lines(c.unseen(true));
    EXPECT_TRUE(c.staleAllowances().empty()) << "allowUnseen entries that are seen or not declared:"
                                             << lines(c.staleAllowances());
}

TEST(ContractModels, Identity) { runSuite(test::contract_models::checkIdentityModels); }
TEST(ContractModels, Vaults) { runSuite(test::contract_models::checkVaultModels); }
TEST(ContractModels, Fs) { runSuite(test::contract_models::checkFsModels); }
TEST(ContractModels, Shares) { runSuite(test::contract_models::checkShareModels); }
TEST(ContractModels, Sync) { runSuite(test::contract_models::checkSyncModels); }
TEST(ContractModels, Stats) { runSuite(test::contract_models::checkStatsModels); }
TEST(ContractModels, S3Gateway) { runSuite(test::contract_models::checkS3GatewayModels); }
TEST(ContractModels, Admin) { runSuite(test::contract_models::checkAdminModels); }
TEST(ContractModels, Recovery) { runSuite(test::contract_models::checkRecoveryModels); }
TEST(ContractModels, Upstream) { runSuite(test::contract_models::checkUpstreamModels); }
TEST(ContractModels, Devices) { runSuite(test::contract_models::checkDeviceModels); }

TEST(ContractModels, EveryDeclaredModelIsCheckedAgainstItsSerializer) {
    Checker c;
    for (const auto suite : {test::contract_models::checkIdentityModels, test::contract_models::checkVaultModels,
                             test::contract_models::checkFsModels, test::contract_models::checkShareModels,
                             test::contract_models::checkSyncModels, test::contract_models::checkStatsModels,
                             test::contract_models::checkS3GatewayModels, test::contract_models::checkAdminModels,
                             test::contract_models::checkRecoveryModels, test::contract_models::checkUpstreamModels,
                             test::contract_models::checkDeviceModels})
        suite(c);
    std::vector<std::string> unchecked;
    for (const auto& m : contract::ws::models())
        if (!c.checkedModels().contains(m.name)) unchecked.push_back(m.name);
    EXPECT_TRUE(unchecked.empty()) << "models no suite checks:" << lines(unchecked);
    // Coverage over everything, including models only reached through another model (e.g. a nested recovery
    // figure, or VaultRole inside an S3 gateway assignment).
    EXPECT_TRUE(c.problems().empty()) << lines(c.problems());
    EXPECT_TRUE(c.unseen().empty()) << "declared fields no suite produced:" << lines(c.unseen());
}

}
