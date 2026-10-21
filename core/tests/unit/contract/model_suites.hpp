#pragma once

// One function per area: serializes seeded instances of the area's models and hands them to the Checker
// (models_<area>.cpp). test_contract_models.cpp runs each as its own test and all of them together.

#include "../../helpers/contract_model_check.hpp"

namespace vh::test::contract_models {

void checkIdentityModels(Checker& c);
void checkVaultModels(Checker& c);
void checkFsModels(Checker& c);
void checkShareModels(Checker& c);
void checkSyncModels(Checker& c);
void checkStatsModels(Checker& c);
void checkS3GatewayModels(Checker& c);
void checkAdminModels(Checker& c);
void checkRecoveryModels(Checker& c);
void checkUpstreamModels(Checker& c);
void checkDeviceModels(Checker& c);

}
