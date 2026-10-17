#pragma once

#include "recovery/Model.hpp"

#include <ctime>

// Recovery cost alerts: when a vault's cost_alert_monthly is set and the projected monthly versioning surcharge
// exceeds it, one operator_notification (type recovery_versioning_cost, severity warning, vault-scoped) per vault per
// UTC day is created or refreshed. Alerts never block writes and never change versioning.
namespace vh::recovery::cost {

inline constexpr const char* kAlertType = "recovery_versioning_cost";

// Creates or refreshes today's alert for report.vault_id when report.alert.exceeded. Never throws.
void noteAlert(const CostReport& report, std::time_t now) noexcept;

// Every vault with a threshold: its report, then noteAlert. Never throws (the usage ledger's tick calls it hourly).
void evaluateAlerts(std::time_t now) noexcept;

}
