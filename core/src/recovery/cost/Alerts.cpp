#include "recovery/cost/Alerts.hpp"

#include "db/Transactions.hpp"
#include "log/Registry.hpp"
#include "recovery/cost/Report.hpp"
#include "recovery/usage/Ledger.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

namespace vh::recovery::cost {

namespace {

std::string alertDedupeKey(const uint32_t vaultId, const std::time_t now) {
    return std::string(kAlertType) + ":" + std::to_string(vaultId) + ":" + usage::utcDay(now);
}

}

void noteAlert(const CostReport& report, const std::time_t now) noexcept {
    if (!report.alert.exceeded || !report.alert.threshold || !report.projected_monthly.expected) return;
    try {
        const auto& projected = *report.projected_monthly.expected;
        const auto& threshold = *report.alert.threshold;
        const auto title = std::string("Provider versioning cost above the alert threshold");
        const auto message = "The projected monthly cost of provider versioning for vault " + std::to_string(report.vault_id) +
                             (report.bucket ? " (bucket '" + *report.bucket + "')" : std::string{}) + " is " +
                             projected.amount + " " + projected.currency + ", above the alert threshold of " +
                             threshold.amount + " " + threshold.currency + " (" + report.retention.value_or("no retention") +
                             ", confidence " + report.confidence + "). Versioning and writes are not affected.";
        const nlohmann::json metadata = {{"projected_monthly", projected.amount},
                                         {"threshold", threshold.amount},
                                         {"currency", projected.currency},
                                         {"retention", report.retention.value_or("")},
                                         {"confidence", report.confidence},
                                         {"basis", report.projected_monthly.basis},
                                         {"computed_at", report.computed_at}};
        const auto key = alertDedupeKey(report.vault_id, now);
        db::Transactions::exec("recovery::cost::noteAlert", [&](pqxx::work& txn) {
            const auto updated = txn.exec(
                "UPDATE operator_notification SET message = $3, metadata = $4::jsonb "
                "WHERE type = $1 AND vault_id = $2 AND run_uuid = $5 RETURNING id",
                pqxx::params{std::string(kAlertType), report.vault_id, message, metadata.dump(), key});
            if (!updated.empty()) return;
            txn.exec(
                "INSERT INTO operator_notification (type, severity, title, message, scope, vault_id, provider_key, run_uuid, "
                "metadata, expires_at) VALUES ($1, 'warning', $2, $3, 'vault', $4, $5, $6, $7::jsonb, "
                "CURRENT_TIMESTAMP + INTERVAL '2 days')",
                pqxx::params{std::string(kAlertType), title, message, report.vault_id, report.provider, key, metadata.dump()});
        });
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[recovery::cost] vault {}: cost alert not recorded: {}", report.vault_id, e.what());
    } catch (...) {
    }
}

void evaluateAlerts(const std::time_t now) noexcept {
    try {
        const auto vaults = db::Transactions::read("recovery::cost::alertVaults", [&](pqxx::transaction_base& txn) {
            std::vector<uint32_t> out;
            for (const auto& row : txn.exec("SELECT vault_id FROM vault_recovery_policy WHERE cost_alert_monthly IS NOT NULL "
                                            "ORDER BY vault_id"))
                out.push_back(row[0].as<uint32_t>());
            return out;
        });
        for (const auto vaultId : vaults) {
            try {
                noteAlert(reportForVault(vaultId, {}, now), now);
            } catch (const std::exception& e) {
                log::Registry::storage()->debug("[recovery::cost] vault {}: cost alert not evaluated: {}", vaultId, e.what());
            }
        }
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[recovery::cost] cost alerts not evaluated: {}", e.what());
    } catch (...) {
    }
}

}
