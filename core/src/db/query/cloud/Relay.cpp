#include "db/query/cloud/Relay.hpp"

#include "db/Transactions.hpp"

#include <pqxx/pqxx>

namespace vh::db::query::cloud {

std::optional<RelaySwitchRow> RelaySwitch::get() {
    return Transactions::read("RelaySwitch::get", [](pqxx::transaction_base& txn) -> std::optional<RelaySwitchRow> {
        const auto res = txn.exec("SELECT installation_id, enabled_by, EXTRACT(EPOCH FROM enabled_at)::BIGINT AS at "
                                  "FROM cloud_relay WHERE id = 1");
        if (res.empty()) return std::nullopt;
        const auto row = res.one_row_ref();
        return RelaySwitchRow{.installation_id = row["installation_id"].as<std::string>(),
                              .enabled_by = row["enabled_by"].as<std::string>(),
                              .enabled_at = static_cast<std::time_t>(row["at"].as<int64_t>())};
    });
}

void RelaySwitch::enable(const std::string& installationId, const std::string& by) {
    Transactions::exec("RelaySwitch::enable", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO cloud_relay (id, installation_id, enabled_by) VALUES (1, $1, $2) "
                 "ON CONFLICT (id) DO UPDATE SET installation_id = EXCLUDED.installation_id, "
                 "enabled_by = EXCLUDED.enabled_by, enabled_at = CURRENT_TIMESTAMP",
                 pqxx::params{installationId, by});
    });
}

bool RelaySwitch::disable() {
    return Transactions::exec("RelaySwitch::disable", [](pqxx::work& txn) {
        return txn.exec("DELETE FROM cloud_relay WHERE id = 1").affected_rows() > 0;
    });
}

}
