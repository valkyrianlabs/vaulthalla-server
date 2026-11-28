#include "db/query/health/FindingState.hpp"

#include "db/Transactions.hpp"

#include <pqxx/pqxx>
#include <stdexcept>

namespace vh::db::query::health {

namespace {

::vh::health::Mark markFromRow(const pqxx::row_ref& row) {
    ::vh::health::Mark mark;
    mark.cls = row["class"].as<std::string>();
    mark.subject = row["subject"].as<std::string>();
    mark.state = row["state"].as<std::string>();
    mark.severity = row["severity"].as<std::string>();
    if (!row["set_by"].is_null()) mark.setBy = row["set_by"].as<std::uint32_t>();
    mark.setByName = row["set_by_name"].as<std::string>();
    mark.setAt = static_cast<std::uint64_t>(row["set_at"].as<long long>(0));
    if (!row["expires_at"].is_null()) mark.expiresAt = static_cast<std::uint64_t>(row["expires_at"].as<long long>());
    if (!row["note"].is_null()) mark.note = row["note"].as<std::string>();
    return mark;
}

}

std::vector<::vh::health::Mark> FindingState::list() {
    return Transactions::exec("HealthFindingState::list", [&](pqxx::work& txn) {
        std::vector<::vh::health::Mark> out;
        for (const auto& row : txn.exec(pqxx::prepped{"health_finding_state.list"})) out.push_back(markFromRow(row));
        return out;
    });
}

::vh::health::Mark FindingState::put(const ::vh::health::Mark& mark) {
    return Transactions::exec("HealthFindingState::put", [&](pqxx::work& txn) {
        const auto rows = txn.exec(
            pqxx::prepped{"health_finding_state.put"},
            pqxx::params{mark.cls, mark.subject, mark.state, mark.severity, mark.setBy, mark.setByName,
                         mark.expiresAt ? std::optional<long long>(static_cast<long long>(*mark.expiresAt))
                                        : std::optional<long long>(),
                         mark.note});
        if (rows.empty()) throw std::runtime_error("Unable to save the finding's state.");
        return markFromRow(rows.front());
    });
}

bool FindingState::remove(const std::string& cls, const std::string& subject) {
    return Transactions::exec("HealthFindingState::remove", [&](pqxx::work& txn) {
        return txn.exec(pqxx::prepped{"health_finding_state.remove"}, pqxx::params{cls, subject}).affected_rows() > 0;
    });
}

void FindingState::remove(const std::vector<::vh::health::Key>& keys) {
    if (keys.empty()) return;
    Transactions::exec("HealthFindingState::removeMany", [&](pqxx::work& txn) {
        for (const auto& [cls, subject] : keys)
            txn.exec(pqxx::prepped{"health_finding_state.remove"}, pqxx::params{cls, subject});
    });
}

}
