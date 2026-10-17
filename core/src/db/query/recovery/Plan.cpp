#include "db/query/recovery/Plan.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "db/query/recovery/detail/Fields.hpp"

#include <pqxx/result>

#include <stdexcept>

namespace vh::db::query::recovery {

namespace {

PlanRow planFromRow(const pqxx::row_ref row) {
    PlanRow p;
    p.id = row["id"].as<int64_t>();
    p.vault_id = row["vault_id"].as<uint32_t>();
    p.token = row["token"].as<std::string>();
    p.source_json = row["source"].as<std::string>();
    p.destination = detail::opt<std::string>(row["destination"]);
    p.items_json = row["items"].as<std::string>();
    p.summary_json = row["summary"].as<std::string>();
    p.state = row["state"].as<std::string>();
    p.result_json = detail::opt<std::string>(row["result"]);
    p.created_at = detail::timeOr0(row["created_at"]);
    p.expires_at = detail::timeOr0(row["expires_at"]);
    p.started_at = detail::optTime(row["started_at"]);
    p.completed_at = detail::optTime(row["completed_at"]);
    p.created_by = detail::opt<uint32_t>(row["created_by"]);
    return p;
}

}

int64_t Plan::insert(const PlanRow& row) {
    return Transactions::exec("recovery::Plan::insert", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_plan_insert"},
                                  pqxx::params{row.vault_id, row.token, row.source_json, row.destination, row.items_json,
                                               row.summary_json, static_cast<double>(row.expires_at), row.created_by});
        return res.one_row_ref()["id"].as<int64_t>();
    });
}

std::optional<PlanRow> Plan::get(const int64_t id) {
    return Transactions::read("recovery::Plan::get", [&](pqxx::transaction_base& txn) -> std::optional<PlanRow> {
        const auto res = txn.exec(pqxx::prepped{"recovery_plan_get"}, pqxx::params{id});
        if (res.empty()) return std::nullopt;
        return planFromRow(res.one_row_ref());
    });
}

bool Plan::start(const int64_t id, const std::time_t now) {
    return Transactions::exec("recovery::Plan::start", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_plan_start"}, pqxx::params{id, static_cast<double>(now)});
        return res.affected_rows() > 0;
    });
}

bool Plan::finish(const int64_t id, const std::string& state, const std::string& resultJson) {
    if (state != "done" && state != "partial" && state != "failed")
        throw std::invalid_argument("a finished plan is done, partial or failed");
    return Transactions::exec("recovery::Plan::finish", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_plan_finish"}, pqxx::params{id, state, resultJson});
        return res.affected_rows() > 0;
    });
}

void Plan::saveResult(const int64_t id, const std::string& resultJson) {
    Transactions::exec("recovery::Plan::saveResult", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"recovery_plan_save_result"}, pqxx::params{id, resultJson});
    });
}

void Plan::saveItems(const int64_t id, const std::string& itemsJson) {
    Transactions::exec("recovery::Plan::saveItems", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"recovery_plan_save_items"}, pqxx::params{id, itemsJson});
    });
}

uint64_t Plan::expire(const std::time_t now) {
    return Transactions::exec("recovery::Plan::expire", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_plan_expire"}, pqxx::params{static_cast<double>(now)});
        return static_cast<uint64_t>(res.affected_rows());
    });
}

uint64_t Plan::purgeOlderThan(const std::time_t before) {
    return Transactions::exec("recovery::Plan::purgeOlderThan", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_plan_purge"}, pqxx::params{static_cast<double>(before)});
        return static_cast<uint64_t>(res.affected_rows());
    });
}

std::vector<PlanRow> Plan::listByVault(const uint32_t vaultId, const unsigned int limit) {
    return Transactions::read("recovery::Plan::listByVault", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_plan_list_by_vault"},
                                  pqxx::params{vaultId, detail::clampLimit(limit)});
        return mapRows(res, planFromRow);
    });
}

}
