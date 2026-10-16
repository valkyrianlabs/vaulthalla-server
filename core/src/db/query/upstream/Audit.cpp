#include "db/query/upstream/Audit.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "log/Registry.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/result>

namespace vh::db::query::upstream {

namespace {

// detail must be a JSON object; anything else is wrapped so a caller's mistake never loses the audit row.
std::string objectJson(const std::string& detail) {
    const auto parsed = nlohmann::json::parse(detail.empty() ? std::string("{}") : detail, nullptr, false);
    if (parsed.is_object()) return parsed.dump();
    return nlohmann::json{{"detail", detail}}.dump();
}

}

int64_t Audit::append(const AuditModel& record) {
    return Transactions::exec("upstream::Audit::append", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_audit_append"},
                                  pqxx::params{record.user_id, record.user_name, record.action, record.provider,
                                               record.account_ref, record.bucket, record.api_key_id, record.vault_id,
                                               storage::upstream::model::to_string(record.outcome),
                                               objectJson(record.detail_json)});
        return res.one_field_ref().as<int64_t>();
    });
}

void Audit::appendNoThrow(const AuditModel& record) noexcept {
    try {
        (void)append(record);
    } catch (const std::exception& e) {
        try {
            log::Registry::storage()->error("[upstream::audit] could not record '{}' on '{}': {}", record.action,
                                            record.bucket, e.what());
        } catch (...) {}
    } catch (...) {}
}

std::vector<AuditModel> Audit::list(const std::optional<std::string>& bucket, const unsigned int limit) {
    return Transactions::exec("upstream::Audit::list", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_audit_list"},
                                  pqxx::params{bucket, std::max(1u, std::min(limit, 1000u))});
        return rowsAs<AuditModel>(res);
    });
}

}
