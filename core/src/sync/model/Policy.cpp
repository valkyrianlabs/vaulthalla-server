#include "sync/model/Policy.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/encoding/interval.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/row>

using namespace vh::sync::model;
using namespace vh::db::encoding;

Policy::Policy(pqxx::row_ref row)
    : id(row.at("id").as<unsigned int>()),
      vault_id(row.at("vault_id").as<unsigned int>()),
      interval(clampInterval(std::chrono::seconds(row.at("interval").as<int64_t>()))),
      enabled(row.at("enabled").as<bool>()),
      created_at(parsePostgresTimestamp(row.at("created_at").as<std::string>())),
      updated_at(parsePostgresTimestamp(row.at("updated_at").as<std::string>())) {
    if (!row["last_sync_at"].is_null()) last_sync_at = parsePostgresTimestamp(row["last_sync_at"].as<std::string>());
    if (!row["last_success_at"].is_null()) last_success_at = parsePostgresTimestamp(row["last_success_at"].as<std::string>());
}

std::chrono::seconds Policy::clampInterval(const std::chrono::seconds value) {
    if (value.count() <= 0) return DEFAULT_SYNC_INTERVAL;
    return value;
}

void vh::sync::model::to_json(nlohmann::json& j, const Policy& s) {
    j = nlohmann::json{
        {"id", s.id},
        {"vault_id", s.vault_id},
        {"interval", intervalToString(s.interval)},
        {"enabled", s.enabled},
        {"last_sync_at", timestampToString(s.last_sync_at)},
        {"last_success_at", timestampToString(s.last_success_at)},
        {"created_at", timestampToString(s.created_at)},
        {"updated_at", timestampToString(s.updated_at)}
    };
}

void vh::sync::model::from_json(const nlohmann::json& j, Policy& s) {
    if (j.contains("id")) s.id = j.at("id").get<unsigned int>();
    if (j.contains("vault_id")) s.vault_id = j.at("vault_id").get<unsigned int>();
    if (j.contains("interval")) {
        if (j.at("interval").is_number_integer())
            s.interval = Policy::clampInterval(std::chrono::seconds(j.at("interval").get<int64_t>()));
        else if (j.at("interval").is_string())
            s.interval = Policy::clampInterval(parseSyncInterval(j.at("interval").get<std::string>()));
    }
    s.enabled = j.value("enabled", true);
    if (j.contains("last_sync_at")) s.last_sync_at = parseTimestampFromString(j.at("last_sync_at").get<std::string>());
    if (j.contains("last_success_at")) s.last_success_at = parseTimestampFromString(j.at("last_success_at").get<std::string>());
    if (j.contains("created_at")) s.created_at = parseTimestampFromString(j.at("created_at").get<std::string>());
    if (j.contains("updated_at")) s.updated_at = parseTimestampFromString(j.at("updated_at").get<std::string>());
}

std::string vh::sync::model::to_string(const std::shared_ptr<Policy>& sync) {
    if (!sync) return "null";
    return "Vault Sync Configuration:\n"
           "  Vault ID: " + std::to_string(sync->vault_id) + "\n"
           "  Interval: " + intervalToString(sync->interval) + "\n"
           "  Enabled: " + (sync->enabled ? "true" : "false") + "\n"
           "  Last Sync At: " + timestampToString(sync->last_sync_at) + "\n"
           "  Last Success At: " + timestampToString(sync->last_success_at) + "\n"
           "  Created At: " + timestampToString(sync->created_at) + "\n"
           "  Updated At: " + timestampToString(sync->updated_at);
}
