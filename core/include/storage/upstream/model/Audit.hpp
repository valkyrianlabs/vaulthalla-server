#pragma once

#include "db/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

// One upstream_audit row: a control-plane mutation or refusal worth keeping. Append only.
namespace vh::storage::upstream::model {

enum class AuditOutcome { Ok, Refused, Failed, Partial };

[[nodiscard]] std::string to_string(AuditOutcome o);
[[nodiscard]] AuditOutcome auditOutcomeFromString(const std::string& s);   // throws std::invalid_argument

struct AuditRecord {
    int64_t id{};
    std::time_t at{};
    std::optional<uint32_t> user_id;
    std::optional<std::string> user_name;
    std::string action;                 // "protect", "unprotect", "bucket.create", "cleanup", …
    std::string provider;
    std::string account_ref;
    std::string bucket;
    std::optional<uint32_t> api_key_id;
    std::optional<uint32_t> vault_id;
    AuditOutcome outcome{AuditOutcome::Ok};
    std::string detail_json{"{}"};      // a JSON object; never secrets

    AuditRecord() = default;
    explicit AuditRecord(pqxx::row_ref row);
};

}
