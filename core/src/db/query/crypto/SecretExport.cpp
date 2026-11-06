#include "db/query/crypto/SecretExport.hpp"
#include "db/Transactions.hpp"

#include <pqxx/pqxx>

#include <algorithm>

namespace vh::db::query::crypto {

namespace {

// A PostgreSQL text[] literal: {"a","b"}. The names are fixed identifiers, but quote anyway.
std::string arrayLiteral(const std::vector<std::string>& values) {
    std::string out = "{";
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) out += ',';
        out += '"';
        for (const char c : values[i]) {
            if (c == '"' || c == '\\') out += '\\';
            out += c;
        }
        out += '"';
    }
    return out + "}";
}

}

void SecretExport::record(const std::optional<uint32_t> actorId, const std::string& actorName,
                          const std::vector<std::string>& secrets) {
    Transactions::exec("SecretExport::record", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO secret_exports (actor_id, actor_name, secrets) VALUES ($1, $2, $3::text[])",
                 pqxx::params{actorId ? std::optional<int64_t>(*actorId) : std::nullopt, actorName,
                              arrayLiteral(secrets)});
    });
}

std::optional<std::time_t> SecretExport::lastAt() {
    return Transactions::exec("SecretExport::lastAt", [&](pqxx::work& txn) -> std::optional<std::time_t> {
        const auto row = txn.exec("SELECT EXTRACT(EPOCH FROM MAX(exported_at))::BIGINT FROM secret_exports").one_row();
        if (row[0].is_null()) return std::nullopt;
        return static_cast<std::time_t>(row[0].as<long long>());
    });
}

void SecretExport::ageForTesting(const long long seconds) {
    Transactions::exec("SecretExport::ageForTesting", [&](pqxx::work& txn) {
        txn.exec("UPDATE secret_exports SET exported_at = exported_at - make_interval(secs => $1)",
                 pqxx::params{static_cast<double>(seconds)});
    });
}

void SecretExport::clearForTesting() {
    Transactions::exec("SecretExport::clearForTesting", [&](pqxx::work& txn) { txn.exec("DELETE FROM secret_exports"); });
}

}
