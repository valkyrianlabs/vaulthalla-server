#include "db/query/upstream/WriteIntent.hpp"

#include "db/Transactions.hpp"

#include <pqxx/result>

namespace vh::db::query::upstream {

int64_t WriteIntent::record(const uint32_t vaultId, const std::string& key, const storage::upstream::model::WriteOp op,
                            const std::optional<uint64_t> expectedSize, const std::chrono::seconds ttl) {
    const std::optional<int64_t> size = expectedSize ? std::make_optional(static_cast<int64_t>(*expectedSize)) : std::nullopt;
    return Transactions::exec("upstream::WriteIntent::record", [&](pqxx::work& txn) {
        return txn.exec(pqxx::prepped{"upstream_write_intent_record"},
                        pqxx::params{vaultId, key, storage::upstream::model::to_string(op), size,
                                     static_cast<double>(ttl.count())})
            .one_field_ref()
            .as<int64_t>();
    });
}

void WriteIntent::complete(const int64_t id, const std::optional<std::string>& etag, const std::chrono::seconds ttl) {
    Transactions::exec("upstream::WriteIntent::complete", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_write_intent_complete"}, pqxx::params{id, etag, static_cast<double>(ttl.count())});
    });
}

void WriteIntent::remove(const int64_t id) {
    Transactions::exec("upstream::WriteIntent::remove", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_write_intent_remove"}, pqxx::params{id});
    });
}

bool WriteIntent::consumeMatching(const uint32_t vaultId, const std::string& key, const storage::upstream::model::WriteOp op,
                                  const std::optional<uint64_t> size, const std::time_t eventTime,
                                  const std::optional<std::string>& etag) {
    const std::optional<int64_t> sizeParam = size ? std::make_optional(static_cast<int64_t>(*size)) : std::nullopt;
    return Transactions::exec("upstream::WriteIntent::consumeMatching", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_write_intent_consume"},
                                  pqxx::params{vaultId, key, storage::upstream::model::to_string(op), sizeParam,
                                               static_cast<double>(eventTime), etag});
        return !res.empty();
    });
}

uint64_t WriteIntent::sweepExpired() {
    return Transactions::exec("upstream::WriteIntent::sweepExpired", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_write_intent_sweep"});
        return static_cast<uint64_t>(res.affected_rows());
    });
}

}
