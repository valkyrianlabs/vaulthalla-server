#include "db/query/cloud/Link.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"

#include <pqxx/pqxx>

#include <algorithm>
#include <stdexcept>

namespace vh::db::query::cloud {

namespace link_detail {

constexpr const char* kColumns =
    "endpoint, status, public_key, name, request_id, EXTRACT(EPOCH FROM request_expires_at)::BIGINT, installation_id, "
    "account_id, requested_by, EXTRACT(EPOCH FROM requested_at)::BIGINT, EXTRACT(EPOCH FROM linked_at)::BIGINT, "
    "deployment_id, account_public_id, EXTRACT(EPOCH FROM key_checked_at)::BIGINT, key_check, key_check_detail, "
    "EXTRACT(EPOCH FROM offline_copy_at)::BIGINT";

std::optional<std::string> text(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return f.as<std::string>();
}

std::optional<std::time_t> time(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return static_cast<std::time_t>(f.as<int64_t>());
}

}

std::optional<LinkRow> Link::get() {
    return Transactions::exec("cloud::Link::get", [&](pqxx::work& txn) -> std::optional<LinkRow> {
        const auto res = txn.exec(std::string("SELECT ") + link_detail::kColumns + " FROM cloud_link");
        if (res.empty()) return std::nullopt;
        const auto r = res[0];
        LinkRow row;
        row.endpoint = r[0].as<std::string>();
        row.status = r[1].as<std::string>();
        const auto pk = encoding::from_hex_bytea(r[2].as<std::string>());
        if (pk.size() != row.public_key.size()) throw std::runtime_error("cloud_link.public_key is not 32 bytes");
        std::ranges::copy(pk, row.public_key.begin());
        row.name = r[3].as<std::string>();
        if (!r[4].is_null()) row.request_id = r[4].as<std::string>();
        row.request_expires_at = link_detail::time(r[5]);
        if (!r[6].is_null()) row.installation_id = r[6].as<std::string>();
        if (!r[7].is_null()) row.account_id = r[7].as<int64_t>();
        row.requested_by = r[8].as<std::string>();
        row.requested_at = static_cast<std::time_t>(r[9].as<int64_t>());
        row.linked_at = link_detail::time(r[10]);
        row.deployment_id = link_detail::text(r[11]);
        row.account_public_id = link_detail::text(r[12]);
        row.key_checked_at = link_detail::time(r[13]);
        row.key_check = link_detail::text(r[14]);
        row.key_check_detail = link_detail::text(r[15]);
        row.offline_copy_at = link_detail::time(r[16]);
        return row;
    });
}

bool Link::putPending(const LinkRow& row) {
    return Transactions::exec("cloud::Link::putPending", [&](pqxx::work& txn) {
        const auto existing = txn.exec("SELECT status FROM cloud_link FOR UPDATE");
        if (!existing.empty() && existing[0][0].as<std::string>() == "linked") return false;
        txn.exec("DELETE FROM cloud_link");
        const auto pk = encoding::to_hex_bytea({row.public_key.begin(), row.public_key.end()});
        txn.exec("INSERT INTO cloud_link (endpoint, status, public_key, name, request_id, request_expires_at, requested_by) "
                 "VALUES ($1, 'pending', $2, $3, $4, to_timestamp($5), $6)",
                 pqxx::params{row.endpoint, pk, row.name, row.request_id,
                              static_cast<int64_t>(row.request_expires_at.value_or(0)), row.requested_by});
        return true;
    });
}

bool Link::markLinked(const std::string& requestId, const std::string& installationId, const int64_t accountId,
                      const std::optional<std::string>& deploymentId,
                      const std::optional<std::string>& accountPublicId) {
    return Transactions::exec("cloud::Link::markLinked", [&](pqxx::work& txn) {
        return txn.exec("UPDATE cloud_link SET status = 'linked', installation_id = $2, account_id = $3, "
                        "deployment_id = $4, account_public_id = $5, "
                        "linked_at = CURRENT_TIMESTAMP, request_id = NULL, request_expires_at = NULL "
                        "WHERE status = 'pending' AND request_id = $1",
                        pqxx::params{requestId, installationId, accountId, deploymentId, accountPublicId})
                   .affected_rows() == 1;
    });
}

bool Link::fillAccount(const std::optional<std::string>& deploymentId, const std::string& accountPublicId) {
    return Transactions::exec("cloud::Link::fillAccount", [&](pqxx::work& txn) {
        return txn.exec("UPDATE cloud_link SET account_public_id = $2, "
                        "deployment_id = COALESCE(deployment_id, $1) "
                        "WHERE status = 'linked' AND account_public_id IS NULL",
                        pqxx::params{deploymentId, accountPublicId})
                   .affected_rows() == 1;
    });
}

void Link::recordKeyCheck(const std::string& outcome, const std::optional<std::string>& detail,
                          const std::optional<std::time_t> offlineCopyAt) {
    Transactions::exec("cloud::Link::recordKeyCheck", [&](pqxx::work& txn) {
        txn.exec("UPDATE cloud_link SET key_checked_at = CURRENT_TIMESTAMP, key_check = $1, key_check_detail = $2, "
                 "offline_copy_at = CASE WHEN $1 = 'ok' OR $1 = 'none' THEN to_timestamp($3::bigint) "
                 "ELSE offline_copy_at END WHERE status = 'linked'",
                 pqxx::params{outcome, detail,
                              offlineCopyAt ? std::optional<int64_t>(static_cast<int64_t>(*offlineCopyAt))
                                            : std::optional<int64_t>{}});
    });
}

void Link::clear() {
    Transactions::exec("cloud::Link::clear", [&](pqxx::work& txn) { txn.exec("DELETE FROM cloud_link"); });
}

}
