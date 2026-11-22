#include "db/query/connector/Connector.hpp"

#include "db/Transactions.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <cctype>

namespace vh::db::query::connector {

// Named, not anonymous: the unity build joins this file with the other query files.
namespace connector_query_detail {

using Json = nlohmann::json;

std::optional<std::time_t> optTime(const pqxx::field_ref& f) {
    if (f.is_null()) return std::nullopt;
    return static_cast<std::time_t>(f.as<int64_t>());
}

std::optional<std::string> optStr(const pqxx::field_ref& f) {
    if (f.is_null()) return std::nullopt;
    return f.as<std::string>();
}

std::optional<uint32_t> optId(const pqxx::field_ref& f) {
    if (f.is_null()) return std::nullopt;
    return f.as<uint32_t>();
}

std::optional<int64_t> optParam(const std::optional<uint32_t>& v) {
    return v ? std::optional<int64_t>(*v) : std::nullopt;
}

std::optional<int64_t> optParam(const std::optional<std::time_t>& v) {
    return v ? std::optional<int64_t>(static_cast<int64_t>(*v)) : std::nullopt;
}

// TEXT[] travels as JSON both ways, so no array-literal quoting is ever written by hand.
std::string jsonArray(const std::vector<std::string>& v) { return Json(v).dump(); }

std::vector<std::string> fromJsonArray(const pqxx::field_ref& f) {
    if (f.is_null()) return {};
    return Json::parse(f.as<std::string>()).get<std::vector<std::string>>();
}

constexpr const char* kClientColumns =
    "id::text, client_id, kind, name, array_to_json(redirect_uris)::text AS redirect_uris, document_sha256, "
    "EXTRACT(EPOCH FROM fetched_at)::BIGINT AS fetched_at, EXTRACT(EPOCH FROM cache_until)::BIGINT AS cache_until, "
    "created_by, EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, "
    "EXTRACT(EPOCH FROM last_used_at)::BIGINT AS last_used_at, EXTRACT(EPOCH FROM disabled_at)::BIGINT AS disabled_at";

ClientRow clientFrom(const pqxx::row_ref& r) {
    return {.id = r["id"].as<std::string>(),
            .client_id = r["client_id"].as<std::string>(),
            .kind = r["kind"].as<std::string>(),
            .name = r["name"].as<std::string>(),
            .redirect_uris = fromJsonArray(r["redirect_uris"]),
            .document_sha256 = optStr(r["document_sha256"]),
            .fetched_at = optTime(r["fetched_at"]),
            .cache_until = optTime(r["cache_until"]),
            .created_by = optId(r["created_by"]),
            .created_at = static_cast<std::time_t>(r["created_at"].as<int64_t>()),
            .last_used_at = optTime(r["last_used_at"]),
            .disabled_at = optTime(r["disabled_at"])};
}

constexpr const char* kGrantColumns =
    "g.id::text AS id, g.user_id, g.client_row::text AS client_row, g.client_id, g.client_name, g.redirect_uri, "
    "g.scope, g.resource, g.label, g.approved_via, EXTRACT(EPOCH FROM g.created_at)::BIGINT AS created_at, "
    "EXTRACT(EPOCH FROM g.expires_at)::BIGINT AS expires_at, EXTRACT(EPOCH FROM g.last_used_at)::BIGINT AS last_used_at, "
    "g.last_ip, EXTRACT(EPOCH FROM g.revoked_at)::BIGINT AS revoked_at, g.revoked_reason, g.revoked_by, "
    "EXISTS (SELECT 1 FROM connector_refresh_tokens t WHERE t.grant_id = g.id) AS redeemed, "
    "(SELECT EXTRACT(EPOCH FROM MAX(t.expires_at))::BIGINT FROM connector_refresh_tokens t WHERE t.grant_id = g.id "
    "AND t.used_at IS NULL AND t.revoked_at IS NULL) AS refresh_expires_at";

GrantRow grantFrom(const pqxx::row_ref& r) {
    return {.id = r["id"].as<std::string>(),
            .user_id = r["user_id"].as<uint32_t>(),
            .client_row = r["client_row"].as<std::string>(),
            .client_id = r["client_id"].as<std::string>(),
            .client_name = r["client_name"].as<std::string>(),
            .redirect_uri = r["redirect_uri"].as<std::string>(),
            .scope = r["scope"].as<std::string>(),
            .resource = r["resource"].as<std::string>(),
            .label = optStr(r["label"]),
            .approved_via = r["approved_via"].as<std::string>(),
            .created_at = static_cast<std::time_t>(r["created_at"].as<int64_t>()),
            .expires_at = static_cast<std::time_t>(r["expires_at"].as<int64_t>()),
            .last_used_at = optTime(r["last_used_at"]),
            .last_ip = optStr(r["last_ip"]),
            .revoked_at = optTime(r["revoked_at"]),
            .revoked_reason = optStr(r["revoked_reason"]),
            .revoked_by = optId(r["revoked_by"]),
            .redeemed = r["redeemed"].as<bool>(),
            .refresh_expires_at = optTime(r["refresh_expires_at"])};
}

std::optional<GrantRow> grantById(pqxx::transaction_base& txn, const std::string& id) {
    const auto res = txn.exec(std::string("SELECT ") + kGrantColumns + " FROM connector_grants g WHERE g.id = $1::uuid",
                              pqxx::params{id});
    if (res.empty()) return std::nullopt;
    return grantFrom(res[0]);
}

bool revokeIn(pqxx::work& txn, const std::string& id, const std::string& reason, const std::optional<uint32_t> by) {
    const bool was = txn.exec("UPDATE connector_grants SET revoked_at = NOW(), revoked_reason = $2, revoked_by = $3 "
                              "WHERE id = $1::uuid AND revoked_at IS NULL",
                              pqxx::params{id, reason, optParam(by)})
                         .affected_rows() > 0;
    txn.exec("UPDATE connector_refresh_tokens SET revoked_at = NOW() WHERE grant_id = $1::uuid AND revoked_at IS NULL",
             pqxx::params{id});
    return was;
}

bool looksLikeUuid(const std::string& s) {
    if (s.size() != 36) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return false;
        } else if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

}

// ---- settings ---------------------------------------------------------------------------------------------------------

SettingsRow Settings::get() {
    namespace d = connector_query_detail;
    return Transactions::read("connector::Settings::get", [](pqxx::transaction_base& txn) {
        const auto res = txn.exec("SELECT enabled, public_origin, max_scope, dcr_enabled, "
                                  "array_to_json(client_hosts)::text AS client_hosts, changed_by, "
                                  "EXTRACT(EPOCH FROM changed_at)::BIGINT AS changed_at FROM connector_settings WHERE id = 1");
        if (res.empty()) return SettingsRow{};
        const auto r = res[0];
        return SettingsRow{.enabled = r["enabled"].as<bool>(),
                           .public_origin = d::optStr(r["public_origin"]),
                           .max_scope = r["max_scope"].as<std::string>(),
                           .dcr_enabled = r["dcr_enabled"].as<bool>(),
                           .client_hosts = d::fromJsonArray(r["client_hosts"]),
                           .changed_by = d::optId(r["changed_by"]),
                           .changed_at = d::optTime(r["changed_at"])};
    });
}

void Settings::put(const SettingsRow& row, const std::optional<uint32_t> by) {
    namespace d = connector_query_detail;
    Transactions::exec("connector::Settings::put", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO connector_settings (id, enabled, public_origin, max_scope, dcr_enabled, client_hosts, "
                 "changed_by, changed_at) VALUES (1, $1, $2, $3, $4, ARRAY(SELECT jsonb_array_elements_text($5::jsonb)), "
                 "$6, NOW()) ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled, "
                 "public_origin = EXCLUDED.public_origin, max_scope = EXCLUDED.max_scope, "
                 "dcr_enabled = EXCLUDED.dcr_enabled, client_hosts = EXCLUDED.client_hosts, "
                 "changed_by = EXCLUDED.changed_by, changed_at = EXCLUDED.changed_at",
                 pqxx::params{row.enabled, row.public_origin, row.max_scope, row.dcr_enabled, d::jsonArray(row.client_hosts),
                              d::optParam(by)});
    });
}

// ---- clients ----------------------------------------------------------------------------------------------------------

std::optional<ClientRow> Clients::byClientId(const std::string& clientId) {
    namespace d = connector_query_detail;
    return Transactions::read("connector::Clients::byClientId", [&](pqxx::transaction_base& txn) -> std::optional<ClientRow> {
        const auto res = txn.exec(std::string("SELECT ") + d::kClientColumns + " FROM connector_clients WHERE client_id = $1",
                                  pqxx::params{clientId});
        if (res.empty()) return std::nullopt;
        return d::clientFrom(res[0]);
    });
}

std::optional<ClientRow> Clients::byId(const std::string& id) {
    namespace d = connector_query_detail;
    if (!d::looksLikeUuid(id)) return std::nullopt;
    return Transactions::read("connector::Clients::byId", [&](pqxx::transaction_base& txn) -> std::optional<ClientRow> {
        const auto res = txn.exec(std::string("SELECT ") + d::kClientColumns + " FROM connector_clients WHERE id = $1::uuid",
                                  pqxx::params{id});
        if (res.empty()) return std::nullopt;
        return d::clientFrom(res[0]);
    });
}

std::vector<ClientRow> Clients::list() {
    namespace d = connector_query_detail;
    return Transactions::read("connector::Clients::list", [](pqxx::transaction_base& txn) {
        std::vector<ClientRow> out;
        for (const auto& r : txn.exec(std::string("SELECT ") + d::kClientColumns +
                                      " FROM connector_clients ORDER BY disabled_at IS NOT NULL, created_at DESC, id"))
            out.push_back(d::clientFrom(r));
        return out;
    });
}

ClientRow Clients::insert(const NewClient& c) {
    namespace d = connector_query_detail;
    return Transactions::exec("connector::Clients::insert", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            std::string("INSERT INTO connector_clients (client_id, kind, name, redirect_uris, document_sha256, fetched_at, "
                        "cache_until, created_by) VALUES ($1, $2, $3, ARRAY(SELECT jsonb_array_elements_text($4::jsonb)), $5, "
                        "to_timestamp($6), to_timestamp($7), $8) RETURNING ") + d::kClientColumns,
            pqxx::params{c.client_id, c.kind, c.name, d::jsonArray(c.redirect_uris), c.document_sha256,
                         d::optParam(c.fetched_at), d::optParam(c.cache_until), d::optParam(c.created_by)});
        return d::clientFrom(res[0]);
    });
}

bool Clients::disable(const std::string& id) {
    namespace d = connector_query_detail;
    if (!d::looksLikeUuid(id)) return false;
    return Transactions::exec("connector::Clients::disable", [&](pqxx::work& txn) {
        return txn.exec("UPDATE connector_clients SET disabled_at = NOW() WHERE id = $1::uuid AND disabled_at IS NULL",
                        pqxx::params{id})
                   .affected_rows() > 0;
    });
}

// ---- grants -----------------------------------------------------------------------------------------------------------

GrantRow Grants::create(const NewGrant& g) {
    namespace d = connector_query_detail;
    return Transactions::exec("connector::Grants::create", [&](pqxx::work& txn) {
        const auto id = txn.exec("INSERT INTO connector_grants (user_id, client_row, client_id, client_name, redirect_uri, "
                                 "scope, resource, label, approved_via, expires_at) VALUES ($1, $2::uuid, $3, $4, $5, $6, "
                                 "$7, $8, $9, to_timestamp($10)) RETURNING id::text",
                                 pqxx::params{g.user_id, g.client_row, g.client_id, g.client_name, g.redirect_uri, g.scope,
                                              g.resource, g.label, g.approved_via, static_cast<int64_t>(g.expires_at)})
                            .one_field_ref()
                            .as<std::string>();
        return *d::grantById(txn, id);
    });
}

std::optional<GrantRow> Grants::byId(const std::string& id) {
    namespace d = connector_query_detail;
    if (!d::looksLikeUuid(id)) return std::nullopt;
    return Transactions::read("connector::Grants::byId",
                              [&](pqxx::transaction_base& txn) { return d::grantById(txn, id); });
}

std::vector<GrantRow> Grants::list(const std::optional<uint32_t> userId) {
    namespace d = connector_query_detail;
    return Transactions::read("connector::Grants::list", [&](pqxx::transaction_base& txn) {
        std::vector<GrantRow> out;
        for (const auto& r : txn.exec(std::string("SELECT ") + d::kGrantColumns +
                                          " FROM connector_grants g WHERE ($1::INTEGER IS NULL OR g.user_id = $1) "
                                          "ORDER BY g.revoked_at IS NOT NULL, g.created_at DESC, g.id",
                                      pqxx::params{d::optParam(userId)}))
            out.push_back(d::grantFrom(r));
        return out;
    });
}

std::vector<GrantRow> Grants::listLive(const std::optional<std::vector<uint32_t>>& userIds) {
    namespace d = connector_query_detail;
    std::optional<std::string> ids;
    if (userIds) {
        nlohmann::json a = nlohmann::json::array();
        for (const auto id : *userIds) a.push_back(id);
        ids = a.dump();
    }
    return Transactions::read("connector::Grants::listLive", [&](pqxx::transaction_base& txn) {
        std::vector<GrantRow> out;
        for (const auto& r : txn.exec(std::string("SELECT ") + d::kGrantColumns +
                                          " FROM connector_grants g WHERE g.revoked_at IS NULL AND ($1::jsonb IS NULL OR "
                                          "g.user_id IN (SELECT jsonb_array_elements_text($1::jsonb)::INTEGER)) "
                                          "ORDER BY g.created_at, g.id",
                                      pqxx::params{ids}))
            out.push_back(d::grantFrom(r));
        return out;
    });
}

bool Grants::revoke(const std::string& id, const std::string& reason, const std::optional<uint32_t> by) {
    namespace d = connector_query_detail;
    if (!d::looksLikeUuid(id)) return false;
    return Transactions::exec("connector::Grants::revoke", [&](pqxx::work& txn) { return d::revokeIn(txn, id, reason, by); });
}

void Grants::touch(const std::string& id, const std::optional<std::string>& ip) {
    namespace d = connector_query_detail;
    if (!d::looksLikeUuid(id)) return;
    Transactions::exec("connector::Grants::touch", [&](pqxx::work& txn) {
        txn.exec("UPDATE connector_grants SET last_used_at = NOW(), last_ip = COALESCE($2, last_ip) WHERE id = $1::uuid",
                 pqxx::params{id, ip});
    });
}

bool Grants::insertFirstRefreshToken(const std::string& grantId, const std::string& digest, const std::time_t expiresAt) {
    namespace d = connector_query_detail;
    if (!d::looksLikeUuid(grantId)) return false;
    return Transactions::exec("connector::Grants::insertFirstRefreshToken", [&](pqxx::work& txn) {
        // The grant row is locked, so two redemptions of one code can't both find it without a token.
        const auto g = txn.exec("SELECT 1 FROM connector_grants WHERE id = $1::uuid AND revoked_at IS NULL "
                                "AND expires_at > NOW() FOR UPDATE",
                                pqxx::params{grantId});
        if (g.empty()) return false;
        if (!txn.exec("SELECT 1 FROM connector_refresh_tokens WHERE grant_id = $1::uuid LIMIT 1", pqxx::params{grantId})
                 .empty())
            return false;
        txn.exec("INSERT INTO connector_refresh_tokens (grant_id, token_digest, expires_at) VALUES "
                 "($1::uuid, $2, LEAST(to_timestamp($3), (SELECT expires_at FROM connector_grants WHERE id = $1::uuid)))",
                 pqxx::params{grantId, digest, static_cast<int64_t>(expiresAt)});
        return true;
    });
}

Rotation Grants::rotate(const std::string& digest, const std::string& clientId, const std::string& successorDigest,
                        const int64_t idleSeconds, const int64_t allowanceSeconds) {
    namespace d = connector_query_detail;
    return Transactions::exec("connector::Grants::rotate", [&](pqxx::work& txn) {
        using O = Rotation::Outcome;
        const auto res = txn.exec(
            "SELECT t.id, t.grant_id::text AS grant_id, t.successor_id, "
            "t.used_at IS NOT NULL AS used, t.revoked_at IS NOT NULL AS revoked, t.expires_at <= NOW() AS expired, "
            "t.used_at > NOW() - make_interval(secs => $2) AS within_allowance, "
            "g.revoked_at IS NOT NULL AS grant_revoked, g.expires_at <= NOW() AS grant_expired, g.client_id "
            "FROM connector_refresh_tokens t JOIN connector_grants g ON g.id = t.grant_id "
            "WHERE t.token_digest = $1 FOR UPDATE OF t, g",
            pqxx::params{digest, static_cast<double>(allowanceSeconds)});
        if (res.empty()) return Rotation{.outcome = O::Unknown};
        const auto r = res[0];
        const auto tokenId = r["id"].as<int64_t>();
        const auto grantId = r["grant_id"].as<std::string>();
        if (r["client_id"].as<std::string>() != clientId) return Rotation{.outcome = O::WrongClient};
        if (r["grant_revoked"].as<bool>()) return Rotation{.outcome = O::GrantEnded, .grant = d::grantById(txn, grantId)};
        if (r["grant_expired"].as<bool>() || (!r["used"].as<bool>() && !r["revoked"].as<bool>() && r["expired"].as<bool>())) {
            (void)d::revokeIn(txn, grantId, "expired", std::nullopt);
            return Rotation{.outcome = O::Expired, .grant = d::grantById(txn, grantId)};
        }

        const auto storeSuccessor = [&] {
            const auto next = txn.exec("INSERT INTO connector_refresh_tokens (grant_id, token_digest, expires_at) VALUES "
                                       "($1::uuid, $2, LEAST(NOW() + make_interval(secs => $3), "
                                       "(SELECT expires_at FROM connector_grants WHERE id = $1::uuid))) RETURNING id",
                                       pqxx::params{grantId, successorDigest, static_cast<double>(idleSeconds)})
                                  .one_field_ref()
                                  .as<int64_t>();
            txn.exec("UPDATE connector_refresh_tokens SET used_at = COALESCE(used_at, NOW()), successor_id = $2 WHERE id = $1",
                     pqxx::params{tokenId, next});
        };

        if (!r["used"].as<bool>() && !r["revoked"].as<bool>()) {
            storeSuccessor();
            return Rotation{.outcome = O::Rotated, .grant = d::grantById(txn, grantId)};
        }

        // Presented again. A lost response is allowed for once: the token was used moments ago and the successor it
        // got has never been used (nor revoked); that successor is revoked and replaced. Anything else is reuse.
        if (!r["revoked"].as<bool>() && !r["within_allowance"].is_null() && r["within_allowance"].as<bool>() &&
            !r["successor_id"].is_null()) {
            const auto successor = r["successor_id"].as<int64_t>();
            const auto s = txn.exec("SELECT used_at IS NULL AND revoked_at IS NULL FROM connector_refresh_tokens "
                                    "WHERE id = $1 FOR UPDATE",
                                    pqxx::params{successor});
            if (!s.empty() && s[0][0].as<bool>()) {
                txn.exec("UPDATE connector_refresh_tokens SET revoked_at = NOW() WHERE id = $1", pqxx::params{successor});
                storeSuccessor();
                return Rotation{.outcome = O::Allowance, .grant = d::grantById(txn, grantId)};
            }
        }
        (void)d::revokeIn(txn, grantId, "refresh_reuse", std::nullopt);
        return Rotation{.outcome = O::Reused, .grant = d::grantById(txn, grantId)};
    });
}

}
