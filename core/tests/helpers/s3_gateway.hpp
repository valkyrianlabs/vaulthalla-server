#pragma once

// S3 gateway test helpers shared by test_s3_gateway.cpp, test_s3_cost_safety.cpp and test_fs_cache_delete.cpp:
// config restore, unique labels, a request signed as a client signs it (vl-sigv4) and raw-SQL users with an admin role.

#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "protocols/s3/Router.hpp"
#include "rbac/role/Admin.hpp"

#include <pqxx/pqxx>
#include <vl/sigv4/canonical.hpp>
#include <vl/sigv4/crypto.hpp>
#include <vl/sigv4/signer.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

namespace vh::test::s3gw {

// Puts the config back when the test ends.
struct ConfigRestore {
    vh::config::Config previous;

    explicit ConfigRestore(vh::config::Config cfg) : previous(std::move(cfg)) {}
    ~ConfigRestore() { vh::config::Registry::set(previous); }
};

inline std::string uniqueSuffix(const std::string& label) {
    return label + "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
}

// Signs `request` (its method, target, Host header and body) now, in us-east-1, as a client does with vl::sigv4::sign:
// sets host, x-amz-date, x-amz-content-sha256 (the body's hash), Authorization and the request-target. `extraSigned`
// headers are signed too and set on the request.
inline void signRequest(vh::protocols::s3::Router::Request& request, const std::string& accessKey,
                        const std::string& secretKey, const vl::sigv4::HeaderList& extraSigned = {}) {
    const std::string target(request.target());
    const auto q = target.find('?');
    const vl::sigv4::Request toSign{
        .method = std::string(request.method_string()),
        .host = std::string(request[boost::beast::http::field::host]),
        .path = vl::sigv4::uriDecode(target.substr(0, q)),
        .query = q == std::string::npos ? vl::sigv4::QueryParams{} : vl::sigv4::parseQuery(target.substr(q + 1)),
        .headers = extraSigned,
        .payload_hash = vl::sigv4::sha256Hex(request.body())};
    const auto s = vl::sigv4::sign(toSign, {.access_key = accessKey, .secret_key = secretKey, .session_token = {}},
                                   "us-east-1", "s3", vl::sigv4::Clock::now());
    request.target(s.target());
    for (const auto& [name, value] : s.headers) request.set(name, value);
}

// Upserts `role` into admin_role by name; returns its id.
inline uint32_t ensureAdminRole(pqxx::work& txn, const vh::rbac::role::Admin& role) {
    return txn.exec(
        R"SQL(
            INSERT INTO admin_role (
                name, description, identity_permissions, audit_permissions, settings_permissions, roles_permissions,
                vaults_permissions, keys_permissions, s3_gateway_permissions
            )
            VALUES ($1, $2, $3::bit(32), $4::bit(8), $5::bit(64), $6::bit(16), $7::bit(32), $8::bit(32), $9::bit(8))
            ON CONFLICT (name) DO UPDATE SET
                description = EXCLUDED.description,
                identity_permissions = EXCLUDED.identity_permissions,
                audit_permissions = EXCLUDED.audit_permissions,
                settings_permissions = EXCLUDED.settings_permissions,
                roles_permissions = EXCLUDED.roles_permissions,
                vaults_permissions = EXCLUDED.vaults_permissions,
                keys_permissions = EXCLUDED.keys_permissions,
                s3_gateway_permissions = EXCLUDED.s3_gateway_permissions
            RETURNING id
        )SQL",
        pqxx::params{role.name, role.description, role.identities.toBitString(), role.audits.toBitString(),
                     role.settings.toBitString(), role.roles.toBitString(), role.vaults.toBitString(),
                     role.keys.toBitString(), role.s3Gateway.toBitString()})
        .one_field_ref()
        .as<uint32_t>();
}

// A users row (password hash "hash") assigned `role`, hydratable by identities::Manager; returns its id.
inline uint32_t insertUser(pqxx::work& txn, const std::string& name, const std::string& email,
                           const vh::rbac::role::Admin& role = vh::rbac::role::Admin::None()) {
    const auto userId = txn.exec("INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
                                 pqxx::params{name, email, "hash"})
                            .one_field_ref()
                            .as<uint32_t>();
    txn.exec("INSERT INTO admin_role_assignments (user_id, role_id) VALUES ($1, $2)",
             pqxx::params{userId, ensureAdminRole(txn, role)});
    return userId;
}

}
