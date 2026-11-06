#include "crypto/secrets/Dependents.hpp"

#include "db/Transactions.hpp"

#include <pqxx/pqxx>

#include <string>

namespace vh::crypto::secrets::dependents {

namespace {

std::optional<std::string> describe(const char* ctx, const char* sql, const char* what) {
    const auto n = db::Transactions::exec(ctx, [&](pqxx::work& txn) {
        return txn.exec(sql).one_field().as<long long>();
    });
    if (n <= 0) return std::nullopt;
    return std::to_string(n) + " " + what;
}

}

DependentsCheck vaultMaster() {
    return [] {
        return describe("secrets::dependents::vaultMaster",
                        "SELECT (SELECT COUNT(*) FROM vault_keys) + (SELECT COUNT(*) FROM vault_keys_trashed) + "
                        "(SELECT COUNT(*) FROM vault_deletion_key)",
                        "vault key version(s)");
    };
}

DependentsCheck apiKeyMaster() {
    return [] {
        return describe("secrets::dependents::apiKeyMaster", "SELECT COUNT(*) FROM api_keys",
                        "provider API key secret(s)");
    };
}

DependentsCheck gatewayMaster() {
    return [] {
        return describe("secrets::dependents::gatewayMaster", "SELECT COUNT(*) FROM s3_gateway_credentials",
                        "S3 gateway credential secret(s)");
    };
}

DependentsCheck mfaSeal() {
    return [] {
        return describe("secrets::dependents::mfaSeal", "SELECT COUNT(*) FROM totp_factors", "sealed TOTP factor(s)");
    };
}

DependentsCheck mfaPepper() {
    return [] {
        return describe("secrets::dependents::mfaPepper", "SELECT COUNT(*) FROM recovery_codes",
                        "recovery code hash(es)");
    };
}

}
