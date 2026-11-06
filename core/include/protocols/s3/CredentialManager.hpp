#pragma once

#include "db/query/s3/Gateway.hpp"
#include "identities/Fwd.hpp"

#include <memory>
#include <optional>
#include <string>
#include <ctime>
#include <vector>

namespace vh::protocols::s3 {

struct GatewaySecret {
    db::query::s3::GatewayCredential credential;
    std::string secret_access_key;
};

using CredentialVaultAccessShorthand = db::query::s3::CredentialVaultAccessShorthand;

struct CredentialCreateOptions {
    uint32_t created_by{};
    uint32_t principal_user_id{};
    std::string name{};
    std::string scope_mode{"user_access"};
    std::optional<std::string> description{};
    std::optional<std::time_t> expires_at{};
    std::optional<uint32_t> default_vault_role_id{};
    std::vector<uint32_t> selected_vault_ids{};
    std::vector<vh::rbac::permission::Override> default_role_overrides{};
    std::vector<CredentialVaultAccessShorthand> vault_scopes{};
    bool enforce_budget_for_local_requests{false};
};

// S3 gateway credentials. Their secrets are wrapped under the S3 gateway master (s3gw_master), by version
// (crypto/secrets/Versioned.hpp; `vh secret master rotate --slot s3-gateway` rewraps them, #353): each row is
// unwrapped under the version it names, and a new one is written inside a Writer.
class CredentialManager {
public:
    CredentialManager();

    GatewaySecret createCredential(uint32_t userId, const std::string& name) const;
    GatewaySecret createCredential(const CredentialCreateOptions& options) const;
    std::vector<db::query::s3::GatewayCredential> listCredentials(std::optional<uint32_t> userId = std::nullopt) const;
    bool revokeCredential(const std::string& accessKeyOrName, std::optional<uint32_t> userId = std::nullopt) const;

    std::optional<GatewaySecret> findEnabledSecret(const std::string& accessKey) const;
    void markUsed(uint32_t credentialId) const;

    static std::string generateAccessKey();
    static std::string generateSecretKey();

private:
    [[nodiscard]] static std::string decryptSecret(const db::query::s3::GatewayCredential& credential);
};

}
