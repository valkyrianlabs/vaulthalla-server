#include "protocols/s3/CredentialManager.hpp"
#include "crypto/SecretBytes.hpp"
#include "crypto/secrets/Versioned.hpp"
#include "db/query/s3/Gateway.hpp"

#include <array>
#include <sodium.h>
#include <stdexcept>

namespace vh::protocols::s3 {

namespace {
constexpr auto kGatewayMasterSlot = crypto::secrets::versioned::Slot::GatewayMaster;
constexpr std::string_view kAccessAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
constexpr std::string_view kSecretAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";

std::string randomFromAlphabet(const std::string_view alphabet, const std::size_t length) {
    if (sodium_init() < 0) throw std::runtime_error("libsodium initialization failed");
    std::string out;
    out.reserve(length);
    for (std::size_t i = 0; i < length; ++i)
        out.push_back(alphabet[randombytes_uniform(alphabet.size())]);
    return out;
}

bool validScopeMode(const std::string& mode) {
    return mode == "user_access" || mode == "global" || mode == "vault_allowlist";
}

// Shape only. Who may create which credential is ops::s3_gateway's to decide, before it calls this.
void validateScopeRequest(const CredentialCreateOptions& options) {
    if (options.created_by == 0) throw std::invalid_argument("credential creation requires created_by");
    if (options.principal_user_id == 0) throw std::invalid_argument("credential creation requires principal_user_id");
    if (options.name.empty()) throw std::invalid_argument("credential name must not be empty");
    if (!validScopeMode(options.scope_mode))
        throw std::invalid_argument("invalid S3 gateway credential scope mode: " + options.scope_mode);
}
}

CredentialManager::CredentialManager() {
    // The current S3 gateway master, unsealed (once per process): generated only while no credential exists, else
    // MasterSecretLost (#326).
    using namespace crypto::secrets;
    (void)versioned::provider(kGatewayMasterSlot, versioned::currentVersion(kGatewayMasterSlot));
}

GatewaySecret CredentialManager::createCredential(const uint32_t userId, const std::string& name) const {
    return createCredential({
        .created_by = userId,
        .principal_user_id = userId,
        .name = name,
        .scope_mode = "user_access",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .default_vault_role_id = std::nullopt,
        .selected_vault_ids = {},
        .default_role_overrides = {},
        .vault_scopes = {},
        .enforce_budget_for_local_requests = false
    });
}

GatewaySecret CredentialManager::createCredential(const CredentialCreateOptions& options) const {
    validateScopeRequest(options);

    GatewaySecret out;
    out.secret_access_key = generateSecretKey();

    // Held until the row is written, so it is stored under the master that wrapped it.
    const crypto::secrets::versioned::Writer writer(kGatewayMasterSlot);
    auto wrapped = writer.wrap(crypto::viewBytes(out.secret_access_key));
    out.credential.user_id = options.principal_user_id;
    out.credential.created_by = options.created_by;
    out.credential.principal_user_id = options.principal_user_id;
    out.credential.name = options.name;
    out.credential.access_key = generateAccessKey();
    out.credential.encrypted_secret_access_key = std::move(wrapped.ciphertext);
    out.credential.iv = std::move(wrapped.iv);
    out.credential.master_version = wrapped.master_version;
    out.credential.enabled = true;
    out.credential.enforce_budget_for_local_requests = options.enforce_budget_for_local_requests;
    out.credential.scope_mode = options.scope_mode;
    out.credential.description = options.description;
    out.credential.expires_at = options.expires_at;
    out.credential.id = db::query::s3::Gateway::createCredential(out.credential);

    if (out.credential.scope_mode == "user_access") {
        db::query::s3::Gateway::replaceCredentialScopeShorthand(out.credential.id, {});
    } else if (out.credential.scope_mode == "vault_allowlist" && !options.vault_scopes.empty()) {
        auto scopes = options.vault_scopes;
        for (auto& scope : scopes) scope.credential_id = out.credential.id;
        db::query::s3::Gateway::replaceCredentialScopeShorthand(out.credential.id, scopes);
    } else {
        db::query::s3::Gateway::replaceCredentialScopeShorthand(out.credential.id, {});
        if (options.default_vault_role_id)
            db::query::s3::Gateway::upsertCredentialDefaultVaultRole(
                out.credential.id,
                *options.default_vault_role_id,
                true,
                options.created_by);
        if (out.credential.scope_mode == "vault_allowlist")
            db::query::s3::Gateway::replaceCredentialSelectedVaults(
                out.credential.id,
                options.selected_vault_ids,
                options.created_by);
    }

    if (out.credential.scope_mode != "user_access") {
        for (const auto& overrideRule : options.default_role_overrides)
            db::query::s3::Gateway::upsertCredentialDefaultVaultRoleOverride(out.credential.id, overrideRule);
    }
    return out;
}

std::vector<db::query::s3::GatewayCredential> CredentialManager::listCredentials(const std::optional<uint32_t> userId) const {
    return db::query::s3::Gateway::listCredentials(userId);
}

bool CredentialManager::revokeCredential(const std::string& accessKeyOrName, const std::optional<uint32_t> userId) const {
    if (accessKeyOrName.starts_with("VH"))
        return db::query::s3::Gateway::deleteCredentialByAccessKey(accessKeyOrName);
    if (!userId) return false;
    return db::query::s3::Gateway::deleteCredentialByName(*userId, accessKeyOrName);
}

std::optional<GatewaySecret> CredentialManager::findEnabledSecret(const std::string& accessKey) const {
    const auto credential = db::query::s3::Gateway::getCredentialByAccessKey(accessKey);
    if (!credential || !credential->enabled) return std::nullopt;
    if (credential->expires_at && *credential->expires_at <= std::time(nullptr)) return std::nullopt;
    return GatewaySecret{
        .credential = *credential,
        .secret_access_key = decryptSecret(*credential)
    };
}

void CredentialManager::markUsed(const uint32_t credentialId) const {
    db::query::s3::Gateway::updateCredentialLastUsed(credentialId);
}

std::string CredentialManager::generateAccessKey() {
    return "VH" + randomFromAlphabet(kAccessAlphabet, 24);
}

std::string CredentialManager::generateSecretKey() {
    return randomFromAlphabet(kSecretAlphabet, 40);
}

std::string CredentialManager::decryptSecret(const db::query::s3::GatewayCredential& credential) {
    const crypto::WipedKeyCopy decrypted(crypto::secrets::versioned::unwrap(
        kGatewayMasterSlot, credential.encrypted_secret_access_key, credential.iv, credential.master_version));
    return {decrypted.bytes.begin(), decrypted.bytes.end()};
}

} // namespace vh::protocols::s3
