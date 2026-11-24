#pragma once

#include "db/query/s3/Gateway.hpp"
#include "identities/Fwd.hpp"
#include "rbac/Fwd.hpp"
#include "vault/Fwd.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace vh::protocols::ws::handler {

// The JSON shapes s3.gateway.* answers with: the ws contract's S3Gateway* models (core/usage/src/contract/models/
// s3gateway.cpp). Every input is already looked up (S3Gateway.cpp does the lookups), so
// core/tests/unit/contract/models_s3gateway.cpp checks these against their declarations without a database.
struct S3GatewayJson {
    // `principal`: the credential's principal user, or null when it no longer exists. `upstream`: the shaped
    // credentialUpstream (what the credential's CreateBucket creates).
    static nlohmann::json credential(const db::query::s3::GatewayCredential& credential,
                                     const std::shared_ptr<identities::User>& principal, nlohmann::json upstream);
    // `key`: the profile's API key (metadata only), or null when it can't be read. `serverDefault`: the profile is
    // s3_gateway.default_upstream_profile.
    static nlohmann::json upstreamProfile(const db::query::s3::UpstreamProfile& profile,
                                          const std::shared_ptr<vault::model::APIKey>& key, bool serverDefault);
    // `profile`: the shaped profile a CreateBucket would use now, or null. `problem`: why there is none although the
    // source asks for one (empty: no problem).
    // `allowed`: the shaped profiles a request may name besides `profile` (an array).
    static nlohmann::json credentialUpstream(const std::string& source, nlohmann::json profile, const std::string& problem,
                                             std::optional<bool> reapply, bool reapplyEffective, nlohmann::json allowed);
    static nlohmann::json reappliedBucket(const std::string& bucketName, std::uint32_t vaultId, bool applied,
                                          const std::string& detail);
    static nlohmann::json vault(const std::shared_ptr<vault::model::Vault>& vault);
    // `credential`, `vault`, `role`: the already-shaped (or null) credential, vault and vault role.
    static nlohmann::json assignment(const db::query::s3::CredentialVaultRoleAssignment& assignment,
                                     nlohmann::json credential, nlohmann::json vault, nlohmann::json role);
    static nlohmann::json defaultRole(const db::query::s3::CredentialDefaultVaultRole& defaultRole,
                                      nlohmann::json credential, nlohmann::json role);
    static nlohmann::json selectedVault(const db::query::s3::CredentialSelectedVault& selectedVault,
                                        nlohmann::json vault);
    // A per-vault role override; `vault` is the shaped vault, or null for a default-role override.
    static nlohmann::json roleOverride(std::uint32_t credentialId, nlohmann::json credential,
                                       const nlohmann::json& vault, const rbac::permission::Override& overrideRule);
    static nlohmann::json defaultRoleOverride(std::uint32_t credentialId, nlohmann::json credential,
                                              const rbac::permission::Override& overrideRule);
    static nlohmann::json bucket(const db::query::s3::BucketBinding& bucket);
};

}
