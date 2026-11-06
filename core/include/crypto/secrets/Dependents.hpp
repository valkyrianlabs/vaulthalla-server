#pragma once

#include "crypto/secrets/KeyProvider.hpp"

// What each data-wrapping master secret protects, for KeyProvider::initGuarded (#326). Every row counted here is
// encrypted with the slot's secret; a fresh secret could never decrypt it.
//   vault_master: vault key versions (vault_keys, vault_keys_trashed) and keys retained for deleted vaults
//                 (vault_deletion_key)
//   ak_master:    provider API key secrets (api_keys)
//   s3gw_master:  S3 gateway credential secrets (s3_gateway_credentials)
//   mfa_seal:     sealed TOTP seeds (totp_factors), an internal secret (Manager::sealedKey, #356)
//   mfa_pepper:   recovery code hashes (recovery_codes), an internal secret (Manager::sealedKey, #356)
// Other slots regenerate by design: master (the JWT secret: sessions sign in again), key_attest (old public keys stay
// on record), device_tls (devices see the new identity and re-pair), psql (set from the installer).
namespace vh::crypto::secrets::dependents {

[[nodiscard]] DependentsCheck vaultMaster();
[[nodiscard]] DependentsCheck apiKeyMaster();
[[nodiscard]] DependentsCheck gatewayMaster();
[[nodiscard]] DependentsCheck mfaSeal();
[[nodiscard]] DependentsCheck mfaPepper();

}
