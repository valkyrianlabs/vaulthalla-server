#pragma once

#include <string_view>
#include "rbac/Fwd.hpp"

namespace vh::seed {

static constexpr std::string_view ADMIN_DEFAULT_VAULT_NAME = "Admin Default Vault";

void seed_database();
void initPermissions();
void initRoles();
void initSystemUser();
void initAdmin();
void initAdminGroup();
void initAdminDefaultVault();
void initRoot();
void reconcileSystemPrincipals();
// Accounts written before 1.8.0 have a single all-zero "self" row in user_global_vault_policy and no admin/user rows
// (every scope defaulted to "self", and roles loaded by name carried no preset). Give them their built-in role's
// preset. Accounts that already have admin/user rows are left alone. Idempotent; runs at every start.
void reconcileGlobalVaultPolicies();

// The `share_upload_dropbox` vault role template new installs seed (upload-only: no List). Exposed for tests.
rbac::role::Vault shareUploadDropboxRole();

}
