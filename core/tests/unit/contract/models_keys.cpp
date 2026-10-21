// Contract models: vault key backup against their declared shapes (see model_suites.hpp): the ops::vault_keys::toJson
// overloads for key status, the export document and an import's result. DB-free: the structs are seeded directly.

#include "model_suites.hpp"

#include "crypto/SecretKey.hpp"
#include "ops/VaultKeys.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>

namespace vh::test_contract_models_keys {

namespace keys = ops::vault_keys;

crypto::SecretKeyPtr keyOf(const uint8_t fill) {
    std::array<uint8_t, 32> bytes{};
    bytes.fill(fill);
    return std::make_shared<const crypto::SecretKey>(bytes);
}

// A vault mid-rotation whose current key doesn't unseal here: every nullable member set.
keys::KeyStatus unavailableStatus() {
    return {.vault_id = 12,
            .vault_name = "archive",
            .deleted = true,
            .key_retain_until = 1770000000,
            .version = 3,
            .key_check = std::string(32, 'a'),
            .key_available = false,
            .unavailable_reason = "version_missing",
            .unavailable_detail = "the outgoing key of the vault's pending rotation (version 2) is not held here; "
                                  "restore it with `vh vault keys import 12 --file <export.json>`",
            .exported_version = 2,
            .exported_at = 1760000000,
            .rotation_in_progress = true,
            .needed_versions = {{.version = 3, .key_check = std::string(32, 'a'), .reason = keys::NeedReason::Current},
                                {.version = 2, .key_check = std::nullopt, .reason = keys::NeedReason::Rotation},
                                {.version = 1, .key_check = std::string(32, 'b'), .reason = keys::NeedReason::Recovery}},
            .missing_versions = {2}};
}

// A healthy live vault never exported: the nullable members null.
keys::KeyStatus freshStatus() {
    return {.vault_id = 1,
            .vault_name = "photos",
            .version = 1,
            .key_check = std::string(32, 'c'),
            .needed_versions = {{.version = 1, .key_check = std::string(32, 'c')}},
            .missing_versions = {}};
}

// A deleted vault mid-rotation whose recovery-referenced version 1 is gone: every optional member present.
keys::VaultExport fullExport() {
    keys::VaultExport e;
    e.vault_id = 12;
    e.vault_name = "archive";
    e.deleted = true;
    e.current = {.version = 3, .key = keyOf(3), .key_check = std::string(32, 'a'), .created_at = 1760000000};
    e.historical = {{.version = 2, .key = keyOf(2), .key_check = std::string(32, 'd'),
                     .reason = keys::NeedReason::Rotation, .created_at = 1755000000, .retired_at = 1760000000}};
    e.missing = {1};
    return e;
}

// One live vault, one version: the optional members absent.
keys::VaultExport currentOnlyExport() {
    keys::VaultExport e;
    e.vault_id = 1;
    e.vault_name = "photos";
    e.current = {.version = 1, .key = keyOf(9), .key_check = std::string(32, 'c'), .created_at = 1760000000};
    return e;
}

keys::ImportResult restoredImport() {
    return {.vault_id = 12,
            .vault_name = "archive",
            .written = true,
            .key_available = true,
            .versions = {{.version = 2, .outcome = keys::ImportOutcome::Restored,
                          .detail = "verified against 3 sealed file(s)", .verified_files = 3, .failed_files = 1},
                         {.version = 3, .outcome = keys::ImportOutcome::Unchanged, .detail = "already held"}}};
}

keys::ImportResult partialDeletedImport() {
    return {.vault_id = 13,
            .vault_name = "old",
            .deleted = true,
            .note = "the vault is deleted: restore it to use the imported keys",
            .versions = {{.version = 1, .outcome = keys::ImportOutcome::Unverifiable,
                          .detail = "nothing local is sealed under this version"}}};
}

}

namespace vh::test::contract_models {

void checkVaultKeyModels(Checker& c) {
    namespace t = test_contract_models_keys;
    namespace keys = ops::vault_keys;
    c.check(keys::toJson(t::unavailableStatus()), "VaultKeyStatus", "vault.keys.status vaults[] (unavailable)");
    c.check(keys::toJson(t::freshStatus()), "VaultKeyStatus", "vault.keys.status vaults[] (healthy)");
    c.check(keys::toJson(t::fullExport(), "alice"), "VaultKeyExport", "vault.keys.export (deleted, mid-rotation)");
    c.check(keys::toJson(t::currentOnlyExport(), "alice"), "VaultKeyExport", "vault.keys.export (current only)");
    c.check(keys::toJson(t::restoredImport()), "VaultKeyImportResult", "vault.keys.import (restored)");
    c.check(keys::toJson(t::partialDeletedImport()), "VaultKeyImportResult", "vault.keys.import (deleted, skipped)");
}

}
