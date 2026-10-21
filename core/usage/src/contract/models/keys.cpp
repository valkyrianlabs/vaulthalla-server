// ws models: vault key backup (Vaulthalla Desktop S2/S6; .claude/context/key-backup.md). The ops::vault_keys::toJson
// overloads (core/src/ops/VaultKeys.cpp). Checked against those serializers by
// core/tests/unit/contract/models_keys.cpp. Key bytes appear only in VaultKeyExport (paired devices and the CLI).

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField vaultKeyCheck(std::string name) {
    return str(std::move(name)).desc("32 lowercase hex digits: BLAKE2b-128 keyed by the 32-byte key over "
                                     "\"vh-key-check-v1\" ‖ vault_id (ASCII decimal) ‖ UInt32BE(version).");
}

WsField vaultKeyReason() {
    return str("reason").oneOf({"current", "rotation", "recovery"}).desc(
        "Why the version is needed: the current key, the outgoing key of an unfinished rotation (or a version live "
        "files are still sealed under), or a retired key recovery data references. A version that is several reports "
        "the first.");
}

WsField vaultKeyTime(std::string name) { return uinteger(std::move(name)).desc("Unix seconds."); }

}

std::vector<WsModel> vaultKeyModels() {
    std::vector<WsModel> out;

    out.push_back(model("VaultKeyNeededVersion",
        "A key version still needed to decrypt the vault's data, identified by its key check (never key bytes): "
        "ops::vault_keys::toJson(KeyStatus) needed_versions[] (core/src/ops/VaultKeys.cpp).",
        {uinteger("version"),
         vaultKeyCheck("key_check").nullable().desc("Null when this host can't read that version."),
         vaultKeyReason()}));

    out.push_back(model("VaultKeyStatus",
        "One vault's key backup state: ops::vault_keys::toJson(KeyStatus) (core/src/ops/VaultKeys.cpp; also "
        "`vh vault keys status --json`). Never key bytes.",
        {vaultId(), str("vault_name"),
         boolean("deleted").desc("A deleted vault within its key retention window."),
         vaultKeyTime("key_retain_until").nullable().desc("Deleted vaults: when the retained key is destroyed."),
         uinteger("version").desc("The current key version (with no key record, the highest version data records)."),
         vaultKeyCheck("key_check").nullable().desc("The current key's check; null when it can't be read here."),
         boolean("key_available").desc("Every key the vault needs to run is readable on this host."),
         str("unavailable_reason").oneOf({"key_missing", "key_unsealable", "version_missing"}).nullable()
             .desc("vault::KeyUnavailable's code: why the vault's keys can't be used here (null when they can)."),
         str("unavailable_detail").nullable().desc("What happened and the command that restores the keys."),
         uinteger("exported_version").nullable().desc("The last version recorded as exported."),
         vaultKeyTime("exported_at").nullable(),
         boolean("rotation_in_progress"),
         objectArray("needed_versions", "VaultKeyNeededVersion").desc("Current first, then ascending."),
         intArray("missing_versions").desc("Needed versions this host can't read.")}));

    out.push_back(model("VaultKeyExport",
        "One vault's export document: ops::vault_keys::toJson(VaultExport) (core/src/ops/VaultKeys.cpp), the CLI's "
        "`vh vault keys export` shape (vault::model::generate_json_key_object) plus key_check and every needed "
        "version. vault.keys.import (and `vh vault keys import`) takes it back, alone or in an `all` array.",
        {vaultId(), str("vault_name"),
         str("key").desc("The current key, base64 (32 bytes)."),
         vaultKeyCheck("key_check").desc("The current key's key check."),
         object("key_info", "",
                {str("type").desc("\"AES-256-GCM\"."), uinteger("key_size"), uinteger("key_version"),
                 uinteger("iv_size"), uinteger("tag_size"), str("iv_gen"), str("cipher_impl"), str("hardware_accel"),
                 boolean("aad"), str("files_hashed_with"), str("sealed_by").desc("\"Vaulthalla v<version>\"."),
                 str("created_at"), str("exported_by"), str("exported_at"), vaultKeyCheck("key_check")})
             .desc("Key metadata (timestamps as the database's text form)."),
         objectArray("historical_keys", "",
                     {uinteger("key_version"), str("key").desc("base64 (32 bytes)."), vaultKeyCheck("key_check"),
                      vaultKeyReason(), str("created_at").nullable(), str("retired_at").nullable()})
             .opt()
             .desc("Every other version still needed: an unfinished rotation's outgoing key (rotation) and retired "
                   "versions recovery data references (recovery), ascending. Absent when there are none."),
         intArray("missing_key_versions").opt().desc("Needed versions this host no longer holds."),
         boolean("deleted_vault").opt().desc("Present (true) for a deleted vault within its key retention window.")}));

    out.push_back(model("VaultKeyImportResult",
        "What a key import did: ops::vault_keys::toJson(ImportResult) (core/src/ops/VaultKeys.cpp; also "
        "`vh vault keys import --json`).",
        {vaultId(), str("vault_name"), boolean("deleted"),
         boolean("written").desc("False when every version was unchanged or skipped."),
         boolean("key_available").desc("The vault runs on this host now (a deleted vault needs a restore first)."),
         str("note").nullable().desc("What is still missing or needed, when anything is."),
         objectArray("versions", "",
                     {uinteger("version"), str("outcome").oneOf({"restored", "unchanged", "unverifiable"}),
                      str("detail"), uinteger("verified_files").desc("Ciphertexts that authenticated under it."),
                      uinteger("failed_files").desc("Sampled ciphertexts that did not (damaged files).")})
             .desc("Every version the backup carries for the vault, ascending.")}));

    return out;
}

}
