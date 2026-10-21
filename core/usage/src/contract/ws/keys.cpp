// ws book: vault.keys.* (core/src/protocols/ws/handler/vault/Keys.cpp, ops::vault_keys; .claude/context/key-backup.md).
//
// D4: key bytes go only to a paired device (the device listener) or the local CLI. Export, its confirmation and import
// are "human"-level commands in the router's sense (a browser session reaches the handler), and the op refuses every
// session that isn't a paired device's with data.code export_requires_device / import_requires_device. MCP has no ws
// path; its CLI paths are excluded (mcp::exclusions()).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField keyCheck(std::string name) {
    return str(std::move(name)).desc("32 lowercase hex digits: BLAKE2b-128 keyed by the 32-byte key over "
                                     "\"vh-key-check-v1\" ‖ vault_id (ASCII decimal) ‖ UInt32BE(version).");
}

WsField uintArray(std::string name) { return {.name = std::move(name), .types = {"array"}, .items = "integer"}; }

WsField reason() { return str("reason").oneOf({"current", "rotation", "recovery"}); }

std::vector<WsField> exportResponse() {
    return {vaultId(),
            str("vault_name"),
            str("key").desc("The current key, base64 (32 bytes)."),
            keyCheck("key_check").desc("The current key's key check."),
            object("key_info", "", {str("type"), uinteger("key_size"), uinteger("key_version"), uinteger("iv_size"),
                                    uinteger("tag_size"), str("created_at"), str("exported_by"), str("exported_at"),
                                    keyCheck("key_check")})
                .desc("Key metadata as `vh vault keys export` writes it (plus key_check)."),
            objectArray("historical_keys", "",
                        {uinteger("key_version"), str("key").desc("base64"), keyCheck("key_check"), reason(),
                         str("created_at").nullable(), str("retired_at").nullable()})
                .opt()
                .desc("Every other version still needed: an unfinished rotation's outgoing key (reason rotation) and "
                      "retired versions recovery data references (reason recovery). Absent when there are none."),
            uintArray("missing_key_versions").opt().desc("Needed versions this host no longer holds."),
            boolean("deleted_vault").opt().desc("A deleted vault within its key retention window.")};
}

std::vector<std::string> exportRefusals() {
    return {"denied", "invalid", "not_found", "conflict", "unauthorized", "export_requires_device"};
}

}

std::vector<WsCommandUsage> vaultKeyCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "vault.keys.status",
        .description = "Key backup state of every vault the caller may inspect (the encryption-key View permission; "
                       "deleted vaults within key retention for callers who may remove them), or of vault_id. Never "
                       "key bytes: each key version is identified by its key_check. Read-only; safe for any session.",
        .payload = {vaultId().opt().nullable().desc("One vault; absent for all.")},
        .response = {objectArray(
            "vaults", "",
            {vaultId(), str("vault_name"), boolean("deleted"),
             uinteger("key_retain_until").nullable().desc("Deleted vaults: when the retained key is destroyed."),
             uinteger("version").desc("The current key version."),
             keyCheck("key_check").nullable().desc("Null when the key can't be read on this host."),
             boolean("key_available"), str("unavailable_reason").nullable(),
             uinteger("exported_version").nullable().desc("The last version recorded as exported."),
             uinteger("exported_at").nullable().desc("Unix seconds."),
             boolean("rotation_in_progress"),
             objectArray("needed_versions", "", {uinteger("version"), keyCheck("key_check").nullable(), reason()})
                 .desc("Every version still needed to decrypt the vault's data, current first."),
             uintArray("missing_versions").desc("Needed versions this host can't read.")})},
        .refusal_codes = {"denied", "invalid", "not_found", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "vault.keys.export",
        .description = "The vault's keys in `vh vault keys export`'s JSON shape plus every needed version with its "
                       "key_check. Paired devices only: any other session is refused with export_requires_device "
                       "(D4). Needs the encryption-key Export permission. Not recorded as exported: confirm with "
                       "vault.keys.export.confirm once the key is stored.",
        .payload = {vaultId()},
        .response = exportResponse(),
        .refusal_codes = exportRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "vault.keys.export.confirm",
        .description = "Record that the device stored key `version` of the vault. Succeeds only while that version is "
                       "still current and key_check matches the daemon's key, else conflict (e.g. a rotation in "
                       "between). Paired devices only (export_requires_device otherwise).",
        .payload = {vaultId(), uinteger("version").gen(gen::ref("vault.key", {"version"})),
                    keyCheck("key_check").gen(gen::ref("vault.key", {"key_check"}))},
        .response = {vaultId(), uinteger("version"), uinteger("exported_at").desc("Unix seconds.")},
        .refusal_codes = exportRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "vault.keys.import",
        .description = "Restore the vault's keys from a backup (`keys`: an export, one vault object or an `all` "
                       "array) when this host can't unseal or doesn't hold them. Every version is verified before "
                       "anything is written (its key_check, then a GCM tag check of files sealed under it); a key "
                       "this host can unseal is never replaced (conflict), identical bytes are unchanged, versions "
                       "with nothing to verify against are skipped (unverifiable). Writing needs confirm_name = the "
                       "vault's name, else data.code vault_key_import with what would be written. Paired devices only "
                       "(import_requires_device otherwise); the encryption-key Export permission.",
        .payload = {vaultId(),
                    anyOf("keys", {"object", "array"}).gen(gen::ref("vault.key", {"export"}))
                        .desc("The export document, as vault.keys.export returns it (or the CLI's `all` array)."),
                    str("confirm_name").opt().desc("The vault's name: the person confirmed the import.")},
        .response = {vaultId(), str("vault_name"), boolean("deleted"), boolean("written"),
                     boolean("key_available").desc("The vault runs on this host now (a deleted vault needs a restore)."),
                     str("note").nullable(),
                     objectArray("versions", "",
                                 {uinteger("version"), str("outcome").oneOf({"restored", "unchanged", "unverifiable"}),
                                  str("detail"), uinteger("verified_files"), uinteger("failed_files")})},
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "import_requires_device",
                          "vault_key_import"},
        .client_timeout = std::chrono::milliseconds(120'000),
    });

    return out;
}

}
