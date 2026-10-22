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

// Besides the generic kinds, export, its confirmation and import answer one ops::Refused code of their own (D4): a
// session that isn't a paired device's (a browser) gets export_requires_device / import_requires_device, so a
// client can say "use Vaulthalla Desktop or the vh CLI" instead of "permission denied". An agent (MCP) is denied.
// A vault whose key can't be read on this host is conflict (vault::KeyUnavailable's codes are reported by
// vault.keys.status, never as refusals).
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
        .response = {objectArray("vaults", "VaultKeyStatus")},
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
        .response = modelFields("VaultKeyExport"),
        .refusal_codes = exportRefusals(),
        .response_model = "VaultKeyExport",
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
        .description = "Recover the vault's keys from a backup (`keys`: an export, one vault object or an `all` "
                       "array) when this host can't unseal or doesn't hold them. A recovery mechanism, never a way to "
                       "set a key: a version is restored only when the vault's records reference it and its "
                       "attestation by this node verifies (or it matches a key this host holds); a key this host can "
                       "unseal is never replaced (conflict), identical bytes are unchanged, unreferenced versions are "
                       "refused, the rest are needs_salvage. mode salvage additionally re-encrypts the files of the "
                       "needs_salvage versions under a fresh daemon key (the supplied key is never stored) and returns "
                       "the report. Writing needs confirm_name = the vault's name, else data.code vault_key_import "
                       "(mode recover) or vault_key_salvage (mode salvage, even when nothing turns out to need "
                       "salvage) with what would be done. Paired devices only (import_requires_device otherwise); the "
                       "encryption-key Export permission.",
        .payload = {vaultId(),
                    anyOf("keys", {"object", "array"})
                        .alternatives({WsField{.types = {"object"}, .model = "VaultKeyImportDocument"}
                                           .desc("One vault's entry: what the import reads of an export (a whole "
                                                 "vault.keys.export answer is one)."),
                                       WsField{.types = {"array"}, .items = "object", .model = "VaultKeyImportDocument"}
                                           .desc("The CLI's `vh vault keys export all` array; the entry whose "
                                                 "vault_id matches is used.")})
                        .gen(gen::ref("vault.key", {"export"}))
                        .desc("The export document: the members VaultKeyImportDocument declares are read, anything "
                              "else is ignored."),
                    str("mode").oneOf({"recover", "salvage"}).opt()
                        .desc("recover (default): restore attested versions only. salvage: also re-encrypt what "
                              "unproven versions decrypt under a fresh key."),
                    str("confirm_name").opt().desc("The vault's name: the person confirmed the import.")},
        .response = modelFields("VaultKeyImportResult"),
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "import_requires_device"},
        .confirmations = {{.code = "vault_key_import",
                           .accept_field = "confirm_name",
                           .description = "mode recover: the import would re-seal the listed key versions under "
                                          "this host's vault master (the error text says which): resend with "
                                          "confirm_name set to the vault's name (a string, not a flag) once the person "
                                          "typed it."},
                          {.code = "vault_key_salvage",
                           .accept_field = "confirm_name",
                           .description = "Every mode salvage request that would write. It would create a fresh key "
                                          "version and re-encrypt every file the supplied key decrypts under it (the "
                                          "error text says which versions; files it can't decrypt are reported "
                                          "unrecoverable), and restore any attested versions as recover does; when no "
                                          "version needs salvage the text says so and only the restore happens. Resend "
                                          "with confirm_name set to the vault's name once the person typed it."}},
        .response_model = "VaultKeyImportResult",
        .client_timeout = std::chrono::milliseconds(600'000),
    });

    return out;
}

}
