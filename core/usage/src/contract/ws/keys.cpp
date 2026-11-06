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

    out.push_back({
        .command = "vault.recover",
        .description = "Rebuild a vault on this instance from its bucket and the customer's recovery material (#371, "
                       "spec 03 §6): a recovery kit (its seed unwraps the vault's KEV1 envelopes) and/or a key export. "
                       "A key version is restored only when its original node's attestation verifies against an "
                       "attestation key the material pins (D1); otherwise the answer is salvage_required with the "
                       "per-version verdicts, and salvage (confirmed with confirm_name) re-encrypts what the supplied "
                       "keys decrypt under a fresh key, never storing them. dry_run reads and reports, writing nothing. "
                       "The vault starts in the cache strategy: nothing beyond headers, the manifest and envelopes is "
                       "downloaded until a file is read. Paired devices only (recover_requires_device otherwise), with "
                       "a keys step-up bound to the bucket; the encryption-key Export permission and vault Create.",
        .payload = {uinteger("api_key_id").gen(gen::ref("api_key", {"id"})).desc("The API key that reaches the bucket."),
                    str("bucket").gen(gen::pattern("vh-test-{a}{a}{a}{9}{9}")).desc("The bucket holding the vault."),
                    object("kit").opt().nullable().desc("The recovery kit (vh.recovery-kit v1)."),
                    anyOf("export", {"object", "array"})
                        .alternatives({WsField{.types = {"object"}, .model = "VaultKeyImportDocument"}
                                           .desc("One vault's entry of an export."),
                                       WsField{.types = {"array"}, .items = "object", .model = "VaultKeyImportDocument"}
                                           .desc("The CLI's `vh vault keys export all` array; the entry whose "
                                                 "vault_uid matches the bucket's vault is used.")})
                        .opt()
                        .nullable()
                        .desc("A key export (its keys, and the attestation public keys it carries as anchors)."),
                    str("into").opt().nullable().desc("The restored vault's name (default: the manifest's)."),
                    str("vault_uid").opt().nullable().desc("Which vault of the bucket (default: the kit's)."),
                    uinteger("owner_id").opt().nullable().desc("The owner (default: the caller)."),
                    boolean("accept_rollback").opt().desc("Restore a root older than the kit's checkpoint."),
                    boolean("dry_run").opt().desc("Report only; write nothing."),
                    boolean("salvage").opt().desc("Re-encrypt what unproven versions decrypt under a fresh key."),
                    str("confirm_name").opt().nullable().desc("The restored vault's name: the person confirmed a salvage.")},
        .response = modelFields("VaultRecoverResult"),
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "recover_requires_device",
                          "salvage_required", "rollback", "fork", "kit_vault_mismatch", "export_vault_mismatch",
                          "recovery_material_mismatch", "no_key_material", "vault_unknown"},
        .confirmations = {{.code = "vault_recover_salvage",
                           .accept_field = "confirm_name",
                           .description = "A salvage restore would create a fresh key on this node and re-encrypt "
                                          "every file the supplied keys decrypt (the text says which versions); resend "
                                          "with confirm_name set to the restored vault's name once the person typed "
                                          "it."}},
        .response_model = "VaultRecoverResult",
        .client_timeout = std::chrono::milliseconds(600'000),
    });

    out.push_back({
        .command = "vault.keys.recipients.list",
        .description = "The vault's recovery recipients (spec 03 §5; #370): customer-held X25519 public keys every key "
                       "version is wrapped to (KEV1 envelopes in the vault's own bucket), revoked ones included, with "
                       "the vault's D2 recovery state. Public data only; the encryption-key View permission.",
        .payload = {vaultId()},
        .response = modelFields("VaultRecoveryRecipientList"),
        .refusal_codes = {"denied", "invalid", "not_found", "unauthorized"},
        .response_model = "VaultRecoveryRecipientList",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "vault.keys.recipients.add",
        .description = "Enroll a recovery recipient: an X25519 public key generated on the customer's own device "
                       "(Vaulthalla Desktop, or the offline `vh-recovery kit create`); the server never receives the "
                       "seed. Every key version the vault holds is wrapped to it now and every future version at "
                       "rotation, into the vault's bucket only. Customer-controlled (class customer) is the only kind. "
                       "S3 vaults only (conflict otherwise). Paired devices only (recipient_requires_device "
                       "otherwise), with a keys step-up bound to the vault (#359); the encryption-key Export "
                       "permission.",
        .payload = {vaultId(),
                    str("public_key")
                        .gen(gen::constant("9jB0b7LvRAo3+fTz//m8OhJQkp39Kcd1PjiFpjtmrTs="))
                        .desc("The recipient's X25519 public key: base64 (32 bytes) or 64 hex digits."),
                    str("label").opt().nullable().desc("A name the customer recognizes (at most 200 characters).")},
        .response = modelFields("VaultRecoveryRecipientAdd"),
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "recipient_requires_device"},
        .response_model = "VaultRecoveryRecipientAdd",
        .client_timeout = std::chrono::milliseconds(120'000),
    });

    out.push_back({
        .command = "vault.keys.recipients.revoke",
        .description = "Revoke a recovery recipient: no new envelopes are written for it. Access it already has is "
                       "not revoked (an envelope keeps unwrapping the versions it covers): recovery.rotation_needed "
                       "says when a key rotation is needed to cut it off from new data. Paired devices only "
                       "(recipient_requires_device otherwise), with a keys step-up bound to the vault (#359); the "
                       "encryption-key Export permission.",
        .payload = {vaultId(), str("grant_id")
                                   .gen(gen::ref("vault.recipient", {"grant_id"}))
                                   .desc("The recipient's grant_id (vault.keys.recipients.list).")},
        .response = modelFields("VaultRecoveryRecipientRevoke"),
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "recipient_requires_device"},
        .response_model = "VaultRecoveryRecipientRevoke",
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
