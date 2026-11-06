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

// Import document members (VaultKeyImportDocument): optional, and null reads as absent.
WsField importKeyCheck(const std::string& what) {
    return vaultKeyCheck("key_check").opt().nullable().desc("32 lowercase hex digits. " + what);
}

WsField importAttestation() { return object("attestation", "VaultKeyAttestation").opt().nullable(); }

WsField vaultKeyAttestation(std::string name) {
    return object(std::move(name), "VaultKeyAttestation").nullable()
        .desc("This node's attestation of the version (public, like the key check); null when none is recorded.");
}

}

std::vector<WsModel> vaultKeyModels() {
    std::vector<WsModel> out;

    out.push_back(model("VaultKeyAttestation",
        "This node's Ed25519 signature over one key version (vault/KeyAttestation.hpp): \"vh-key-attest-v1\" ‖ node_id "
        "‖ UInt64BE(vault_id) ‖ UInt32BE(version) ‖ key_check (16 bytes). `vh vault keys import` restores a version as "
        "canonical only when it verifies under one of this node's attestation keys.",
        {uinteger("key_id").min(1).max(2147483647)
             .desc("Which of this node's attestation keys signed (key_attestation_keys.id, a PostgreSQL integer). An "
                   "import reads any other value as a malformed attestation: that version needs salvage."),
         str("signature").desc("base64 (64 bytes)."),
         str("public_key").opt().nullable()
             .desc("base64 (32 bytes): the signing key's public key (key_attestation_keys), so the backup can anchor "
                   "provenance on another node (spec 03 §5.4). An import on this node requires it to be this node's key "
                   "of key_id; absent in exports from before #370, which still import here.")}));

    out.push_back(model("VaultKeyAttestationKey",
        "One of this node's attestation signing keys (key_attestation_keys): what a recovery kit pins as "
        "attestation_public_keys (spec 03 §5.3). Public.",
        {uinteger("key_id").min(1).max(2147483647), str("public_key").desc("base64 (32 bytes, Ed25519)."),
         vaultKeyTime("retired_at").nullable().desc("When a newer signing key replaced it (its signatures stay valid).")}));

    out.push_back(model("VaultKeyCheckpoint",
        "The vault's manifest v2 chain position (opaque_v1 vaults): a recovery kit's checkpoint bounds rollback (spec 03 "
        "§4.5).",
        {uinteger("epoch").min(1), str("root_sha256").desc("64 lowercase hex digits: SHA-256 of the root object.")}));

    out.push_back(model("VaultRecoveryMaterial",
        "D2 (spec 03 §5.5): whether the vault has recovery material independent of this host. "
        "ops::vault_keys::toJson(RecoveryMaterial) (core/src/ops/VaultKeys.cpp).",
        {boolean("required").desc("A self-hosted S3 vault that encrypts upstream: it needs a recovery recipient or a "
                                  "current export."),
         str("state").oneOf({"not_required", "recipient", "export", "recovery_material_missing"})
             .desc("recipient: a recovery recipient's envelopes cover every needed key version; export: the current "
                   "version was exported (a rotation makes an export stale); recovery_material_missing: neither "
                   "(health is degraded); not_required: a local or transparent vault (the export guidance applies)."),
         uinteger("recipients").desc("Usable (customer, not revoked) recovery recipients."),
         intArray("uncovered_versions").desc("Needed key versions without an envelope for a usable recipient (only "
                                             "with recipients)."),
         boolean("export_current").desc("The recorded export is of the current key version."),
         boolean("rotation_needed").desc("A revoked recipient still holds envelopes of key versions the vault uses: "
                                         "only a key rotation cuts it off from new data."),
         str("detail").nullable().desc("What is missing and what to do.")}));

    out.push_back(model("VaultRecoveryRecipient",
        "A recovery recipient: an independently revocable grant of the vault's key versions to a customer-held X25519 "
        "public key (spec 03 §5.7). ops::recovery_recipients::toJson(Recipient) (core/src/ops/RecoveryRecipients.cpp). "
        "Public: never a seed or key.",
        {str("grant_id").desc("26 base32 symbols."),
         str("recipient_id").desc("64 lowercase hex digits: SHA-256 of the public key (KEV1 recipient_id)."),
         str("public_key").desc("base64 (32 bytes, X25519)."),
         uinteger("suite").desc("KEV1 suite: 1 (X25519 + HKDF-SHA-256 + AES-256-GCM)."),
         str("class").oneOf({"customer"}).desc("Customer-controlled: the only class implemented."),
         str("label").nullable(), vaultKeyTime("added_at"),
         str("authorized_by").desc("Who enrolled it: user:<id> via cli|device."),
         vaultKeyTime("revoked_at").nullable(), str("revoked_by").nullable(),
         intArray("envelope_versions").desc("Key versions wrapped to it (KEV1 envelopes in the vault's bucket).")}));

    out.push_back(model("VaultRecoveryRecipientList",
        "A vault's recovery recipients: ops::recovery_recipients::toJson(RecipientList).",
        {vaultId(), str("vault_name"),
         str("vault_uid").desc("26 base32 symbols: how a recovery kit names the vault."),
         objectArray("recipients", "VaultRecoveryRecipient").desc("Oldest first, revoked ones included."),
         object("recovery", "VaultRecoveryMaterial")}));

    out.push_back(model("VaultRecoveryRecipientAdd",
        "An enrollment: ops::recovery_recipients::toJson(AddResult).",
        {object("recipient", "VaultRecoveryRecipient"),
         uinteger("envelopes_written").desc("KEV1 envelopes written to the vault's bucket now."),
         intArray("versions").desc("The key versions wrapped to the recipient."),
         str("note").nullable().desc("Set when not every envelope could be written yet (the sync pass retries)."),
         object("recovery", "VaultRecoveryMaterial")}));

    out.push_back(model("VaultRecoveryRecipientRevoke",
        "A revocation: ops::recovery_recipients::toJson(RevokeResult). recovery.rotation_needed says whether a key "
        "rotation is needed to cut the recipient off from new data.",
        {object("recipient", "VaultRecoveryRecipient"), object("recovery", "VaultRecoveryMaterial")}));

    out.push_back(model("VaultKeySalvageFailure",
        "One file a key salvage could not re-encrypt.",
        {str("path").desc("Vault path."), uinteger("version").desc("The key version it is sealed under."),
         str("kind").oneOf({"unrecoverable", "skipped_remote", "deferred", "failed"})
             .desc("unrecoverable: does not authenticate under the supplied key (corrupted, or another key's file) or "
                   "its local copy is gone; skipped_remote: the remote read was refused (price budget, request caps) or "
                   "the object changed, the reason carries the estimate; deferred: open for writing; failed: anything "
                   "else. All but unrecoverable can be retried by running the salvage again."),
         str("reason")}));

    out.push_back(model("VaultKeySalvageReport",
        "A key salvage pass: ops::vault_keys::toJson(SalvageReport) (core/src/ops/VaultKeys.cpp; the vault_key_salvage "
        "row). Files sealed under unverified key versions are re-encrypted under a fresh daemon key; the supplied keys "
        "are never stored.",
        {uinteger("id"), intArray("versions").desc("The unverified versions files were salvaged from."),
         uinteger("new_version").nullable().desc("The fresh key version files were re-encrypted under."),
         str("state").oneOf({"running", "finished"}).desc("running: interrupted (run the salvage again to resume)."),
         vaultKeyTime("started_at"), vaultKeyTime("finished_at").nullable(),
         uinteger("salvaged").desc("Files re-encrypted under new_version."), uinteger("unrecoverable"),
         uinteger("skipped_remote"), uinteger("deferred"), uinteger("failed"),
         objectArray("failures", "VaultKeySalvageFailure").desc("The first 50 files not salvaged.")}));

    out.push_back(model("VaultKeyNeededVersion",
        "A key version still needed to decrypt the vault's data, identified by its key check (never key bytes): "
        "ops::vault_keys::toJson(KeyStatus) needed_versions[] (core/src/ops/VaultKeys.cpp).",
        {uinteger("version"),
         vaultKeyCheck("key_check").nullable().desc("Null when this host can't read that version."),
         vaultKeyReason(), vaultKeyAttestation("attestation")}));

    out.push_back(model("VaultKeyStatus",
        "One vault's key backup state: ops::vault_keys::toJson(KeyStatus) (core/src/ops/VaultKeys.cpp; also "
        "`vh vault keys status --json`). Never key bytes.",
        {vaultId(), str("vault_name"),
         boolean("deleted").desc("A deleted vault within its key retention window."),
         vaultKeyTime("key_retain_until").nullable().desc("Deleted vaults: when the retained key is destroyed."),
         uinteger("version").desc("The current key version (with no key record, the highest version the daemon's "
                                  "records reference)."),
         vaultKeyCheck("key_check").nullable().desc("The current key's check; null when it can't be read here."),
         boolean("key_available").desc("Every key the vault needs to run is readable on this host."),
         str("unavailable_reason").oneOf({"key_missing", "key_unsealable", "version_missing"}).nullable()
             .desc("vault::KeyUnavailable's code: why the vault's keys can't be used here (null when they can)."),
         str("unavailable_detail").nullable().desc("What happened and the command that restores the keys."),
         uinteger("exported_version").nullable().desc("The last version recorded as exported."),
         vaultKeyTime("exported_at").nullable(),
         boolean("rotation_in_progress"),
         objectArray("needed_versions", "VaultKeyNeededVersion").desc("Current first, then ascending."),
         intArray("missing_versions").desc("Needed versions this host can't read."),
         vaultKeyAttestation("attestation").desc("The current version's attestation; null when none is recorded."),
         object("last_salvage", "VaultKeySalvageReport").nullable().desc("The vault's last key salvage, if any."),
         str("vault_uid").nullable().opt().desc("26 base32 symbols (null for a deleted vault): how a recovery kit "
                                                "names the vault."),
         str("node_id").opt().desc("This node's id (device_node.node_id): the origin a recovery kit records."),
         objectArray("attestation_public_keys", "VaultKeyAttestationKey").opt()
             .desc("Every attestation signing key this node has had: what a recovery kit pins."),
         object("checkpoint", "VaultKeyCheckpoint").nullable().opt()
             .desc("The last manifest root this node recorded (opaque_v1 vaults), else null."),
         object("recovery", "VaultRecoveryMaterial").opt().desc("D2: the vault's recovery material.")}));

    out.push_back(model("VaultKeyExport",
        "One vault's export document: ops::vault_keys::toJson(VaultExport) (core/src/ops/VaultKeys.cpp), the CLI's "
        "`vh vault keys export` shape (vault::model::generate_json_key_object) plus key_check and every needed "
        "version. vault.keys.import (and `vh vault keys import`) takes it back, alone or in an `all` array.",
        {vaultId(), str("vault_name"),
         str("key").desc("The current key, base64 (32 bytes)."),
         vaultKeyCheck("key_check").desc("The current key's key check."),
         vaultKeyAttestation("attestation").opt().desc("The current version's attestation by this node: what makes the "
                                                       "export importable as canonical. Absent in exports from before "
                                                       "attestations (they can only be salvaged)."),
         object("key_info", "",
                {str("type").desc("\"AES-256-GCM\"."), uinteger("key_size"), uinteger("key_version"),
                 uinteger("iv_size"), uinteger("tag_size"), str("iv_gen"), str("cipher_impl"), str("hardware_accel"),
                 boolean("aad"), str("files_hashed_with"), str("sealed_by").desc("\"Vaulthalla v<version>\"."),
                 str("created_at"), str("exported_by"), str("exported_at"), vaultKeyCheck("key_check"),
                 vaultKeyAttestation("attestation").opt()})
             .desc("Key metadata (timestamps as the database's text form)."),
         objectArray("historical_keys", "",
                     {uinteger("key_version"), str("key").desc("base64 (32 bytes)."), vaultKeyCheck("key_check"),
                      vaultKeyAttestation("attestation").opt(), vaultKeyReason(), str("created_at").nullable(),
                      str("retired_at").nullable()})
             .opt()
             .desc("Every other version still needed: an unfinished rotation's outgoing key (rotation) and retired "
                   "versions recovery data references (recovery), ascending. Absent when there are none."),
         intArray("missing_key_versions").opt().desc("Needed versions this host no longer holds."),
         boolean("deleted_vault").opt().desc("Present (true) for a deleted vault within its key retention window.")}));

    // What ops::vault_keys::readImportDocument (the import's parser) reads; the rest of an export is ignored.
    // ContractModels.VaultKeyImportDocument* hold this model to that parser, member by member.
    out.push_back(model("VaultKeyImportDocument",
        "One vault's entry in a key import (vault.keys.import keys, `vh vault keys import --file`): what "
        "ops::vault_keys::importKeys reads (core/src/ops/VaultKeys.cpp readImportDocument). A whole VaultKeyExport is "
        "one; members not declared here, at any depth, are accepted and ignored. Missing or mistyped required members, "
        "a key that isn't base64 of 32 bytes, a version given two different keys, or a key_check that doesn't match "
        "its key refuse the whole import (invalid). An attestation that is malformed (key_id out of range, a signature "
        "that isn't base64 of 64 bytes) is not an error: that version needs salvage.",
        {vaultId().desc("The vault the entry is for: the request's vault_id (the entry of an `all` array whose "
                        "vault_id matches is used; the others are not read)."),
         str("key").desc("The key of key_info.key_version, base64 (32 bytes)."),
         importKeyCheck("The backup's own key check of `key` (consistency only: a mismatch refuses the import as "
                        "damaged). When absent, key_info.key_check is read; null or absent in both: none."),
         importAttestation().desc("This node's attestation of key_info.key_version, as the export carried it: what "
                                  "restores that version as canonical. When absent, key_info.attestation is read; null "
                                  "or absent in both: the version can only be salvaged."),
         object("key_info", "",
                {uinteger("key_version").min(1).max(4294967295).desc("The version `key` is."),
                 importKeyCheck("Read only when the entry has no key_check member."),
                 importAttestation().desc("Read only when the entry has no attestation member.")})
             .desc("Only key_version is required; the export's other key metadata is ignored."),
         objectArray("historical_keys", "",
                     {uinteger("key_version").min(1).max(4294967295), str("key").desc("base64 (32 bytes)."),
                      importKeyCheck("The backup's own key check of this key (consistency only)."),
                      importAttestation().desc("This node's attestation of this version; null or absent: it can only "
                                               "be salvaged.")})
             .opt()
             .desc("The entry's other versions (an export's rotation and recovery versions). A version listed twice "
                   "must carry the same key.")}));

    out.push_back(model("VaultKeyImportResult",
        "What a key import did: ops::vault_keys::toJson(ImportResult) (core/src/ops/VaultKeys.cpp; also "
        "`vh vault keys import --json`).",
        {vaultId(), str("vault_name"), boolean("deleted"),
         str("mode").oneOf({"recover", "salvage"}),
         boolean("written").desc("False when nothing was restored or salvaged."),
         boolean("key_available").desc("The vault runs on this host now (a deleted vault needs a restore first)."),
         str("note").nullable().desc("What is still missing or needed, when anything is."),
         objectArray("versions", "",
                     {uinteger("version"),
                      str("outcome").oneOf({"restored", "unchanged", "needs_salvage", "refused", "salvaged"})
                          .desc("restored: attested by this node (or matching a key it holds) and re-sealed here; "
                                "unchanged: already held; needs_salvage: the vault references it but the backup can't "
                                "prove it is this vault's key, nothing written; refused: the vault has no record of "
                                "the version (an import never introduces one); salvaged: its files went through the "
                                "salvage pass, the key itself was not stored."),
                      str("detail").desc("Which proof restored it, or why not.")})
             .desc("Every version the backup carries for the vault, ascending."),
         object("salvage", "VaultKeySalvageReport").nullable().desc("Salvage mode: the pass's report."),
         object("recovery_kit", "",
                {uinteger("envelopes").desc("Objects under .vaulthalla/key/ in the vault's bucket."),
                 uinteger("unwrapped").desc("Addressed to the kit's recipient and authentic."),
                 uinteger("skipped").desc("Another recipient's, or a reserved purpose or recipient class."),
                 uinteger("rejected").desc("Damaged, for another vault, or not KEV1."),
                 uinteger("ignored").desc("Unwrapped, but not the key the vault's records name for that version."),
                 boolean("root_consulted").desc("The manifest root's key history supplied attestations.")})
             .opt()
             .desc("`vh vault keys import --recovery-kit` only: what the envelopes in the bucket held.")}));

    return out;
}

}
