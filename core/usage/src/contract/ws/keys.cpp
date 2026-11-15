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
        .command = "vault.layout.status",
        .description = "The vault's bucket layout and its migration path_v0 -> opaque_v1 (#373): state, the cost "
                       "estimate and usage, inventory counts, and every legacy version that stays in the bucket with "
                       "its reason. The encryption-key View permission.",
        .payload = {vaultId()},
        .response = modelFields("VaultLayoutStatus"),
        .refusal_codes = opsRefusals(),
        .response_model = "VaultLayoutStatus",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "vault.layout.migrate",
        .description = "Start (or resume after a failure) the vault's bucket layout migration path_v0 -> opaque_v1: it "
                       "runs in the background (vault.layout.status follows it). Refused (conflict) when the vault "
                       "can't migrate now (not an encrypting S3 vault on path_v0, a rotation or salvage, a key version "
                       "not held, no recovery material, a protected bucket) or already migrates. With a keys step-up "
                       "bound to the vault (#359); the encryption-key Rotate permission.",
        .payload = {vaultId(), boolean("accept_unpriced").opt().desc("Start even when the cost can't be priced.")},
        .response = modelFields("VaultLayoutStatus"),
        .refusal_codes = opsRefusals(),
        .response_model = "VaultLayoutStatus",
        .client_timeout = std::chrono::milliseconds(60'000),
    });

    out.push_back({
        .command = "vault.layout.cleanup",
        .description = "After the cutover and its waiting period: the legacy (path-named) objects a cleanup would "
                       "delete by version id, and those that stay (a dry run without confirm). With confirm set to the "
                       "vault's name the cleanup is confirmed and runs in the background (a data.destroy step-up bound "
                       "to the vault, #359). Never on a protected bucket, never a version under Object Lock retention "
                       "or a legal hold. The encryption-key Rotate permission.",
        .payload = {vaultId(), str("confirm").opt().nullable().desc("The vault's name: delete what the dry run lists.")},
        .response = modelFields("VaultLayoutCleanup"),
        .refusal_codes = opsRefusals(),
        .response_model = "VaultLayoutCleanup",
        .client_timeout = std::chrono::milliseconds(300'000),
    });

    out.push_back({
        .command = "vault.storage.probe",
        .description = "Probe what the vault's bucket supports for writes that must never overwrite another writer's "
                       "object (design/encryption/06-publish-without-preconditions.md §7): conditional PUT honoured, "
                       "rejected or ignored, object versions, GET If-Match. About ten requests under "
                       ".vaulthalla/probe/, whose versions are deleted by id afterwards. Records the verdict, which "
                       "replaces a bucket_capability_changed mark. The vault's admin Edit permission; refused (denied) "
                       "on a protected bucket, bucket_probe_failed when the bucket can't be reached.",
        .payload = {vaultId()},
        .response = modelFields("VaultStorageProbe"),
        .refusal_codes = {"denied", "invalid", "not_found", "unauthorized", "bucket_probe_failed"},
        .response_model = "VaultStorageProbe",
        .client_timeout = std::chrono::milliseconds(60'000),
    });

    {
        const auto remoteRefusals = [](std::vector<std::string> extra) {
            auto codes = opsRefusals();
            codes.insert(codes.end(), extra.begin(), extra.end());
            return codes;
        };
        out.push_back({
            .command = "vault.remote.attach",
            .description = "Attach a bucket to a local vault (design/storage/attach-remote.md): the vault keeps its "
                           "id, keys, permissions, shares and files and becomes an encrypting S3/R2 vault in place. "
                           "Checks every precondition now (a local vault with its keys loaded, no key rotation or "
                           "salvage, no content in a legacy format, every key version held and attested, recovery "
                           "material independent of this host, an empty bucket no vault holds, a bucket that can "
                           "publish the manifest) and probes the bucket; then the upload runs in the background and "
                           "resumes after a restart (vault.remote.status follows it). Nothing of the vault changes "
                           "before the cutover. A failed attach started again with the same API key and bucket "
                           "resumes. With a keys step-up bound to the vault (#359). Needs the vault's admin Edit "
                           "and sync config Edit permissions, the API key's Consume permission and the "
                           "encryption-key Rotate permission.",
            .payload = {vaultId(),
                        uinteger("api_key_id").min(1).gen(gen::ref("api_key", {"id"})).desc("The API key that reaches the bucket."),
                        str("bucket").gen(gen::pattern("vh-test-{a}{a}{a}{9}{9}")).desc("An empty bucket no vault holds."),
                        str("storage_tier").opt().nullable().desc("Provider-local storage tier for the uploads."),
                        boolean("accept_unpriced").opt().desc("Start even when the cost can't be priced.")},
            .response = modelFields("VaultRemoteStatus"),
            .refusal_codes = remoteRefusals({"key_rotation_running", "key_salvage_running", "legacy_content",
                                             "key_version_missing", "key_version_unattested",
                                             "recovery_material_missing", "bucket_listing_failed", "bucket_not_empty",
                                             "bucket_probe_failed", "bucket_capability_insufficient"}),
            .response_model = "VaultRemoteStatus",
            .client_timeout = std::chrono::milliseconds(120'000),
        });

        out.push_back({
            .command = "vault.remote.detach",
            .description = "Detach the remote of an S3 vault (design/storage/attach-remote.md, \"The reverse\"): the "
                           "vault keeps its id, keys, permissions, shares and files and becomes a local vault in "
                           "place. Checks the preconditions now (an S3 vault with its keys loaded, no attach, layout "
                           "migration, key rotation or salvage running, no content in a legacy format, every key "
                           "version its files use held, no event-driven sync, no open sync conflict); then in the "
                           "background every file without a local copy is fetched, every local copy is authenticated, "
                           "and every recovery envelope is copied from the bucket into the database, before the vault "
                           "switches in one transaction. The bucket and its objects are left in place. "
                           "vault.remote.status follows it; a failed detach started again resumes. confirm must be "
                           "the vault's name. With a keys step-up bound to the vault (#359); the vault's admin Edit "
                           "and sync config Edit permissions and the encryption-key Rotate permission.",
            .payload = {vaultId(), str("confirm").gen(gen::ref("vault", {"name"})).desc("The vault's name.")},
            .response = modelFields("VaultRemoteStatus"),
            .refusal_codes = remoteRefusals({"attach_running", "layout_migration_running", "key_rotation_running",
                                             "key_salvage_running", "legacy_content", "key_version_missing",
                                             "event_sync_active", "sync_conflicts_open"}),
            .response_model = "VaultRemoteStatus",
            .client_timeout = std::chrono::milliseconds(60'000),
        });

        out.push_back({
            .command = "vault.remote.status",
            .description = "Where attaching (or detaching) a remote stands for vault_id, or for every vault with an "
                           "attach or detach the caller may view: state, bucket, publish mode, progress (files and "
                           "bytes, rate, time left), the estimate and usage, the last error, and after an attach's "
                           "cutover the first sync pass's result. The vault's admin View permission. Read-only; safe "
                           "for any session.",
            .payload = {vaultId().opt().nullable().desc("One vault; absent for all.")},
            .response = {objectArray("vaults", "VaultRemoteStatus")},
            .refusal_codes = {"denied", "invalid", "not_found", "unauthorized"},
            .client_timeout = kDefaultTimeout,
        });

        out.push_back({
            .command = "vault.remote.abort",
            .description = "Abort an attach or a detach before its cutover. An attach's abort deletes everything it "
                           "uploaded from the bucket, each object by the version the attach recorded, in the "
                           "background, and releases the bucket (state aborted); nothing the attach did not write is "
                           "deleted, the vault itself was never changed, and a delete the provider refuses is retried "
                           "and stays listed. A detach's abort leaves the vault an S3 vault; the local copies it "
                           "fetched stay. confirm must be the vault's name. With a keys step-up bound to the vault "
                           "(#359); the same permissions as vault.remote.attach, without the API key's.",
            .payload = {vaultId(), str("confirm").gen(gen::ref("vault", {"name"})).desc("The vault's name.")},
            .response = modelFields("VaultRemoteStatus"),
            .refusal_codes = opsRefusals(),
            .response_model = "VaultRemoteStatus",
            .client_timeout = std::chrono::milliseconds(60'000),
        });
    }

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
                       "rotation, into the vault's bucket only (a local vault: this server's database). "
                       "Customer-controlled (class customer) is the only kind. With account_key: the linked account's "
                       "pinned recovery key (conflict without a pin). Paired devices only (recipient_requires_device "
                       "otherwise), with a keys step-up bound to the vault (#359); the encryption-key Export "
                       "permission.",
        .payload = {vaultId(),
                    str("public_key")
                        .opt()
                        .nullable()
                        .gen(gen::constant("9jB0b7LvRAo3+fTz//m8OhJQkp39Kcd1PjiFpjtmrTs="))
                        .desc("The recipient's X25519 public key: base64 (32 bytes) or 64 hex digits. Required "
                              "unless account_key."),
                    str("label").opt().nullable().desc("A name the customer recognizes (at most 200 characters)."),
                    boolean("account_key").opt().nullable().desc(
                        "Add the linked account's pinned recovery key instead of public_key.")},
        .response = modelFields("VaultRecoveryRecipientAdd"),
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "recipient_requires_device"},
        .response_model = "VaultRecoveryRecipientAdd",
        .client_timeout = std::chrono::milliseconds(120'000),
    });

    out.push_back({
        .command = "vault.keys.recipients.revoke",
        .description = "Revoke a recovery recipient: no new envelopes are written for it (a recipient the account's "
                       "signed recovery policy added is refused recovery_policy_account_managed). Access it already has is "
                       "not revoked (an envelope keeps unwrapping the versions it covers): recovery.rotation_needed "
                       "says when a key rotation is needed to cut it off from new data. Paired devices only "
                       "(recipient_requires_device otherwise), with a keys step-up bound to the vault (#359); the "
                       "encryption-key Export permission.",
        .payload = {vaultId(), str("grant_id")
                                   .gen(gen::ref("vault.recipient", {"grant_id"}))
                                   .desc("The recipient's grant_id (vault.keys.recipients.list).")},
        .response = modelFields("VaultRecoveryRecipientRevoke"),
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "recipient_requires_device",
                          "recovery_policy_account_managed"},
        .response_model = "VaultRecoveryRecipientRevoke",
        .client_timeout = kDefaultTimeout,
    });

    // ---- the linked account's recovery key (design/cloud/key-manager.md; ops::cloud_keys) ----------------------
    out.push_back({
        .command = "cloud.key.status",
        .description = "The linked account's recovery key as this server pinned it: the pinned generation and "
                       "fingerprint, a key waiting for confirmation, the accepted recovery policy, the vaults it covers "
                       "and the last check. Reads the database only; public values only. Super admins or the "
                       "encryption-key View permission.",
        .response = modelFields("CloudKeyStatus"),
        .refusal_codes = {"denied", "unauthorized"},
        .response_model = "CloudKeyStatus",
        .client_timeout = kDefaultTimeout,
    });
    out.push_back({
        .command = "cloud.key.confirm",
        .description = "Pin the waiting account recovery key: the first one after linking, or a replacement. The "
                       "fingerprint must be the waiting generation's (a device derives it from the key it holds); a "
                       "mismatch pins nothing (cloud_key_mismatch). Super admins; a paired device only "
                       "(cloud_key_requires_device otherwise), with a keys step-up.",
        .payload = {str("fingerprint")
                        .gen(gen::constant("0000-0000-0000-0000-0000-0000-0000-0000"))
                        .desc("Eight groups of four hex digits (upper case, spaces or no separators accepted).")},
        .response = modelFields("CloudKeyConfirm"),
        .refusal_codes = {"denied", "invalid", "conflict", "unauthorized", "cloud_key_requires_device",
                          "cloud_key_mismatch", "cloud_account_key_tampered"},
        .response_model = "CloudKeyConfirm",
        .client_timeout = kDefaultTimeout,
    });
    out.push_back({
        .command = "cloud.key.refresh",
        .description = "Ask for a check of the account recovery key and recovery policy now. The check runs in the "
                       "background (this answers at once, with the status as it stands); a signed rotation is followed, "
                       "anything else waits for a confirmation. Super admins.",
        .response = modelFields("CloudKeyStatus"),
        .refusal_codes = {"denied", "conflict", "unauthorized"},
        .response_model = "CloudKeyStatus",
        .client_timeout = kDefaultTimeout,
    });
    out.push_back({
        .command = "cloud.link.status",
        .description = "Whether this server is linked to an account, and as what: installation, deployment, account "
                       "public id and the pinned account recovery key. Reads the database only. Super admins and the "
                       "encryption-key View permission see the identifiers; any other session sees linked alone.",
        .response = modelFields("CloudLinkStatus"),
        .refusal_codes = {"unauthorized"},
        .response_model = "CloudLinkStatus",
        .client_timeout = kDefaultTimeout,
    });

    // ---- managed storage (design/cloud/managed-remotes.md; ops::cloud_storage) ------------------------------------------
    const std::vector<std::string> storageRefusals = {"denied", "invalid", "not_found", "conflict", "unauthorized"};
    out.push_back({
        .command = "cloud.storage.status",
        .description = "Managed storage on this server: whether it is available (linked, the account recovery key "
                       "confirmed, the account entitled), the plan state, usage against the quota (the account's figure, "
                       "with its date) beside this server's own, the offer for vaults that existed before it was "
                       "available, and every vault's switch and state in words. Reads the database only. Super admins "
                       "or the admin cloud View permission.",
        .response = modelFields("CloudStorageStatus"),
        .refusal_codes = {"denied", "unauthorized"},
        .response_model = "CloudStorageStatus",
        .client_timeout = kDefaultTimeout,
    });
    out.push_back({
        .command = "cloud.storage.switch",
        .description = "A vault's managed-storage switch. On: the vault is uploaded to a bucket of its own once it is "
                       "ready (an empty vault waits for its first file); off: before a bucket exists the request stops, "
                       "with one every file is fetched and verified locally and the vault becomes local again (the "
                       "bucket is left in place; `confirm` with the vault's name is required then). Records the intent: "
                       "the background service carries it out, and cloud.storage.status follows it. No step-up. The "
                       "admin cloud Storage permission and the vault's admin Edit permission.",
        .payload = {vaultId(), boolean("enabled").gen(gen::boolean()).desc("On or off."),
                    str("confirm").opt().nullable().desc("Off on a vault with a bucket: the vault's name.")},
        .response = modelFields("CloudStorageVault"),
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "managed_storage_unavailable"},
        .response_model = "CloudStorageVault",
        .client_timeout = kDefaultTimeout,
    });
    out.push_back({
        .command = "cloud.storage.offer.accept",
        .description = "Accept the offer for vaults that existed when managed storage became available: the listed ones "
                       "or, without vault_ids, every offered vault (their switches go on). Nothing is uploaded before "
                       "this. The admin cloud Storage permission and each vault's admin Edit permission.",
        .payload = {intArray("vault_ids").opt().nullable().desc("The vaults to accept; absent for every offered one.")},
        .response = modelFields("CloudStorageOffer"),
        .refusal_codes = storageRefusals,
        .response_model = "CloudStorageOffer",
        .client_timeout = kDefaultTimeout,
    });
    out.push_back({
        .command = "cloud.storage.offer.decline",
        .description = "Decline the offer for the listed vaults (or every one still offered): they stay local; each can "
                       "be switched on later. The admin cloud Storage permission.",
        .payload = {intArray("vault_ids").opt().nullable().desc("The vaults to decline; absent for every offered one.")},
        .response = modelFields("CloudStorageOffer"),
        .refusal_codes = storageRefusals,
        .response_model = "CloudStorageOffer",
        .client_timeout = kDefaultTimeout,
    });
    out.push_back({
        .command = "cloud.storage.rotate",
        .description = "Ask for a new bucket key for a vault in managed storage (the service exchanges, probes and "
                       "acknowledges it; the old key is revoked then). The admin cloud Storage permission and the "
                       "vault's admin Edit permission.",
        .payload = {vaultId()},
        .response = modelFields("CloudStorageVault"),
        .refusal_codes = storageRefusals,
        .response_model = "CloudStorageVault",
        .client_timeout = kDefaultTimeout,
    });
    out.push_back({
        .command = "cloud.storage.new_vaults",
        .description = "Whether vaults created from now on use managed storage by default (on unless turned off). The "
                       "admin cloud Storage permission.",
        .payload = {boolean("enabled").gen(gen::boolean()).desc("On or off.")},
        .response = {boolean("new_vaults")},
        .refusal_codes = {"denied", "invalid", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });
    out.push_back({
        .command = "cloud.storage.billing.handoff",
        .description = "The address of the account's billing page (checkout: choose a plan; portal: manage it), to open "
                       "in a browser; short-lived and never stored. The service polls the account's state fast for a "
                       "few minutes afterwards. The admin cloud Billing permission.",
        .payload = {str("kind").gen(gen::constant("portal")).desc("checkout or portal."),
                    str("plan").opt().nullable().desc("checkout: the plan.")},
        .response = modelFields("CloudStorageHandoff"),
        .refusal_codes = {"denied", "invalid", "conflict", "unauthorized", "cloud_unreachable", "cloud_refused"},
        .response_model = "CloudStorageHandoff",
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
