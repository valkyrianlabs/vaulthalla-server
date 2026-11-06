#pragma once

#include "ops/Actor.hpp"
#include "crypto/SecretKey.hpp"
#include "fs/Fwd.hpp"
#include "storage/Fwd.hpp"
#include "vault/Fwd.hpp"

#include <functional>
#include <map>
#include <memory>

#include <ctime>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

// Vault key backup (Vaulthalla Desktop S2, decisions D4/D6): key status, export and export confirmation, shared by
// `vh vault keys status|export` and the ws vault.keys.* commands. See .claude/context/key-backup.md.
//
// Who: status needs the encryption-key View permission (the CLI's `vh vault keys inspect`), export and its
// confirmation the encryption-key Export permission; super admins hold both. A deleted vault (within its key
// retention window) is included only for callers who may remove it (ops::vaults' deleted-vault rule).
//
// Where (D4): key bytes leave the daemon only through the local CLI or a paired device's session, never through a
// browser session or an agent. The transports say which one they are (Channel); the ops refuse the others.
namespace vh::ops::vault_keys {

enum class Channel {
    Cli,      // vh on the control socket (a person at the terminal or a script)
    Device,   // a paired device's session on the device listener
    Console,  // a signed-in browser session: never key bytes
    Agent,    // MCP (vh mcp, /mcp): never key bytes
};

// Why a version is still needed to decrypt something: the current key, the outgoing key of a rotation that has not
// finished re-encrypting the vault, or a retired key that recovery data (snapshots, local versions, provider object
// versions) still references. A version that is several of these reports the first.
enum class NeedReason { Current, Rotation, Recovery };
[[nodiscard]] std::string to_string(NeedReason reason);

// This node's attestation of one key version (vault/KeyAttestation.hpp): public, like the key check.
struct KeyAttestationInfo {
    unsigned int key_id{};
    std::string signature{};  // base64 (64 bytes)
    // base64 (32 bytes): the signing key's public key (key_attestation_keys), so the export can anchor provenance on
    // another node (spec 03 §5.4). An import on this node checks it against its own key of that id; older exports
    // without it still import here.
    std::optional<std::string> public_key{};
};

// One of this node's attestation signing keys: what a recovery kit pins (spec 03 §5.3, attestation_public_keys).
struct AttestationPublicKey {
    unsigned int key_id{};
    std::string public_key{};  // base64 (32 bytes)
    std::optional<std::time_t> retired_at{};
};

// The vault's manifest v2 chain position (opaque_v1 vaults): a recovery kit's checkpoint (spec 03 §4.5).
struct ManifestCheckpoint {
    uint64_t epoch{};
    std::string root_sha256{};
};

// D2 (spec 03 §5.5): whether the vault has recovery material independent of this host (vault::envelopes::material).
struct RecoveryMaterial {
    bool required{false};          // a self-hosted S3 vault that encrypts upstream
    std::string state{};           // not_required | recipient | export | recovery_material_missing
    unsigned int recipients{};     // usable recovery recipients
    std::vector<unsigned int> uncovered_versions{};  // needed versions without an envelope (with recipients)
    bool export_current{false};    // the recorded export is of the current version
    bool rotation_needed{false};   // a revoked recipient still holds envelopes of needed versions
    std::optional<std::string> detail{};
};
// `needed` empty: read from the database (health).
[[nodiscard]] RecoveryMaterial recoveryMaterialOf(unsigned int vaultId, const std::vector<unsigned int>& needed = {},
                                                  unsigned int current = 0);
[[nodiscard]] nlohmann::json toJson(const RecoveryMaterial& material);

// A version `vh vault recover` recovered on this node (#371): attested by the node that minted it, verified with an
// attestation key the customer's material pinned (vault_key_origin).
struct KeyOriginInfo {
    std::string node_id{};
    uint64_t vault_id{};
    unsigned int key_id{};
    std::string anchor{};  // kit | export
    std::time_t recovered_at{};
};

struct NeededVersion {
    unsigned int version{};
    std::optional<std::string> key_check{};  // null when this host can't read that version
    NeedReason reason{NeedReason::Current};
    std::optional<KeyAttestationInfo> attestation{};  // null when none is recorded (or the version isn't readable)
    std::optional<KeyOriginInfo> origin{};            // recovered from another node (vh vault recover)
};

// A key salvage pass (import mode salvage; key-backup.md "Salvage"): what it re-keyed and what it couldn't.
struct SalvageFailure {
    std::string path{};
    unsigned int version{};
    std::string kind{};  // unrecoverable | skipped_remote | deferred | failed
    std::string reason{};
};
struct SalvageReport {
    unsigned int id{};
    std::vector<unsigned int> versions{};      // the unverified versions it salvaged files from
    std::optional<unsigned int> new_version{};  // the fresh key version files were re-encrypted under
    std::string state{};                         // running | finished
    std::time_t started_at{};
    std::optional<std::time_t> finished_at{};
    unsigned int salvaged{}, unrecoverable{}, skipped_remote{}, deferred{}, failed{};
    std::vector<SalvageFailure> failures{};      // the first 50
};

struct KeyStatus {
    unsigned int vault_id{};
    std::string vault_name{};
    bool deleted{false};
    std::optional<std::time_t> key_retain_until{};  // deleted vaults: when the retained key is destroyed
    unsigned int version{};                         // current key version
    std::optional<std::string> key_check{};         // null when the key can't be read on this host
    bool key_available{true};
    // key_missing | key_unsealable | version_missing (vault::KeyUnavailable's codes); unavailable_detail says what to do.
    std::optional<std::string> unavailable_reason{};
    std::optional<std::string> unavailable_detail{};
    std::optional<unsigned int> exported_version{};
    std::optional<std::time_t> exported_at{};
    bool rotation_in_progress{false};
    std::vector<NeededVersion> needed_versions{};   // current first, then ascending
    std::vector<unsigned int> missing_versions{};   // needed, but no key for them is held
    std::optional<KeyAttestationInfo> attestation{};  // the current version's
    std::optional<SalvageReport> last_salvage{};
    // What a recovery kit records about the vault (spec 03 §5.3): its uid, this node, this node's attestation keys and
    // the manifest checkpoint. Public, like the key checks.
    std::optional<std::string> vault_uid{};  // base32
    std::string node_id{};
    std::vector<AttestationPublicKey> attestation_public_keys{};
    std::optional<ManifestCheckpoint> checkpoint{};
    RecoveryMaterial recovery{};
};

// Every vault the caller may inspect (live, and deleted ones within key retention they may remove), or one vault.
// Never key bytes.
[[nodiscard]] std::vector<KeyStatus> status(const Actor& actor, std::optional<unsigned int> vaultId = std::nullopt);
// The ws/`--json` shape of one vault's status (times as Unix seconds or null).
[[nodiscard]] nlohmann::json toJson(const KeyStatus& status);

struct ExportedKey {
    unsigned int version{};
    crypto::SecretKeyPtr key{};
    std::string key_check{};
    std::optional<KeyAttestationInfo> attestation{};
    NeedReason reason{NeedReason::Current};
    std::time_t created_at{}, retired_at{};
};

struct VaultExport {
    unsigned int vault_id{};
    std::string vault_name{};
    bool deleted{false};
    ExportedKey current{};
    std::vector<ExportedKey> historical{};  // every other needed version, ascending
    std::vector<unsigned int> missing{};    // needed versions the vault no longer holds
};

// One vault's needed keys (live, or deleted within key retention). Refused on Console/Agent channels.
[[nodiscard]] VaultExport exportVault(const Actor& actor, unsigned int vaultId, Channel channel);
// Every live vault whose key this host can read; `skipped` names the ones it can't.
struct ExportAll {
    std::vector<VaultExport> vaults{};
    std::vector<std::string> skipped{};
};
[[nodiscard]] ExportAll exportAll(const Actor& actor, Channel channel);

// The export's JSON: the CLI's shape (vault_id, vault_name, key, key_info, historical_keys, missing_key_versions,
// deleted_vault) plus key_check, with every needed version (rotation and recovery) under historical_keys, each with
// its key_check and reason.
[[nodiscard]] nlohmann::json toJson(const VaultExport& exported, const std::string& exportedBy);

// The CLI's mark after a successful export: the current version counts as exported (a rotation makes it stale).
void recordExport(const VaultExport& exported);

// A device stored `version` (Desktop: in 1Password) and confirms it by its key check. Recorded only while that
// version is still the vault's current one and the check matches the daemon's key (else Conflict).
struct Confirmed {
    unsigned int vault_id{};
    unsigned int version{};
    std::time_t exported_at{};
};
[[nodiscard]] Confirmed confirmExport(const Actor& actor, unsigned int vaultId, unsigned int version,
                                      const std::string& keyCheck, Channel channel);

// ---- import (S6, D7, revision 3): restoring keys from a backup. Design: .claude/context/key-backup.md "Key import".
//
// Same permission and channels as export (the console gets import_requires_device). `keys` is an export: one vault
// object or the `all` array; the entry for vault_id is used. Recover (the default) restores as canonical only versions
// the daemon's records reference whose attestation by this node verifies (or that match a key this host still
// unseals); never another key: a key this host can unseal is never replaced (Conflict), identical bytes are a no-op,
// unreferenced versions are refused, the rest need salvage. Salvage additionally re-encrypts files sealed under the
// versions that need it under a fresh daemon key, with the supplied key held only in memory. Writing needs
// `confirm_name` = the vault's name, else NeedsConfirmation "vault_key_import" (recover) or "vault_key_salvage" (any
// salvage-mode request that writes, even when nothing turns out to need salvage).
enum class ImportMode { Recover, Salvage };
[[nodiscard]] std::string to_string(ImportMode mode);

struct ImportRequest {
    unsigned int vault_id{};
    nlohmann::json const* keys{};  // the export document (not owned)
    std::optional<std::string> confirm_name{};
    ImportMode mode{ImportMode::Recover};
    // Instead of `keys`: a recovery kit (spec 03 §5.6, `vh vault keys import --recovery-kit`). Its seed unwraps the
    // vault's KEV1 envelopes from the vault's bucket; the versions they hold go through the same recover rules, proven
    // by the attestations this node recorded for them (and the manifest root's key history). Recover mode only.
    nlohmann::json const* recovery_kit{};
};

// How importKeys reads `keys` (the ws contract's VaultKeyImportDocument): the versions the document carries for
// vaultId, ascending. Throws Invalid when it lacks something an import needs; a malformed attestation is no error (that
// version needs salvage) and is reported per version. Pure (no database); the contract tests hold the model to it.
struct ImportDocumentVersion {
    unsigned int version{};
    bool key_check{false};                             // the backup carries its own key check
    std::optional<unsigned int> attestation_key_id{};  // a well-formed attestation names this signing key
    std::optional<std::string> attestation_problem{};  // an attestation is present but malformed
};
[[nodiscard]] std::vector<ImportDocumentVersion> readImportDocument(const nlohmann::json& keys, unsigned int vaultId);

enum class ImportOutcome {
    Restored,      // attested by this node (or matching a key it holds): re-sealed under this host's vault master
    Unchanged,     // this host already holds exactly these bytes
    NeedsSalvage,  // referenced, but not provably this vault's key: nothing written (salvage mode re-keys its files)
    Refused,       // the vault has no record of this version: an import never introduces one
    Salvaged,      // salvage mode: its files went through a salvage pass (see the report); the key was not stored
};
[[nodiscard]] std::string to_string(ImportOutcome outcome);

struct ImportedVersion {
    unsigned int version{};
    ImportOutcome outcome{ImportOutcome::Unchanged};
    std::string detail{};
};

// What a recovery-kit import found in the bucket.
struct KitImportReport {
    unsigned int envelopes{};   // objects under .vaulthalla/key/
    unsigned int unwrapped{};   // addressed to the kit's recipient and authentic
    unsigned int skipped{};     // another recipient's, or a reserved purpose or recipient class (never fatal)
    unsigned int rejected{};    // damaged, for another vault, or not KEV1
    unsigned int ignored{};     // unwrapped, but not the key the vault's records name for that version
    bool root_consulted{false}; // the manifest root's key history supplied attestations the database lacked
};

struct ImportResult {
    unsigned int vault_id{};
    std::string vault_name{};
    bool deleted{false};
    ImportMode mode{ImportMode::Recover};
    bool written{false};
    bool key_available{false};  // the vault's engine runs (live vaults); a deleted vault needs a restore first
    std::optional<std::string> note{};
    std::vector<ImportedVersion> versions{};
    std::optional<SalvageReport> salvage{};
    std::optional<KitImportReport> recovery_kit{};
};

[[nodiscard]] ImportResult importKeys(const Actor& actor, const ImportRequest& request, Channel channel);

// ---- for `vh vault recover` (ops::vault_recover, #371): the same rules for whoever handles key material

// The encryption-key Export permission (super admins hold it) and D4's channels: `refusalCode` for a browser session,
// Denied for an agent.
void requireKeyMaterialAccess(const Actor& actor, Channel channel, const std::string& refusalCode);
// The salvage pass of a vault a restore just created: its vault_key_salvage row (state running, new_version = the
// fresh current key) names `supplied`'s versions; their files are re-encrypted under the fresh key exactly as an
// import's salvage does, and the supplied keys are never stored.
[[nodiscard]] SalvageReport salvageRecoveredVault(const Actor& actor, unsigned int vaultId,
                                                  std::map<unsigned int, crypto::SecretKeyPtr> supplied, Channel channel);

// Test seam: called after each step of a salvage pass's per-file protocol (sync::rotation's Step, as an int so this
// header stays light); throwing sync::rotation::SimulatedCrash from it simulates a crash there. Empty: none.
using SalvageStepHook = std::function<void(int step, const std::shared_ptr<fs::model::File>& file)>;
void setSalvageStepHookForTesting(SalvageStepHook hook);
// Test seam: called with the vault's engine once a salvage pass has it, before any file is touched (tests install a
// fake bucket and a price gate there). Empty: none.
using SalvageEngineHook = std::function<void(const std::shared_ptr<storage::Engine>& engine)>;
void setSalvageEngineHookForTesting(SalvageEngineHook hook);
[[nodiscard]] nlohmann::json toJson(const SalvageReport& report);
[[nodiscard]] nlohmann::json toJson(const ImportResult& result);

}
