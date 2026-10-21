#pragma once

#include "ops/Actor.hpp"
#include "crypto/SecretKey.hpp"
#include "fs/Fwd.hpp"
#include "storage/Fwd.hpp"
#include "vault/Fwd.hpp"

#include <functional>
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
};

struct NeededVersion {
    unsigned int version{};
    std::optional<std::string> key_check{};  // null when this host can't read that version
    NeedReason reason{NeedReason::Current};
    std::optional<KeyAttestationInfo> attestation{};  // null when none is recorded (or the version isn't readable)
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
// `confirm_name` = the vault's name, else NeedsConfirmation "vault_key_import" (recover) or "vault_key_salvage".
enum class ImportMode { Recover, Salvage };
[[nodiscard]] std::string to_string(ImportMode mode);

struct ImportRequest {
    unsigned int vault_id{};
    nlohmann::json const* keys{};  // the export document (not owned)
    std::optional<std::string> confirm_name{};
    ImportMode mode{ImportMode::Recover};
};

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
};

[[nodiscard]] ImportResult importKeys(const Actor& actor, const ImportRequest& request, Channel channel);

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
