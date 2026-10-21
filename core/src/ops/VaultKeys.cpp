#include "ops/VaultKeys.hpp"

#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/util/Gcm.hpp"
#include "crypto/util/encrypt.hpp"
#include "crypto/util/verify.hpp"
#include "fs/model/File.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Vaults.hpp"
#include "rbac/permission/admin/Keys.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/rotation/Rotation.hpp"
#include "sync/rotation/Runtime.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <fcntl.h>
#include <paths.h>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fmt/format.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <ranges>
#include <set>
#include <tuple>

#include <nlohmann/json.hpp>

namespace vh::ops::vault_keys {

namespace {

using KeyQ = db::query::vault::Key;
using DeletionQ = db::query::vault::Deletion;
using KeyRecord = std::shared_ptr<vault::model::Key>;
using EnginePtr = std::shared_ptr<storage::Engine>;
using FileSP = sync::rotation::FileSP;

void requireView(const Actor& actor) {
    requireActor(actor);
    if (actor->isSuperAdmin() || actor->encryptionKeysPerms().canView()) return;
    throw Denied("only super admins or users with the view encryption keys permission can inspect vault keys");
}

void requireExport(const Actor& actor) {
    requireActor(actor);
    if (actor->isSuperAdmin()) return;
    if (!actor->encryptionKeysPerms().canExport())
        throw Denied("only super admins or users with the export encryption keys permission can export vault keys");
    log::Registry::audit()->warn("[ops::vault_keys] {} uses the export encryption keys permission without being a super "
                                 "admin. It is extremely dangerous to grant it to anyone else.", actor->name());
}

// D4: key bytes go to the local CLI or a paired device, nowhere else.
void requireKeyChannel(const Channel channel) {
    if (channel == Channel::Console)
        throw Refused("export_requires_device",
                      "vault keys leave the daemon only through a paired device (Vaulthalla Desktop) or the local vh "
                      "CLI, never through the browser");
    if (channel == Channel::Agent)
        throw Denied("vault key material is never handled by agents (D4); the human runs this in a terminal themselves");
}

std::string channelName(const Channel channel) {
    switch (channel) {
        case Channel::Cli: return "the CLI";
        case Channel::Device: return "a paired device";
        case Channel::Console: return "the console";
        case Channel::Agent: return "an agent";
    }
    return "?";
}

EnginePtr engineFor(const unsigned int vaultId) {
    // getEngine() warns on a miss; a vault without an engine is an expected state here (its key can't be unsealed).
    for (const auto& engine : runtime::Deps::get().storageManager->getEngines())
        if (engine && engine->vault && engine->vault->id == vaultId) return engine;
    return nullptr;
}

// Key checks of sealed rows this process could not take from an engine (deleted vaults, vaults without an engine),
// keyed by the sealed bytes so a re-sealed row is checked again. An empty value: the row does not unseal here.
struct SealedCheckCache {
    std::mutex mutex;
    std::map<std::tuple<unsigned int, unsigned int, std::string>, std::string> checks;
};

SealedCheckCache& sealedChecks() {
    static SealedCheckCache cache;
    return cache;
}

std::string sealedId(const vault::model::Key& rec) {
    return crypto::util::b64_encode(rec.encrypted_key) + "/" + crypto::util::b64_encode(rec.iv);
}

// Unseals rows under this host's vault master (the TPM is asked only when a row actually needs unsealing).
class Unsealer {
public:
    // Throws when the row does not authenticate under this host's vault master.
    crypto::SecretKeyPtr unseal(const vault::model::Key& rec) {
        if (!provider_) {
            provider_.emplace(paths::testMode ? "test_vault_master" : "vault_master");
            provider_->init();
        }
        auto raw = crypto::util::decrypt_aes256_gcm(rec.encrypted_key, provider_->getMasterKey(), rec.iv);
        if (raw.size() != crypto::util::AES_KEY_SIZE) {
            sodium_memzero(raw.data(), raw.size());
            throw std::runtime_error("the sealed key is not a 32-byte AES key");
        }
        if (rec.vaultId != 0) vault::attestation::backfill(rec, raw);  // records its provenance if it never was
        auto key = std::make_shared<const crypto::SecretKey>(raw);
        sodium_memzero(raw.data(), raw.size());
        return key;
    }

    // Seals key bytes under this host's vault master with a fresh IV: {encrypted_key, iv}.
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> seal(const crypto::SecretKey& key) {
        if (!provider_) {
            provider_.emplace(paths::testMode ? "test_vault_master" : "vault_master");
            provider_->init();
        }
        std::vector<uint8_t> raw(key.bytes().begin(), key.bytes().end());
        std::vector<uint8_t> iv;
        auto sealed = crypto::util::encrypt_aes256_gcm(raw, provider_->getMasterKey(), iv);
        sodium_memzero(raw.data(), raw.size());
        return {std::move(sealed), std::move(iv)};
    }

    std::optional<std::string> check(const unsigned int vaultId, const vault::model::Key& rec) {
        auto& cache = sealedChecks();
        const auto id = std::make_tuple(vaultId, rec.version, sealedId(rec));
        {
            std::scoped_lock lock(cache.mutex);
            if (const auto it = cache.checks.find(id); it != cache.checks.end())
                return it->second.empty() ? std::nullopt : std::make_optional(it->second);
        }
        std::string value;
        try {
            value = vault::keyCheck(unseal(rec)->bytes(), vaultId, rec.version);
        } catch (const std::exception& e) {
            log::Registry::crypto()->warn("[ops::vault_keys] key version {} of vault {} does not unseal on this host: {}",
                                          rec.version, vaultId, e.what());
        }
        std::scoped_lock lock(cache.mutex);
        if (cache.checks.size() > 4096) cache.checks.clear();
        cache.checks[id] = value;
        return value.empty() ? std::nullopt : std::make_optional(value);
    }

private:
    std::optional<crypto::secrets::KeyProvider> provider_;
};

// Where one vault's key versions come from: its engine (memory, retired versions unsealed on demand), or its sealed
// rows (a vault without an engine, a deleted vault's retained copies).
struct Source {
    unsigned int vault_id{};
    std::string vault_name{};
    bool deleted{false};
    std::optional<std::time_t> key_retain_until{};
    EnginePtr engine{};
    unsigned int current{};
    bool rotating{false};
    std::map<unsigned int, KeyRecord> sealed{};  // every version held as a sealed row (always loaded)
    std::optional<unsigned int> exported_version{};
    std::optional<std::time_t> exported_at{};
};

Source liveSource(const std::shared_ptr<vault::model::Vault>& vault) {
    Source s{.vault_id = vault->id, .vault_name = vault->name, .engine = engineFor(vault->id)};
    if (const auto rec = KeyQ::getVaultKey(vault->id)) s.sealed[rec->version] = rec;
    for (const auto v : KeyQ::retiredKeyVersions(vault->id))
        if (const auto rec = KeyQ::getRetiredVaultKey(vault->id, v)) s.sealed[v] = rec;
    if (s.engine) {
        const auto [_, version] = s.engine->encryptionManager->currentKey();
        s.current = version;
        s.rotating = s.engine->encryptionManager->rotation_in_progress();
    } else if (const auto rec = KeyQ::getVaultKey(vault->id)) {
        s.current = rec->version;
        s.rotating = KeyQ::keyRotationInProgress(vault->id);
    } else {
        // No key record (load_key refused to mint one over sealed content): the highest version the records reference.
        const auto versions = KeyQ::referencedKeyVersions(vault->id);
        s.current = versions.empty() ? 0 : versions.back();
        s.rotating = KeyQ::keyRotationInProgress(vault->id);
    }
    const auto exported = KeyQ::exportRecord(vault->id);
    s.exported_version = exported.version;
    s.exported_at = exported.at;
    return s;
}

Source deletedSource(const vault::model::Deletion& d) {
    Source s{.vault_id = d.vault_id, .vault_name = d.vault_name, .deleted = true, .key_retain_until = d.key_retain_until};
    for (const auto& rec : DeletionQ::retainedKeys(d.vault_id)) s.sealed[rec->version] = rec;
    if (s.sealed.empty()) throw Conflict("the key of deleted vault '" + d.vault_name + "' was destroyed when its key "
                                         "retention window ended");
    s.current = d.key_version.value_or(s.sealed.rbegin()->first);
    // While the vault row exists (pending or purging), its rotation state is still there.
    s.rotating = !KeyQ::rotationPendingKeyVersions(d.vault_id).empty();
    if (d.key_exported_at) {
        s.exported_version = s.current;
        s.exported_at = d.key_exported_at;
    }
    return s;
}

// The versions still needed, current first: the outgoing key of an unfinished rotation, then retired versions
// recovery data references.
std::vector<std::pair<unsigned int, NeedReason>> neededVersions(const Source& s) {
    std::vector<std::pair<unsigned int, NeedReason>> out{{s.current, NeedReason::Current}};
    const auto add = [&](const unsigned int v, const NeedReason reason) {
        if (v == 0 || std::ranges::any_of(out, [&](const auto& p) { return p.first == v; })) return;
        out.emplace_back(v, reason);
    };
    for (const auto v : KeyQ::rotationPendingKeyVersions(s.vault_id)) add(v, NeedReason::Rotation);
    // Live files still sealed under an older version (a rotation the database no longer records as pending), except
    // versions a key salvage took over: their files were re-keyed or are unrecoverable.
    const auto salvaged = KeyQ::salvageVersions(s.vault_id);
    for (const auto v : KeyQ::liveFileKeyVersions(s.vault_id))
        if (v < s.current && std::ranges::find(salvaged, v) == salvaged.end()) add(v, NeedReason::Rotation);
    for (const auto v : KeyQ::recoveryReferencedKeyVersions(s.vault_id)) add(v, NeedReason::Recovery);
    std::sort(out.begin() + 1, out.end());
    return out;
}

// The key of `version`, or null when this host doesn't hold it or can't unseal it (`why` says which).
crypto::SecretKeyPtr keyOf(const Source& s, const unsigned int version, Unsealer& unsealer, std::string& why) {
    if (s.engine && s.engine->encryptionManager->hasKeyVersion(version)) {
        try {
            return s.engine->encryptionManager->historicalKeySnapshot(version);
        } catch (const std::exception& e) {
            why = e.what();
            return nullptr;
        }
    }
    const auto it = s.sealed.find(version);
    if (it == s.sealed.end()) {
        why = "not held";
        return nullptr;
    }
    try {
        return unsealer.unseal(*it->second);
    } catch (const std::exception& e) {
        why = std::string("does not unseal on this host: ") + e.what();
        return nullptr;
    }
}

std::optional<std::string> checkOf(const Source& s, const unsigned int version, Unsealer& unsealer) {
    if (s.engine && s.engine->encryptionManager->hasKeyVersion(version)) {
        try {
            return vault::keyCheck(s.engine->encryptionManager->historicalKeySnapshot(version)->bytes(), s.vault_id,
                                   version);
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    const auto it = s.sealed.find(version);
    if (it == s.sealed.end()) return std::nullopt;
    return unsealer.check(s.vault_id, *it->second);
}

std::optional<KeyAttestationInfo> attestationInfoOf(const std::optional<unsigned int>& keyId, const std::vector<uint8_t>& sig) {
    if (!keyId || sig.empty()) return std::nullopt;
    return KeyAttestationInfo{.key_id = *keyId, .signature = crypto::util::b64_encode(sig)};
}

// The version's sealed row as stored now (a backfill may have written its provenance since the Source was read).
KeyRecord freshKeyRow(const Source& s, const unsigned int version) {
    if (s.deleted) {
        for (const auto& rec : DeletionQ::retainedKeys(s.vault_id))
            if (rec->version == version) return rec;
        return nullptr;
    }
    if (const auto cur = KeyQ::getVaultKey(s.vault_id); cur && cur->version == version) return cur;
    return KeyQ::getRetiredVaultKey(s.vault_id, version);
}

// The recorded attestation of a version whose key check is `check` (a row whose recorded check differs says nothing
// about this key).
std::optional<KeyAttestationInfo> recordedAttestation(const Source& s, const unsigned int version,
                                                      const std::string& check) {
    auto row = s.sealed.contains(version) ? s.sealed.at(version) : nullptr;
    if (!row || row->attestation.empty()) row = freshKeyRow(s, version);
    if (!row || !row->key_check || !vault::keyCheckEquals(*row->key_check, check)) return std::nullopt;
    return attestationInfoOf(row->attestation_key_id, row->attestation);
}

// The attestation an export carries: the recorded one, else this node signs now and records it (the key is in hand).
std::optional<KeyAttestationInfo> exportAttestation(const Source& s, const unsigned int version,
                                                    const crypto::SecretKey& key, const std::string& check) {
    if (auto recorded = recordedAttestation(s, version, check)) return recorded;
    const auto p = vault::attestation::provenanceOf(s.vault_id, version, key.bytes());
    if (const auto row = freshKeyRow(s, version)) {
        try {
            (void)KeyQ::recordProvenance(*row, p);
        } catch (const std::exception& e) {
            log::Registry::crypto()->warn("[ops::vault_keys] could not record the attestation of vault {} key version "
                                          "{}: {}", s.vault_id, version, e.what());
        }
    }
    return attestationInfoOf(p.attestation_key_id, p.attestation);
}

SalvageReport salvageReportFrom(const KeyQ::Salvage& r) {
    SalvageReport out{.id = r.id, .versions = r.versions, .new_version = r.new_version, .state = r.state,
                      .started_at = r.started_at, .finished_at = r.finished_at, .salvaged = r.salvaged,
                      .unrecoverable = r.unrecoverable, .skipped_remote = r.skipped_remote, .deferred = r.deferred,
                      .failed = r.failed};
    try {
        for (const auto& f : nlohmann::json::parse(r.failures_json))
            out.failures.push_back({.path = f.value("path", ""), .version = f.value("version", 0u),
                                    .kind = f.value("kind", ""), .reason = f.value("reason", "")});
    } catch (const std::exception&) {}
    return out;
}

KeyStatus statusOf(const Source& s, Unsealer& unsealer) {
    KeyStatus out{.vault_id = s.vault_id, .vault_name = s.vault_name, .deleted = s.deleted,
                  .key_retain_until = s.key_retain_until, .version = s.current,
                  .exported_version = s.exported_version, .exported_at = s.exported_at,
                  .rotation_in_progress = s.rotating};
    for (const auto& [version, reason] : neededVersions(s)) {
        auto check = checkOf(s, version, unsealer);
        if (!check) out.missing_versions.push_back(version);
        auto att = check ? recordedAttestation(s, version, *check) : std::nullopt;
        out.needed_versions.push_back({.version = version, .key_check = check, .reason = reason,
                                       .attestation = std::move(att)});
    }
    out.key_check = out.needed_versions.front().key_check;
    out.attestation = out.needed_versions.front().attestation;
    if (!s.deleted)
        if (const auto last = KeyQ::lastSalvage(s.vault_id)) out.last_salvage = salvageReportFrom(*last);
    // The codes vault::KeyUnavailable uses when the engine refuses to start.
    const auto hint = fmt::format("; restore it with `vh vault keys import {} --file <export.json>`", s.vault_id);
    if (!s.sealed.contains(s.current)) {
        out.unavailable_reason = "key_missing";
        out.unavailable_detail = "this host holds no key record for the vault's current version " +
                                 std::to_string(s.current) + hint;
    } else if (!out.key_check) {
        out.unavailable_reason = "key_unsealable";
        out.unavailable_detail = "the vault's key does not unseal on this host (the vault master changed or the key "
                                 "row is damaged)" + hint;
    } else {
        for (const auto& n : out.needed_versions)
            if (!n.key_check && n.reason != NeedReason::Recovery) {
                out.unavailable_reason = "version_missing";
                out.unavailable_detail = fmt::format("key version {} ({}) is not held or doesn't unseal on this host{}",
                                                     n.version, to_string(n.reason), hint);
                break;
            }
    }
    out.key_available = !out.unavailable_reason.has_value();
    return out;
}

std::time_t createdAtOf(const Source& s, const unsigned int version) {
    const auto it = s.sealed.find(version);
    return it == s.sealed.end() ? 0 : it->second->created_at;
}

// A retired row's updated_at is when it retired (get_retired_vault_key); a deleted vault's copies don't say.
std::time_t retiredAtOf(const Source& s, const unsigned int version) {
    if (version == s.current || s.deleted) return 0;
    const auto it = s.sealed.find(version);
    return it == s.sealed.end() ? 0 : it->second->updated_at;
}

VaultExport exportFrom(const Source& s) {
    Unsealer unsealer;
    VaultExport out{.vault_id = s.vault_id, .vault_name = s.vault_name, .deleted = s.deleted};
    for (const auto& [version, reason] : neededVersions(s)) {
        std::string why;
        auto key = keyOf(s, version, unsealer, why);
        if (!key) {
            if (reason == NeedReason::Current)
                throw Conflict("the current key of vault '" + s.vault_name + "' can't be read on this host (" + why +
                               "); restore it with `vh vault keys import`");
            log::Registry::audit()->error("[ops::vault_keys] vault {} still needs key version {}, which this host "
                                          "can't read ({})", s.vault_id, version, why);
            out.missing.push_back(version);
            continue;
        }
        const auto check = vault::keyCheck(key->bytes(), s.vault_id, version);
        ExportedKey k{.version = version, .key = key, .key_check = check,
                      .attestation = exportAttestation(s, version, *key, check), .reason = reason,
                      .created_at = createdAtOf(s, version), .retired_at = retiredAtOf(s, version)};
        if (reason == NeedReason::Current) out.current = std::move(k);
        else out.historical.push_back(std::move(k));
    }
    return out;
}

Source sourceFor(const Actor& actor, const unsigned int vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    if (const auto vault = db::query::vault::Vault::getVault(vaultId)) return liveSource(vault);
    if (const auto d = DeletionQ::get(vaultId)) {
        try {
            (void)ops::vaults::findDeleted(actor, std::to_string(vaultId), std::nullopt);
        } catch (const NotFound&) {
            throw NotFound("no vault with ID " + std::to_string(vaultId));
        }
        if (!d->keyRetained())
            throw Conflict("the key of deleted vault '" + d->vault_name + "' was destroyed when its key retention "
                           "window ended");
        return deletedSource(*d);
    }
    throw NotFound("no vault with ID " + std::to_string(vaultId));
}

std::string auditName(const VaultExport& e) {
    return fmt::format("vault {} ('{}'{}), key version {}", e.vault_id, e.vault_name, e.deleted ? ", deleted" : "",
                       e.current.version);
}

}

std::string to_string(const NeedReason reason) {
    switch (reason) {
        case NeedReason::Current: return "current";
        case NeedReason::Rotation: return "rotation";
        case NeedReason::Recovery: return "recovery";
    }
    return "current";
}

std::vector<KeyStatus> status(const Actor& actor, const std::optional<unsigned int> vaultId) {
    requireView(actor);
    Unsealer unsealer;
    std::vector<KeyStatus> out;
    if (vaultId) {
        out.push_back(statusOf(sourceFor(actor, *vaultId), unsealer));
        return out;
    }
    for (const auto& vault : db::query::vault::Vault::listVaults()) {
        try {
            out.push_back(statusOf(liveSource(vault), unsealer));
        } catch (const Conflict& e) {
            log::Registry::crypto()->warn("[ops::vault_keys] no key status for vault {}: {}", vault->id, e.what());
        }
    }
    for (const auto& d : ops::vaults::listDeleted(actor)) {
        if (!d || !d->keyRetained()) continue;
        // A pending deletion's vault row still exists; it is listed once, as deleted.
        std::erase_if(out, [&](const KeyStatus& s) { return s.vault_id == d->vault_id; });
        try {
            out.push_back(statusOf(deletedSource(*d), unsealer));
        } catch (const Conflict&) {}
    }
    return out;
}

namespace {
nlohmann::json attestationJson(const std::optional<KeyAttestationInfo>& a) {
    if (!a) return nullptr;
    return {{"key_id", a->key_id}, {"signature", a->signature}};
}
}

nlohmann::json toJson(const KeyStatus& s) {
    const auto time = [](const std::optional<std::time_t>& t) {
        return t ? nlohmann::json(static_cast<int64_t>(*t)) : nlohmann::json(nullptr);
    };
    auto needed = nlohmann::json::array();
    for (const auto& n : s.needed_versions)
        needed.push_back({{"version", n.version},
                          {"key_check", n.key_check ? nlohmann::json(*n.key_check) : nlohmann::json(nullptr)},
                          {"reason", to_string(n.reason)},
                          {"attestation", attestationJson(n.attestation)}});
    return {{"vault_id", s.vault_id},
            {"vault_name", s.vault_name},
            {"deleted", s.deleted},
            {"key_retain_until", time(s.key_retain_until)},
            {"version", s.version},
            {"key_check", s.key_check ? nlohmann::json(*s.key_check) : nlohmann::json(nullptr)},
            {"key_available", s.key_available},
            {"unavailable_reason", s.unavailable_reason ? nlohmann::json(*s.unavailable_reason) : nlohmann::json(nullptr)},
            {"unavailable_detail", s.unavailable_detail ? nlohmann::json(*s.unavailable_detail) : nlohmann::json(nullptr)},
            {"exported_version", s.exported_version ? nlohmann::json(*s.exported_version) : nlohmann::json(nullptr)},
            {"exported_at", time(s.exported_at)},
            {"rotation_in_progress", s.rotation_in_progress},
            {"needed_versions", std::move(needed)},
            {"missing_versions", s.missing_versions},
            {"attestation", attestationJson(s.attestation)},
            {"last_salvage", s.last_salvage ? toJson(*s.last_salvage) : nlohmann::json(nullptr)}};
}

VaultExport exportVault(const Actor& actor, const unsigned int vaultId, const Channel channel) {
    requireExport(actor);
    requireKeyChannel(channel);
    auto out = exportFrom(sourceFor(actor, vaultId));
    log::Registry::audit()->warn("[ops::vault_keys] {} exported {} and {} other needed version(s) through {}",
                                 actor->name(), auditName(out), out.historical.size(), channelName(channel));
    return out;
}

ExportAll exportAll(const Actor& actor, const Channel channel) {
    requireExport(actor);
    requireKeyChannel(channel);
    ExportAll out;
    for (const auto& vault : db::query::vault::Vault::listVaults()) {
        try {
            out.vaults.push_back(exportFrom(liveSource(vault)));
            log::Registry::audit()->warn("[ops::vault_keys] {} exported {} and {} other needed version(s) through {}",
                                         actor->name(), auditName(out.vaults.back()),
                                         out.vaults.back().historical.size(), channelName(channel));
        } catch (const Error& e) {
            out.skipped.push_back(vault->name + " (ID " + std::to_string(vault->id) + "): " + e.what());
        }
    }
    return out;
}

nlohmann::json toJson(const VaultExport& exported, const std::string& exportedBy) {
    auto v = std::make_shared<vault::model::Vault>();
    v->id = exported.vault_id;
    v->name = exported.vault_name;
    auto record = std::make_shared<vault::model::Key>();
    record->vaultId = exported.vault_id;
    record->version = exported.current.version;
    record->created_at = exported.current.created_at;

    std::vector<uint8_t> raw(exported.current.key->bytes().begin(), exported.current.key->bytes().end());
    auto out = vault::model::generate_json_key_object(v, raw, record, exportedBy);
    sodium_memzero(raw.data(), raw.size());
    out["key_check"] = exported.current.key_check;
    out["key_info"]["key_check"] = exported.current.key_check;
    out["attestation"] = attestationJson(exported.current.attestation);
    out["key_info"]["attestation"] = attestationJson(exported.current.attestation);

    if (!exported.historical.empty()) {
        auto historical = nlohmann::json::array();
        for (const auto& k : exported.historical) {
            std::vector<uint8_t> bytes(k.key->bytes().begin(), k.key->bytes().end());
            historical.push_back({
                {"key_version", k.version},
                {"key", crypto::util::b64_encode(bytes)},
                {"key_check", k.key_check},
                {"attestation", attestationJson(k.attestation)},
                {"reason", to_string(k.reason)},
                {"created_at", k.created_at ? nlohmann::json(db::encoding::timestampToString(k.created_at)) : nlohmann::json(nullptr)},
                {"retired_at", k.retired_at ? nlohmann::json(db::encoding::timestampToString(k.retired_at)) : nlohmann::json(nullptr)},
            });
            sodium_memzero(bytes.data(), bytes.size());
        }
        out["historical_keys"] = std::move(historical);
    }
    if (!exported.missing.empty()) out["missing_key_versions"] = exported.missing;
    if (exported.deleted) out["deleted_vault"] = true;
    return out;
}

void recordExport(const VaultExport& exported) {
    if (exported.deleted) DeletionQ::markKeyExported(exported.vault_id);
    else KeyQ::markExported(exported.vault_id, exported.current.version);
}

Confirmed confirmExport(const Actor& actor, const unsigned int vaultId, const unsigned int version,
                        const std::string& keyCheck, const Channel channel) {
    requireExport(actor);
    requireKeyChannel(channel);
    if (version == 0) throw Invalid("version must be a positive integer");
    if (keyCheck.size() != 32 || !std::ranges::all_of(keyCheck, [](const char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        }))
        throw Invalid("key_check must be 32 lowercase hex digits");

    const auto source = sourceFor(actor, vaultId);
    if (version != source.current)
        throw Conflict(fmt::format("key version {} is no longer the current key of vault '{}' (current: {}); back up "
                                   "the current version and confirm that", version, source.vault_name, source.current));
    Unsealer unsealer;
    const auto check = checkOf(source, version, unsealer);
    if (!check) throw Conflict("the current key of vault '" + source.vault_name + "' can't be read on this host");
    if (!vault::keyCheckEquals(*check, keyCheck))
        throw Conflict(fmt::format("the key check does not match key version {} of vault '{}': the stored key is not "
                                   "this vault's key", version, source.vault_name));

    std::time_t at = std::time(nullptr);
    if (source.deleted) {
        DeletionQ::markKeyExported(vaultId);
    } else {
        const auto recorded = KeyQ::markExportedIfCurrent(vaultId, version);
        if (!recorded)
            throw Conflict(fmt::format("vault '{}' rotated its key while this was confirmed; back up the new version",
                                       source.vault_name));
        at = *recorded;
    }
    log::Registry::audit()->info("[ops::vault_keys] {} confirmed a backup of vault {} ('{}'), key version {}, through {}",
                                 actor->name(), vaultId, source.vault_name, version, channelName(channel));
    return {.vault_id = vaultId, .version = version, .exported_at = at};
}

namespace {

struct Candidate {
    unsigned int version{};
    crypto::SecretKeyPtr key{};
    std::optional<std::string> backup_check{};
    std::optional<vault::attestation::Attestation> attestation{};
    std::optional<std::string> attestation_problem{};  // present but malformed
};

std::optional<std::vector<uint8_t>> decodeKey(const nlohmann::json& v) {
    if (!v.is_string()) return std::nullopt;
    const auto& text = v.get_ref<const std::string&>();
    std::vector<uint8_t> out(text.size());
    std::size_t len = 0;
    if (sodium_base642bin(out.data(), out.size(), text.data(), text.size(), nullptr, &len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return std::nullopt;
    out.resize(len);
    return out;
}

unsigned int versionOf(const nlohmann::json& v, const char* what) {
    if (!v.is_number_unsigned() || v.get<uint64_t>() == 0 || v.get<uint64_t>() > UINT32_MAX)
        throw Invalid(std::string(what) + " must be a positive integer");
    return v.get<unsigned int>();
}

// {key_id, signature (base64, 64 bytes)}; a malformed one is kept as a problem (that version needs salvage).
void parseAttestation(const nlohmann::json* field, Candidate& c) {
    if (!field || field->is_null()) return;
    if (!field->is_object() || !field->contains("key_id") || !field->at("key_id").is_number_unsigned() ||
        !field->contains("signature")) {
        c.attestation_problem = "the backup's attestation is malformed";
        return;
    }
    auto sig = decodeKey(field->at("signature"));
    if (!sig || sig->size() != vault::attestation::kSignatureSize) {
        c.attestation_problem = "the backup's attestation signature is not 64 bytes of base64";
        return;
    }
    c.attestation = vault::attestation::Attestation{.key_id = field->at("key_id").get<unsigned int>(),
                                                    .signature = std::move(*sig)};
}

const nlohmann::json* fieldIn(const nlohmann::json& entry, const char* name) {
    if (entry.contains(name)) return &entry.at(name);
    if (entry.contains("key_info") && entry.at("key_info").is_object() && entry.at("key_info").contains(name))
        return &entry.at("key_info").at(name);
    return nullptr;
}

// The entry for `vaultId` in an export (one object, or the `all` array), as candidate versions.
std::vector<Candidate> candidatesFrom(const nlohmann::json& keys, const unsigned int vaultId) {
    const nlohmann::json* entry = nullptr;
    const auto matches = [&](const nlohmann::json& e) {
        return e.is_object() && e.contains("vault_id") && e.at("vault_id").is_number_unsigned() &&
               e.at("vault_id").get<uint64_t>() == vaultId;
    };
    if (keys.is_array()) {
        for (const auto& e : keys)
            if (matches(e)) {
                if (entry) throw Invalid("the export lists vault " + std::to_string(vaultId) + " twice");
                entry = &e;
            }
    } else if (matches(keys)) {
        entry = &keys;
    }
    if (!entry) throw Invalid("the export has no entry for vault " + std::to_string(vaultId) +
                              " (keys are imported into the vault they were exported from)");

    std::vector<Candidate> out;
    const auto add = [&](const nlohmann::json& keyField, const unsigned int version, const nlohmann::json* check,
                         const nlohmann::json* attestation) {
        auto bytes = decodeKey(keyField);
        if (!bytes || bytes->size() != crypto::util::AES_KEY_SIZE) {
            if (bytes) sodium_memzero(bytes->data(), bytes->size());
            throw Invalid("key version " + std::to_string(version) + " is not a base64 32-byte key");
        }
        auto key = std::make_shared<const crypto::SecretKey>(*bytes);
        sodium_memzero(bytes->data(), bytes->size());
        for (const auto& c : out)
            if (c.version == version) {
                if (sodium_memcmp(c.key->bytes().data(), key->bytes().data(), crypto::util::AES_KEY_SIZE) != 0)
                    throw Invalid("the export holds two different keys for version " + std::to_string(version));
                return;
            }
        Candidate c{.version = version, .key = std::move(key)};
        if (check && check->is_string()) c.backup_check = check->get<std::string>();
        parseAttestation(attestation, c);
        out.push_back(std::move(c));
    };

    if (!entry->contains("key") || !entry->contains("key_info") || !entry->at("key_info").is_object() ||
        !entry->at("key_info").contains("key_version"))
        throw Invalid("the export entry needs key and key_info.key_version");
    add(entry->at("key"), versionOf(entry->at("key_info").at("key_version"), "key_info.key_version"),
        fieldIn(*entry, "key_check"), fieldIn(*entry, "attestation"));
    if (entry->contains("historical_keys")) {
        if (!entry->at("historical_keys").is_array()) throw Invalid("historical_keys must be an array");
        for (const auto& h : entry->at("historical_keys")) {
            if (!h.is_object() || !h.contains("key") || !h.contains("key_version"))
                throw Invalid("every historical_keys entry needs key and key_version");
            add(h.at("key"), versionOf(h.at("key_version"), "historical_keys[].key_version"),
                h.contains("key_check") ? &h.at("key_check") : nullptr,
                h.contains("attestation") ? &h.at("attestation") : nullptr);
        }
    }
    std::ranges::sort(out, {}, &Candidate::version);
    return out;
}

// Where an import writes: the vault's live key rows (while its vault row exists) and, for a deleted vault, its
// retained copies; and what the daemon's records reference.
struct ImportTarget {
    unsigned int vault_id{};
    std::string name{};
    bool deleted{false};
    bool live_rows{false};
    std::optional<unsigned int> current{};
    KeyRecord current_row{};
    std::map<unsigned int, KeyRecord> retired{};
    std::map<unsigned int, KeyRecord> copies{};
    std::vector<unsigned int> referenced{};
};

ImportTarget importTarget(const Actor& actor, const unsigned int vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    ImportTarget t{.vault_id = vaultId};
    if (const auto vault = db::query::vault::Vault::getVault(vaultId)) {
        t.name = vault->name;
        t.live_rows = true;
    } else if (const auto d = DeletionQ::get(vaultId)) {
        try {
            (void)ops::vaults::findDeleted(actor, std::to_string(vaultId), std::nullopt);
        } catch (const NotFound&) {
            throw NotFound("no vault with ID " + std::to_string(vaultId));
        }
        if (!d->keyRetained())
            throw Conflict("the key of deleted vault '" + d->vault_name + "' was destroyed when its key retention "
                           "window ended");
        if (!d->restorable())
            throw Conflict("deleted vault '" + d->vault_name + "' is being or has been purged: its files are gone, so "
                           "there is nothing left to restore a key for");
        t.name = d->vault_name;
        t.deleted = true;
        t.live_rows = DeletionQ::getDeletedVault(vaultId) != nullptr;
        t.current = d->key_version;
        for (const auto& rec : DeletionQ::retainedKeys(vaultId)) t.copies[rec->version] = rec;
    } else {
        throw NotFound("no vault with ID " + std::to_string(vaultId));
    }
    t.referenced = KeyQ::referencedKeyVersions(vaultId);
    if (t.live_rows) {
        t.current_row = KeyQ::getVaultKey(vaultId);
        if (t.current_row) t.current = t.current_row->version;
        // No key record (load_key refuses to mint one over sealed content): the highest version the daemon's records
        // reference, never what a backup claims.
        else if (!t.referenced.empty()) t.current = t.referenced.back();
        for (const auto v : KeyQ::retiredKeyVersions(vaultId))
            if (const auto rec = KeyQ::getRetiredVaultKey(vaultId, v)) t.retired[v] = rec;
    }
    if (!t.current || *t.current == 0)
        throw Conflict("vault '" + t.name + "' has no key record to restore into");
    return t;
}

struct Slot {
    KeyQ::SealedTable table{};
    KeyRecord row{};  // null: no row yet
};

bool sameKey(const crypto::SecretKey& a, const crypto::SecretKey& b) {
    return sodium_memcmp(a.bytes().data(), b.bytes().data(), crypto::util::AES_KEY_SIZE) == 0;
}

std::string versionList(const std::vector<unsigned int>& versions) {
    std::string out;
    for (const auto v : versions) out += (out.empty() ? "" : ", ") + std::to_string(v);
    return out;
}

std::string verdictText(const vault::attestation::Verdict verdict, const unsigned int keyId) {
    switch (verdict) {
        case vault::attestation::Verdict::Valid: return "attested";
        case vault::attestation::Verdict::Missing:
            return "the backup carries no attestation by this node for it (an export from before attestations, or "
                   "not from this node)";
        case vault::attestation::Verdict::UnknownKey:
            return fmt::format("its attestation names signing key {}, which this node never had", keyId);
        case vault::attestation::Verdict::BadSignature:
            return "its attestation does not verify for this node, vault, version and key (forged, damaged, or from "
                   "another node, vault or version)";
    }
    return "not attested";
}

// ---- salvage

SalvageStepHook& salvageStepHook() {
    static SalvageStepHook hook;
    return hook;
}

SalvageEngineHook& salvageEngineHook() {
    static SalvageEngineHook hook;
    return hook;
}

// A file whose ciphertext doesn't authenticate under the supplied key.
struct SalvageAuthFailure : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Vaults with a salvage pass running in this process.
struct RunningSalvages {
    std::mutex mutex;
    std::set<unsigned int> vaults;
};

RunningSalvages& runningSalvages() {
    static RunningSalvages r;
    return r;
}

struct SalvageGuard {
    unsigned int vault_id;
    explicit SalvageGuard(const unsigned int id) : vault_id(id) {
        auto& r = runningSalvages();
        std::scoped_lock lock(r.mutex);
        if (!r.vaults.insert(id).second) throw Conflict("a key salvage of this vault is already running");
    }
    ~SalvageGuard() {
        auto& r = runningSalvages();
        std::scoped_lock lock(r.mutex);
        r.vaults.erase(vault_id);
    }
    SalvageGuard(const SalvageGuard&) = delete;
    SalvageGuard& operator=(const SalvageGuard&) = delete;
};

std::vector<uint8_t> keyCopy(const crypto::SecretKey& key) { return {key.bytes().begin(), key.bytes().end()}; }

// Decrypts `ciphertext` sealed under (iv, key) and re-seals it under `next` with a fresh IV: {sealed, iv}. Throws
// SalvageAuthFailure when the tag doesn't verify. No plaintext survives this frame.
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> resealWith(const std::vector<uint8_t>& ciphertext,
                                                                 const crypto::SecretKey& key, const std::string& ivB64,
                                                                 const crypto::SecretKey& next) {
    auto from = keyCopy(key), to = keyCopy(next);
    std::vector<uint8_t> plaintext;
    try {
        plaintext = crypto::util::decrypt_aes256_gcm(ciphertext, from, crypto::util::b64_decode(ivB64));
    } catch (const std::exception& e) {
        sodium_memzero(from.data(), from.size());
        sodium_memzero(to.data(), to.size());
        throw SalvageAuthFailure(std::string("does not authenticate under the supplied key: ") + e.what());
    }
    std::vector<uint8_t> iv;
    auto sealed = crypto::util::encrypt_aes256_gcm(plaintext, to, iv);
    sodium_memzero(plaintext.data(), plaintext.size());
    sodium_memzero(from.data(), from.size());
    sodium_memzero(to.data(), to.size());
    return {std::move(sealed), std::move(iv)};
}

bool bufferOpensWith(const std::vector<uint8_t>& bytes, const crypto::SecretKey& key, const std::string& ivB64) {
    auto k = keyCopy(key);
    try {
        auto plaintext = crypto::util::decrypt_aes256_gcm(bytes, k, crypto::util::b64_decode(ivB64));
        sodium_memzero(plaintext.data(), plaintext.size());
        sodium_memzero(k.data(), k.size());
        return true;
    } catch (const std::exception&) {
        sodium_memzero(k.data(), k.size());
        return false;
    }
}

struct SalvageKeys {
    unsigned int fresh_version{};
    crypto::SecretKeyPtr fresh{};
    std::map<unsigned int, crypto::SecretKeyPtr> supplied{};  // memory only; wiped when the last reference goes

    [[nodiscard]] crypto::SecretKeyPtr keyFor(const unsigned int version) const {
        if (version == fresh_version) return fresh;
        const auto it = supplied.find(version);
        return it == supplied.end() ? nullptr : it->second;
    }
};

// The rotation protocol's seams with salvage crypto: files sealed under a supplied (unverified) key are re-sealed
// under the fresh daemon key. Catalog (compare-and-set, content lock, busy, cache refresh) and uploads are the
// daemon's own; remote-only objects are fetched through the metered path.
sync::rotation::Deps salvageDeps(const EnginePtr& engine, const std::shared_ptr<const SalvageKeys>& keys) {
    auto deps = sync::rotation::runtimeDeps(engine);
    deps.crypto.currentKeyVersion = [keys] { return keys->fresh_version; };
    deps.crypto.reseal = [keys](const std::vector<uint8_t>& ciphertext, const FileSP& file) {
        const auto from = keys->keyFor(file->encrypted_with_key_version);
        if (!from || file->encrypted_with_key_version == keys->fresh_version)
            throw std::runtime_error("no supplied key for key version " + std::to_string(file->encrypted_with_key_version));
        auto [sealed, iv] = resealWith(ciphertext, *from, file->encryption_iv, *keys->fresh);
        file->encryption_iv = crypto::util::b64_encode(iv);
        file->encrypted_with_key_version = keys->fresh_version;
        return sealed;
    };
    deps.crypto.seal = [keys](const std::vector<uint8_t>& plaintext, const FileSP& file) {
        auto to = keyCopy(*keys->fresh);
        std::vector<uint8_t> iv;
        auto sealed = crypto::util::encrypt_aes256_gcm(plaintext, to, iv);
        sodium_memzero(to.data(), to.size());
        file->encryption_iv = crypto::util::b64_encode(iv);
        file->encrypted_with_key_version = keys->fresh_version;
        return sealed;
    };
    deps.crypto.open = [keys](const std::vector<uint8_t>& ciphertext, const sync::rotation::EncryptionState& state) {
        const auto key = keys->keyFor(state.key_version);
        if (!key) throw std::runtime_error("no key for key version " + std::to_string(state.key_version));
        auto k = keyCopy(*key);
        auto out = crypto::util::decrypt_aes256_gcm(ciphertext, k, crypto::util::b64_decode(state.iv_b64));
        sodium_memzero(k.data(), k.size());
        return out;
    };
    deps.crypto.bufferAuthenticates = [keys](const std::vector<uint8_t>& bytes,
                                             const sync::rotation::EncryptionState& state) {
        const auto key = state.encrypted() ? keys->keyFor(state.key_version) : nullptr;
        return key && bytes.size() >= crypto::util::AES_TAG_SIZE && bufferOpensWith(bytes, *key, state.iv_b64);
    };
    deps.crypto.fileAuthenticates = [keys](const std::filesystem::path& path,
                                           const sync::rotation::EncryptionState& state) {
        const auto key = state.encrypted() ? keys->keyFor(state.key_version) : nullptr;
        if (!key) return false;
        auto k = keyCopy(*key);
        try {
            const bool ok = crypto::util::aes256_gcm_file_authenticates(path, k, crypto::util::b64_decode(state.iv_b64));
            sodium_memzero(k.data(), k.size());
            return ok;
        } catch (...) {
            sodium_memzero(k.data(), k.size());
            throw;
        }
    };
    if (deps.remote) {
        const auto cloud = std::static_pointer_cast<storage::CloudEngine>(engine);
        // The object must still be what the row says (fetchSealedObject checks its HEAD), so its state is the row's.
        auto states = std::make_shared<std::map<std::string, sync::rotation::EncryptionState>>();
        deps.remote->download = [cloud, states](const FileSP& file) {
            const auto key = file->path.string().substr(file->path.string().starts_with('/') ? 1 : 0);
            const auto stored = file->size_bytes + crypto::util::AES_TAG_SIZE;
            try {
                auto bytes = cloud->fetchSealedObject(key, stored, file->encryption_iv, file->encrypted_with_key_version,
                                                      "key_salvage");
                (*states)[file->path.string()] = sync::rotation::stateOf(*file);
                return bytes;
            } catch (const storage::ContentUnavailable& e) {
                throw storage::ContentUnavailable(fmt::format("{} (estimate: 1 HEAD + 1 GET, {} bytes)", e.what(), stored));
            }
        };
        deps.remote->objectState = [states](const FileSP& file) -> std::optional<sync::rotation::EncryptionState> {
            const auto it = states->find(file->path.string());
            if (it == states->end()) return std::nullopt;
            return it->second;
        };
    }
    deps.afterStep = [](const sync::rotation::Step step, const FileSP& file) {
        if (const auto& hook = salvageStepHook()) hook(static_cast<int>(step), file);
    };
    return deps;
}

constexpr std::size_t kSalvageFailuresKept = 50;

void addFailure(nlohmann::json& failures, const FileSP& file, const unsigned int version, const std::string& kind,
                const std::string& reason) {
    if (failures.size() < kSalvageFailuresKept)
        failures.push_back({{"path", file ? file->path.string() : std::string{}}, {"version", version}, {"kind", kind},
                            {"reason", reason}});
}

}

void setSalvageStepHookForTesting(SalvageStepHook hook) { salvageStepHook() = std::move(hook); }
void setSalvageEngineHookForTesting(SalvageEngineHook hook) { salvageEngineHook() = std::move(hook); }

std::string to_string(const ImportMode mode) { return mode == ImportMode::Salvage ? "salvage" : "recover"; }

std::string to_string(const ImportOutcome outcome) {
    switch (outcome) {
        case ImportOutcome::Restored: return "restored";
        case ImportOutcome::Unchanged: return "unchanged";
        case ImportOutcome::NeedsSalvage: return "needs_salvage";
        case ImportOutcome::Refused: return "refused";
        case ImportOutcome::Salvaged: return "salvaged";
    }
    return "unchanged";
}

namespace {

// The salvage pass (key-backup.md "Salvage"). Preconditions were checked by the caller; `keys.supplied` holds the
// unverified versions' keys in memory only.
SalvageReport runSalvage(const Actor& actor, const ImportTarget& target, std::map<unsigned int, crypto::SecretKeyPtr> supplied,
                         Unsealer& unsealer, const Channel channel) {
    const SalvageGuard guard(target.vault_id);
    std::vector<unsigned int> versions;
    for (const auto& v : supplied | std::views::keys) versions.push_back(v);

    const auto previous = KeyQ::lastSalvage(target.vault_id);  // before this pass's row exists
    auto row = KeyQ::runningSalvage(target.vault_id);
    if (!row) {
        const auto id = KeyQ::startSalvage(target.vault_id, versions, actor->id);
        row = KeyQ::runningSalvage(target.vault_id);
        if (!row || row->id != id) throw Conflict("the key salvage could not be started; try again");
    }

    // The fresh daemon key: a resumed pass keeps the one it minted while it is still current.
    auto& manager = *runtime::Deps::get().storageManager;
    const auto currentRow = KeyQ::getVaultKey(target.vault_id);
    unsigned int fresh = 0;
    // A pass run again after one finished (skipped or deferred files) keeps that pass's key while it is current.
    const bool previousCovers =
        previous && previous->state == "finished" && previous->new_version && currentRow &&
        currentRow->version == *previous->new_version &&
        std::ranges::all_of(versions, [&](const unsigned int v) {
            return std::ranges::find(previous->versions, v) != previous->versions.end();
        });
    if (row->new_version && currentRow && currentRow->version == *row->new_version) {
        fresh = *row->new_version;
    } else if (!row->new_version && previousCovers) {
        fresh = *previous->new_version;
        KeyQ::setSalvageNewVersion(row->id, fresh);
        row->new_version = fresh;
    } else {
        bool currentHeld = false;
        if (currentRow) {
            try {
                (void)unsealer.unseal(*currentRow);
                currentHeld = true;
            } catch (const std::exception&) {}
        }
        if (const auto engine = engineFor(target.vault_id); engine && currentHeld) {
            engine->encryptionManager->prepare_key_rotation();  // the normal rotation path
            fresh = engine->encryptionManager->get_key_version();
        } else {
            const auto base = currentRow ? currentRow->version
                                         : (target.referenced.empty() ? 0u : target.referenced.back());
            fresh = vault::EncryptionManager::mintSalvageKey(target.vault_id, base + 1, currentHeld);
        }
        KeyQ::setSalvageNewVersion(row->id, fresh);
        row->new_version = fresh;
    }

    // The vault runs on the fresh key (its own engine does the uploads, cache refreshes and FUSE coordination).
    auto engine = engineFor(target.vault_id);
    if (engine) {
        engine->encryptionManager->load_key();
    } else {
        try {
            (void)manager.reinstateVault(target.vault_id);
        } catch (const std::exception& e) {
            throw Conflict(std::string("the salvage key was created, but the vault still doesn't start: ") + e.what() +
                           ". Nothing was re-encrypted; run the salvage again once that is fixed");
        }
        engine = engineFor(target.vault_id);
    }
    if (!engine) throw Conflict("the vault doesn't run on this host after creating the salvage key");
    if (const auto& hook = salvageEngineHook()) hook(engine);
    const auto [freshKey, runningVersion] = engine->encryptionManager->currentKey();
    if (runningVersion != fresh)
        throw Conflict(fmt::format("the vault's key moved to version {} during the salvage (expected {}); run it again",
                                   runningVersion, fresh));

    auto keys = std::make_shared<SalvageKeys>();
    keys->fresh_version = fresh;
    keys->fresh = freshKey;
    keys->supplied = std::move(supplied);
    const auto deps = salvageDeps(engine, keys);

    KeyQ::Salvage report = *row;
    report.versions = versions;
    nlohmann::json failures = nlohmann::json::array();
    const bool remoteVault = deps.remote.has_value();
    const bool encryptUpstream = remoteVault && deps.remote->encryptUpstream;

    // An interrupted pass may have committed files to the fresh key before renaming their sidecars.
    for (const auto& file : KeyQ::filesSealedUnderVersion(target.vault_id, fresh)) {
        std::error_code ec;
        if (std::filesystem::exists(sync::rotation::sidecarPathFor(file->backing_path), ec))
            (void)sync::rotation::resolveSidecar(file->backing_path, sync::rotation::stateOf(*file), deps.crypto);
    }

    for (const auto version : versions) {
        for (const auto& file : KeyQ::filesSealedUnderVersion(target.vault_id, version)) {
            std::error_code ec;
            const bool local = std::filesystem::is_regular_file(file->backing_path, ec);
            if (!local && remoteVault && !encryptUpstream) {
                ++report.skipped_remote;
                addFailure(failures, file, version, "skipped_remote",
                           "only the bucket's unencrypted copy exists; a sync download restores it");
                continue;
            }
            try {
                switch (sync::rotation::rotateFile(file, deps)) {
                    case sync::rotation::Outcome::Rotated: ++report.salvaged; break;
                    case sync::rotation::Outcome::Skipped: break;
                    case sync::rotation::Outcome::Deferred:
                        ++report.deferred;
                        addFailure(failures, file, version, "deferred",
                                   "open for writing; run the salvage again");
                        break;
                    case sync::rotation::Outcome::Conflict:
                        ++report.failed;
                        addFailure(failures, file, version, "failed",
                                   "changed while it was being salvaged; run the salvage again");
                        break;
                }
            } catch (const SalvageAuthFailure& e) {
                ++report.unrecoverable;
                addFailure(failures, file, version, "unrecoverable", e.what());
            } catch (const storage::ContentUnavailable& e) {
                ++report.skipped_remote;
                addFailure(failures, file, version, "skipped_remote", e.what());
            } catch (const std::exception& e) {
                const std::string what = e.what();
                // The protocol wraps the reseal's error with the path; a missing local copy of a local vault is gone.
                if (what.find("does not authenticate under the supplied key") != std::string::npos ||
                    (!remoteVault && what.find("backing file is missing") != std::string::npos)) {
                    ++report.unrecoverable;
                    addFailure(failures, file, version, "unrecoverable", what);
                } else {
                    ++report.failed;
                    addFailure(failures, file, version, "failed", what);
                }
            }
        }
    }

    report.failures_json = failures.dump();
    KeyQ::finishSalvage(report);
    const auto finished = KeyQ::lastSalvage(target.vault_id);
    auto out = salvageReportFrom(finished ? *finished : report);
    log::Registry::audit()->warn(
        "[ops::vault_keys] {} salvaged vault {} ('{}') key version(s) {} through {}: {} file(s) re-encrypted under new "
        "key version {}, {} unrecoverable, {} skipped (remote), {} deferred, {} failed; the supplied keys were not "
        "stored", actor->name(), target.vault_id, target.name, versionList(versions), channelName(channel),
        report.salvaged, fresh, report.unrecoverable, report.skipped_remote, report.deferred, report.failed);
    return out;
}

}

ImportResult importKeys(const Actor& actor, const ImportRequest& request, const Channel channel) {
    requireExport(actor);
    if (channel == Channel::Console)
        throw Refused("import_requires_device",
                      "vault keys are imported only from a paired device (Vaulthalla Desktop) or the local vh CLI, "
                      "never through the browser");
    requireKeyChannel(channel);
    if (!request.keys) throw Invalid("keys (the export document) is required");

    const auto candidates = candidatesFrom(*request.keys, request.vault_id);
    const auto target = importTarget(actor, request.vault_id);
    ImportResult result{.vault_id = target.vault_id, .vault_name = target.name, .deleted = target.deleted,
                        .mode = request.mode};
    Unsealer unsealer;
    std::vector<KeyQ::SealedWrite> writes;
    std::map<unsigned int, crypto::SecretKeyPtr> needsSalvage;
    const auto current = *target.current;
    const auto salvaging = KeyQ::runningSalvage(target.vault_id);

    for (const auto& c : candidates) {
        ImportedVersion out{.version = c.version};
        const auto check = vault::keyCheck(c.key->bytes(), target.vault_id, c.version);
        // The backup's own key check: consistency only (a damaged backup is refused, whatever else it holds).
        if (c.backup_check && !vault::keyCheckEquals(*c.backup_check, check))
            throw Invalid(fmt::format("key version {} in the backup does not match its own key check: the backup is "
                                      "damaged or belongs to another vault; nothing was written", c.version));

        // Recovery only: a version the daemon's records reference, never a new one.
        if (c.version > current || std::ranges::find(target.referenced, c.version) == target.referenced.end()) {
            out.outcome = ImportOutcome::Refused;
            out.detail = c.version > current
                ? fmt::format("the vault has no record of key version {} (its current version is {}); an import "
                              "never introduces a key version", c.version, current)
                : fmt::format("the vault has no record of key version {}; an import never introduces a key version",
                              c.version);
            result.versions.push_back(std::move(out));
            continue;
        }

        std::vector<Slot> slots;
        if (target.live_rows) {
            if (c.version == current) slots.push_back({KeyQ::SealedTable::Current, target.current_row});
            else {
                const auto it = target.retired.find(c.version);
                slots.push_back({KeyQ::SealedTable::Retired, it == target.retired.end() ? nullptr : it->second});
            }
        }
        if (target.deleted) {
            const auto it = target.copies.find(c.version);
            slots.push_back({KeyQ::SealedTable::DeletionCopy, it == target.copies.end() ? nullptr : it->second});
        }

        // What this host holds: never replace a key it can unseal with other bytes; identical bytes are a no-op.
        bool identical = false;
        std::vector<const Slot*> toWrite;
        std::vector<std::string> recordedChecks;
        for (const auto& slot : slots) {
            if (!slot.row) {
                toWrite.push_back(&slot);
                continue;
            }
            if (slot.row->key_check) recordedChecks.push_back(*slot.row->key_check);
            crypto::SecretKeyPtr held;
            try {
                held = unsealer.unseal(*slot.row);
            } catch (const std::exception&) {
                toWrite.push_back(&slot);  // doesn't unseal here: a proven key replaces it
                continue;
            }
            if (!sameKey(*held, *c.key))
                throw Conflict(fmt::format("this host holds a different key version {} for vault '{}' and can still "
                                           "unseal it; an import never replaces a working key (is the backup from "
                                           "another node or vault?). Nothing was written", c.version, target.name));
            identical = true;
        }
        if (toWrite.empty()) {
            out.outcome = ImportOutcome::Unchanged;
            out.detail = "this host already holds this key";
            result.versions.push_back(std::move(out));
            continue;
        }

        // Proof: a key this host holds, or this node's attestation (and the recorded key check, when there is one).
        KeyQ::Provenance provenance{.key_check = check};
        if (identical) {
            provenance = vault::attestation::provenanceOf(target.vault_id, c.version, c.key->bytes());
            out.detail = "matches a key this host holds; re-sealed the copy that no longer unsealed";
        } else {
            std::optional<std::string> why;
            if (std::ranges::any_of(recordedChecks, [&](const std::string& r) { return !vault::keyCheckEquals(r, check); }))
                why = "the vault's recorded key check for this version does not match this key";
            else if (c.attestation_problem)
                why = *c.attestation_problem;
            else {
                const auto attestation = c.attestation.value_or(vault::attestation::Attestation{});
                const auto verdict = vault::attestation::check(attestation, target.vault_id, c.version, check);
                if (verdict != vault::attestation::Verdict::Valid)
                    why = verdictText(verdict, attestation.key_id);
                else {
                    provenance.attestation_key_id = attestation.key_id;
                    provenance.attestation = attestation.signature;
                    out.detail = fmt::format("attested by this node (signing key {})", attestation.key_id);
                }
            }
            if (why) {
                out.outcome = ImportOutcome::NeedsSalvage;
                out.detail = *why + "; not restored. Salvage (--salvage) re-encrypts what it decrypts under a fresh key";
                if (target.deleted) out.detail = *why + "; not restored (salvage needs the vault restored first)";
                needsSalvage[c.version] = c.key;
                result.versions.push_back(std::move(out));
                continue;
            }
        }

        // Proven: re-seal under this host's vault master.
        const bool pendingRotation = c.version + 1 == current && KeyQ::filesSealedUnder(target.vault_id, c.version) &&
                                     KeyQ::rotationPendingKeyVersions(target.vault_id).empty();
        for (const auto* slot : toWrite) {
            auto [sealed, iv] = unsealer.seal(*c.key);
            KeyQ::SealedWrite w{.table = slot->table, .version = c.version, .encrypted_key = std::move(sealed),
                                .iv = std::move(iv), .provenance = provenance};
            if (slot->row) w.expected = std::make_pair(slot->row->encrypted_key, slot->row->iv);
            else w.rotation_pending = slot->table == KeyQ::SealedTable::Retired && pendingRotation;
            writes.push_back(std::move(w));
        }
        out.outcome = ImportOutcome::Restored;
        result.versions.push_back(std::move(out));
    }

    std::vector<unsigned int> restored, salvage;
    for (const auto& v : result.versions)
        if (v.outcome == ImportOutcome::Restored) restored.push_back(v.version);
    for (const auto& v : needsSalvage | std::views::keys) salvage.push_back(v);

    // Salvage: only the versions that need it, on a live vault, and a resumed pass only with its own versions.
    const bool salvageRun = request.mode == ImportMode::Salvage && !salvage.empty();
    if (salvageRun) {
        if (target.deleted)
            throw Conflict("deleted vault '" + target.name + "' can't be salvaged; restore it (vh vault restore) first");
        if (salvaging) {
            std::vector<unsigned int> missing;
            for (const auto v : salvaging->versions)
                if (!needsSalvage.contains(v)) missing.push_back(v);
            if (!missing.empty())
                throw Conflict(fmt::format("an interrupted salvage of vault '{}' needs key version(s) {} to resume",
                                           target.name, versionList(missing)));
            std::erase_if(needsSalvage, [&](const auto& kv) {
                return std::ranges::find(salvaging->versions, kv.first) == salvaging->versions.end();
            });
            salvage.clear();
            for (const auto& v : needsSalvage | std::views::keys) salvage.push_back(v);
        } else {
            for (const auto v : KeyQ::rotationPendingKeyVersions(target.vault_id)) {
                const auto it = target.retired.find(v);
                bool held = false;
                if (it != target.retired.end()) {
                    try {
                        (void)unsealer.unseal(*it->second);
                        held = true;
                    } catch (const std::exception&) {}
                }
                if (held && !needsSalvage.contains(v))
                    throw Conflict(fmt::format("vault '{}' is still re-encrypting from key version {}; let that "
                                               "rotation finish before a salvage", target.name, v));
            }
            // After the salvage every version live files are sealed under must be held, salvaged or retired.
            const auto salvagedBefore = KeyQ::salvageVersions(target.vault_id);
            for (const auto v : KeyQ::liveFileKeyVersions(target.vault_id)) {
                const bool ok = needsSalvage.contains(v) || target.retired.contains(v) ||
                                std::ranges::find(salvagedBefore, v) != salvagedBefore.end() ||
                                std::ranges::find(restored, v) != restored.end() ||
                                (target.current_row && target.current_row->version == v);
                if (!ok)
                    throw Conflict(fmt::format("files of vault '{}' are sealed under key version {}, which neither "
                                               "this host nor the backup provides; nothing was written", target.name, v));
            }
        }
    }

    if (!writes.empty() || salvageRun) {
        if (!request.confirm_name || *request.confirm_name != target.name) {
            std::string text;
            if (!writes.empty())
                text = fmt::format("Importing keys into vault '{}' (ID {}) restores key version(s) {}, attested by this "
                                   "node, re-sealed under this host's vault master.", target.name, target.vault_id,
                                   versionList(restored));
            if (salvageRun)
                text += fmt::format("{}Salvaging vault '{}' (ID {}) re-encrypts every file sealed under key version(s) "
                                    "{} that the supplied key decrypts under a fresh key this host creates; files it "
                                    "doesn't decrypt are reported unrecoverable, and the supplied key is never stored.",
                                    text.empty() ? "" : " ", target.name, target.vault_id, versionList(salvage));
            else if (!salvage.empty())
                text += " Not restored, need salvage: " + versionList(salvage) + ".";
            text += " Confirm by typing the vault's name.";
            throw NeedsConfirmation(salvageRun ? "vault_key_salvage" : "vault_key_import", text);
        }
    }

    if (!writes.empty()) {
        KeyQ::writeImported(target.vault_id, writes);
        result.written = true;
        log::Registry::audit()->warn("[ops::vault_keys] {} restored key version(s) {} of vault {} ('{}'{}) through {}",
                                     actor->name(), versionList(restored), target.vault_id, target.name,
                                     target.deleted ? ", deleted" : "", channelName(channel));
    }

    if (salvageRun) {
        // Recovered versions first (a running engine reloads them), then the pass.
        if (const auto engine = engineFor(target.vault_id); engine && result.written) {
            try {
                engine->encryptionManager->load_key();
            } catch (const std::exception&) {}
        }
        result.salvage = runSalvage(actor, target, needsSalvage, unsealer, channel);
        result.written = true;
        for (auto& v : result.versions)
            if (v.outcome == ImportOutcome::NeedsSalvage && needsSalvage.contains(v.version)) {
                v.outcome = ImportOutcome::Salvaged;
                v.detail = fmt::format("not stored; its files were salvaged into key version {} (see the report)",
                                       result.salvage->new_version.value_or(0));
            }
    }

    if (target.deleted) {
        result.note = "the vault is deleted: restore it (vh vault restore) to use it again";
    } else if (const auto engine = engineFor(target.vault_id)) {
        // A running engine reloads its keys, so a restored outgoing key (an unfinished rotation) takes effect now.
        if (result.written && !salvageRun) {
            try {
                engine->encryptionManager->load_key();
            } catch (const std::exception& e) {
                result.note = std::string("the keys were written, but the running vault could not reload them: ") +
                              e.what();
            }
        }
        result.key_available = true;
    } else if (result.written) {
        try {
            (void)runtime::Deps::get().storageManager->reinstateVault(target.vault_id);
            result.key_available = engineFor(target.vault_id) != nullptr;
        } catch (const std::exception& e) {
            result.note = std::string("the keys were written, but the vault still doesn't start: ") + e.what();
            log::Registry::crypto()->warn("[ops::vault_keys] vault {} did not start after a key import: {}",
                                          target.vault_id, e.what());
        }
    } else {
        result.note = "the vault isn't running on this host: it still needs key versions this import didn't restore";
    }
    if (!result.note && !needsSalvage.empty() && !salvageRun)
        result.note = "key version(s) " + versionList(salvage) + " can't be restored as this vault's key; a salvage "
                      "(vh vault keys import --salvage, or mode salvage) re-encrypts what they decrypt under a fresh key";
    return result;
}

nlohmann::json toJson(const SalvageReport& r) {
    auto failures = nlohmann::json::array();
    for (const auto& f : r.failures)
        failures.push_back({{"path", f.path}, {"version", f.version}, {"kind", f.kind}, {"reason", f.reason}});
    return {{"id", r.id},
            {"versions", r.versions},
            {"new_version", r.new_version ? nlohmann::json(*r.new_version) : nlohmann::json(nullptr)},
            {"state", r.state},
            {"started_at", static_cast<int64_t>(r.started_at)},
            {"finished_at", r.finished_at ? nlohmann::json(static_cast<int64_t>(*r.finished_at)) : nlohmann::json(nullptr)},
            {"salvaged", r.salvaged},
            {"unrecoverable", r.unrecoverable},
            {"skipped_remote", r.skipped_remote},
            {"deferred", r.deferred},
            {"failed", r.failed},
            {"failures", std::move(failures)}};
}

nlohmann::json toJson(const ImportResult& r) {
    auto versions = nlohmann::json::array();
    for (const auto& v : r.versions)
        versions.push_back({{"version", v.version}, {"outcome", to_string(v.outcome)}, {"detail", v.detail}});
    return {{"vault_id", r.vault_id}, {"vault_name", r.vault_name}, {"deleted", r.deleted}, {"mode", to_string(r.mode)},
            {"written", r.written}, {"key_available", r.key_available},
            {"note", r.note ? nlohmann::json(*r.note) : nlohmann::json(nullptr)}, {"versions", std::move(versions)},
            {"salvage", r.salvage ? toJson(*r.salvage) : nlohmann::json(nullptr)}};
}

}
