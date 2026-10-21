#include "ops/VaultKeys.hpp"

#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/util/Gcm.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Vaults.hpp"
#include "rbac/permission/admin/Keys.hpp"
#include "recovery/Store.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
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
#include <tuple>

#include <nlohmann/json.hpp>

namespace vh::ops::vault_keys {

namespace {

using KeyQ = db::query::vault::Key;
using DeletionQ = db::query::vault::Deletion;
using KeyRecord = std::shared_ptr<vault::model::Key>;
using EnginePtr = std::shared_ptr<storage::Engine>;

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
        // No key record (load_key refused to mint one over sealed content): the highest version the data records.
        const auto versions = KeyQ::dataKeyVersions(vault->id);
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
    // Live files still sealed under an older version (a rotation the database no longer records as pending).
    for (const auto v : KeyQ::liveFileKeyVersions(s.vault_id))
        if (v < s.current) add(v, NeedReason::Rotation);
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

KeyStatus statusOf(const Source& s, Unsealer& unsealer) {
    KeyStatus out{.vault_id = s.vault_id, .vault_name = s.vault_name, .deleted = s.deleted,
                  .key_retain_until = s.key_retain_until, .version = s.current,
                  .exported_version = s.exported_version, .exported_at = s.exported_at,
                  .rotation_in_progress = s.rotating};
    for (const auto& [version, reason] : neededVersions(s)) {
        auto check = checkOf(s, version, unsealer);
        if (!check) out.missing_versions.push_back(version);
        out.needed_versions.push_back({.version = version, .key_check = check, .reason = reason});
    }
    out.key_check = out.needed_versions.front().key_check;
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
        ExportedKey k{.version = version, .key = key, .key_check = vault::keyCheck(key->bytes(), s.vault_id, version),
                      .reason = reason, .created_at = createdAtOf(s, version), .retired_at = retiredAtOf(s, version)};
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
    for (const auto& vault : db::query::vault::Vault::listLiveVaults()) {
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

nlohmann::json toJson(const KeyStatus& s) {
    const auto time = [](const std::optional<std::time_t>& t) {
        return t ? nlohmann::json(static_cast<int64_t>(*t)) : nlohmann::json(nullptr);
    };
    auto needed = nlohmann::json::array();
    for (const auto& n : s.needed_versions)
        needed.push_back({{"version", n.version},
                          {"key_check", n.key_check ? nlohmann::json(*n.key_check) : nlohmann::json(nullptr)},
                          {"reason", to_string(n.reason)}});
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
            {"missing_versions", s.missing_versions}};
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
    for (const auto& vault : db::query::vault::Vault::listLiveVaults()) {
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

    if (!exported.historical.empty()) {
        auto historical = nlohmann::json::array();
        for (const auto& k : exported.historical) {
            std::vector<uint8_t> bytes(k.key->bytes().begin(), k.key->bytes().end());
            historical.push_back({
                {"key_version", k.version},
                {"key", crypto::util::b64_encode(bytes)},
                {"key_check", k.key_check},
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

constexpr std::size_t kSamplePerSource = 16;

struct Candidate {
    unsigned int version{};
    crypto::SecretKeyPtr key{};
    std::optional<std::string> backup_check{};
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

// The entry for `vaultId` in an export (one object, or the `all` array), as candidate versions.
std::vector<Candidate> candidatesFrom(const nlohmann::json& keys, const unsigned int vaultId,
                                      unsigned int& backupCurrent) {
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
    const auto add = [&](const nlohmann::json& keyField, const unsigned int version, const nlohmann::json* check) {
        auto bytes = decodeKey(keyField);
        if (!bytes || bytes->size() != crypto::util::AES_KEY_SIZE) {
            if (bytes) sodium_memzero(bytes->data(), bytes->size());
            throw Invalid("key version " + std::to_string(version) + " is not a base64 32-byte key");
        }
        auto key = std::make_shared<const crypto::SecretKey>(*bytes);
        sodium_memzero(bytes->data(), bytes->size());
        std::optional<std::string> backupCheck;
        if (check && check->is_string()) backupCheck = check->get<std::string>();
        for (const auto& c : out)
            if (c.version == version) {
                if (sodium_memcmp(c.key->bytes().data(), key->bytes().data(), crypto::util::AES_KEY_SIZE) != 0)
                    throw Invalid("the export holds two different keys for version " + std::to_string(version));
                return;
            }
        out.push_back({.version = version, .key = std::move(key), .backup_check = std::move(backupCheck)});
    };

    if (!entry->contains("key") || !entry->contains("key_info") || !entry->at("key_info").is_object() ||
        !entry->at("key_info").contains("key_version"))
        throw Invalid("the export entry needs key and key_info.key_version");
    const auto* topCheck = entry->contains("key_check") ? &entry->at("key_check")
                         : entry->at("key_info").contains("key_check") ? &entry->at("key_info").at("key_check") : nullptr;
    backupCurrent = versionOf(entry->at("key_info").at("key_version"), "key_info.key_version");
    add(entry->at("key"), backupCurrent, topCheck);
    if (entry->contains("historical_keys")) {
        if (!entry->at("historical_keys").is_array()) throw Invalid("historical_keys must be an array");
        for (const auto& h : entry->at("historical_keys")) {
            if (!h.is_object() || !h.contains("key") || !h.contains("key_version"))
                throw Invalid("every historical_keys entry needs key and key_version");
            add(h.at("key"), versionOf(h.at("key_version"), "historical_keys[].key_version"),
                h.contains("key_check") ? &h.at("key_check") : nullptr);
        }
    }
    std::ranges::sort(out, {}, &Candidate::version);
    return out;
}

struct Sample {
    unsigned int verified{}, failed{};
};

// Authenticates `path` (body ‖ tag) under key/IV without keeping any plaintext. nullopt: nothing to check there.
std::optional<bool> authenticates(const std::filesystem::path& path, const crypto::SecretKey& key,
                                  const std::string& ivB64) {
    std::vector<uint8_t> iv;
    try {
        iv = crypto::util::b64_decode(ivB64);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (iv.size() != crypto::util::AES_IV_SIZE) return std::nullopt;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return std::nullopt;
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < static_cast<off_t>(crypto::util::AES_TAG_SIZE)) {
        ::close(fd);
        return std::nullopt;
    }
    bool ok = false;
    try {
        ok = crypto::util::gcmVerifyFd(fd, 0, static_cast<uint64_t>(st.st_size) - crypto::util::AES_TAG_SIZE, key.bytes(),
                                       crypto::util::GcmIv(iv.data(), crypto::util::AES_IV_SIZE));
    } catch (const std::exception&) {
        ::close(fd);
        return std::nullopt;
    }
    ::close(fd);
    return ok;
}


// Where an import writes: the vault's live key rows (while its vault row exists) and, for a deleted vault, its
// retained copies.
struct ImportTarget {
    unsigned int vault_id{};
    std::string name{};
    std::string alias{};  // backing alias (recovery blobs)
    bool deleted{false};
    bool live_rows{false};
    std::optional<unsigned int> current{};
    KeyRecord current_row{};
    std::map<unsigned int, KeyRecord> retired{};
    std::map<unsigned int, KeyRecord> copies{};
};

ImportTarget importTarget(const Actor& actor, const unsigned int vaultId, const unsigned int backupCurrent) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    ImportTarget t{.vault_id = vaultId};
    if (const auto vault = db::query::vault::Vault::getVault(vaultId)) {
        t.name = vault->name;
        t.alias = vault->mount_point.string();
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
                           "nothing on this host can verify a key for it");
        t.name = d->vault_name;
        t.alias = d->backing_alias;
        t.deleted = true;
        t.live_rows = DeletionQ::getDeletedVault(vaultId) != nullptr;
        t.current = d->key_version;
        for (const auto& rec : DeletionQ::retainedKeys(vaultId)) t.copies[rec->version] = rec;
    } else {
        throw NotFound("no vault with ID " + std::to_string(vaultId));
    }
    if (t.live_rows) {
        t.current_row = KeyQ::getVaultKey(vaultId);
        if (t.current_row) {
            t.current = t.current_row->version;
        } else {
            // No key record (load_key refuses to mint one over sealed content): the current version is the higher
            // of what the data records and what the backup calls current; the import inserts it.
            const auto versions = KeyQ::dataKeyVersions(vaultId);
            t.current = std::max(backupCurrent, versions.empty() ? 0u : versions.back());
        }
        for (const auto v : KeyQ::retiredKeyVersions(vaultId))
            if (const auto rec = KeyQ::getRetiredVaultKey(vaultId, v)) t.retired[v] = rec;
    }
    if (!t.current || *t.current == 0)
        throw Conflict("vault '" + t.name + "' has no key record to restore into");
    return t;
}

// The vault as an S3 vault (live or deleted row), or null for a local vault.
std::shared_ptr<vault::model::S3Vault> s3VaultOf(const ImportTarget& t) {
    std::shared_ptr<vault::model::Vault> v = t.deleted ? DeletionQ::getDeletedVault(t.vault_id)
                                                       : db::query::vault::Vault::getVault(t.vault_id);
    return std::dynamic_pointer_cast<vault::model::S3Vault>(v);
}

KeyVerificationEngineFactory& verificationFactory() {
    static KeyVerificationEngineFactory factory;
    return factory;
}

std::shared_ptr<storage::CloudEngine> keyVerificationEngine(const std::shared_ptr<vault::model::S3Vault>& vault) {
    if (const auto& factory = verificationFactory()) return factory(vault);
    return storage::CloudEngine::forKeyVerification(vault);
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

}

void setKeyVerificationEngineFactoryForTesting(KeyVerificationEngineFactory factory) {
    verificationFactory() = std::move(factory);
}

std::string to_string(const ImportOutcome outcome) {
    switch (outcome) {
        case ImportOutcome::Restored: return "restored";
        case ImportOutcome::Unchanged: return "unchanged";
        case ImportOutcome::Unverifiable: return "unverifiable";
    }
    return "unchanged";
}

ImportResult importKeys(const Actor& actor, const ImportRequest& request, const Channel channel) {
    requireExport(actor);
    if (channel == Channel::Console)
        throw Refused("import_requires_device",
                      "vault keys are imported only from a paired device (Vaulthalla Desktop) or the local vh CLI, "
                      "never through the browser");
    requireKeyChannel(channel);
    if (!request.keys) throw Invalid("keys (the export document) is required");

    unsigned int backupCurrent = 0;
    const auto candidates = candidatesFrom(*request.keys, request.vault_id, backupCurrent);
    const auto target = importTarget(actor, request.vault_id, backupCurrent);
    ImportResult result{.vault_id = target.vault_id, .vault_name = target.name, .deleted = target.deleted};
    Unsealer unsealer;
    std::vector<KeyQ::SealedWrite> writes;
    unsigned int verifiedTotal = 0;
    const auto current = *target.current;

    for (const auto& c : candidates) {
        ImportedVersion out{.version = c.version};
        // 1. The backup's own key check (a damaged backup is refused, whatever else it holds).
        if (c.backup_check && !vault::keyCheckEquals(*c.backup_check, vault::keyCheck(c.key->bytes(), target.vault_id, c.version)))
            throw Invalid(fmt::format("key version {} in the backup does not match its own key check: the backup is "
                                      "damaged or belongs to another vault; nothing was written", c.version));

        // Where this version lives on this host.
        std::vector<Slot> slots;
        if (c.version > current) {
            out.outcome = ImportOutcome::Unverifiable;
            out.detail = fmt::format("newer than the vault's current key version {}: the database is older than the "
                                     "backup", current);
            result.versions.push_back(std::move(out));
            continue;
        }
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

        // 2. What this host holds: never replace a key it can unseal with other bytes; identical bytes are a no-op.
        bool identical = false;
        std::vector<const Slot*> toWrite;
        for (const auto& slot : slots) {
            if (!slot.row) {
                toWrite.push_back(&slot);
                continue;
            }
            crypto::SecretKeyPtr held;
            try {
                held = unsealer.unseal(*slot.row);
            } catch (const std::exception&) {
                toWrite.push_back(&slot);  // doesn't unseal here: the verified backup replaces it
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

        // 3. Real ciphertext: the key must authenticate data sealed under it (or match a copy that still unseals).
        std::string verifiedHow = "re-sealed a copy that no longer unsealed (the key matches one this host holds)";
        if (!identical) {
            std::vector<std::filesystem::path> paths;
            std::vector<std::string> ivs;
            std::optional<KeyQ::RemoteSample> remoteOnly;  // the smallest file without a local copy
            for (const auto& f : KeyQ::sampleSealedFiles(target.vault_id, c.version, kSamplePerSource)) {
                std::error_code ec;
                if (!remoteOnly && !std::filesystem::exists(f.path, ec) && f.vault_path.size() > 1)
                    remoteOnly = KeyQ::RemoteSample{.object_key = f.vault_path.substr(1),
                                                    .stored_bytes = f.plaintext_bytes + crypto::util::AES_TAG_SIZE,
                                                    .iv = f.iv};
                paths.emplace_back(f.path);
                ivs.push_back(f.iv);
            }
            for (const auto& b : KeyQ::sampleRecoveryBlobs(target.vault_id, c.version, kSamplePerSource)) {
                try {
                    paths.push_back(recovery::store::blobPath({.id = target.vault_id, .alias = target.alias}, b.path));
                    ivs.push_back(b.iv);
                } catch (const std::exception&) {}
            }
            for (std::size_t i = 0; i < paths.size(); ++i) {
                const auto verdict = authenticates(paths[i], *c.key, ivs[i]);
                if (!verdict) continue;
                if (*verdict) ++out.verified_files;
                else ++out.failed_files;
            }
            if (out.verified_files == 0 && out.failed_files > 0)
                throw Invalid(fmt::format("key version {} does not decrypt vault '{}' ({} sealed file(s) checked): it is "
                                          "not this vault's key. Nothing was written", c.version, target.name,
                                          out.failed_files));
            verifiedHow = fmt::format("verified against {} sealed file(s)", out.verified_files);

            if (out.verified_files == 0) {
                std::optional<std::string> skip;
                if (!KeyQ::ciphertextExistsUnder(target.vault_id, c.version)) {
                    // 6. Nothing anywhere is sealed under it (a fresh rotation target): the backup's own key check is
                    //    what proves it; nothing can be mis-decrypted.
                    if (c.backup_check) verifiedHow = "no ciphertext under this version; accepted on key check";
                    else skip = "no ciphertext under this version and the backup has no key check for it";
                } else if (const auto s3 = s3VaultOf(target)) {
                    // 5. A cloud vault without local ciphertext: the smallest object recorded under the version.
                    auto samples = KeyQ::remoteSamples(target.vault_id, c.version, 1);
                    if (samples.empty() && remoteOnly) samples.push_back(*remoteOnly);
                    if (samples.empty()) {
                        skip = fmt::format("nothing on this host or in the bucket index is sealed under version {}",
                                           c.version);
                    } else {
                        const auto& sample = samples.front();
                        try {
                            const auto engine = keyVerificationEngine(s3);
                            if (!engine->verifyRemoteObjectWithKey(sample.object_key, sample.stored_bytes, sample.iv,
                                                                   c.version, c.key->bytes())) {
                                out.failed_files = 1;
                                throw Invalid(fmt::format("key version {} does not decrypt vault '{}' (upstream object "
                                                          "{}): it is not this vault's key. Nothing was written",
                                                          c.version, target.name, sample.object_key));
                            }
                            out.verified_files = 1;
                            verifiedHow = "verified against upstream object " + sample.object_key;
                        } catch (const Invalid&) {
                            throw;
                        } catch (const std::exception& e) {
                            skip = std::string("couldn't verify against the bucket: ") + e.what();
                        }
                    }
                } else {
                    skip = fmt::format("nothing on this host is sealed under version {}, so it can't be verified",
                                       c.version);
                }
                if (skip) {
                    out.outcome = ImportOutcome::Unverifiable;
                    out.detail = *skip + "; skipped";
                    result.versions.push_back(std::move(out));
                    continue;
                }
            }
            verifiedTotal += out.verified_files;
        }

        // Verified: re-seal under this host's vault master.
        const bool pendingRotation = c.version + 1 == current && KeyQ::filesSealedUnder(target.vault_id, c.version) &&
                                     KeyQ::rotationPendingKeyVersions(target.vault_id).empty();
        for (const auto* slot : toWrite) {
            auto [sealed, iv] = unsealer.seal(*c.key);
            KeyQ::SealedWrite w{.table = slot->table, .version = c.version, .encrypted_key = std::move(sealed),
                                .iv = std::move(iv)};
            if (slot->row) w.expected = std::make_pair(slot->row->encrypted_key, slot->row->iv);
            else w.rotation_pending = slot->table == KeyQ::SealedTable::Retired && pendingRotation;
            writes.push_back(std::move(w));
        }
        out.outcome = ImportOutcome::Restored;
        out.detail = verifiedHow;
        if (out.failed_files > 0)
            out.detail += fmt::format("; {} file(s) sealed under it failed authentication (damaged)", out.failed_files);
        result.versions.push_back(std::move(out));
    }

    std::vector<unsigned int> restored, skipped;
    for (const auto& v : result.versions) {
        if (v.outcome == ImportOutcome::Restored) restored.push_back(v.version);
        if (v.outcome == ImportOutcome::Unverifiable) skipped.push_back(v.version);
    }

    if (!writes.empty()) {
        if (!request.confirm_name || *request.confirm_name != target.name) {
            std::string text = fmt::format("Importing keys into vault '{}' (ID {}) writes key version(s) {}, re-sealed "
                                           "under this host's vault master", target.name, target.vault_id,
                                           versionList(restored));
            if (verifiedTotal > 0) text += fmt::format(" (verified against {} sealed file(s))", verifiedTotal);
            text += ".";
            if (!skipped.empty()) text += " Skipped, can't be verified: " + versionList(skipped) + ".";
            text += " Confirm by typing the vault's name.";
            throw NeedsConfirmation("vault_key_import", text);
        }
        KeyQ::writeImported(target.vault_id, writes);
        result.written = true;
        log::Registry::audit()->warn("[ops::vault_keys] {} imported key version(s) {} of vault {} ('{}'{}) through {}",
                                     actor->name(), versionList(restored), target.vault_id, target.name,
                                     target.deleted ? ", deleted" : "", channelName(channel));
    }

    if (target.deleted) {
        result.note = "the vault is deleted: restore it (vh vault restore) to use it again";
    } else if (const auto engine = engineFor(target.vault_id)) {
        // A running engine reloads its keys, so a restored outgoing key (an unfinished rotation) takes effect now.
        if (result.written) {
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
    return result;
}

nlohmann::json toJson(const ImportResult& r) {
    auto versions = nlohmann::json::array();
    for (const auto& v : r.versions)
        versions.push_back({{"version", v.version}, {"outcome", to_string(v.outcome)}, {"detail", v.detail},
                            {"verified_files", v.verified_files}, {"failed_files", v.failed_files}});
    return {{"vault_id", r.vault_id}, {"vault_name", r.vault_name}, {"deleted", r.deleted}, {"written", r.written},
            {"key_available", r.key_available}, {"note", r.note ? nlohmann::json(*r.note) : nlohmann::json(nullptr)},
            {"versions", std::move(versions)}};
}

}
