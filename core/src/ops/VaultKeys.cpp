#include "ops/VaultKeys.hpp"

#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Vaults.hpp"
#include "rbac/permission/admin/Keys.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/Vault.hpp"

#include <paths.h>
#include <sodium.h>

#include <fmt/format.h>

#include <algorithm>
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
    } else {
        const auto rec = KeyQ::getVaultKey(vault->id);
        if (!rec) throw Conflict("vault '" + vault->name + "' has no key record");
        s.current = rec->version;
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
    out.key_available = out.key_check.has_value();
    if (!out.key_available)
        out.unavailable_reason = s.sealed.contains(s.current)
            ? "the vault's key does not unseal on this host (vault master changed or the key row is damaged); "
              "restore it with `vh vault keys import`"
            : "the vault's current key version is not held on this host; restore it with `vh vault keys import`";
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

}
