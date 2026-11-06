#include "vault/RecoveryEnvelopes.hpp"

#include "crypto/recovery/Kev1.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Vault.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/s3/Controller.hpp"
#include "sync/manifest/Store.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/S3Vault.hpp"

#include <algorithm>
#include <mutex>
#include <stdexcept>

namespace vh::vault::envelopes {

namespace envelopes_detail {

std::mutex factoryMutex;
StoreFactory factory;

std::string versionList(const std::vector<uint32_t>& versions) {
    std::string out;
    for (const auto v : versions) out += (out.empty() ? "" : ", ") + std::to_string(v);
    return out;
}

crypto::kev1::VaultUid vaultUidOf(const uint32_t vaultId) {
    const auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault || !vault->uid) throw std::runtime_error("vault " + std::to_string(vaultId) + " has no uid");
    return *vault->uid;
}

}

void setStoreFactoryForTesting(StoreFactory f) {
    std::scoped_lock lock(envelopes_detail::factoryMutex);
    envelopes_detail::factory = std::move(f);
}

std::shared_ptr<sync::manifest::ObjectStore> storeFor(const uint32_t vaultId) {
    {
        std::scoped_lock lock(envelopes_detail::factoryMutex);
        if (envelopes_detail::factory) return envelopes_detail::factory(vaultId);
    }
    const auto s3 = std::dynamic_pointer_cast<model::S3Vault>(db::query::vault::Vault::getVault(vaultId));
    if (!s3 || s3->bucket.empty() || s3->api_key_id == 0)
        throw std::runtime_error("vault " + std::to_string(vaultId) + " has no bucket to hold recovery envelopes");
    const auto& keys = runtime::Deps::get().apiKeyManager;
    if (!keys) throw std::runtime_error("the API key manager is not available");
    const auto key = keys->getAPIKey(s3->api_key_id);
    if (!key) throw std::runtime_error("the API key of vault " + std::to_string(vaultId) + " no longer exists");
    auto controller = std::make_shared<storage::s3::Controller>(key, s3->bucket);
    controller->setUsageVault(vaultId);
    // opaque_v1: the request rules hold for envelopes too (spec 01 §4.3; s3::Controller::enforceRequestPolicy).
    controller->setOpaqueLayout(s3->storage_layout == model::StorageLayout::OpaqueV1);
    return std::make_shared<sync::manifest::S3Store>(std::move(controller));
}

Pending put(const uint32_t vaultId, const uint32_t version, const crypto::SecretKey& key) {
    Pending out;
    out.vault_id = vaultId;
    out.version = version;
    const auto grants = db::query::vault::RecoveryGrants::missingFor(vaultId, version);
    if (grants.empty()) return out;
    const auto uid = envelopes_detail::vaultUidOf(vaultId);
    out.store = storeFor(vaultId);
    try {
        for (const auto& g : grants) {
            if (!g.usable() || g.suite != static_cast<uint16_t>(crypto::kev1::Suite::X25519)) continue;
            const auto env = crypto::kev1::wrap(key, crypto::kev1::Suite::X25519, version, uid, g.public_key);
            const auto kid = crypto::kev1::kid(env);
            try {
                (void)out.store->putIfAbsent(crypto::kev1::objectKey(kid), env);
            } catch (const sync::manifest::PreconditionFailed&) {
                // kid is the envelope's hash: an object under it already holds these exact bytes.
            }
            out.envelopes.push_back({g.grant_id, version, kid});
        }
    } catch (...) {
        discard(out);
        throw;
    }
    return out;
}

void record(const Pending& pending) {
    if (pending.empty()) return;
    db::query::vault::RecoveryGrants::recordEnvelopes(pending.vault_id, pending.version, pending.envelopes);
    log::Registry::crypto()->info("[vault::envelopes] Vault {}: wrote {} recovery envelope(s) for key version {}",
                                  pending.vault_id, pending.envelopes.size(), pending.version);
}

void discard(const Pending& pending) noexcept {
    if (!pending.store) return;
    for (const auto& e : pending.envelopes) {
        try {
            pending.store->remove(crypto::kev1::objectKey(e.kid));
        } catch (const std::exception& ex) {
            log::Registry::crypto()->warn("[vault::envelopes] Vault {}: could not remove the unused envelope {}: {}",
                                          pending.vault_id, e.kid, ex.what());
        }
    }
}

unsigned writeFor(const uint32_t vaultId, const uint32_t version, const crypto::SecretKey& key) {
    const auto pending = put(vaultId, version, key);
    record(pending);
    return static_cast<unsigned>(pending.envelopes.size());
}

unsigned ensure(const uint32_t vaultId, const std::vector<uint32_t>& versions,
                const std::function<crypto::SecretKeyPtr(uint32_t)>& keyOf) {
    if (db::query::vault::RecoveryGrants::usable(vaultId).empty()) return 0;
    unsigned written = 0;
    for (const auto v : versions) {
        if (v == 0 || db::query::vault::RecoveryGrants::missingFor(vaultId, v).empty()) continue;
        const auto key = keyOf(v);
        if (!key) continue;
        written += writeFor(vaultId, v, *key);
    }
    return written;
}

Material material(const uint32_t vaultId, const std::vector<uint32_t>& needed, const uint32_t current) {
    using db::query::vault::RecoveryGrants;
    Material m;
    const auto s3 = std::dynamic_pointer_cast<model::S3Vault>(db::query::vault::Vault::getVault(vaultId));
    m.required = s3 && s3->encrypt_upstream;
    m.recipients = static_cast<unsigned>(RecoveryGrants::usable(vaultId).size());
    if (m.recipients > 0) m.uncovered = RecoveryGrants::uncovered(vaultId, needed);
    m.rotation_needed = RecoveryGrants::revokedWithAccess(vaultId, needed);
    const auto exported = db::query::vault::Key::exportRecord(vaultId);
    m.export_current = current != 0 && exported.version && *exported.version == current;

    if (m.recipients > 0 && m.uncovered.empty()) m.state = kMaterialRecipient;
    else if (m.export_current) m.state = kMaterialExport;
    else if (m.required) m.state = kMaterialMissing;
    else m.state = kMaterialNotRequired;

    if (m.state == kMaterialMissing) {
        if (m.recipients > 0)
            m.detail = "recovery envelopes are missing for key version(s) " + envelopes_detail::versionList(m.uncovered) +
                       " (the next sync pass writes them once the bucket is reachable), and the last export is not of "
                       "the current key version";
        else
            m.detail = "no recovery recipient is enrolled and the last key export is not of the current key version: "
                       "if this host's database or TPM is lost, the vault can't be decrypted. Enroll a recovery "
                       "recipient (vh vault keys recipient add) or export the keys (vh vault keys export)";
    }
    if (m.rotation_needed) {
        if (!m.detail.empty()) m.detail += ". ";
        m.detail += "A revoked recovery recipient still holds envelopes of key versions the vault uses: rotate the key "
                    "(vh vault keys rotate) to cut its access to new data off";
    }
    return m;
}

Material material(const uint32_t vaultId) {
    using KeyQ = db::query::vault::Key;
    uint32_t current = 0;
    if (const auto rec = KeyQ::getVaultKey(vaultId)) current = rec->version;
    else if (const auto refs = KeyQ::referencedKeyVersions(vaultId); !refs.empty()) current = refs.back();
    std::vector<uint32_t> needed;
    const auto add = [&](const uint32_t v) {
        if (v != 0 && std::ranges::find(needed, v) == needed.end()) needed.push_back(v);
    };
    add(current);
    for (const auto v : KeyQ::rotationPendingKeyVersions(vaultId)) add(v);
    const auto salvaged = KeyQ::salvageVersions(vaultId);
    for (const auto v : KeyQ::liveFileKeyVersions(vaultId))
        if (v < current && std::ranges::find(salvaged, v) == salvaged.end()) add(v);
    for (const auto v : KeyQ::recoveryReferencedKeyVersions(vaultId)) add(v);
    return material(vaultId, needed, current);
}

}
