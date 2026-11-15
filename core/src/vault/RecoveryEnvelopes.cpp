#include "storage/s3/ManifestStore.hpp"
#include "vault/RecoveryEnvelopes.hpp"

#include <vl/keykit/kev1.hpp>
#include "cloud/AccountPin.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/RemoteAttach.hpp"
#include "db/query/vault/Vault.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/BucketCapability.hpp"
#include "storage/s3/Controller.hpp"
#include <vl/vaultfmt/manifest/Store.hpp>
#include "vault/APIKeyManager.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <mutex>
#include <set>
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

// A local vault's envelopes (design/storage/attach-remote.md, open question 2): it has no bucket, so the database
// holds their bytes (vault_key_envelope.envelope, written by record() in the transaction that records them). They are
// ciphertext to the customer's own recipient key. An attach copies them into the bucket; the cutover clears them here.
class DatabaseStore final : public vl::vaultfmt::manifest::ObjectStore {
public:
    explicit DatabaseStore(const uint32_t vaultId) : vaultId_(vaultId) {}

    [[nodiscard]] std::optional<vl::vaultfmt::manifest::StoredObject> get(const std::string& key,
                                                                  const std::optional<std::string>&) override {
        const auto kid = kidOf(key);
        if (!kid) return std::nullopt;
        auto bytes = db::query::vault::RemoteAttach::envelopeBytes(vaultId_, *kid);
        if (!bytes) return std::nullopt;
        return vl::vaultfmt::manifest::StoredObject{.bytes = std::move(*bytes), .etag = std::nullopt, .version_id = std::nullopt};
    }
    [[nodiscard]] std::optional<std::vector<uint8_t>> getRange(const std::string& key, const uint64_t offset,
                                                               const uint64_t length) override {
        const auto object = get(key, std::nullopt);
        if (!object) return std::nullopt;
        const auto from = std::min<uint64_t>(offset, object->bytes.size());
        const auto to = std::min<uint64_t>(from + length, object->bytes.size());
        return std::vector<uint8_t>(object->bytes.begin() + static_cast<std::ptrdiff_t>(from),
                                    object->bytes.begin() + static_cast<std::ptrdiff_t>(to));
    }
    // The bytes are stored with the envelope's record (record()): nothing is written before the version is recorded,
    // so a version that never came to be leaves nothing behind.
    std::string putIfAbsent(const std::string&, const std::vector<uint8_t>&) override { return {}; }
    std::string putIfMatch(const std::string& key, const std::vector<uint8_t>&, const std::string&) override {
        throw std::logic_error("a database-held envelope is written once: " + key);
    }
    [[nodiscard]] std::vector<vl::vaultfmt::manifest::ListedObject> list(const std::string& prefix) override {
        std::vector<vl::vaultfmt::manifest::ListedObject> out;
        for (const auto& e : db::query::vault::RemoteAttach::envelopes(vaultId_)) {
            auto key = vl::keykit::kev1::objectKey(e.kid);
            if (e.bytes.empty() || !key.starts_with(prefix)) continue;
            out.push_back({.key = std::move(key), .size = e.bytes.size(), .last_modified = std::nullopt,
                           .etag = std::nullopt});
        }
        return out;
    }
    [[nodiscard]] std::vector<vl::vaultfmt::manifest::StoredVersion> versions(const std::string&) override { return {}; }
    void remove(const std::string&) override {}
    [[nodiscard]] vl::vaultfmt::manifest::WriteCapability mode() const override { return vl::vaultfmt::manifest::WriteCapability::Conditional; }

private:
    static std::optional<std::string> kidOf(const std::string& key) {
        const auto prefix = vl::keykit::kev1::kObjectPrefix;
        if (!key.starts_with(prefix)) return std::nullopt;
        return key.substr(prefix.size());
    }

    uint32_t vaultId_;
};

// The wrap guard (design/cloud/key-manager.md, "The account key as a recovery recipient"): an account-managed grant
// is wrapped to only while its key is what the MAC-verified pin says: the pinned account key of its generation, or a
// recipient of the recovery policy the pinned row accepted. A database writer who planted or changed such a grant
// gets nothing; the grant is skipped (and logged) until the pin agrees again.
bool wrapAllowed(const db::query::vault::RecoveryGrant& g) {
    if (g.account_key_generation) {
        if (cloud::pin::isPinnedKey(*g.account_key_generation, g.public_key)) return true;
        log::Registry::crypto()->warn("[vault::envelopes] Vault {}: grant {} names account key generation {}, which "
                                      "isn't the pinned key; nothing is wrapped to it",
                                      g.vault_id, g.grant_id, *g.account_key_generation);
        return false;
    }
    if (g.account_policy_sequence) {
        if (cloud::pin::isPolicyRecipient(g.public_key)) return true;
        log::Registry::crypto()->warn("[vault::envelopes] Vault {}: grant {} isn't a recipient of the accepted account "
                                      "recovery policy; nothing is wrapped to it", g.vault_id, g.grant_id);
        return false;
    }
    return true;
}

vl::keykit::kev1::VaultUid vaultUidOf(const uint32_t vaultId) {
    const auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault || !vault->uid) throw std::runtime_error("vault " + std::to_string(vaultId) + " has no uid");
    return *vault->uid;
}

}

void setStoreFactoryForTesting(StoreFactory f) {
    std::scoped_lock lock(envelopes_detail::factoryMutex);
    envelopes_detail::factory = std::move(f);
}

std::shared_ptr<vl::vaultfmt::manifest::ObjectStore> storeFor(const uint32_t vaultId) {
    const auto vault = db::query::vault::Vault::getVault(vaultId);
    if (vault && vault->type == model::VaultType::Local) return std::make_shared<envelopes_detail::DatabaseStore>(vaultId);
    {
        std::scoped_lock lock(envelopes_detail::factoryMutex);
        if (envelopes_detail::factory) return envelopes_detail::factory(vaultId);
    }
    const auto s3 = std::dynamic_pointer_cast<model::S3Vault>(vault);
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
    // An envelope's name is its hash (kid): If-None-Match bought only idempotence, so a bucket without conditional
    // writes takes a plain PUT (design/encryption/06-publish-without-preconditions.md §7). A bucket probed as
    // conditional that started refusing conditions writes nothing until it is probed again.
    const auto capability = storage::bucket_capability::resolve(vaultId, *controller);
    if (capability.changed)
        throw std::runtime_error("vault " + std::to_string(vaultId) + ": the bucket refused a conditional write since its "
                                 "probe; run vh vault storage probe " + std::to_string(vaultId));
    return std::make_shared<storage::s3::ManifestStore>(std::move(controller), capability.capability);
}

Pending put(const uint32_t vaultId, const uint32_t version, const crypto::SecretKey& key) {
    Pending out;
    out.vault_id = vaultId;
    out.version = version;
    auto grants = db::query::vault::RecoveryGrants::missingFor(vaultId, version);
    std::erase_if(grants, [](const db::query::vault::RecoveryGrant& g) { return !envelopes_detail::wrapAllowed(g); });
    if (grants.empty()) return out;
    const auto uid = envelopes_detail::vaultUidOf(vaultId);
    out.store = storeFor(vaultId);
    try {
        for (const auto& g : grants) {
            if (!g.usable() || g.suite != static_cast<uint16_t>(vl::keykit::kev1::Suite::X25519)) continue;
            const auto env = vl::keykit::kev1::wrap(key.bytes(), vl::keykit::kev1::Suite::X25519, version, uid, g.public_key);
            const auto kid = vl::keykit::kev1::kid(env);
            try {
                (void)out.store->putOnce(vl::keykit::kev1::objectKey(kid), env);
            } catch (const vl::vaultfmt::manifest::PreconditionFailed&) {
                // kid is the envelope's hash: an object under it already holds these exact bytes.
            } catch (const vl::vaultfmt::manifest::ConditionsUnsupported& e) {
                throw std::runtime_error(storage::bucket_capability::noteChanged(vaultId, e.what()));
            }
            // A local vault's envelope travels with its record (the database is where it lives).
            const bool held = dynamic_cast<const envelopes_detail::DatabaseStore*>(out.store.get()) != nullptr;
            out.envelopes.push_back({g.grant_id, version, kid, held ? env : std::vector<uint8_t>{}});
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
            pending.store->remove(vl::keykit::kev1::objectKey(e.kid));
        } catch (const std::exception& ex) {
            log::Registry::crypto()->warn("[vault::envelopes] Vault {}: could not remove the unused envelope {}: {}",
                                          pending.vault_id, e.kid, ex.what());
        }
    }
}

unsigned wrapIntoDatabase(const uint32_t vaultId, const uint32_t version, const crypto::SecretKey& key) {
    std::set<std::string> heldFor;
    for (const auto& e : db::query::vault::RemoteAttach::envelopes(vaultId))
        if (e.key_version == version && !e.bytes.empty()) heldFor.insert(e.grant_id);
    const auto uid = envelopes_detail::vaultUidOf(vaultId);
    std::vector<db::query::vault::KeyEnvelope> written;
    for (const auto& g : db::query::vault::RecoveryGrants::usable(vaultId)) {
        if (heldFor.contains(g.grant_id) || !envelopes_detail::wrapAllowed(g) ||
            g.suite != static_cast<uint16_t>(vl::keykit::kev1::Suite::X25519))
            continue;
        auto env = vl::keykit::kev1::wrap(key.bytes(), vl::keykit::kev1::Suite::X25519, version, uid, g.public_key);
        const auto kid = vl::keykit::kev1::kid(env);
        written.push_back({g.grant_id, version, kid, std::move(env)});
    }
    if (written.empty()) return 0;
    for (const auto& e : written) db::query::vault::RecoveryGrants::holdEnvelope(vaultId, e);
    log::Registry::crypto()->info("[vault::envelopes] Vault {}: wrapped {} recovery envelope(s) of key version {} into "
                                  "the database", vaultId, written.size(), version);
    return static_cast<unsigned>(written.size());
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
        if (v == 0) continue;
        auto missing = db::query::vault::RecoveryGrants::missingFor(vaultId, v);
        std::erase_if(missing, [](const db::query::vault::RecoveryGrant& g) { return !envelopes_detail::wrapAllowed(g); });
        if (missing.empty()) continue;
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
