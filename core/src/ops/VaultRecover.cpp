#include "ops/VaultRecover.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "crypto/id/Generator.hpp"
#include <vl/keykit/kev1.hpp>
#include "db/query/sync/Manifest.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Recover.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Path.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/BucketCapability.hpp"
#include "storage/s3/Controller.hpp"
#include "sync/manifest/Objects.hpp"
#include "sync/manifest/Store.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/Master.hpp"
#include "vault/Recover.hpp"
#include "vault/RecoveryEnvelopes.hpp"

#include <fmt/format.h>
#include <sodium.h>

#include <algorithm>
#include <mutex>
#include <set>

namespace vh::ops::vault_recover {

namespace vault_recover_detail {

namespace mf = sync::manifest;
namespace rec = vault::recover;
using vault_keys::Channel;

std::mutex seamMutex;
StoreFactory storeFactory;
EngineHook engineHook;

std::string versionList(const std::vector<uint32_t>& v) {
    if (v.empty()) return "none";
    std::string out;
    for (const auto x : v) out += (out.empty() ? "" : ", ") + std::to_string(x);
    return out;
}

std::shared_ptr<mf::ObjectStore> storeFor(const unsigned int apiKeyId, const std::string& bucket) {
    {
        std::scoped_lock lock(seamMutex);
        if (storeFactory) return storeFactory(apiKeyId, bucket);
    }
    const auto& keys = runtime::Deps::get().apiKeyManager;
    if (!keys) throw Conflict("the API key manager is not available");
    const auto key = keys->getAPIKey(apiKeyId);
    if (!key) throw NotFound("API key not found: " + std::to_string(apiKeyId));
    auto controller = std::make_shared<storage::s3::Controller>(key, bucket);
    // The opaque_v1 request rules (spec 01 §4.3): a restore names nothing but o/, .vaulthalla/ and no metadata.
    controller->setOpaqueLayout(true);
    // No probe here (a dry run writes nothing): a root published on a bucket without conditional writes says so
    // (`publish: version_log`), and manifest::load then reads the canonical head by rule C1 (spec 06 §5.3).
    return std::make_shared<mf::S3Store>(std::move(controller));
}

std::vector<std::vector<uint8_t>> selfKeys() {
    std::vector<std::vector<uint8_t>> out;
    for (const auto& k : db::query::vault::Key::attestationKeys()) out.push_back(k.public_key);
    return out;
}

std::string hexOf(std::span<const uint8_t> bytes) {
    std::string out;
    for (const auto b : bytes) out += fmt::format("{:02x}", b);
    return out;
}

std::optional<std::vector<uint8_t>> b64(const std::string& text) {
    std::vector<uint8_t> out(text.size());
    std::size_t len = 0;
    if (sodium_base642bin(out.data(), out.size(), text.data(), text.size(), nullptr, &len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return std::nullopt;
    out.resize(len);
    return out;
}

// The grants the root lists that this node can re-enroll: class customer, suite 1, with a public key the root or the
// kit supplies (the kit's own recipient: its seed derives the key).
std::vector<db::query::vault::RecoverGrant> grantsOf(const rec::Plan& plan, const rec::Material& material) {
    std::vector<db::query::vault::RecoverGrant> out;
    if (!plan.recovery_policy || !plan.recovery_policy->understood) return out;
    std::optional<std::vector<uint8_t>> kitKey;
    if (material.kit) kitKey = material.kit->seed.x25519PublicKey();
    for (const auto& g : plan.recovery_policy->grants) {
        if (g.recipient_class != mf::kCustomerClass || g.suite != 1) continue;
        std::optional<std::vector<uint8_t>> pk;
        if (g.public_key) pk = b64(*g.public_key);
        if ((!pk || pk->size() != vl::keykit::kev1::kX25519KeySize) && kitKey &&
            hexOf(vl::keykit::kev1::recipientId(*kitKey)) == g.recipient_id)
            pk = kitKey;
        if (!pk || pk->size() != vl::keykit::kev1::kX25519KeySize || hexOf(vl::keykit::kev1::recipientId(*pk)) != g.recipient_id)
            continue;
        out.push_back({g.grant_id, g.recipient_id, *pk, 1, g.label, g.added_at, g.authorized_by, g.revoked_at});
    }
    return out;
}

std::string defaultName(const rec::Plan& plan) {
    if (plan.vault_name && !plan.vault_name->empty()) return *plan.vault_name;
    return "recovered-" + mf::uidText(plan.vault_uid).substr(0, 8);
}

}  // namespace vault_recover_detail

void setStoreFactoryForTesting(StoreFactory factory) {
    std::scoped_lock lock(vault_recover_detail::seamMutex);
    vault_recover_detail::storeFactory = std::move(factory);
}

void setEngineHookForTesting(EngineHook hook) {
    std::scoped_lock lock(vault_recover_detail::seamMutex);
    vault_recover_detail::engineHook = std::move(hook);
}

Result recover(const Actor& actor, const Request& req, const vault_keys::Channel channel) {
    using namespace vault_recover_detail;
    vault_keys::requireKeyMaterialAccess(actor, channel, "recover_requires_device");
    if (!req.kit && !req.exported)
        throw Invalid("a restore needs customer recovery material: a recovery kit (--kit) and/or a key export (--export)");
    if (req.api_key_id == 0) throw Invalid("api key is required");
    if (req.bucket.empty()) throw Invalid("bucket is required");
    const auto ownerId = req.owner_id.value_or(actor->id);
    // The name is known once the manifest is read; everything else create() would check is checked first.
    vaults::requireCanRecoverInto(actor, ownerId, req.api_key_id, req.bucket, req.into);
    // #361: key material is unwrapped here, bound to the bucket; the host CLI is exempt by design.
    auth::stepup::require(auth::stepup::Family::Keys, "vault.recover:" + req.bucket);

    rec::Material material;
    if (req.kit) {
        try {
            material.kit.emplace(vl::keykit::parseKit(*req.kit));
        } catch (const vl::keykit::KitError& e) {
            throw Invalid(std::string("the recovery kit is not usable: ") + e.what());
        }
    }
    if (req.exported) {
        try {
            material.exports = rec::parseExport(*req.exported);
        } catch (const std::invalid_argument& e) {
            throw Invalid(std::string("the key export is not usable: ") + e.what());
        }
    }
    material.checkpoint = req.checkpoint;
    rec::Options options;
    options.accept_rollback = req.accept_rollback;
    options.self_keys = selfKeys();
    if (req.vault_uid) {
        options.vault_uid = crypto::id::fromBase32(*req.vault_uid);
        if (!options.vault_uid) throw Invalid("vault uid is not a vault uid (26 base32 symbols)");
    }

    const auto store = storeFor(req.api_key_id, req.bucket);
    rec::Plan plan;
    try {
        plan = rec::plan(*store, material, options);
    } catch (const rec::Refusal& e) {
        throw Refused(e.code(), e.what());
    } catch (const ops::Error&) {
        throw;
    } catch (const std::exception& e) {
        throw Conflict(std::string("the bucket can't be read for a restore (") + e.what() +
                       "); check the API key and bucket, then try again");
    }

    Result result;
    result.dry_run = req.dry_run;
    result.report = rec::toJson(plan);
    result.vault_name = req.into.value_or(defaultName(plan));
    vaults::requireCanRecoverInto(actor, ownerId, req.api_key_id, req.bucket, result.vault_name);

    const auto blocking = plan.blocking();
    const auto salvageable = plan.salvageable();
    std::vector<uint32_t> unrecoverable;
    for (const auto v : blocking)
        if (std::ranges::find(salvageable, v) == salvageable.end()) unrecoverable.push_back(v);
    const bool salvage = !blocking.empty();
    result.mode = salvage ? "salvage" : "canonical";
    result.report["mode"] = result.mode;

    // Files sealed under a version nothing holds (or a refused key) can't be read or salvaged: left out, reported.
    std::set<std::string> skip;
    for (const auto& e : plan.content.entries)
        if (e.kind == mf::EntryKind::File && !e.trashed && e.key_version &&
            std::ranges::find(unrecoverable, *e.key_version) != unrecoverable.end())
            skip.insert(e.uid);
    result.report["unrecoverable_files"] = skip.size();

    if (req.dry_run) {
        result.note = salvage ? fmt::format("a restore would need salvage for key version(s) {} ({} unrecoverable); "
                                            "nothing was written", versionList(blocking), versionList(unrecoverable))
                              : std::string("a restore would recover every needed key version canonically; nothing was "
                                            "written");
        return result;
    }
    if (salvage && !req.salvage)
        throw Refused("salvage_required",
                      fmt::format("vault '{}' can't be restored canonically: key version(s) {} are not proven by an "
                                  "attestation key your material pins (or no material holds them). Nothing was written. "
                                  "--dry-run shows why per version; --salvage re-encrypts what the supplied keys decrypt "
                                  "under a fresh key this node creates (the supplied keys are never stored){}",
                                  result.vault_name, versionList(blocking),
                                  unrecoverable.empty() ? ""
                                                        : fmt::format("; version(s) {} can't be salvaged either: {} "
                                                                      "file(s) sealed under them stay unrecoverable",
                                                                      versionList(unrecoverable), skip.size())));
    if (salvage && (!req.confirm_name || *req.confirm_name != result.vault_name))
        throw NeedsConfirmation(
            RECOVER_SALVAGE,
            fmt::format("Restoring vault '{}' from bucket '{}' with salvage creates a fresh key on this node and "
                        "re-encrypts every file sealed under key version(s) {} that the supplied key decrypts; the "
                        "supplied keys are never stored. Canonical versions: {}. {} file(s) sealed under version(s) {} "
                        "are unrecoverable. Confirm by typing the vault's name.",
                        result.vault_name, req.bucket, versionList(salvageable), versionList(plan.canonical()),
                        skip.size(), versionList(unrecoverable)));

    // ---- the key rows, computed before the transaction (sealing and signing read the database)
    const auto vaultId = db::query::vault::Recover::reserveVaultId();
    db::query::vault::RecoverInput in;
    in.vault_id = vaultId;
    in.vault_uid = plan.vault_uid;
    in.name = result.vault_name;
    in.owner_id = ownerId;
    in.api_key_id = req.api_key_id;
    in.bucket = req.bucket;
    in.mount_point = crypto::id::Generator({.namespace_token = result.vault_name}).generate();
    in.content = &plan.content;
    in.root_uid = plan.root_uid;
    in.skip_uids = skip;
    in.created_by = ownerId;
    if (const auto cache = runtime::Deps::get().fsCache)
        in.inode_for = [cache, mount = in.mount_point](const std::string& fuseName,
                                                       const std::string& vaultPath) -> std::optional<uint64_t> {
            const fs::model::Path paths(fs::model::makeAbsolute(fuseName), mount);
            return cache->assignInode(paths.absRelToAbsRel(vaultPath, fs::model::PathType::VAULT_ROOT,
                                                           fs::model::PathType::FUSE_ROOT));
        };
    if (plan.content.vault && plan.content.vault->quota_bytes) in.quota = *plan.content.vault->quota_bytes;
    in.description = "Recovered from bucket " + req.bucket;
    in.epoch = plan.epoch;
    in.root_sha256 = plan.root_sha256;
    in.root_etag = plan.root_etag;
    in.root_version_id = plan.root_version_id;

    const vault::master::Writer writer(true);
    uint32_t freshVersion = 0;
    crypto::SecretKeyPtr freshKey;
    if (salvage) {
        uint32_t base = plan.highest_seen;
        for (const auto v : plan.canonical()) base = std::max(base, v);
        freshVersion = base + 1;
        freshKey = crypto::SecretKey::random();
    }
    const auto canonical = plan.canonical();
    for (const auto v : canonical) {
        const auto* vp = plan.version(v);
        db::query::vault::RecoverKeyRow row;
        row.version = v;
        row.current = !salvage && vp->current;
        const auto wrapped = writer.wrap(vp->key->bytes());
        row.encrypted_key = wrapped.encrypted_key;
        row.iv = wrapped.iv;
        row.master_version = wrapped.master_version;
        row.provenance = vault::attestation::provenanceOf(vaultId, v, vp->key->bytes());
        row.created_at = vp->created_at;
        row.retired_at = vp->retired_at;
        row.rotation_pending = !row.current && vp->needed;
        const auto& ev = *vp->proof.evidence;
        row.origin = db::query::vault::RecoverKeyRow::Origin{
            .node_id = ev.node_id,
            .vault_id = ev.vault_id,
            .key_check = vault::keyCheck(vp->key->bytes(), static_cast<unsigned>(ev.vault_id), v),
            .attestation_key_id = ev.attestation->key_id,
            .attestation_public_key = vp->proof.anchor->public_key,
            .attestation = ev.attestation->signature,
            .anchor = vp->proof.anchor->source};
        in.keys.push_back(std::move(row));
    }
    if (salvage) {
        db::query::vault::RecoverKeyRow row;
        row.version = freshVersion;
        row.current = true;
        const auto wrapped = writer.wrap(freshKey->bytes());
        row.encrypted_key = wrapped.encrypted_key;
        row.iv = wrapped.iv;
        row.master_version = wrapped.master_version;
        row.provenance = vault::attestation::provenanceOf(vaultId, freshVersion, freshKey->bytes());
        in.keys.push_back(std::move(row));
        in.salvage = db::query::vault::RecoverInput::Salvage{
            .versions = salvageable, .new_version = freshVersion, .started_by = actor->id};
    }
    if (in.keys.empty()) throw Conflict("nothing to restore: no key version of the vault can be recovered");

    in.grants = grantsOf(plan, material);
    std::map<std::string, std::string> grantByRecipient;
    for (const auto& g : in.grants)
        if (!g.revoked_at) grantByRecipient[g.recipient_id] = g.grant_id;
    for (const auto& g : in.grants) grantByRecipient.try_emplace(g.recipient_id, g.grant_id);
    for (const auto& [kid, rv] : plan.envelope_index) {
        if (std::ranges::find(canonical, rv.second) == canonical.end()) continue;
        if (const auto g = grantByRecipient.find(rv.first); g != grantByRecipient.end())
            in.envelopes.push_back({g->second, rv.second, kid});
    }
    if (plan.epoch) {
        // The sids of the loaded root (garbage collection keeps them while it is one of the last three).
        if (const auto root = store->get(std::string(mf::kRootKey), plan.root_version_id); root && plan.root_sha256)
            if (mf::sha256Hex(root->bytes) == *plan.root_sha256) {
                const crypto::vhf1::KeyLookup lookup = [&](const uint32_t v) -> crypto::SecretKeyPtr {
                    const auto* vp = plan.version(v);
                    return vp ? vp->key : nullptr;
                };
                try {
                    const auto doc = mf::openRoot(root->bytes, plan.vault_uid, lookup);
                    for (const auto& s : doc.segments) in.root_sids.push_back(s.sid);
                    for (const auto& s : doc.snapshots) in.root_sids.push_back(s.sid);
                } catch (const std::exception&) {}
            }
    }

    const auto written = db::query::vault::Recover::apply(in);
    result.written = true;
    result.vault_id = vaultId;
    result.report["restored"] = {{"vault_id", vaultId}, {"files", written.files}, {"folders", written.dirs},
                                 {"symlinks", written.symlinks}, {"trashed", written.trashed},
                                 {"index_rows", written.index_rows}, {"provider_versions", written.provider_versions},
                                 {"snapshots", written.snapshots}, {"snapshot_members", written.snapshot_members},
                                 {"left_out", written.skipped}, {"notes", written.notes}};
    if (salvage) result.report["restored"]["fresh_version"] = freshVersion;

    vh::audit::record({.action = "vault.recover", .outcome = vh::audit::Outcome::Success, .actor_id = actor->id,
                       .actor = actor->name(), .vault_id = vaultId,
                       .details = {{"mode", result.mode}, {"canonical", versionList(canonical)},
                                   {"salvage", versionList(salvageable)}, {"blind", plan.blind},
                                   {"freshness", std::string(mf::to_string(plan.freshness))},
                                   {"channel", channel == Channel::Device ? "device" : "cli"}}},
                      fmt::format("[ops::vault_recover] {} restored vault {} from its bucket through {}: key version(s) "
                                  "{} recovered (attested by the original node, verified with the customer's pinned "
                                  "keys){}", actor->name(), vaultId, channel == Channel::Device ? "a paired device" : "the CLI",
                                  versionList(canonical),
                                  salvage ? fmt::format(", version(s) {} salvaged into fresh version {}",
                                                        versionList(salvageable), freshVersion)
                                          : ""),
                      spdlog::level::warn);

    // The fresh key's envelopes before anything is sealed under it (the next pass writes whatever is still missing).
    if (salvage && freshKey) {
        try {
            (void)vault::envelopes::writeFor(vaultId, freshVersion, *freshKey);
        } catch (const std::exception& e) {
            log::Registry::crypto()->warn("[ops::vault_recover] vault {}: the fresh key's recovery envelopes were not "
                                          "written yet ({}); the next sync pass writes them", vaultId, e.what());
        }
    }

    // What the bucket can do for the manifest's writes (spec 06 §7), before the vault's first publish uses it. A probe
    // that can't run leaves it to the first sync pass; a bucket without conditional writes still restores (the files
    // are readable), and its first publish says why the manifest isn't written.
    try {
        (void)storage::bucket_capability::probeVault(vaultId);
    } catch (const std::exception& e) {
        log::Registry::cloud()->warn("[ops::vault_recover] vault {}: the bucket could not be probed ({}); the first "
                                     "sync pass probes it", vaultId, e.what());
    }

    // Start the vault (cache strategy) and publish its first root on top of the loaded one.
    std::shared_ptr<storage::Engine> engine;
    try {
        (void)runtime::Deps::get().storageManager->reinstateVault(vaultId);
        engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    } catch (const std::exception& e) {
        result.note = std::string("the vault was restored, but it does not start yet: ") + e.what();
        return result;
    }
    EngineHook hook;
    {
        std::scoped_lock lock(seamMutex);
        hook = engineHook;
    }
    if (hook && engine) hook(engine);
    result.key_available = engine != nullptr;

    if (salvage && !salvageable.empty()) {
        std::map<unsigned int, crypto::SecretKeyPtr> supplied;
        for (const auto v : salvageable) supplied[v] = plan.version(v)->key;
        try {
            result.salvage = vault_keys::salvageRecoveredVault(actor, vaultId, std::move(supplied), channel);
        } catch (const std::exception& e) {
            result.note = std::string("the vault was restored, but its salvage pass did not run: ") + e.what() +
                          "; run vh vault keys import with --salvage and the key export to resume it";
        }
    }

    if (const auto cloud = std::dynamic_pointer_cast<storage::CloudEngine>(engine)) {
        try {
            cloud->publishRemoteIndexManifest();
            result.published_epoch = db::query::sync::Manifest::state(vaultId).epoch;
        } catch (const std::exception& e) {
            if (!result.note)
                result.note = std::string("the vault was restored; its first manifest publish failed (") + e.what() +
                              "), the next sync pass retries it";
        }
    }
    return result;
}

nlohmann::json toJson(const Result& r) {
    nlohmann::json j = r.report;
    j["dry_run"] = r.dry_run;
    j["written"] = r.written;
    j["vault_id"] = r.vault_id ? nlohmann::json(*r.vault_id) : nlohmann::json(nullptr);
    j["vault_name"] = r.vault_name;
    j["mode"] = r.mode;
    j["key_available"] = r.key_available;
    j["published_epoch"] = r.published_epoch ? nlohmann::json(*r.published_epoch) : nlohmann::json(nullptr);
    j["salvage"] = r.salvage ? vault_keys::toJson(*r.salvage) : nlohmann::json(nullptr);
    j["note"] = r.note ? nlohmann::json(*r.note) : nlohmann::json(nullptr);
    return j;
}

}
