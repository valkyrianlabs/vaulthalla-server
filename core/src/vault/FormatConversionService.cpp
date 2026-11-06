#include "vault/FormatConversionService.hpp"

#include "config/Registry.hpp"
#include "db/query/vault/FormatConversion.hpp"
#include "db/query/vault/Key.hpp"
#include "fs/model/File.hpp"
#include "log/Registry.hpp"
#include "recovery/Store.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/rotation/Runtime.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <map>
#include <mutex>
#include <system_error>

namespace vh::vault::conversion {

namespace {

namespace sfs = std::filesystem;
using ConversionQ = db::query::vault::FormatConversion;

std::mutex progressMutex;
std::map<uint32_t, Progress>& progressTable() {
    static std::map<uint32_t, Progress> table;
    return table;
}

// The store's directories are 0700 at every level it owns (recovery/Store.cpp ensurePrivateDir).
void preparePrivateDir(const sfs::path& shard) {
    std::error_code ec;
    sfs::create_directories(shard, ec);
    if (ec) throw std::system_error(ec, "creating recovery store directory " + shard.string());
    for (const auto& p : {shard.parent_path(), shard}) {
        sfs::permissions(p, sfs::perms::owner_all, sfs::perm_options::replace, ec);
        if (ec) throw std::system_error(ec, "securing recovery store directory " + p.string());
    }
}

}

Limits limitsFrom(const config::VaultsFormatConversionConfig& cfg) {
    return {.maxBytesPerSecond = static_cast<uint64_t>(cfg.max_mib_per_second) * 1024 * 1024,
            .maxCpuPercent = cfg.max_cpu_percent};
}

bool convertsLiveFiles(const storage::Engine& engine) {
    if (engine.type() != storage::StorageType::Cloud) return true;
    const auto s3 = std::dynamic_pointer_cast<model::S3Vault>(engine.vault);
    return s3 && !s3->encrypt_upstream;
}

PassDeps runtimePassDeps(const std::shared_ptr<storage::Engine>& engine, const Limits& limits) {
    if (!engine || !engine->vault || !engine->encryptionManager)
        throw std::invalid_argument("format conversion needs an engine with a vault and an encryption manager");

    const auto em = engine->encryptionManager;
    const auto vaultId = engine->vault->id;
    const auto ref = recovery::store::vaultRef(*engine->vault);

    PassDeps pass;
    auto& d = pass.item;
    d.rotation = sync::rotation::runtimeDeps(engine);
    d.rotation.remote.reset();  // never used here: nothing is uploaded
    d.vaultUid = em->vaultUid();
    d.liveKey = [em](const unsigned int version) -> crypto::SecretKeyPtr {
        const auto current = em->currentKey();
        return current.version == version ? current.key : nullptr;
    };
    d.historicalKey = [em](const unsigned int version) { return em->historicalKeySnapshot(version); };
    d.blocked = [em, vaultId]() -> std::optional<std::string> {
        if (em->rotation_in_progress()) return "a key rotation of the vault is in progress";
        if (db::query::vault::Key::runningSalvage(vaultId)) return "a key salvage of the vault is running";
        return std::nullopt;
    };
    d.sharedBlob = [vaultId](const std::string& generation, const unsigned int keyVersion) {
        return ConversionQ::blobByGeneration(vaultId, generation, keyVersion);
    };
    d.commitFile = [](const fs::model::File& file, const sync::rotation::EncryptionState& expected,
                      const std::optional<BlobSwap>& blob) {
        return ConversionQ::commitFile(file, expected.iv_b64, expected.key_version, blob);
    };
    d.commitBlob = [vaultId](const BlobSwap& swap) { return ConversionQ::commitBlob(vaultId, swap); };
    d.blobPath = [ref](const std::string& name) { return recovery::store::blobPath(ref, name); };
    d.newStorageName = [] { return recovery::store::newStorageName(); };
    d.prepareBlobDir = [](const sfs::path& dir) { preparePrivateDir(dir); };
    d.plaintextUpstream = engine->type() == storage::StorageType::Cloud && convertsLiveFiles(*engine);
    d.usageChanged = [vaultId] { recovery::store::invalidateUsage(vaultId); };

    pass.convertLiveFiles = convertsLiveFiles(*engine);
    const auto keyVersion = em->get_key_version();
    pass.liveFiles = [vaultId, keyVersion](const uint32_t after, const std::size_t limit) {
        return ConversionQ::legacyFiles(vaultId, keyVersion, after, limit);
    };
    const auto exceptLiveOn = pass.convertLiveFiles ? std::make_optional(keyVersion) : std::nullopt;
    pass.blobs = [vaultId, exceptLiveOn](const int64_t after, const std::size_t limit) {
        return ConversionQ::legacyBlobs(vaultId, after, limit, exceptLiveOn);
    };
    pass.limits = limits;
    return pass;
}

std::optional<Progress> progressOf(const uint32_t vaultId) {
    std::scoped_lock lock(progressMutex);
    const auto it = progressTable().find(vaultId);
    if (it == progressTable().end()) return std::nullopt;
    return it->second;
}

PassResult convertVault(const std::shared_ptr<storage::Engine>& engine, const Limits& limits,
                        const std::function<bool()>& stop, const std::function<void(std::chrono::nanoseconds)>& pause) {
    const auto vaultId = engine->vault->id;
    {
        std::scoped_lock lock(progressMutex);
        auto& p = progressTable()[vaultId];
        p.running = true;
        p.started_at = std::time(nullptr);
    }
    PassResult result;
    try {
        auto deps = runtimePassDeps(engine, limits);
        deps.stop = stop;
        deps.pause = pause;
        result = runPass(deps);
    } catch (const std::exception& e) {
        result.failures.push_back({{}, e.what()});
        ++result.failed;
    }
    {
        std::scoped_lock lock(progressMutex);
        auto& p = progressTable()[vaultId];
        p.running = false;
        p.finished_at = std::time(nullptr);
        p.last = result;
    }

    if (result.files || result.blobs || result.cleared)
        log::Registry::crypto()->info(
            "[FormatConversion] Vault {}: converted {} file(s) and {} recovery blob(s) to VHF1 ({} bytes), cleared {} "
            "stale generation id(s); {} failed, {} deferred, {} changed meanwhile{}",
            vaultId, result.files, result.blobs, result.bytes, result.cleared, result.failed, result.deferred,
            result.conflicts, result.blocked ? "; stopped: " + *result.blocked : std::string{});
    else if (result.failed)
        log::Registry::crypto()->warn("[FormatConversion] Vault {}: {} item(s) could not be converted (first: {})",
                                      vaultId, result.failed, result.failures.front().reason);
    return result;
}

}

namespace vh::vault {

FormatConversionService::FormatConversionService() : AsyncService("FormatConversionService") {}

void FormatConversionService::runLoop() {
    if (!lazySleep(kStartDelay)) return;
    const auto stop = [this] { return shouldStop(); };
    const auto pause = [this](const std::chrono::nanoseconds d) { (void)lazySleep(d); };

    while (!shouldStop()) {
        const auto cfg = config::Registry::get().vaults.format_conversion;
        if (cfg.enabled) {
            try {
                const auto& manager = runtime::Deps::get().storageManager;
                for (const auto& engine : manager ? manager->getEngines() : std::vector<std::shared_ptr<storage::Engine>>{}) {
                    if (shouldStop()) break;
                    if (!engine || !engine->vault || !engine->encryptionManager) continue;
                    // Cheap check first: a converted vault costs two indexed counts per interval.
                    const auto left = db::query::vault::FormatConversion::remaining(
                        engine->vault->id, engine->encryptionManager->get_key_version());
                    const bool liveWork = left.files > 0 && conversion::convertsLiveFiles(*engine);
                    if (!liveWork && left.blobs == 0) continue;
                    (void)conversion::convertVault(engine, conversion::limitsFrom(cfg), stop, pause);
                }
            } catch (const std::exception& e) {
                // The database may be down; the next pass retries. Every item is committed or left as it was.
                log::Registry::crypto()->warn("[FormatConversion] Pass failed: {}", e.what());
            }
        }
        (void)lazySleep(cfg.pass_interval);
    }
}

}
