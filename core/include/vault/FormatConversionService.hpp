#pragma once

#include "concurrency/AsyncService.hpp"
#include "config/Config.hpp"
#include "storage/Fwd.hpp"
#include "vault/FormatConversion.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <functional>
#include <memory>
#include <optional>

namespace vh::vault::conversion {

// vaults.format_conversion as limits.
[[nodiscard]] Limits limitsFrom(const config::VaultsFormatConversionConfig& cfg);

// Whether this converter re-seals the vault's live backing files: every vault except a cloud vault that encrypts
// upstream, whose local and remote bytes are one generation and convert together through the bucket layout migration
// (design/encryption/01-provider-blind-storage.md §6). Recovery blobs convert in every vault.
[[nodiscard]] bool convertsLiveFiles(const storage::Engine& engine);

// The daemon's seams for one vault: its EncryptionManager (strict live keys for files, retained keys for blobs), the
// rotation protocol's catalog seams (sync::rotation::runtimeDeps: content lock, busy, cache refresh, sidecars), the
// recovery store's paths and the catalog queries (db::query::vault::FormatConversion). Blocked while the vault's
// key rotation is in progress or a key salvage of it is running.
[[nodiscard]] PassDeps runtimePassDeps(const std::shared_ptr<storage::Engine>& engine, const Limits& limits);

// What the last pass over a vault did (in memory: the database's legacy rows are what decides "done").
struct Progress {
    bool running{false};
    std::optional<std::time_t> started_at, finished_at;
    std::optional<PassResult> last;
};
[[nodiscard]] std::optional<Progress> progressOf(uint32_t vaultId);

// One pass over the vault with the daemon's seams, recorded in progressOf. `stop` ends it early, `pause` paces it.
PassResult convertVault(const std::shared_ptr<storage::Engine>& engine, const Limits& limits,
                        const std::function<bool()>& stop, const std::function<void(std::chrono::nanoseconds)>& pause);

}

namespace vh::vault {

// Runs the local format conversion (#372) in the background: every vaults.format_conversion.pass_interval, a pass
// over every loaded vault that still has legacy rows, rate-limited by max_mib_per_second and max_cpu_percent and
// resumable from any point (each item is committed or left as it was). Its own thread; never a FUSE thread, never
// inside a DB transaction.
class FormatConversionService final : public concurrency::AsyncService {
public:
    // The first pass waits this long after start, so startup recovery (rotation sidecars, repairAtRest) runs first.
    static constexpr auto kStartDelay = std::chrono::seconds(60);

    FormatConversionService();
    ~FormatConversionService() override = default;

protected:
    void runLoop() override;
};

}
