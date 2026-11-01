#pragma once

#include "stats/model/CacheStats.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

namespace vh::stats::model {

enum class FuseOperation : std::size_t {
    GetAttr,
    SetAttr,
    ReadDir,
    Lookup,
    ReadLink,
    Create,
    Symlink,
    Open,
    Read,
    Write,
    MkDir,
    Rename,
    Forget,
    Access,
    Unlink,
    RmDir,
    Flush,
    Release,
    Fsync,
    StatFs,
    Unknown,
    Count
};

struct FuseOpStatsSnapshot {
    std::string op;
    std::uint64_t count = 0;
    std::uint64_t successes = 0;
    std::uint64_t errors = 0;
    std::uint64_t expectedErrors = 0;
    std::uint64_t alertableErrors = 0;
    std::uint64_t bytesRead = 0;
    std::uint64_t bytesWritten = 0;
    std::uint64_t totalUs = 0;
    std::uint64_t maxUs = 0;
    double avgMs = 0.0;
    double maxMs = 0.0;
    double errorRate = 0.0;
    double expectedErrorRate = 0.0;
    double alertableErrorRate = 0.0;
};

struct FuseErrnoStatsSnapshot {
    int errnoValue = 0;
    std::string name;
    std::uint64_t count = 0;
    // Occurrences of this errno that were not expected for the op that returned it (see isExpectedError).
    std::uint64_t alertableCount = 0;
};

struct FuseStatsSnapshot {
    std::uint64_t totalOps = 0;
    std::uint64_t totalSuccesses = 0;
    std::uint64_t totalErrors = 0;
    std::uint64_t expectedErrors = 0;
    std::uint64_t alertableErrors = 0;
    double errorRate = 0.0;
    double expectedErrorRate = 0.0;
    double alertableErrorRate = 0.0;
    std::uint64_t readBytes = 0;
    std::uint64_t writeBytes = 0;
    std::uint64_t openHandlesCurrent = 0;
    std::uint64_t openHandlesPeak = 0;
    std::vector<FuseOpStatsSnapshot> ops;
    std::vector<FuseErrnoStatsSnapshot> topErrors;
    // Distinct errnos with at least one alertable occurrence, counted before topErrors is truncated.
    std::uint64_t alertableErrnoTypes = 0;
    std::uint64_t checkedAt = 0;
};

class FuseStats {
public:
    FuseStats() noexcept;

    void record_success(
        FuseOperation op,
        std::uint64_t elapsedUs,
        std::uint64_t bytesRead = 0,
        std::uint64_t bytesWritten = 0
    ) noexcept;

    void record_error(FuseOperation op, int errnum, std::uint64_t elapsedUs) noexcept;

    void record_open_handle() noexcept;
    void record_close_handle() noexcept;

    [[nodiscard]] FuseStatsSnapshot snapshot() const;

private:
    struct OpCounters {
        PaddedAtomic<std::uint64_t> count;
        PaddedAtomic<std::uint64_t> successes;
        PaddedAtomic<std::uint64_t> errors;
        PaddedAtomic<std::uint64_t> expectedErrors;
        PaddedAtomic<std::uint64_t> alertableErrors;
        PaddedAtomic<std::uint64_t> bytesRead;
        PaddedAtomic<std::uint64_t> bytesWritten;
        PaddedAtomic<std::uint64_t> totalUs;
        PaddedAtomic<std::uint64_t> maxUs;
    };

    static constexpr int kErrnoBucketCount = 4096;

    [[nodiscard]] static std::size_t opIndex(FuseOperation op) noexcept;
    [[nodiscard]] static double ratio(std::uint64_t numerator, std::uint64_t denominator) noexcept;
    [[nodiscard]] static bool isExpectedError(FuseOperation op, int errnum) noexcept;

    std::array<OpCounters, static_cast<std::size_t>(FuseOperation::Count)> ops_{};
    std::array<std::atomic<std::uint64_t>, kErrnoBucketCount> errnoCounts_{};
    std::array<std::atomic<std::uint64_t>, kErrnoBucketCount> alertableErrnoCounts_{};
    PaddedAtomic<std::uint64_t> unknownErrnoCount_;
    PaddedAtomic<std::uint64_t> openHandlesCurrent_;
    PaddedAtomic<std::uint64_t> openHandlesPeak_;
};

class ScopedFuseOpTimer {
public:
    ScopedFuseOpTimer(FuseStats* stats, FuseOperation op) noexcept;
    ScopedFuseOpTimer(const ScopedFuseOpTimer&) = delete;
    ScopedFuseOpTimer& operator=(const ScopedFuseOpTimer&) = delete;
    ~ScopedFuseOpTimer();

    void success(std::uint64_t bytesRead = 0, std::uint64_t bytesWritten = 0) noexcept;
    void error(int errnum) noexcept;
    void cancel() noexcept;

    // An op that throws before replying is answered by fuse::task::Guard (#263). Its timer, destroyed while the
    // exception unwinds, can't know that errno: it leaves the measurement with its thread, and the guard records it
    // here as an error with the errno it answered (never as a success).
    static void recordUnanswered(int errnum) noexcept;

private:
    [[nodiscard]] std::uint64_t elapsedUs() const noexcept;

    FuseStats* stats_ = nullptr;
    FuseOperation op_ = FuseOperation::Unknown;
    std::chrono::steady_clock::time_point start_{};
    int uncaught_ = 0;
    bool completed_ = false;
};

std::string to_string(FuseOperation op);

void to_json(nlohmann::json& j, const FuseOpStatsSnapshot& stats);
void to_json(nlohmann::json& j, const FuseErrnoStatsSnapshot& stats);
void to_json(nlohmann::json& j, const FuseStatsSnapshot& stats);
void to_json(nlohmann::json& j, const std::shared_ptr<FuseStatsSnapshot>& stats);
void to_json(nlohmann::json& j, const FuseStats& stats);
void to_json(nlohmann::json& j, const std::shared_ptr<FuseStats>& stats);

}
