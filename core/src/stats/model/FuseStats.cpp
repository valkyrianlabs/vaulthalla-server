#include "stats/model/FuseStats.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <exception>
#include <utility>
#include <nlohmann/json.hpp>

namespace vh::stats::model {

namespace {

std::uint64_t fuseStatsUnixTimestamp() {
    const auto now = std::chrono::system_clock::now();
    return static_cast<std::uint64_t>(std::chrono::system_clock::to_time_t(now));
}

// A timer destroyed by an exception, waiting for fuse::task::Guard to say which errno the request got.
struct UnansweredOp {
    FuseStats* stats = nullptr;
    FuseOperation op = FuseOperation::Unknown;
    std::uint64_t elapsedUs = 0;
};
thread_local UnansweredOp unansweredFuseOp;

void observeMax(PaddedAtomic<std::uint64_t>& counter, const std::uint64_t value) noexcept {
    auto current = counter.v.load(std::memory_order_relaxed);
    while (value > current && !counter.v.compare_exchange_weak(current, value, std::memory_order_relaxed)) {}
}

std::string errnoName(const int errnum) {
    switch (errnum) {
        case EACCES:
            return "EACCES";
        case EPERM:
            return "EPERM";
        case ENOENT:
            return "ENOENT";
        case EEXIST:
            return "EEXIST";
        case EINVAL:
            return "EINVAL";
        case EIO:
            return "EIO";
        case EBADF:
            return "EBADF";
        case EISDIR:
            return "EISDIR";
        case ENOTDIR:
            return "ENOTDIR";
        case ENOSPC:
            return "ENOSPC";
        case ENOTEMPTY:
            return "ENOTEMPTY";
        case EROFS:
            return "EROFS";
#ifdef ENOTSUP
        case ENOTSUP:
            return "ENOTSUP";
#endif
#if defined(EOPNOTSUPP) && (!defined(ENOTSUP) || EOPNOTSUPP != ENOTSUP)
        case EOPNOTSUPP:
            return "EOPNOTSUPP";
#endif
        default:
            return "ERRNO_" + std::to_string(errnum);
    }
}

}

FuseStats::FuseStats() noexcept {
    for (auto& counter : errnoCounts_) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : alertableErrnoCounts_) {
        counter.store(0, std::memory_order_relaxed);
    }
}

std::size_t FuseStats::opIndex(const FuseOperation op) noexcept {
    const auto index = static_cast<std::size_t>(op);
    return index < static_cast<std::size_t>(FuseOperation::Count)
        ? index
        : static_cast<std::size_t>(FuseOperation::Unknown);
}

double FuseStats::ratio(const std::uint64_t numerator, const std::uint64_t denominator) noexcept {
    return denominator ? static_cast<double>(numerator) / static_cast<double>(denominator) : 0.0;
}

bool FuseStats::isExpectedError(const FuseOperation op, const int errnum) noexcept {
    return (op == FuseOperation::Lookup && errnum == ENOENT) ||
           (op == FuseOperation::StatFs && errnum == EACCES);
}

void FuseStats::record_success(
    const FuseOperation op,
    const std::uint64_t elapsedUs,
    const std::uint64_t bytesRead,
    const std::uint64_t bytesWritten
) noexcept {
    auto& counters = ops_[opIndex(op)];
    counters.count.v.fetch_add(1, std::memory_order_relaxed);
    counters.successes.v.fetch_add(1, std::memory_order_relaxed);
    if (bytesRead > 0) counters.bytesRead.v.fetch_add(bytesRead, std::memory_order_relaxed);
    if (bytesWritten > 0) counters.bytesWritten.v.fetch_add(bytesWritten, std::memory_order_relaxed);
    counters.totalUs.v.fetch_add(elapsedUs, std::memory_order_relaxed);
    observeMax(counters.maxUs, elapsedUs);
}

void FuseStats::record_error(const FuseOperation op, const int errnum, const std::uint64_t elapsedUs) noexcept {
    auto& counters = ops_[opIndex(op)];
    counters.count.v.fetch_add(1, std::memory_order_relaxed);
    counters.errors.v.fetch_add(1, std::memory_order_relaxed);
    const bool expected = isExpectedError(op, errnum);
    if (expected) {
        counters.expectedErrors.v.fetch_add(1, std::memory_order_relaxed);
    } else {
        counters.alertableErrors.v.fetch_add(1, std::memory_order_relaxed);
    }
    counters.totalUs.v.fetch_add(elapsedUs, std::memory_order_relaxed);
    observeMax(counters.maxUs, elapsedUs);

    if (errnum >= 0 && errnum < kErrnoBucketCount) {
        errnoCounts_[static_cast<std::size_t>(errnum)].fetch_add(1, std::memory_order_relaxed);
        if (!expected) alertableErrnoCounts_[static_cast<std::size_t>(errnum)].fetch_add(1, std::memory_order_relaxed);
    } else {
        unknownErrnoCount_.v.fetch_add(1, std::memory_order_relaxed);
    }
}

void FuseStats::record_open_handle() noexcept {
    const auto current = openHandlesCurrent_.v.fetch_add(1, std::memory_order_relaxed) + 1;
    observeMax(openHandlesPeak_, current);
}

void FuseStats::record_close_handle() noexcept {
    auto current = openHandlesCurrent_.v.load(std::memory_order_relaxed);
    while (current > 0 && !openHandlesCurrent_.v.compare_exchange_weak(
        current,
        current - 1,
        std::memory_order_relaxed
    )) {}
}

FuseStatsSnapshot FuseStats::snapshot() const {
    FuseStatsSnapshot out;
    out.ops.reserve(static_cast<std::size_t>(FuseOperation::Count));

    for (std::size_t i = 0; i < static_cast<std::size_t>(FuseOperation::Count); ++i) {
        const auto& counters = ops_[i];
        const auto count = counters.count.v.load(std::memory_order_relaxed);
        const auto successes = counters.successes.v.load(std::memory_order_relaxed);
        const auto errors = counters.errors.v.load(std::memory_order_relaxed);
        const auto expectedErrors = counters.expectedErrors.v.load(std::memory_order_relaxed);
        const auto alertableErrors = counters.alertableErrors.v.load(std::memory_order_relaxed);
        const auto bytesRead = counters.bytesRead.v.load(std::memory_order_relaxed);
        const auto bytesWritten = counters.bytesWritten.v.load(std::memory_order_relaxed);
        const auto totalUs = counters.totalUs.v.load(std::memory_order_relaxed);
        const auto maxUs = counters.maxUs.v.load(std::memory_order_relaxed);

        out.totalOps += count;
        out.totalSuccesses += successes;
        out.totalErrors += errors;
        out.expectedErrors += expectedErrors;
        out.alertableErrors += alertableErrors;
        out.readBytes += bytesRead;
        out.writeBytes += bytesWritten;

        out.ops.push_back({
            .op = to_string(static_cast<FuseOperation>(i)),
            .count = count,
            .successes = successes,
            .errors = errors,
            .expectedErrors = expectedErrors,
            .alertableErrors = alertableErrors,
            .bytesRead = bytesRead,
            .bytesWritten = bytesWritten,
            .totalUs = totalUs,
            .maxUs = maxUs,
            .avgMs = count ? (static_cast<double>(totalUs) / 1000.0) / static_cast<double>(count) : 0.0,
            .maxMs = static_cast<double>(maxUs) / 1000.0,
            .errorRate = ratio(errors, count),
            .expectedErrorRate = ratio(expectedErrors, count),
            .alertableErrorRate = ratio(alertableErrors, count)
        });
    }

    for (std::size_t i = 0; i < errnoCounts_.size(); ++i) {
        const auto count = errnoCounts_[i].load(std::memory_order_relaxed);
        if (count == 0) continue;
        const auto alertableCount = alertableErrnoCounts_[i].load(std::memory_order_relaxed);
        if (alertableCount > 0) ++out.alertableErrnoTypes;
        out.topErrors.push_back({
            .errnoValue = static_cast<int>(i),
            .name = errnoName(static_cast<int>(i)),
            .count = count,
            .alertableCount = alertableCount
        });
    }

    // An out-of-range errno is never on the expected list, so every occurrence is alertable.
    const auto unknownErrnoCount = unknownErrnoCount_.v.load(std::memory_order_relaxed);
    if (unknownErrnoCount > 0) {
        ++out.alertableErrnoTypes;
        out.topErrors.push_back({
            .errnoValue = -1,
            .name = "ERRNO_UNKNOWN",
            .count = unknownErrnoCount,
            .alertableCount = unknownErrnoCount
        });
    }

    std::ranges::sort(out.topErrors, [](const auto& a, const auto& b) {
        if (a.count != b.count) return a.count > b.count;
        return a.errnoValue < b.errnoValue;
    });
    if (out.topErrors.size() > 10) out.topErrors.resize(10);

    out.errorRate = ratio(out.totalErrors, out.totalOps);
    out.expectedErrorRate = ratio(out.expectedErrors, out.totalOps);
    out.alertableErrorRate = ratio(out.alertableErrors, out.totalOps);
    out.openHandlesCurrent = openHandlesCurrent_.v.load(std::memory_order_relaxed);
    out.openHandlesPeak = openHandlesPeak_.v.load(std::memory_order_relaxed);
    out.checkedAt = fuseStatsUnixTimestamp();

    return out;
}

ScopedFuseOpTimer::ScopedFuseOpTimer(FuseStats* stats, const FuseOperation op) noexcept
    : stats_(stats), op_(op), start_(std::chrono::steady_clock::now()), uncaught_(std::uncaught_exceptions()) {}

ScopedFuseOpTimer::~ScopedFuseOpTimer() {
    if (completed_ || !stats_) return;
    if (std::uncaught_exceptions() > uncaught_) {
        completed_ = true;
        unansweredFuseOp = {stats_, op_, elapsedUs()};
        return;
    }
    success();
}

void ScopedFuseOpTimer::recordUnanswered(const int errnum) noexcept {
    const auto op = std::exchange(unansweredFuseOp, {});
    if (op.stats) op.stats->record_error(op.op, errnum, op.elapsedUs);
}

std::uint64_t ScopedFuseOpTimer::elapsedUs() const noexcept {
    const auto end = std::chrono::steady_clock::now();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(end - start_).count()
    );
}

void ScopedFuseOpTimer::success(const std::uint64_t bytesRead, const std::uint64_t bytesWritten) noexcept {
    if (completed_) return;
    completed_ = true;
    if (stats_) stats_->record_success(op_, elapsedUs(), bytesRead, bytesWritten);
}

void ScopedFuseOpTimer::error(const int errnum) noexcept {
    if (completed_) return;
    completed_ = true;
    if (stats_) stats_->record_error(op_, errnum, elapsedUs());
}

void ScopedFuseOpTimer::cancel() noexcept {
    completed_ = true;
}

std::string to_string(const FuseOperation op) {
    switch (op) {
        case FuseOperation::GetAttr:
            return "getattr";
        case FuseOperation::SetAttr:
            return "setattr";
        case FuseOperation::ReadDir:
            return "readdir";
        case FuseOperation::Lookup:
            return "lookup";
        case FuseOperation::ReadLink:
            return "readlink";
        case FuseOperation::Create:
            return "create";
        case FuseOperation::Symlink:
            return "symlink";
        case FuseOperation::Open:
            return "open";
        case FuseOperation::Read:
            return "read";
        case FuseOperation::Write:
            return "write";
        case FuseOperation::MkDir:
            return "mkdir";
        case FuseOperation::Rename:
            return "rename";
        case FuseOperation::Forget:
            return "forget";
        case FuseOperation::Access:
            return "access";
        case FuseOperation::Unlink:
            return "unlink";
        case FuseOperation::RmDir:
            return "rmdir";
        case FuseOperation::Flush:
            return "flush";
        case FuseOperation::Release:
            return "release";
        case FuseOperation::Fsync:
            return "fsync";
        case FuseOperation::StatFs:
            return "statfs";
        case FuseOperation::Unknown:
        case FuseOperation::Count:
        default:
            return "unknown";
    }
}

void to_json(nlohmann::json& j, const FuseOpStatsSnapshot& stats) {
    j = nlohmann::json{
        {"op", stats.op},
        {"count", stats.count},
        {"successes", stats.successes},
        {"errors", stats.errors},
        {"expected_errors", stats.expectedErrors},
        {"alertable_errors", stats.alertableErrors},
        {"bytes_read", stats.bytesRead},
        {"bytes_written", stats.bytesWritten},
        {"total_us", stats.totalUs},
        {"max_us", stats.maxUs},
        {"avg_ms", stats.avgMs},
        {"max_ms", stats.maxMs},
        {"error_rate", stats.errorRate},
        {"expected_error_rate", stats.expectedErrorRate},
        {"alertable_error_rate", stats.alertableErrorRate},
    };
}

void to_json(nlohmann::json& j, const FuseErrnoStatsSnapshot& stats) {
    j = nlohmann::json{
        {"errno_value", stats.errnoValue},
        {"name", stats.name},
        {"count", stats.count},
        {"alertable_count", stats.alertableCount},
    };
}

void to_json(nlohmann::json& j, const FuseStatsSnapshot& stats) {
    j = nlohmann::json{
        {"total_ops", stats.totalOps},
        {"total_successes", stats.totalSuccesses},
        {"total_errors", stats.totalErrors},
        {"expected_errors", stats.expectedErrors},
        {"alertable_errors", stats.alertableErrors},
        {"error_rate", stats.errorRate},
        {"expected_error_rate", stats.expectedErrorRate},
        {"alertable_error_rate", stats.alertableErrorRate},
        {"read_bytes", stats.readBytes},
        {"write_bytes", stats.writeBytes},
        {"open_handles_current", stats.openHandlesCurrent},
        {"open_handles_peak", stats.openHandlesPeak},
        {"ops", stats.ops},
        {"top_errors", stats.topErrors},
        {"alertable_errno_types", stats.alertableErrnoTypes},
        {"checked_at", stats.checkedAt},
    };
}

void to_json(nlohmann::json& j, const std::shared_ptr<FuseStatsSnapshot>& stats) {
    j = *stats;
}

void to_json(nlohmann::json& j, const FuseStats& stats) {
    j = stats.snapshot();
}

void to_json(nlohmann::json& j, const std::shared_ptr<FuseStats>& stats) {
    j = stats ? nlohmann::json(*stats) : nlohmann::json(nullptr);
}

}
