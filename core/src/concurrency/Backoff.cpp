#include "concurrency/Backoff.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstdint>

namespace vh::concurrency {

std::chrono::milliseconds jitteredBackoff(const unsigned attempt, const std::chrono::milliseconds floor,
                                          const std::chrono::milliseconds cap) {
    const int64_t floorMs = std::max<int64_t>(0, floor.count());
    const int64_t capMs = std::max<int64_t>(floorMs, cap.count());
    // floor * 2^attempt, without overflowing (2^16 is far past any cap in use).
    const int64_t grown = floorMs * (int64_t{1} << std::min(attempt, 16u));
    const int64_t upper = std::min(capMs, std::max(floorMs, grown));
    const auto span = static_cast<uint32_t>(std::min<int64_t>(upper - floorMs, UINT32_MAX - 1));
    return std::chrono::milliseconds(floorMs + (span == 0 ? 0 : randombytes_uniform(span + 1)));
}

}
