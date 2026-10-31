#pragma once

#include "storage/Fwd.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

// The device listener's transfer calibration lanes (device.lanes.transfer, docs/reference/transfer-protocol.md §4):
// GET /transfer/probe, POST /transfer/sink, GET /transfer/source?bytes=<n>. Nothing touches the disk. The HTTP
// mechanics (reading and discarding a body, streaming one) are http::Session's; this is the policy.
namespace vh::protocols::device::transfer {

inline constexpr uint64_t kMaxBytes = 256ull * 1024 * 1024;
// Calibration requests (sink, source) one device may run at once; more are 429.
inline constexpr unsigned kMaxConcurrentPerDevice = 2;

// "/transfer", "/transfer/…" or "/transfer?…".
[[nodiscard]] bool isTarget(std::string_view target) noexcept;

// A held calibration slot; released when the last copy goes away.
using Slot = std::shared_ptr<void>;
// A slot for `deviceRowId`, or null when it already holds kMaxConcurrentPerDevice.
[[nodiscard]] Slot acquire(uint32_t deviceRowId);
[[nodiscard]] unsigned inFlightForTesting(uint32_t deviceRowId);

// GET /transfer/probe: {node_id, server_time_ms, capabilities}. The node id is cached after the first read.
[[nodiscard]] std::string probeJson();

// `?bytes=<n>` of a /transfer/source target: n when it is a decimal integer in [0, kMaxBytes], else nullopt.
[[nodiscard]] std::optional<uint64_t> sourceBytes(std::string_view target);

// `bytes` pseudo-random bytes (SplitMix64 keyed by `seed`, positioned: read(offset) needs no state), never stored.
[[nodiscard]] std::shared_ptr<storage::PlaintextReader> randomSource(uint64_t bytes, uint64_t seed);

}
