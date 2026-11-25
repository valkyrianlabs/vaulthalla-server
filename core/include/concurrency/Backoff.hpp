#pragma once

#include <chrono>

// Reconnect delays with full jitter (the cloud relay link, the server link): uniform between `floor` and the smaller of
// `cap` and floor * 2^attempt, from libsodium's CSPRNG (attempt 0 waits exactly `floor`).
namespace vh::concurrency {

[[nodiscard]] std::chrono::milliseconds jitteredBackoff(unsigned attempt, std::chrono::milliseconds floor,
                                                        std::chrono::milliseconds cap);

}
