#pragma once

// Check 1 of design section 4.1: WebAuthn challenges as single-use, short-lived records in memory, bound to the ws
// session that asked, the ceremony purpose, the user (except discoverable `login`) and, for step-up and approvals,
// the family/target scope. A daemon restart drops them all, which only makes an open ceremony start over.
//
// Lookup is by value: the map is keyed by a keyed BLAKE2b digest of the challenge (a per-process random key), and the
// stored value is compared with sodium_memcmp. consume() removes the record before it reports anything, so every
// attempt, failed or not, burns the challenge before any signature is checked.

#include "auth/webauthn/Types.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

namespace vh::auth::webauthn {

class ChallengeStore {
public:
    using Clock = std::chrono::steady_clock;
    static constexpr std::size_t kBytes = 32;
    using Challenge = std::array<std::uint8_t, kBytes>;

    explicit ChallengeStore(std::chrono::seconds ttl = std::chrono::seconds(120), std::size_t capacity = 16384,
                            std::size_t perSession = 8);

    // A fresh random challenge bound to `binding`. A session's oldest open challenge makes room once it has
    // perSession; nullopt when the store holds `capacity` unexpired challenges.
    [[nodiscard]] std::optional<Challenge> issue(const Expectation& binding, Clock::time_point now = Clock::now());

    // Burns the challenge and checks its record against `expected`: Failure::None when it matches.
    [[nodiscard]] Failure consume(ByteView challenge, const Expectation& expected, Clock::time_point now = Clock::now());

    // Drops every challenge of a session (sign-out, socket closed).
    void forgetSession(std::string_view session);

    [[nodiscard]] std::size_t size() const;

private:
    struct Record {
        Challenge value{};
        Expectation binding;
        Clock::time_point issued;
        Clock::time_point expires;
    };

    [[nodiscard]] std::string slot(ByteView challenge) const;
    void purgeExpired(Clock::time_point now);

    std::chrono::seconds ttl_;
    std::size_t capacity_;
    std::size_t perSession_;
    std::array<std::uint8_t, 32> lookupKey_{};
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Record> records_;
};

}
