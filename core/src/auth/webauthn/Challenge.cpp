#include "auth/webauthn/Challenge.hpp"

#include <sodium.h>

#include <stdexcept>

namespace vh::auth::webauthn {

ChallengeStore::ChallengeStore(const std::chrono::seconds ttl, const std::size_t capacity, const std::size_t perSession)
    : ttl_(ttl), capacity_(capacity), perSession_(perSession) {
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
    if (ttl_.count() <= 0 || capacity_ == 0 || perSession_ == 0)
        throw std::invalid_argument("ChallengeStore: ttl, capacity and perSession must be positive");
    randombytes_buf(lookupKey_.data(), lookupKey_.size());
}

std::string ChallengeStore::slot(const ByteView challenge) const {
    std::string digest(crypto_generichash_BYTES, '\0');
    crypto_generichash(reinterpret_cast<unsigned char*>(digest.data()), digest.size(), challenge.data(),
                       challenge.size(), lookupKey_.data(), lookupKey_.size());
    return digest;
}

void ChallengeStore::purgeExpired(const Clock::time_point now) {
    std::erase_if(records_, [now](const auto& entry) { return entry.second.expires <= now; });
}

std::optional<ChallengeStore::Challenge> ChallengeStore::issue(const Expectation& binding, const Clock::time_point now) {
    Record record;
    randombytes_buf(record.value.data(), record.value.size());
    record.binding = binding;
    record.issued = now;
    record.expires = now + ttl_;

    const std::scoped_lock lock(mutex_);
    // One session holds at most perSession open challenges: the oldest goes.
    std::size_t open = 0;
    auto oldest = records_.end();
    for (auto it = records_.begin(); it != records_.end(); ++it) {
        if (it->second.binding.session != binding.session) continue;
        ++open;
        if (oldest == records_.end() || it->second.issued < oldest->second.issued) oldest = it;
    }
    if (open >= perSession_ && oldest != records_.end()) records_.erase(oldest);
    if (records_.size() >= capacity_) purgeExpired(now);
    if (records_.size() >= capacity_) return std::nullopt;

    const auto value = record.value;
    records_.emplace(slot(value), std::move(record));
    return value;
}

Failure ChallengeStore::consume(const ByteView challenge, const Expectation& expected, const Clock::time_point now) {
    if (challenge.size() != kBytes) return Failure::ChallengeUnknown;
    Record record;
    {
        const std::scoped_lock lock(mutex_);
        const auto it = records_.find(slot(challenge));
        if (it == records_.end()) return Failure::ChallengeUnknown;
        if (sodium_memcmp(it->second.value.data(), challenge.data(), kBytes) != 0) return Failure::ChallengeUnknown;
        record = std::move(it->second);
        records_.erase(it);  // single use: burnt whatever happens next
    }
    if (record.expires <= now) return Failure::ChallengeExpired;
    if (record.binding.session != expected.session) return Failure::ChallengeSessionMismatch;
    if (record.binding.purpose != expected.purpose) return Failure::ChallengePurposeMismatch;
    // Discoverable sign-in names no user up front; every other purpose is bound to exactly one.
    const bool userless = expected.purpose == Purpose::Login;
    if (userless != !expected.user.has_value() || record.binding.user != expected.user)
        return Failure::ChallengeUserMismatch;
    if (record.binding.scope != expected.scope) return Failure::ChallengeScopeMismatch;
    return Failure::None;
}

void ChallengeStore::forgetSession(const std::string_view session) {
    const std::scoped_lock lock(mutex_);
    std::erase_if(records_, [session](const auto& entry) { return entry.second.binding.session == session; });
}

std::size_t ChallengeStore::size() const {
    const std::scoped_lock lock(mutex_);
    return records_.size();
}

}
