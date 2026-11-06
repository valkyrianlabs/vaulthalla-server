#pragma once

#include "audit/Chain.hpp"
#include "concurrency/AsyncService.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/common.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

// The tamper-evident audit trail (#323). Every line written to the audit logger (log::Registry::audit()) also
// becomes an event in the database's hash chain (audit_event, migration 117; audit/Chain.hpp). record() writes one
// with structured fields; plain audit()->info(...) lines are recorded too, with the action taken from their
// "[component]" tag.
//
// Writing never blocks the caller on the database: the audit logger's sink hands each event to a bounded queue, and
// this service appends them in batches. While the database is unreachable events wait in the queue (and in
// audit.log); if the queue overflows, the oldest are dropped and an `audit.gap` event records how many, so a
// verifier sees the gap instead of a silently shorter history. The service also signs the chain head every
// auditing.trail.head_interval_minutes (and on shutdown), and purges events past auditing.trail.retention_days.
namespace vh::audit {

enum class Outcome { Success, Failure, Denied, Info };
[[nodiscard]] std::string to_string(Outcome outcome);

struct Event {
    std::string action{};  // dotted, lower case: auth.login.success, rbac.role.update, fs.delete
    Outcome outcome{Outcome::Success};
    std::optional<uint32_t> actor_id{};
    std::string actor{};
    std::optional<uint32_t> vault_id{};
    std::optional<uint64_t> entry_id{};
    nlohmann::json details = nlohmann::json::object();  // strings, integers and booleans; never names or paths
};

// Writes `message` to the audit log (and syslog, when enabled) and appends it to the chain with `event`'s fields.
void record(const Event& event, const std::string& message, spdlog::level::level_enum level = spdlog::level::info);

// Records an event when the scope it guards ends normally (the operation succeeded); nothing when it ends by an
// exception. For operations with several return paths.
class OnSuccess {
public:
    OnSuccess(Event event, std::string message);
    ~OnSuccess();
    OnSuccess(const OnSuccess&) = delete;
    OnSuccess& operator=(const OnSuccess&) = delete;
    [[nodiscard]] Event& event() noexcept { return event_; }

private:
    Event event_;
    std::string message_;
    int exceptions_;
};

// The audit logger's sink that feeds Trail (log::Registry attaches it).
[[nodiscard]] spdlog::sink_ptr makeChainSink();

// The action an untagged audit line gets: "[ops::users] admin created ..." -> "ops.users".
[[nodiscard]] std::string actionFromMessage(std::string_view message);

class Trail final : public concurrency::AsyncService {
public:
    static constexpr std::size_t kQueueCapacity = 100'000;
    static constexpr std::size_t kBatch = 500;

    static std::shared_ptr<Trail> instance();

    Trail();
    ~Trail() override;

    // From the audit logger's sink. Never blocks on the database and never throws.
    void submit(Record record) noexcept;

    // Signs the current head when the chain advanced since the last signed head. nullopt when there was nothing new
    // or signing failed (logged).
    std::optional<SignedHead> signHead();
    // Applies auditing.trail.retention_days; returns the number of events removed.
    uint64_t purge();

    // Tests: writes everything queued now (on the calling thread); false if the database refused.
    bool flushNow();
    void resetForTesting();
    [[nodiscard]] std::size_t queuedForTesting();

protected:
    void runLoop() override;
    void onStop() override;

private:
    bool loadTail();
    bool writeBatch(std::unique_lock<std::mutex>& lock);

    std::mutex mutex_{};
    std::condition_variable cv_{};
    std::deque<Record> queue_{};
    uint64_t dropped_{0};
    std::optional<uint64_t> seq_{};  // the last appended seq, once loaded
    Hash hash_{};
    uint64_t signedSeq_{0};
    std::mutex writeMutex_{};  // one writer at a time (the service loop, flushNow, shutdown)
};

}
