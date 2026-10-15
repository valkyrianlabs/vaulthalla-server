#pragma once

#include "concurrency/AsyncService.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/model/Channel.hpp"
#include "sync/events/Applier.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

// UpstreamEventService (#96): consumes the event channels (AWS SQS long polls, Cloudflare Queues HTTP pull), one
// poller thread per channel, writes every decoded event to the inbox before acknowledging it, and drives the applier.
// Every 30 s it reloads the protection guard and retries subscription teardowns left half done.
//
// Shutdown is bounded: requestStop() cancels in-flight requests on every thread of the service (pollers and the main
// loop: maintenance, teardown retries, the applier's HEADs and manifest publish run under http::ScopedCancellation),
// the applier stops between keys, and the pollers are joined at the end of runLoop. Pollers that leave while the
// service runs (channel removed) are joined only once they have finished, never waited for on the service thread.
namespace vh::sync::events {

struct PollOutcome {
    size_t messages = 0, events = 0, inserted = 0, acked = 0, ignored = 0, undecodable = 0, unrouted = 0;
    std::optional<uint64_t> backlog;
};

class Service final : public concurrency::AsyncService {
public:
    Service();
    ~Service() override;

    // One poll of a channel: receive, decode, ingest durably, then acknowledge what was stored or ignorable.
    // Throws on a provider or database failure (nothing stored is acknowledged; nothing acknowledged is lost).
    static PollOutcome pollOnce(const storage::upstream::model::Channel& channel,
                                storage::s3::provider::admin::EventsClient& client,
                                std::chrono::seconds wait = std::chrono::seconds{20});

    // One poller iteration over a channel (the loop body; public for tests): poll + ingest + ack, then the channel's
    // poll bookkeeping (success, or failure with backoff and degraded state).
    enum class StepResult { Polled, Inserted, Failed, Stopped };
    struct PollerState {
        std::unique_ptr<storage::s3::provider::admin::EventsClient> client;
        std::optional<uint32_t> clientKey;
        unsigned int idlePolls = 0;
        PollOutcome last;
    };
    static StepResult pollStep(const storage::upstream::model::Channel& channel, PollerState& state,
                               const std::atomic<bool>* stop = nullptr);

    // Wakes the applier (after an ingest).
    void notifyWork();
    // Runs one maintenance + apply cycle synchronously (tests, and the loop body).
    void cycle();

    [[nodiscard]] size_t pollerCount() const;

protected:
    void runLoop() override;
    void onStop() override;

private:
    struct Poller {
        int64_t channelId = 0;
        std::atomic<bool> stop{false};
        std::atomic<bool> finished{false};   // the loop ended on its own (channel removed/failed): restartable
        std::thread thread;
    };

    // A stop was requested (unlike shouldStop(), false for a service that was never started: tests drive cycle()).
    [[nodiscard]] bool stopRequested() const { return interruptFlag_.load(std::memory_order_acquire); }

    void superviseChannels();
    void reapRetired();
    void stopPollers();
    void pollerLoop(const std::shared_ptr<Poller>& poller);
    void maintenance();
    // Dead-letter queue depth per channel (every kDlqCheckInterval): growth means events were lost.
    void checkDeadLetters();

    Applier applier_;
    mutable std::mutex pollersMutex_;
    std::map<int64_t, std::shared_ptr<Poller>> pollers_;
    std::vector<std::shared_ptr<Poller>> retired_;   // told to stop, joined once finished
    std::mutex workMutex_;
    std::condition_variable workCv_;
    bool workPending_ = false;
    std::chrono::steady_clock::time_point lastMaintenance_{};
    std::chrono::steady_clock::time_point lastDlqCheck_{};
};

// Backoff after `failures` consecutive channel failures: 5 s doubling to 5 min.
[[nodiscard]] std::chrono::seconds channelBackoff(unsigned int failures);

}
