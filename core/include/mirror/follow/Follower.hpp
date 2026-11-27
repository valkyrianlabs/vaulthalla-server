#pragma once

#include "concurrency/AsyncService.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "mirror/apply/Applier.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>

// The mirror's follower and the core's notices (design/peers/mirror.md "Following the core", "As built: following the
// core"). Registered with runtime::Manager as "MirrorFollower", started after PeerLinks.
//
// Mirror side: every vault with a `mirror` row here is driven by itself (piece A only creates the row): the first copy
// (peer.mirror.tree pages into the empty vault, resumable at every page), then the log (peer.mirror.log from the last
// applied position), each page or group applied by mirror::apply and acknowledged (peer.mirror.ack) with this server's
// digest. A vault is visited on a short timer while its first copy is unfinished, when its link comes up, when the core
// sends a notice, and on a slow timer otherwise; errors back off; a vault that stops (diverged, expired, stopped) or
// whose row goes is left alone. Every request is bounded (the link's request timeout), every pass is bounded in time,
// and nothing runs on a FUSE worker or on the link's read thread. Contents are fetched in the background by the
// MirrorContents service (mirror/start/BackgroundContents.hpp), the one drainer of the pending queue; not here.
//
// Core side: the sequencer reports each vault it numbered (numbered()); the notice (peer.mirror.notify) is sent from
// this service's thread, coalesced per vault, never blocking the sequencer. A lost notice is harmless: the follower
// also polls.
//
// For a drill: the vault's mirror_vault row holds the applied position (term, last_seq), copy_finished, copy_cursor,
// digest and the stop reason; the log says "first copy finished" and "applied through" with the digest.
//
// Gate: while peers.experimental is off nothing is requested or sent.
namespace vh::mirror::follow {

// How the follower reaches the core (the link service by default; tests replay what the core answered).
class Transport {
public:
    struct Answer {
        bool ok{false};
        nlohmann::json data{};
        std::string code{};
        std::string error{};
    };
    virtual ~Transport() = default;
    [[nodiscard]] virtual bool connected(uint32_t peerId) = 0;
    // nullopt: no connection, or no answer within the link's request timeout.
    [[nodiscard]] virtual std::optional<Answer> request(uint32_t peerId, const std::string& command,
                                                        const nlohmann::json& payload) = 0;
    virtual bool notify(uint32_t peerId, const std::string& command, const nlohmann::json& payload) = 0;

    // The sealed bytes of a change made here, to the vault's core ahead of the change (mirror::submit): PUT on the
    // sealed lane (peer::object::put) by default.
    struct Sent {
        bool ok{false};          // the core holds them, verified
        bool retry{false};       // not reached, or broken off: send again later
        std::string code{};      // the core's refusal
        std::string error{};
    };
    struct Content {
        std::string vault_uid{};   // uuid text
        std::string object_uid{};  // uuid text
        std::string generation{};
        uint32_t key_version{};
        uint64_t size{};
        std::string content_hash{};
        std::string path{};        // the sealed bytes here
    };
    virtual Sent sendContent(uint32_t peerId, const Content& content);
};

// The link service's (peer::LinkService::request / notify).
[[nodiscard]] std::shared_ptr<Transport> linkTransport();

enum class Step {
    Idle,          // nothing new
    Progress,      // applied something; more may be waiting
    CopyFinished,  // the first copy is complete and matched the baseline
    Waiting,       // the link is down, a file is open, or the core did not answer: later
    Stopped,       // the vault is not live (diverged, expired, stopped, paused)
    Gone,          // no mirror row (any more)
    Error,         // something failed: back off
};
[[nodiscard]] const char* toString(Step s);

struct StepResult {
    Step step{Step::Idle};
    std::string detail{};
    std::size_t applied{};   // pages or groups applied
};

class Follower : public concurrency::AsyncService {
public:
    // While the first copy is unfinished; after a notice or link-up at once; otherwise.
    static constexpr std::chrono::milliseconds kCopyInterval{1'000};
    static constexpr std::chrono::seconds kSlowInterval{30};
    static constexpr std::chrono::seconds kBackoffCap{60};
    static constexpr std::chrono::seconds kRowReload{5};
    // One visit of one vault applies for at most this long.
    static constexpr std::chrono::seconds kStepBudget{3};
    // Files fetched per visit of the contents thread.

    Follower();
    ~Follower() override;

    static const std::shared_ptr<Follower>& instance();

    // One visit of one mirror vault through `transport` (the loop's; tests call it directly).
    StepResult step(uint32_t vaultId, Transport& transport, const vh::mirror::apply::Options& options = {});

    // The core's notice for a vault this server mirrors: visit it now.
    void wake(uint32_t vaultId);
    // Core side: the sequencer numbered groups of `vaultId` through `last` (coalesced; sent from this service).
    void numbered(uint32_t vaultId, vh::db::query::mirror::Position last);

    // Tests: the transport the loop uses (null: the link service's).
    void setTransportForTesting(std::shared_ptr<Transport> transport);
    // Tests: the notices waiting to be sent, then sent through `transport`; how many were sent.
    std::size_t sendNoticesForTesting(Transport& transport);

protected:
    void runLoop() override;
    void onStop() override;

private:
    struct Partial {
        vh::db::query::mirror::Position after{};
        vh::mirror::apply::LogGroup group{};
    };
    struct Schedule {
        std::chrono::steady_clock::time_point next{};
        std::chrono::milliseconds backoff{0};
        bool linkWasUp{false};
    };

    std::size_t sendNotices(Transport& transport);
    bool acknowledge(Transport& transport, const vh::db::query::mirror::MirrorVault& mv, const std::string& vaultUid,
                     vh::db::query::mirror::Position at, const vh::mirror::Digest& digest);
    std::shared_ptr<Transport> transport();

    std::mutex mutex_;
    std::condition_variable cv_;
    std::set<uint32_t> woken_;
    std::map<uint32_t, vh::db::query::mirror::Position> notices_;
    std::map<uint32_t, Partial> partials_;
    std::map<uint32_t, Schedule> schedule_;
    std::shared_ptr<Transport> testTransport_;
};

}
