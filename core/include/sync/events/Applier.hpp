#pragma once

#include "sync/Controller.hpp"
#include "sync/model/Scope.hpp"

#include <cstdint>
#include <ctime>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>

// Applies a vault's inbox (#96): pending rows move the remote object index (ordered per key, stale and duplicate
// events dropped, Vaulthalla's own writes recognised), the index manifest is republished while the vault's pass lease
// is held, and an event-scoped sync pass reconciles exactly the affected keys. Rows end `done` when that pass
// succeeds, and are retried with backoff when it doesn't.
namespace vh::sync::events {

class Applier {
public:
    // Seams for tests; defaults go to runtime::Deps (the sync controller).
    struct Hooks {
        std::function<bool(uint32_t)> tryAcquirePass;
        std::function<void(uint32_t)> releasePass;
        std::function<Controller::ScopedResult(uint32_t, std::shared_ptr<model::PassScope>)> runScoped;
    };

    struct Outcome {
        size_t claimed = 0, applied = 0, skipped = 0, self = 0, failed = 0;
        bool held = false;        // baseline not done yet: nothing applied
        bool busy = false;        // another pass held the vault: retried later
        bool pass_started = false;
        bool index_changed = false;
    };

    Applier();
    explicit Applier(Hooks hooks);

    // One batch: apply due pending rows, then schedule a scoped pass for due applied rows. Never throws for
    // per-row problems (they are recorded on the rows); a database outage propagates.
    Outcome applyVault(uint32_t vaultId);

    // The vault's keys with an applied, unsettled removal event (Cloud's pending-removals provider).
    [[nodiscard]] static std::unordered_set<std::u8string> pendingRemovals(uint32_t vaultId);

    // Baseline (adoption): the vault's first full listing finished; events older than it are superseded.
    static void onBaselineListed(uint32_t vaultId, std::time_t listStartedAt);
    [[nodiscard]] static bool baselineNeeded(uint32_t vaultId);
    // An active subscription with a recently healthy channel keeps the remote index fresh.
    [[nodiscard]] static bool indexKeptFresh(uint32_t vaultId, std::chrono::seconds maxAge);

    // Clock skew allowed between a provider's event time and our listing start.
    static constexpr std::time_t kBaselineSkewSeconds = 60;
    static constexpr unsigned int kMaxPassAttempts = 10;

private:
    Hooks hooks_;
    void schedule(uint32_t vaultId, Outcome& outcome);
};

}
