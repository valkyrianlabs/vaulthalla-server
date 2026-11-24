#include "sync/Executor.hpp"
#include "sync/Cloud.hpp"
#include "sync/model/Action.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/s3/Controller.hpp"
#include "log/Registry.hpp"

#include <exception>

using namespace vh::sync;

namespace {
    void throwIfS3BudgetExceeded(const std::shared_ptr<Cloud>& ctx) {
        const auto metrics = ctx->cloudEngine()->s3RequestMetrics();
        if (!metrics.budget_exceeded) return;
        throw vh::storage::s3::RequestBudgetExceeded(metrics.budget_exceeded_reason);
    }
}

void Executor::run(const std::shared_ptr<Cloud>& ctx, const std::vector<model::Action>& plan) {
    // Option: stable grouping for determinism & perf
    // EnsureDirectories first, then uploads, then downloads, then deletes
    for (const auto type : {model::ActionType::EnsureDirectories, model::ActionType::Upload, model::ActionType::Download,
                      model::ActionType::IndexRemoteOnly,
                      model::ActionType::DeleteRemote, model::ActionType::DeleteLocal}) {
        // The action behind each future this phase pushes, so the ones that succeeded can be recorded on their own:
        // futures[phaseStart + i] is pushed[i]. Local::push is the only writer of ctx->futures and
        // Local::processFutures, which empties it, the only reader, so phaseStart is 0 in practice; the offset keeps
        // the mapping right whatever an earlier stage left there.
        const auto phaseStart = ctx->futures.size();
        std::vector<const model::Action*> pushed;
        std::exception_ptr stopped;
        try {
            for (const auto& a : plan) {
                if (a.type != type) continue;
                const auto before = ctx->futures.size();
                dispatch(ctx, a);
                for (auto i = before; i < ctx->futures.size(); ++i) pushed.push_back(&a);
            }
        } catch (...) {
            stopped = std::current_exception();   // what was already handed out still runs: wait for it below
        }
        ctx->processFutures(); // barrier between phases (also when dispatching stopped half-way)
        if (ctx->futureOutcomes.size() == phaseStart + pushed.size()) {
            for (std::size_t i = 0; i < pushed.size(); ++i) {
                if (!ctx->futureOutcomes[phaseStart + i]) continue;
                if (pushed[i]->type == model::ActionType::Upload || pushed[i]->type == model::ActionType::DeleteRemote)
                    ctx->completedActions.push_back(*pushed[i]);
            }
        } else {
            // Not expected (see above). Nothing of this phase is recorded: it is planned again, never named unsent.
            vh::log::Registry::sync()->error("[SyncExecutor] {} outcome(s) for {} future(s) of the phase; its operations "
                                             "are not recorded", ctx->futureOutcomes.size(), phaseStart + pushed.size());
        }
        if (stopped) std::rethrow_exception(stopped);
        // After the phase's outcomes are recorded: the uploads that completed before the budget ran out count.
        throwIfS3BudgetExceeded(ctx);
    }
}

void Executor::dispatch(const std::shared_ptr<Cloud>& ctx, const model::Action& action) {
    switch (action.type) {
    case model::ActionType::EnsureDirectories:
        ctx->ensureDirectoriesFromRemote(); // extracted shared function
        return;
    case model::ActionType::Upload:
        ctx->upload(action.local);
        return;
    case model::ActionType::Download:
        // if cache mode sets freeAfterDownload, forward it
        ctx->download(action.remote ? action.remote : action.local, action.freeAfterDownload);
        return;
    case model::ActionType::IndexRemoteOnly:
        ctx->indexRemoteOnly(action.remote ? action.remote : action.local);
        return;
    case model::ActionType::DeleteLocal:
        ctx->remove(action.local, tasks::Delete::Type::LOCAL);
        return;
    case model::ActionType::DeleteRemote:
        ctx->remove(action.remote, tasks::Delete::Type::REMOTE);
        return;
    }
}
