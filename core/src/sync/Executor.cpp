#include "sync/Executor.hpp"
#include "sync/Cloud.hpp"
#include "sync/model/Action.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/s3/Controller.hpp"

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
        // The action behind each future this phase pushes, so the ones that succeeded can be recorded on their own.
        std::vector<const model::Action*> pushed;
        for (const auto& a : plan) {
            if (a.type != type) continue;
            const auto before = ctx->futures.size();
            dispatch(ctx, a);
            for (auto i = before; i < ctx->futures.size(); ++i) pushed.push_back(&a);
        }
        ctx->processFutures(); // barrier between phases
        for (std::size_t i = 0; i < pushed.size() && i < ctx->futureOutcomes.size(); ++i) {
            if (!ctx->futureOutcomes[i]) continue;
            if (pushed[i]->type == model::ActionType::Upload || pushed[i]->type == model::ActionType::DeleteRemote)
                ctx->completedActions.push_back(*pushed[i]);
        }
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
