#pragma once

#include "Local.hpp"
#include "sync/tasks/Delete.hpp"
#include "model/helpers.hpp"
#include "fs/Fwd.hpp"
#include "storage/Fwd.hpp"
#include "sync/Fwd.hpp"
#include "sync/model/Action.hpp"
#include "sync/model/Baseline.hpp"
#include "db/query/sync/Conflict.hpp"
#include "sync/model/Scope.hpp"

#include <functional>
#include <unordered_set>

#include <memory>
#include <unordered_map>
#include <string>
#include <vector>

namespace vh::sync {
    struct Cloud final : Local {
        std::vector<std::shared_ptr<fs::model::File> > localFiles, s3Files;
        std::unordered_map<std::u8string, std::shared_ptr<fs::model::File> > localMap, s3Map;
        std::unordered_map<std::u8string, std::optional<std::string> > remoteHashMap;

        // Conflict state for this pass (#187): loaded with the bins, decided by the planner, written by
        // flushConflictState() before anything executes.
        std::unordered_map<uint32_t, model::Baseline> baselines;                       // by file id
        std::unordered_map<uint32_t, db::query::sync::ConflictRecord> openConflicts;    // by file id
        db::query::sync::ConflictPassWrites conflictWrites;

        // Event-driven sync (#96). A scoped pass reconciles only scope->keys from the remote index; a regular pass has
        // no scope. Either way, keys with a pending upstream removal (an applied removal event not yet settled) follow
        // the removal rule instead of being re-uploaded as "local only".
        std::shared_ptr<const model::PassScope> scope;
        std::unordered_set<std::u8string> removedKeys;

        // Installed by the event service: the vault's keys with an applied, unsettled removal event.
        using PendingRemovalsProvider = std::function<std::unordered_set<std::u8string>(uint32_t vaultId)>;
        static void setPendingRemovalsProvider(PendingRemovalsProvider provider);

        ~Cloud() override = default;

        explicit Cloud(const std::shared_ptr<storage::Engine> &engine) : Local(engine) {
        }

        Cloud(const std::shared_ptr<storage::Engine> &engine, std::shared_ptr<const model::PassScope> passScope)
            : Local(engine), scope(std::move(passScope)) {
        }

        [[nodiscard]] bool requeueAfterRun() const override { return scope == nullptr; }

        // ##########################################
        // ########### FSTask Overrides #############
        // ##########################################

        void operator()() override;

        // ##########################################
        // ############# Sync Operations ############
        // ##########################################

        void sync();

        void initBins();
        void initScopedBins();
        // removedKeys from the pending-removals provider (and the scope's own removals).
        void loadRemovedKeys();

        void clearBins();

        // ##########################################
        // ########### File Operations #############
        // ##########################################

        void upload(const std::shared_ptr<fs::model::File> &file);

        void download(const std::shared_ptr<fs::model::File> &file, bool freeAfterDownload = false);

        void indexRemoteOnly(const std::shared_ptr<fs::model::File> &file);

        void remove(const std::shared_ptr<fs::model::File> &file,
                    const tasks::Delete::Type &type = tasks::Delete::Type::PURGE);

        // ##########################################
        // ############ Internal Helpers ############
        // ##########################################

        std::shared_ptr<storage::CloudEngine> cloudEngine() const;

        std::vector<model::EntryKey> allKeysSorted() const;

        void ensureDirectoriesFromRemote();

        // ##########################################
        // ########### Conflict Handling ############
        // ##########################################

        [[nodiscard]] static bool hasPotentialConflict(const std::shared_ptr<fs::model::File> &local,
                                                       const std::shared_ptr<fs::model::File> &upstream,
                                                       bool upstream_decryption_failure);

        std::shared_ptr<model::Conflict> maybeBuildConflict(const std::shared_ptr<fs::model::File> &local,
                                                            const std::shared_ptr<fs::model::File> &upstream) const;

        // Records the conflict on the event; an unresolved one is queued for its single open row (or left alone
        // when that row already describes both sides), an auto-resolved one closes the file's open row.
        // True when it stays unresolved (nothing is planned for the file).
        bool handleConflict(const std::shared_ptr<model::Conflict> &c);

        void loadConflictState();
        void flushConflictState();
        // Planner::build followed by flushConflictState(): what one pass plans and records.
        std::vector<model::Action> planPass(model::S3CostEstimate *planningNotes = nullptr);

        [[nodiscard]] const model::Baseline *baselineFor(uint32_t fileId) const;
        [[nodiscard]] bool hasOpenConflict(uint32_t fileId) const;
        // Both sides agree: refresh the file's baseline if it moved and close an open conflict as converged.
        void noteInSync(const fs::model::File &local, const fs::model::File &remote);
        void closeOpenConflict(uint32_t fileId, const std::string &resolution);

        // ##########################################
        // ########### Static Helpers ###############
        // ##########################################

        static uintmax_t computeReqFreeSpaceForDownload(const std::vector<std::shared_ptr<fs::model::File> > &files);

        static std::vector<std::shared_ptr<fs::model::File> > uMap2Vector(
            std::unordered_map<std::u8string, std::shared_ptr<fs::model::File> > &map);

        static std::unordered_map<std::u8string, std::shared_ptr<fs::model::File> > intersect(
            const std::unordered_map<std::u8string, std::shared_ptr<fs::model::File> > &a,
            const std::unordered_map<std::u8string, std::shared_ptr<fs::model::File> > &b);
    };
}
