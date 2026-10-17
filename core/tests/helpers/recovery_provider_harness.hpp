#pragma once

// Shared by test_recovery_provider.cpp and test_recovery_smart_cache.cpp (file recovery, provider versions): a remote
// vault over the VersionedBucket fake (S3 versioning semantics behind the real s3::Controller metering), real sync
// passes run inline, and the provider restore primitives.

#include "sync_conflict_harness.hpp"
#include "versioned_bucket.hpp"

#include "db/query/recovery/ObjectVersion.hpp"
#include "recovery/Model.hpp"
#include "recovery/provider/Points.hpp"
#include "recovery/provider/Restore.hpp"
#include "recovery/provider/Versions.hpp"
#include "sync/Controller.hpp"
#include "sync/model/RemoteManifest.hpp"

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <string>
#include <vector>

namespace vh::test_support::recovery_provider {

using VersionRow = db::query::recovery::ObjectVersionRow;
using versioned::VersionedBucket;
using versioned::Versioning;
using Strategy = sync::model::RemotePolicy::Strategy;

class ProviderHarness : public sync_conflicts::Harness {
protected:
    struct VFixture {
        ops::vaults::VaultPtr vault;
        std::shared_ptr<storage::CloudEngine> engine;
        std::shared_ptr<VersionedBucket> bucket;
    };

    // The pass lease a restore takes, as the sync controller would hand it out.
    static sync::Controller& leases() {
        static sync::Controller controller;
        return controller;
    }

    static recovery::provider::RestoreOptions restoreOptions(const bool acceptUnverified = false) {
        recovery::provider::RestoreOptions o;
        o.accept_unverified = acceptUnverified;
        o.hooks.tryAcquirePass = [](const uint32_t v) { return leases().tryAcquirePass(v); };
        o.hooks.releasePass = [](const uint32_t v) { leases().releasePass(v); };
        return o;
    }

    // An S3 vault (encrypting upstream unless told otherwise) on a versioned in-memory bucket.
    static VFixture versionedVault(const Strategy strategy = Strategy::Cache, const bool encryptUpstream = true,
                                   const Versioning mode = Versioning::Enabled) {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "rp_key_" + sync_conflicts::tag(),
                                                          vault::model::S3Provider::AWS, "AKIATESTACCESSKEY000",
                                                          "secret-value-0000000000000000000000000", "us-east-1",
                                                          "https://s3.us-east-1.amazonaws.com");
        const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        VFixture f;
        f.vault = ops::vaults::create(superUser, {.name = "rp_vault_" + sync_conflicts::tag(),
                                                  .type = vault::model::VaultType::S3, .owner_id = superUser->id,
                                                  .s3 = ops::vaults::S3Spec{.api_key_id = keyId,
                                                                            .bucket = "rp-" + sync_conflicts::tag(),
                                                                            .encrypt_upstream = encryptUpstream}});
        f.engine = std::static_pointer_cast<storage::CloudEngine>(runtime::Deps::get().storageManager->getEngine(f.vault->id));
        f.bucket = std::make_shared<VersionedBucket>(mode);
        // Bucket clock ≈ real clock (every mutation ticks it by a second), so own-write rows and listings agree.
        f.bucket->setNow(std::time(nullptr) - 600);
        f.engine->setS3ControllerForTesting(f.bucket);
        const auto rp = f.engine->remote_policy();
        rp->strategy = strategy;
        rp->conflict_policy = sync::model::RemotePolicy::ConflictPolicy::Ask;
        return f;
    }

    static void attach(VFixture& f) {
        f.engine = std::static_pointer_cast<storage::CloudEngine>(runtime::Deps::get().storageManager->getEngine(f.vault->id));
        f.engine->setS3ControllerForTesting(f.bucket);
    }

    static std::shared_ptr<fs::model::File> put(const VFixture& f, const std::string& path, const std::string& content) {
        const auto parent = std::filesystem::path(path).parent_path();
        if (!parent.empty() && parent != "/")
            (void)fs::Filesystem::mkdir({.path = f.engine->vaultPathToFusePath(parent), .engine = f.engine, .user = superUser});
        return fs::Filesystem::createFile({.path = path, .fuse_path = f.engine->vaultPathToFusePath(path),
                                           .buffer = sync_conflicts::bytes(content), .engine = f.engine,
                                           .user = superUser, .overwrite = true});
    }

    // One regular sync pass, inline: the real planner, transfers and index/manifest bookkeeping.
    static std::vector<sync::model::Action> runPass(const VFixture& f) {
        auto cloud = std::make_shared<sync::Cloud>(f.engine);
        cloud->event = std::make_shared<sync::model::Event>();
        cloud->event->vault_id = f.vault->id;
        cloud->event->timestamp_begin = std::time(nullptr);
        db::query::sync::Event::create(cloud->event);
        cloud->initBins();
        const auto plan = cloud->planPass();
        for (const auto& a : plan) {
            using AT = sync::model::ActionType;
            if (a.type == AT::EnsureDirectories) cloud->ensureDirectoriesFromRemote();
            else if (a.type == AT::Upload)
                sync::tasks::Upload(f.engine, a.local, cloud->op(sync::model::Throughput::Metric::UPLOAD))();
            else if (a.type == AT::Download)
                sync::tasks::Download(f.engine, a.remote, cloud->op(sync::model::Throughput::Metric::DOWNLOAD), false)();
            else if (a.type == AT::IndexRemoteOnly)
                sync::tasks::Download(f.engine, a.remote, cloud->op(sync::model::Throughput::Metric::INDEX), true)();
        }
        f.engine->applyRemoteIndexMutation(plan);
        cloud->clearBins();
        return plan;
    }

    static unsigned transfers(const std::vector<sync::model::Action>& plan) {
        unsigned n = 0;
        for (const auto& a : plan)
            if (a.type == sync::model::ActionType::Upload || a.type == sync::model::ActionType::Download ||
                a.type == sync::model::ActionType::DeleteRemote || a.type == sync::model::ActionType::DeleteLocal)
                ++n;
        return n;
    }

    // Drops the local cached content: the row becomes index-only (the remote object's metadata), as a cache eviction
    // or the sync IndexRemoteOnly path leaves it.
    static void evict(const VFixture& f, const std::string& path) {
        const auto indexed = db::query::sync::RemoteObjectIndex::getFile(f.vault->id, path);
        if (!indexed) throw std::runtime_error("no remote index row for " + path);
        (void)f.engine->indexAndDeleteFile(indexed);
    }

    static std::filesystem::path backingOf(const VFixture& f, const std::string& path) {
        const auto row = db::query::fs::File::getFileByPath(f.vault->id, path);
        return row ? row->backing_path : std::filesystem::path{};
    }

    static std::string readVia(const VFixture& f, const std::string& path) {
        const auto file = db::query::fs::File::getFileByPath(f.vault->id, path);
        if (!file) throw std::runtime_error("no file " + path);
        const auto reader = f.engine->openPlaintextReader(file);
        const auto data = storage::readAll(*reader, 1 << 24);
        return {data.begin(), data.end()};
    }

    // The index's versions of one file, newest first.
    static std::vector<VersionRow> history(const VFixture& f, const std::string& path, const bool includeGone = false) {
        return db::query::recovery::ObjectVersion::listForKey(f.vault->id, recovery::provider::versions::objectKeyOf(path),
                                                              includeGone, 1000);
    }

    static std::optional<VersionRow> rowFor(const VFixture& f, const std::string& path, const std::string& versionId) {
        return db::query::recovery::ObjectVersion::find(f.vault->id, recovery::provider::versions::objectKeyOf(path),
                                                        versionId);
    }

    static std::string pv(const VersionRow& r) {
        return recovery::RecoveryId{.type = recovery::RecoveryId::Type::ProviderVersion, .id = static_cast<uint64_t>(r.id)}.str();
    }

    static std::optional<std::string> sourceIdOf(const VFixture& f, const std::string& path) {
        const auto row = db::query::fs::File::getFileByPath(f.vault->id, path);
        if (!row) return std::nullopt;
        return storage::generationOf(*row).sourceId();
    }

    // Plan one version, then restore it against the generation the plan saw.
    static recovery::provider::RestoreOutcome restoreVersion(const VFixture& f, const VersionRow& version,
                                                             const recovery::provider::RestoreOptions& options = restoreOptions()) {
        const auto item = recovery::provider::planFor(f.engine, version);
        return recovery::provider::restore(f.engine, item, item.destination_source_id, options);
    }

    static unsigned manifestVersions(const VFixture& f) {
        return static_cast<unsigned>(f.bucket->history(sync::model::remote_manifest::INDEX_V1_KEY).size());
    }
};

}
