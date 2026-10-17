#include "sync/tasks/Upload.hpp"
#include "storage/CloudEngine.hpp"
#include "fs/model/File.hpp"
#include "log/Registry.hpp"
#include "recovery/local/Backlog.hpp"
#include "sync/model/ScopedOp.hpp"
#include "sync/model/Baseline.hpp"
#include "sync/tasks/Baseline.hpp"

using namespace vh::sync::tasks;
using namespace vh::storage;
using namespace vh::fs::model;

Upload::Upload(std::shared_ptr<CloudEngine> eng, std::shared_ptr<File> f, std::shared_ptr<model::ScopedOp> op)
    : engine(std::move(eng)), file(std::move(f)), op(std::move(op)) {}

void Upload::operator()() {
    try {
        if (!op) throw std::runtime_error("UploadTask: null scoped operation");
        op->start(file->size_bytes);
        // Local versioning's backlog first: the provider's history keeps the local order (recovery.md). A failed
        // replay holds this upload back; the next pass retries both.
        if (const auto replay = vh::recovery::local::backlog::replayBeforeUpload(*engine, *file); replay.blocked)
            throw std::runtime_error("earlier versions could not be replayed upstream: " + replay.error.value_or("unknown"));
        engine->upload(file);
        op->success = true;
        recordBaseline(engine, vh::sync::model::Baseline::afterUpload(*file));
    } catch (const std::exception& e) {
        log::Registry::sync()->error("[UploadTask] Failed to upload file: {} - {}", file->path.string(), e.what());
    }

    if (op) op->stop();
    promise.set_value(op && op->success);
}
