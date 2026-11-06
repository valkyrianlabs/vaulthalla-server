#include "sync/tasks/Download.hpp"
#include "storage/CloudEngine.hpp"
#include "fs/model/File.hpp"
#include "log/Registry.hpp"
#include "log/Redact.hpp"
#include "sync/model/ScopedOp.hpp"
#include "sync/model/Baseline.hpp"
#include "sync/tasks/Baseline.hpp"

using namespace vh::sync::tasks;
using namespace vh::storage;
using namespace vh::fs::model;

Download::Download(std::shared_ptr<CloudEngine> eng,
                           std::shared_ptr<File> f,
                           std::shared_ptr<model::ScopedOp> op,
                           const bool freeAfter)
    : engine(std::move(eng)), file(std::move(f)), op(std::move(op)), freeAfterDownload(freeAfter) {}

void Download::operator()() {
    try {
        if (!op) throw std::runtime_error("DownloadTask: null scoped operation");
        op->start(file->size_bytes);
        std::shared_ptr<File> local;
        if (freeAfterDownload) local = engine->indexAndDeleteFile(file);
        else {
            if (engine->selectedDownloadRequiresRestore(file))
                throw std::runtime_error("S3 object is in an archive tier and requires explicit restore before download");
            local = engine->downloadFile(file);
        }
        op->success = true;
        if (local) recordBaseline(engine, vh::sync::model::Baseline::afterDownload(*local, *file));
    } catch (const std::exception& e) {
        log::Registry::sync()->error("[DownloadTask] Failed to download file: {} - {}", log::file(file->id, file->path), e.what());
    }

    if (op) op->stop();
    promise.set_value(op && op->success);
}
