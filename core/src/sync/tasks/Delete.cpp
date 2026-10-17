#include "sync/tasks/Delete.hpp"

#include "log/Registry.hpp"
#include "recovery/local/Backlog.hpp"
#include "storage/CloudEngine.hpp"
#include "fs/model/File.hpp"
#include "fs/model/file/Trashed.hpp"
#include "sync/model/ScopedOp.hpp"

#include <stdexcept>
#include <utility>

using namespace vh::sync::tasks;
using namespace vh::storage;
using namespace vh::fs::model;

Delete::Delete(std::shared_ptr<Engine> eng,
                       Target tgt,
                       std::shared_ptr<model::ScopedOp> op,
                       Type type)
    : engine(std::move(eng)),
      target(std::move(tgt)),
      op(std::move(op)),
      type(type) {}

namespace {

template <class... Ts>
struct Overloaded : Ts... { using Ts::operator()...; };
template <class... Ts>
Overloaded(Ts...) -> Overloaded<Ts...>;

} // namespace

void Delete::operator()() {
    auto getSizeBytes = [&](const Target& t) -> uint64_t {
        return std::visit(Overloaded{
            [](const std::shared_ptr<File>& f) -> uint64_t {
                return f ? f->size_bytes : 0;
            },
            [](const std::shared_ptr<file::Trashed>& f) -> uint64_t {
                return f ? f->size_bytes : 0;
            }
        }, t);
    };

    auto getPathString = [&](const Target& t) -> std::string {
        return std::visit(Overloaded{
            [](const std::shared_ptr<File>& f) -> std::string {
                return f ? f->path.string() : std::string{"<null file>"};
            },
            [](const std::shared_ptr<file::Trashed>& f) -> std::string {
                return f ? f->path.string() : std::string{"<null trashed file>"};
            }
        }, t);
    };

    try {
        if (!op)
            throw std::runtime_error("DeleteTask: null scoped operation");
        op->start(getSizeBytes(target));

        if (!engine)
            throw std::runtime_error("DeleteTask: null storage engine");

        // Local engine path: just remove locally regardless of File vs TrashedFile.
        if (engine->type() == StorageType::Local) {
            std::visit(Overloaded{
                [&](const std::shared_ptr<File>& f) {
                    if (!f) throw std::runtime_error("DeleteTask: null File");
                    engine->removeLocally(f->path);
                },
                [&](const std::shared_ptr<file::Trashed>& f) {
                    if (!f) throw std::runtime_error("DeleteTask: null TrashedFile");
                    engine->removeLocally(f);
                }
            }, target);
        }
        // Cloud engine path: needs CloudStorageEngine, and the API differs slightly.
        else if (engine->type() == StorageType::Cloud) {
            auto cloud = std::static_pointer_cast<CloudEngine>(engine);
            if (!cloud)
                throw std::runtime_error("DeleteTask: failed to cast to CloudStorageEngine");

            // Local versioning's backlog for the key goes upstream before the delete marker does (recovery.md).
            const auto replayBeforeRemoteDelete = [&](const std::filesystem::path& path) {
                if (type != Type::PURGE && type != Type::REMOTE) return;
                if (const auto replay = vh::recovery::local::backlog::replayBeforeRemoteDelete(*cloud, path); replay.blocked)
                    throw std::runtime_error("earlier versions could not be replayed upstream: " +
                                             replay.error.value_or("unknown"));
            };

            std::visit(Overloaded{
                [&](const std::shared_ptr<File>& f) {
                    if (!f) throw std::runtime_error("DeleteTask: null File");
                    replayBeforeRemoteDelete(f->path);

                    if (type == Type::PURGE)      cloud->purge(f->path);
                    else if (type == Type::LOCAL) cloud->removeLocally(f->path);
                    else if (type == Type::REMOTE) cloud->removeRemotely(f->path);
                    else throw std::runtime_error("DeleteTask: unknown delete type");
                },
                [&](const std::shared_ptr<file::Trashed>& f) {
                    if (!f) throw std::runtime_error("DeleteTask: null TrashedFile");
                    replayBeforeRemoteDelete(f->path);

                    // Mirrors your existing DeleteTask behavior for trashed files.
                    if (type == Type::PURGE)      cloud->purge(f);
                    else if (type == Type::LOCAL) cloud->removeLocally(f);
                    else if (type == Type::REMOTE) cloud->removeRemotely(f);
                    else throw std::runtime_error("DeleteTask: unknown delete type");
                }
            }, target);
        }
        else throw std::runtime_error("DeleteTask: unsupported storage engine type");

        op->success = true;
    } catch (const std::exception& e) {
        log::Registry::sync()->error(
            "[DeleteTask] Failed to delete file: {} - {}",
            getPathString(target),
            e.what()
        );
    }

    if (op) op->stop();
    promise.set_value(op && op->success);
}
