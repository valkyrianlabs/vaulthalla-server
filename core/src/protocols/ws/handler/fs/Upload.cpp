#include "protocols/ws/handler/fs/Upload.hpp"
#include "protocols/ws/Session.hpp"
#include "fs/model/File.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "fs/Filesystem.hpp"
#include "ops/Error.hpp"

#include <filesystem>
#include <stdexcept>
#include <system_error>

using namespace vh::storage;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::fs;

namespace vh::protocols::ws::handler::fs {

    Upload::Upload(const std::shared_ptr<Session>& session) : session_(session) {}

    void Upload::startUpload(const UploadArgs& args) {
        log::Registry::ws()->debug("[UploadHandler] Starting upload (uploadId: {}, tmpPath: {}, finalPath: {}, "
                                "fuseFrom: {}, fuseTo: {}, expectedSize: {})",
                                 args.uploadId, args.tmpPath.string(), args.finalPath.string(),
                                 args.fuseFrom.string(), args.fuseTo.string(), args.expectedSize);

        auto session = session_.lock();
        if (uploadInProgress()) throw vh::ops::Conflict("Upload already in progress");
        if (!session || !session->user) throw std::runtime_error("Authenticated user upload requires a human session");

        if (std::filesystem::is_directory(args.finalPath))
            throw vh::ops::Invalid("Upload final path is a directory — filename must be provided");

        if (const auto err = Filesystem::mkdir({
                .path = args.fuseFrom.parent_path(),
                .engine = args.engine,
                .user = session->user
            }); err)
            throw std::runtime_error(std::string("Failed to create directory ") + args.fuseFrom.parent_path().string());

        currentUpload_.emplace(args);
    }

    void Upload::startShareUpload(const ShareUploadArgs& args) {
        log::Registry::ws()->debug("[UploadHandler] Starting share upload (uploadId: {}, shareSessionId: {}, expectedSize: {})",
                                  args.uploadId, args.shareSessionId, args.expectedSize);

        if (uploadInProgress()) throw vh::ops::Conflict("Upload already in progress");
        if (args.uploadId.empty()) throw std::invalid_argument("Share upload id is required");
        if (args.shareId.empty()) throw std::invalid_argument("Share upload share id is required");
        if (args.shareSessionId.empty()) throw std::invalid_argument("Share upload session id is required");
        if (args.websocketSessionUuid.empty()) throw std::invalid_argument("Share upload websocket session id is required");
        auto session = session_.lock();
        if (!session || session->uuid != args.websocketSessionUuid)
            throw vh::ops::Denied("Share upload websocket session mismatch");
        if (!args.onChunk || !args.onFinish || !args.onCancel || !args.onFail)
            throw std::invalid_argument("Share upload callbacks are required");

        currentShareUpload_.emplace(args);
    }

    void Upload::handleBinaryFrame(beast::flat_buffer& buffer) {
        if (currentShareUpload_) {
            auto& upload = *currentShareUpload_;
            const auto size = static_cast<uint64_t>(buffer.size());
            try {
                auto session = session_.lock();
                if (!session || upload.websocketSessionUuid != session->uuid)
                    throw std::runtime_error("Share upload does not belong to this websocket session");
                if (upload.shareSessionId != session->shareSessionId())
                    throw std::runtime_error("Share upload does not belong to this share session");
                if (size == 0) throw std::runtime_error("Empty upload chunk");
                if (size > upload.maxChunkSize) throw std::runtime_error("Upload chunk exceeds maximum size");
                if (upload.bytesReceived > upload.expectedSize ||
                    size > upload.expectedSize - upload.bytesReceived)
                    throw std::runtime_error("Upload chunk exceeds expected size");

                const auto data = static_cast<const uint8_t*>(buffer.data().data());
                upload.buffer.insert(upload.buffer.end(), data, data + static_cast<std::ptrdiff_t>(size));
                upload.onChunk(size);
                upload.bytesReceived += size;
                buffer.consume(size);
                return;
            } catch (const std::exception& e) {
                abortShareUpload(e.what());
                throw;
            }
        }

        if (!currentUpload_) throw vh::ops::Conflict("No upload in progress");

        auto& upload = *currentUpload_;
        const auto data = static_cast<const char*>(buffer.data().data());
        const auto size = static_cast<uint64_t>(buffer.size());

        if (size == 0) throw std::runtime_error("Empty upload chunk");
        if (upload.bytesReceived > upload.expectedSize ||
            size > upload.expectedSize - upload.bytesReceived) {
            abortHumanUpload("upload_chunk_exceeds_expected_size");
            throw std::runtime_error("Upload chunk exceeds expected size");
        }

        try {
            upload.file.write(data, static_cast<long>(size));
            if (!upload.file) throw std::runtime_error("Write error during upload");

            upload.bytesReceived += size;
            buffer.consume(size);
        } catch (...) {
            abortHumanUpload("upload_write_failed");
            throw;
        }
    }

    void Upload::abortActiveUpload(const std::string& reason) noexcept {
        if (currentShareUpload_) abortShareUpload(reason);
        if (currentUpload_) abortHumanUpload(reason);
    }

    void Upload::abortHumanUpload(const std::string& reason) noexcept {
        if (!currentUpload_) return;

        auto upload = std::move(*currentUpload_);
        currentUpload_.reset();

        try {
            if (upload.file.is_open()) upload.file.close();
        } catch (...) {
            log::Registry::ws()->debug("[UploadHandler] Failed to close aborted upload file (uploadId: {}, reason: {})",
                                      upload.uploadId, reason);
        }

        if (!upload.tmpPath.empty()) {
            std::error_code ec;
            std::filesystem::remove(upload.tmpPath, ec);
            if (ec) {
                log::Registry::ws()->debug("[UploadHandler] Failed to remove aborted upload temp file (uploadId: {}, tmpPath: {}, reason: {}, error: {})",
                                          upload.uploadId, upload.tmpPath.string(), reason, ec.message());
            }
        }

        log::Registry::ws()->debug("[UploadHandler] Aborted upload (uploadId: {}, reason: {})",
                                  upload.uploadId, reason);
    }

    void Upload::abortShareUpload(const std::string& reason) noexcept {
        if (!currentShareUpload_) return;

        auto upload = std::move(*currentShareUpload_);
        currentShareUpload_.reset();

        try {
            if (upload.onFail) upload.onFail(reason);
        } catch (const std::exception& e) {
            log::Registry::ws()->debug("[UploadHandler] Share upload fail callback failed (uploadId: {}, reason: {}, error: {})",
                                      upload.uploadId, reason, e.what());
        } catch (...) {
            log::Registry::ws()->debug("[UploadHandler] Share upload fail callback failed with unknown error (uploadId: {}, reason: {})",
                                      upload.uploadId, reason);
        }

        log::Registry::ws()->debug("[UploadHandler] Aborted share upload (uploadId: {}, shareSessionId: {}, reason: {})",
                                  upload.uploadId, upload.shareSessionId, reason);
    }

    void Upload::finishUpload() {
        if (!currentUpload_) throw vh::ops::Conflict("No upload in progress");

        auto& upload = *currentUpload_;
        upload.file.close();

        if (upload.bytesReceived != upload.expectedSize) {
            abortHumanUpload("upload_size_mismatch");
            throw vh::ops::Invalid("Upload size mismatch");
        }

        auto session = session_.lock();
        if (!session || !session->user) throw std::runtime_error("Authenticated user upload requires a human session");

        log::Registry::ws()->debug("[UploadHandler] Finishing upload (uploadId: {}, fuseFrom: {}, fuseTo: {}, userId: {})",
                                 upload.uploadId, upload.fuseFrom.string(), upload.fuseTo.string(), session->user->id);

        if (const auto err = Filesystem::rename(upload.fuseFrom, upload.fuseTo, session->user, upload.engine); err) {
            abortHumanUpload("upload_finish_failed");
            throw std::runtime_error(std::string("Failed to move uploaded file to final location: ") + std::strerror(err));
        }

        currentUpload_.reset();
    }

    std::shared_ptr<vh::fs::model::File> Upload::finishShareUpload(
        const std::string& uploadId,
        const std::string& shareSessionId
    ) {
        if (!currentShareUpload_) throw vh::ops::Conflict("No share upload in progress");

        auto& upload = *currentShareUpload_;
        if (upload.uploadId != uploadId) throw vh::ops::NotFound("Share upload id mismatch");
        if (upload.shareSessionId != shareSessionId) throw vh::ops::Denied("Share upload session mismatch");
        if (upload.bytesReceived != upload.expectedSize) throw vh::ops::Invalid("Upload size mismatch");

        auto onFinish = upload.onFinish;
        auto buffer = std::move(upload.buffer);
        currentShareUpload_.reset();
        return onFinish(buffer);
    }

    void Upload::cancelShareUpload(const std::string& uploadId, const std::string& shareSessionId) {
        if (!currentShareUpload_) throw vh::ops::Conflict("No share upload in progress");

        auto& upload = *currentShareUpload_;
        if (upload.uploadId != uploadId) throw vh::ops::NotFound("Share upload id mismatch");
        if (upload.shareSessionId != shareSessionId) throw vh::ops::Denied("Share upload session mismatch");

        auto onCancel = upload.onCancel;
        currentShareUpload_.reset();
        if (onCancel) onCancel();
    }

    std::optional<std::string> Upload::activeShareUploadId() const {
        if (!currentShareUpload_) return std::nullopt;
        return currentShareUpload_->uploadId;
    }

}
