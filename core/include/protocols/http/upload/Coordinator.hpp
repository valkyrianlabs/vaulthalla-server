#pragma once

#include "protocols/http/Router.hpp"
#include "protocols/ws/Fwd.hpp"
#include "share/Fwd.hpp"
#include "storage/Fwd.hpp"

#include <boost/beast/http.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>

namespace vh::protocols::http::upload {

struct ParsedFileTarget {
    std::string upload_id;
    std::string file_id;
};

class Coordinator {
public:
    using SessionResolver = std::function<std::shared_ptr<vh::protocols::ws::Session>(const request&)>;
    using ShareManagerFactory = std::function<std::shared_ptr<vh::share::Manager>()>;
    using ShareResolverFactory = std::function<std::shared_ptr<vh::share::TargetResolver>()>;
    using EngineResolver = std::function<std::shared_ptr<vh::storage::Engine>(uint32_t)>;
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    class FileStream {
    public:
        FileStream();
        FileStream(FileStream&& other) noexcept;
        FileStream& operator=(FileStream&& other) noexcept;
        FileStream(const FileStream&) = delete;
        FileStream& operator=(const FileStream&) = delete;
        ~FileStream();

        void write(const void* data, std::size_t size);
        [[nodiscard]] nlohmann::json finish();
        void fail(std::string reason) noexcept;
        [[nodiscard]] bool valid() const noexcept;

    private:
        friend class Coordinator;
        struct Impl;
        explicit FileStream(std::unique_ptr<Impl> impl);
        std::unique_ptr<Impl> impl_;
    };

    static Coordinator& instance();

    [[nodiscard]] static bool isUploadFileRequest(boost::beast::http::verb method, std::string_view target);
    [[nodiscard]] static ParsedFileTarget parseUploadFileTarget(std::string_view target);

    [[nodiscard]] nlohmann::json createSession(const request& req, const nlohmann::json& payload);
    [[nodiscard]] FileStream beginFile(const request& req, std::optional<uint64_t> contentLength);
    [[nodiscard]] nlohmann::json finishSession(const request& req, std::string_view uploadId);
    [[nodiscard]] nlohmann::json cancelSession(const request& req, std::string_view uploadId);
    void abortAll(std::string reason) noexcept;

    static void setSessionResolverForTesting(SessionResolver resolver);
    static void resetSessionResolverForTesting();
    static void setShareManagerFactoryForTesting(ShareManagerFactory factory);
    static void resetShareManagerFactoryForTesting();
    static void setShareResolverFactoryForTesting(ShareResolverFactory factory);
    static void resetShareResolverFactoryForTesting();
    static void setEngineResolverForTesting(EngineResolver resolver);
    static void resetEngineResolverForTesting();
    // Session expiry (sliding idle TTL + hard ceiling) reads this clock.
    static void setClockForTesting(Clock clock);
    static void resetClockForTesting();
    static void clearForTesting();

private:
    Coordinator() = default;
};

} // namespace vh::protocols::http::upload
