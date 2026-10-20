#pragma once

#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "fs/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"
#include "share/Fwd.hpp"

namespace vh::protocols::ws::handler::share {

using json = nlohmann::json;

class UploadWriter {
public:
    virtual ~UploadWriter() = default;

    [[nodiscard]] virtual std::shared_ptr<vh::fs::model::File> createFile(
        const vh::share::ResolvedTarget& parent,
        const std::shared_ptr<vh::identities::User>& user,
        const std::string& finalVaultPath,
        const std::vector<uint8_t>& bytes
    ) const = 0;
};

class Upload {
public:
    using ManagerFactory = std::function<std::shared_ptr<vh::share::Manager>()>;
    using ResolverFactory = std::function<std::shared_ptr<vh::share::TargetResolver>()>;
    using WriterFactory = std::function<std::shared_ptr<UploadWriter>()>;

    static json start(const json& payload, const std::shared_ptr<Session>& session);
    static json finish(const json& payload, const std::shared_ptr<Session>& session);
    static json cancel(const json& payload, const std::shared_ptr<Session>& session);
    static json nativeStart(const json& payload, const std::shared_ptr<Session>& session);
    static json nativeFinish(const json& payload, const std::shared_ptr<Session>& session);
    static json nativeCancel(const json& payload, const std::shared_ptr<Session>& session);

    // The file a finished share upload created, as the share sees it (ShareUploadedFile).
    static json uploadedFileJson(const vh::fs::model::File& file, const vh::share::Principal& principal);

    static void setManagerFactoryForTesting(ManagerFactory factory);
    static void resetManagerFactoryForTesting();
    static void setResolverFactoryForTesting(ResolverFactory factory);
    static void resetResolverFactoryForTesting();
    static void setWriterFactoryForTesting(WriterFactory factory);
    static void resetWriterFactoryForTesting();
};

}
