#pragma once

#include "protocols/ws/Session.hpp"
#include "ops/Error.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "fs/Fwd.hpp"
#include "fs/model/Path.hpp"
#include "share/Fwd.hpp"

#include <filesystem>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string_view>

namespace vh::protocols::ws::handler::fs {

using json = nlohmann::json;

class Storage {
public:
    using ShareManagerFactory = std::function<std::shared_ptr<vh::share::Manager>()>;
    using ShareResolverFactory = std::function<std::shared_ptr<vh::share::TargetResolver>()>;

    static json startUpload(const json& payload, const std::shared_ptr<Session>& session);

    static json finishUpload(const json& payload, const std::shared_ptr<Session>& session);

    static json cancelUpload(const json& payload, const std::shared_ptr<Session>& session);

    static json mkdir(const json& payload, const std::shared_ptr<Session>& session);

    static json move(const json& payload, const std::shared_ptr<Session>& session);

    static json rename(const json& payload, const std::shared_ptr<Session>& session);

    static json copy(const json& payload, const std::shared_ptr<Session>& session);

    static json metadata(const json& payload, const std::shared_ptr<Session>& session);

    static json list(const json& payload, const std::shared_ptr<Session>& session);

    static json listDir(const json& payload, const std::shared_ptr<Session>& session);

    static json remove(const json& payload, const std::shared_ptr<Session>& session);

    // A share session's view of an entry (share-relative path, no ownership or backing details): the ShareEntry the
    // share-mode fs.* and share.fs.* commands return.
    static json shareEntryJson(const vh::fs::model::Entry& entry, const vh::share::Principal& principal);

    static json shareCompatibilityMetadata(const json& payload, const std::shared_ptr<Session>& session);

    static json shareCompatibilityList(const json& payload, const std::shared_ptr<Session>& session);

    static void setShareManagerFactoryForTesting(ShareManagerFactory factory);
    static void resetShareManagerFactoryForTesting();
    static void setShareResolverFactoryForTesting(ShareResolverFactory factory);
    static void resetShareResolverFactoryForTesting();

private:
    template<typename EnumT>
    static void enforcePermission(const std::shared_ptr<Session>& session,
                                  const std::shared_ptr<storage::Engine>& engine,
                                  const std::filesystem::path& path,
                                  const EnumT permission,
                                  const std::string_view error = "Permission denied") {
        if (!session || !session->user)
            throw std::runtime_error("Unauthorized");

        if (!engine || !engine->vault)
            throw std::runtime_error("Internal server error: Storage engine not available");

        if (!vh::rbac::resolver::Vault::has<EnumT>({
            .user = session->user,
            .permission = permission,
            .vault_id = engine->vault->id,
            .path = engine->vaultPathToFusePath(path)
        })) throw vh::ops::Denied(std::string(error));
    }

    template<typename EnumT, typename... EnumTs>
    static void enforceAnyPermission(const std::shared_ptr<Session>& session,
                                     const std::shared_ptr<storage::Engine>& engine,
                                     const std::filesystem::path& path,
                                     const EnumT permission,
                                     const EnumTs... permissions) {
        if (!session || !session->user)
            throw std::runtime_error("Unauthorized");

        if (!vh::rbac::resolver::Vault::hasAny(
            vh::rbac::resolver::vault::Context<EnumT>{
                .user = session->user,
                .permission = permission,
                .vault_id = engine->vault->id,
                .path = path
            },
            vh::rbac::resolver::vault::Context<EnumTs>{
                .user = session->user,
                .permission = permissions,
                .vault_id = engine->vault->id,
                .path = path
            }...
        )) throw vh::ops::Denied("Permission denied: Required permission not granted");
    }
};

}
