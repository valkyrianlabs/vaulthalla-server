#pragma once

#include <memory>
#include "protocols/ws/Fwd.hpp"

namespace vh::protocols::ws {

class Handler {
  public:
    static void registerAllHandlers(const std::shared_ptr<Router>& r);

  private:
    static void registerAuthHandlers(const std::shared_ptr<Router>& r);
    static void registerMetaHandlers(const std::shared_ptr<Router>& r);
    static void registerFileSystemHandlers(const std::shared_ptr<Router>& r);
    static void registerStorageHandlers(const std::shared_ptr<Router>& r);
    static void registerAPIKeyHandlers(const std::shared_ptr<Router>& r);
    static void registerRoleHandlers(const std::shared_ptr<Router>& r);
    static void registerPermissionsHandlers(const std::shared_ptr<Router>& r);
    static void registerSettingsHandlers(const std::shared_ptr<Router>& r);
    static void registerEmailHandlers(const std::shared_ptr<Router>& r);
    static void registerPricingHandlers(const std::shared_ptr<Router>& r);
    static void registerS3GatewayHandlers(const std::shared_ptr<Router>& r);
    static void registerGroupHandlers(const std::shared_ptr<Router>& r);
    static void registerStatHandlers(const std::shared_ptr<Router>& r);
    static void registerSyncConflictHandlers(const std::shared_ptr<Router>& r);
    static void registerDashboardPreferenceHandlers(const std::shared_ptr<Router>& r);
    static void registerShareManagementHandlers(const std::shared_ptr<Router>& r);
    static void registerShareSessionHandlers(const std::shared_ptr<Router>& r);
    static void registerShareFilesystemHandlers(const std::shared_ptr<Router>& r);
    static void registerShareDownloadHandlers(const std::shared_ptr<Router>& r);
    static void registerSharePreviewHandlers(const std::shared_ptr<Router>& r);
    static void registerShareUploadHandlers(const std::shared_ptr<Router>& r);
};

}
