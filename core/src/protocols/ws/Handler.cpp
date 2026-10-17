#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/handler/Auth.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "protocols/ws/handler/rbac/Permissions.hpp"
#include "protocols/ws/handler/Settings.hpp"
#include "protocols/ws/handler/Email.hpp"
#include "protocols/ws/handler/Pricing.hpp"
#include "protocols/ws/handler/S3Gateway.hpp"
#include "protocols/ws/handler/Groups.hpp"
#include "protocols/ws/handler/Meta.hpp"
#include "protocols/ws/handler/Stats.hpp"
#include "protocols/ws/handler/SyncConflicts.hpp"
#include "protocols/ws/handler/dashboard/Preferences.hpp"
#include "protocols/ws/handler/rbac/roles/Admin.hpp"
#include "protocols/ws/handler/rbac/roles/Vault.hpp"
#include "protocols/ws/handler/vault/Vaults.hpp"
#include "protocols/ws/handler/vault/APIKeys.hpp"
#include "protocols/ws/handler/Upstream.hpp"
#include "protocols/ws/handler/Recovery.hpp"
#include "protocols/ws/handler/share/Download.hpp"
#include "protocols/ws/handler/share/Filesystem.hpp"
#include "protocols/ws/handler/share/Links.hpp"
#include "protocols/ws/handler/share/Preview.hpp"
#include "protocols/ws/handler/share/Sessions.hpp"
#include "protocols/ws/handler/share/Upload.hpp"
#include "log/Registry.hpp"

using namespace vh::protocols::ws;

void Handler::registerAllHandlers(const std::shared_ptr<Router>& r) {
    registerAuthHandlers(r);
    registerMetaHandlers(r);
    registerFileSystemHandlers(r);
    registerStorageHandlers(r);
    registerAPIKeyHandlers(r);
    registerUpstreamHandlers(r);
    registerRecoveryHandlers(r);
    registerRoleHandlers(r);
    registerPermissionsHandlers(r);
    registerSettingsHandlers(r);
    registerEmailHandlers(r);
    registerPricingHandlers(r);
    registerS3GatewayHandlers(r);
    registerGroupHandlers(r);
    registerStatHandlers(r);
    registerSyncConflictHandlers(r);
    registerDashboardPreferenceHandlers(r);
    registerShareManagementHandlers(r);
    registerShareSessionHandlers(r);
    registerShareFilesystemHandlers(r);
    registerShareDownloadHandlers(r);
    registerSharePreviewHandlers(r);
    registerShareUploadHandlers(r);

    log::Registry::ws()->debug("[WebSocketHandler] All handlers registered successfully.");
}

void Handler::registerAuthHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("auth.login", &handler::Auth::login);
    r->registerPayload("auth.register", &handler::Auth::registerUser);
    r->registerPayload("auth.user.delete", &handler::Auth::deleteUser);
    r->registerSessionOnlyHandler("auth.logout", &handler::Auth::logout);
    r->registerPayload("auth.user.update", &handler::Auth::updateUser);
    r->registerPayload("auth.user.change_password", &handler::Auth::changePassword);
    r->registerHandlerWithToken("auth.isAuthenticated", &handler::Auth::isUserAuthenticated);
    r->registerPayload("auth.user.get", &handler::Auth::getUser);
    r->registerPayload("auth.user.get.byName", &handler::Auth::getUserByName);
    r->registerSessionOnlyHandler("auth.users.list", &handler::Auth::listUsers);
    r->registerSessionOnlyHandler("auth.security.status", &handler::Auth::securityStatus);
    r->registerHandlerWithToken("auth.refresh", &handler::Auth::refreshToken);
}

void Handler::registerMetaHandlers(const std::shared_ptr<Router>& r) {
    r->registerEmptyHandler("meta.contract.get", &handler::Meta::contract);
}

void Handler::registerFileSystemHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("fs.upload.start", &handler::fs::Storage::startUpload);
    r->registerPayload("fs.upload.finish", &handler::fs::Storage::finishUpload);
    r->registerPayload("fs.upload.cancel", &handler::fs::Storage::cancelUpload);
    r->registerPayload("fs.download.start", &handler::share::Download::nativeStart);
    r->registerPayload("fs.download.chunk", &handler::share::Download::nativeChunk);
    r->registerPayload("fs.download.cancel", &handler::share::Download::nativeCancel);
    r->registerPayload("fs.dir.create", &handler::fs::Storage::mkdir);
    r->registerPayload("fs.dir.list", &handler::fs::Storage::listDir);
    r->registerPayload("fs.metadata", &handler::fs::Storage::metadata);
    r->registerPayload("fs.list", &handler::fs::Storage::list);
    r->registerPayload("fs.entry.delete", &handler::fs::Storage::remove);
    r->registerPayload("fs.entry.move", &handler::fs::Storage::move);
    r->registerPayload("fs.entry.rename", &handler::fs::Storage::rename);
    r->registerPayload("fs.entry.copy", &handler::fs::Storage::copy);
}

void Handler::registerStorageHandlers(const std::shared_ptr<Router>& r) {
    r->registerSessionOnlyHandler("storage.vault.list", &handler::Vaults::list);
    r->registerPayload("storage.vault.add", &handler::Vaults::add);
    r->registerPayload("storage.vault.update", &handler::Vaults::update);
    r->registerPayload("storage.vault.remove", &handler::Vaults::remove);
    r->registerPayload("storage.vault.remove.plan", &handler::Vaults::removalPlan);
    r->registerSessionOnlyHandler("storage.vault.deleted.list", &handler::Vaults::listDeleted);
    r->registerPayload("storage.vault.restore", &handler::Vaults::restore);
    r->registerPayload("storage.vault.get", &handler::Vaults::get);
    r->registerPayload("storage.vault.sync", &handler::Vaults::sync);
}

void Handler::registerAPIKeyHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("storage.apiKey.add", &handler::APIKeys::add);
    r->registerPayload("storage.apiKey.update", &handler::APIKeys::update);
    r->registerPayload("storage.apiKey.remove", &handler::APIKeys::remove);
    r->registerSessionOnlyHandler("storage.apiKey.list", &handler::APIKeys::list);
    r->registerPayload("storage.apiKey.get", &handler::APIKeys::get);
}

// File recovery (ops::recovery): recovery points, restore plans, snapshots, costs and the vault policy.
void Handler::registerRecoveryHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("recovery.list", &handler::Recovery::list);
    r->registerPayload("recovery.inspect", &handler::Recovery::inspect);
    r->registerPayload("recovery.plan", &handler::Recovery::plan);
    r->registerPayload("recovery.plan.get", &handler::Recovery::planGet);
    r->registerPayload("recovery.restore", &handler::Recovery::restore);
    r->registerPayload("recovery.snapshot.create", &handler::Recovery::snapshotCreate);
    r->registerPayload("recovery.point.delete", &handler::Recovery::pointDelete);
    r->registerPayload("recovery.costs", &handler::Recovery::costs);
    r->registerPayload("vault.recovery.status", &handler::Recovery::vaultStatus);
    r->registerPayload("vault.recovery.update", &handler::Recovery::vaultUpdate);
    r->registerPayload("vault.recovery.disclosure", &handler::Recovery::vaultDisclosure);
    r->registerPayload("vault.recovery.suspend", &handler::Recovery::vaultSuspend);
}

void Handler::registerUpstreamHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("upstream.admin.enable", &handler::Upstream::adminEnable);
    r->registerPayload("upstream.admin.disable", &handler::Upstream::adminDisable);
    r->registerPayload("upstream.admin.status", &handler::Upstream::adminStatus);
    r->registerPayload("upstream.bucket.list", &handler::Upstream::bucketList);
    r->registerPayload("upstream.bucket.protect", &handler::Upstream::bucketProtect);
    r->registerPayload("upstream.bucket.unprotect", &handler::Upstream::bucketUnprotect);
    r->registerPayload("upstream.bucket.inspect", &handler::Upstream::bucketInspect);
    r->registerPayload("upstream.bucket.lifecycle.set", &handler::Upstream::bucketLifecycleSet);
    r->registerPayload("upstream.bucket.adopt.preflight", &handler::Upstream::bucketAdoptPreflight);
    r->registerPayload("upstream.bucket.detach", &handler::Upstream::bucketDetach);
    r->registerPayload("upstream.bucket.cleanup.preflight", &handler::Upstream::bucketCleanupPreflight);
    r->registerPayload("upstream.bucket.cleanup", &handler::Upstream::bucketCleanup);
    r->registerPayload("upstream.events.enable", &handler::Upstream::eventsEnable);
    r->registerPayload("upstream.events.disable", &handler::Upstream::eventsDisable);
    r->registerPayload("upstream.events.repair", &handler::Upstream::eventsRepair);
    r->registerPayload("upstream.events.status", &handler::Upstream::eventsStatus);
    r->registerPayload("upstream.audit.list", &handler::Upstream::auditList);
}

void Handler::registerRoleHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("role.admin.add", &handler::rbac::roles::Admin::add);
    r->registerPayload("role.admin.update", &handler::rbac::roles::Admin::update);
    r->registerPayload("role.admin.delete", &handler::rbac::roles::Admin::remove);
    r->registerPayload("role.admin.get", &handler::rbac::roles::Admin::get);
    r->registerPayload("role.admin.get.byName", &handler::rbac::roles::Admin::getByName);
    r->registerSessionOnlyHandler("roles.admin.list", &handler::rbac::roles::Admin::list);

    r->registerPayload("role.vault.add", &handler::rbac::roles::Vault::add);
    r->registerPayload("role.vault.update", &handler::rbac::roles::Vault::update);
    r->registerPayload("role.vault.delete", &handler::rbac::roles::Vault::remove);
    r->registerPayload("role.vault.get", &handler::rbac::roles::Vault::get);
    r->registerPayload("role.vault.get.byName", &handler::rbac::roles::Vault::getByName);
    r->registerSessionOnlyHandler("roles.vault.list", &handler::rbac::roles::Vault::list);
    r->registerPayload("roles.vault.list.assigned", &handler::rbac::roles::Vault::listAssigned);

    r->registerPayload("role.vault.assign", &handler::rbac::roles::Vault::assign);
    r->registerPayload("role.vault.unassign", &handler::rbac::roles::Vault::unassign);
    r->registerPayload("role.vault.overrides.list", &handler::rbac::roles::Vault::listOverrides);
    r->registerPayload("role.vault.overrides.add", &handler::rbac::roles::Vault::addOverrides);
    r->registerPayload("role.vault.overrides.update", &handler::rbac::roles::Vault::updateOverride);
    r->registerPayload("role.vault.overrides.remove", &handler::rbac::roles::Vault::removeOverride);
}

void Handler::registerPermissionsHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayloadOnly("permission.get", &handler::rbac::Permissions::get);
    r->registerPayloadOnly("permission.get.byName", &handler::rbac::Permissions::getByName);
    r->registerEmptyHandler("permissions.list", &handler::rbac::Permissions::list);
}

void Handler::registerSettingsHandlers(const std::shared_ptr<Router>& r) {
    r->registerSessionOnlyHandler("settings.get", &handler::Settings::get);
    r->registerSessionOnlyHandler("settings.policy.get", &handler::Settings::policy);
    r->registerPayload("settings.update", &handler::Settings::update);
}

void Handler::registerEmailHandlers(const std::shared_ptr<Router>& r) {
    r->registerSessionOnlyHandler("email.config.get", &handler::Email::config);
    r->registerPayload("email.config.update", &handler::Email::updateConfig);
    r->registerPayload("email.provider.secret.set", &handler::Email::setProviderSecret);
    r->registerPayload("email.test.send", &handler::Email::testSend);
    r->registerPayload("email.history", &handler::Email::history);
}

void Handler::registerPricingHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("pricing.budget.policy.list", &handler::Pricing::policyList);
    r->registerPayload("pricing.budget.policy.upsert", &handler::Pricing::policyUpsert);
    r->registerPayload("pricing.budget.policy.disable", &handler::Pricing::policyDisable);
    r->registerPayload("pricing.budget.ledger.list", &handler::Pricing::ledgerList);
    r->registerPayload("pricing.budget.status", &handler::Pricing::status);
    r->registerPayload("pricing.budget.preflight", &handler::Pricing::preflight);
    r->registerPayload("pricing.budget.override.request", &handler::Pricing::overrideRequest);
    r->registerPayload("pricing.budget.override.approve", &handler::Pricing::overrideApprove);
    r->registerPayload("pricing.budget.override.deny", &handler::Pricing::overrideDeny);
    r->registerPayload("pricing.budget.override.list", &handler::Pricing::overrideList);
    r->registerPayload("pricing.notifications.list", &handler::Pricing::notificationsList);
    r->registerPayload("pricing.notifications.ack", &handler::Pricing::notificationsAck);
}

void Handler::registerS3GatewayHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("s3.gateway.status", &handler::S3Gateway::status);
    r->registerPayload("s3.gateway.credentials.create", &handler::S3Gateway::credentialsCreate);
    r->registerPayload("s3.gateway.credentials.list", &handler::S3Gateway::credentialsList);
    r->registerPayload("s3.gateway.credentials.revoke", &handler::S3Gateway::credentialsRevoke);
    r->registerPayload("s3.gateway.credentials.scope.update", &handler::S3Gateway::credentialsScopeUpdate);
    r->registerPayload("s3.gateway.credentials.defaultRole.get", &handler::S3Gateway::credentialsDefaultRoleGet);
    r->registerPayload("s3.gateway.credentials.defaultRole.set", &handler::S3Gateway::credentialsDefaultRoleSet);
    r->registerPayload("s3.gateway.credentials.defaultRole.clear", &handler::S3Gateway::credentialsDefaultRoleClear);
    r->registerPayload("s3.gateway.credentials.selectedVaults.list", &handler::S3Gateway::credentialsSelectedVaultsList);
    r->registerPayload("s3.gateway.credentials.selectedVaults.replace", &handler::S3Gateway::credentialsSelectedVaultsReplace);
    r->registerPayload("s3.gateway.credentials.selectedVaults.add", &handler::S3Gateway::credentialsSelectedVaultsAdd);
    r->registerPayload("s3.gateway.credentials.selectedVaults.remove", &handler::S3Gateway::credentialsSelectedVaultsRemove);
    r->registerPayload("s3.gateway.credentials.defaultRole.overrides.list", &handler::S3Gateway::credentialsDefaultRoleOverridesList);
    r->registerPayload("s3.gateway.credentials.defaultRole.overrides.add", &handler::S3Gateway::credentialsDefaultRoleOverridesAdd);
    r->registerPayload("s3.gateway.credentials.defaultRole.overrides.remove", &handler::S3Gateway::credentialsDefaultRoleOverridesRemove);
    r->registerPayload("s3.gateway.credentials.roles.list", &handler::S3Gateway::credentialsRolesList);
    r->registerPayload("s3.gateway.credentials.roles.assign", &handler::S3Gateway::credentialsRolesAssign);
    r->registerPayload("s3.gateway.credentials.roles.revoke", &handler::S3Gateway::credentialsRolesRevoke);
    r->registerPayload("s3.gateway.credentials.roles.overrides.list", &handler::S3Gateway::credentialsRoleOverridesList);
    r->registerPayload("s3.gateway.credentials.roles.overrides.add", &handler::S3Gateway::credentialsRoleOverridesAdd);
    r->registerPayload("s3.gateway.credentials.roles.overrides.remove", &handler::S3Gateway::credentialsRoleOverridesRemove);
    r->registerPayload("s3.gateway.buckets.list", &handler::S3Gateway::bucketsList);
    r->registerPayload("s3.gateway.buckets.bind", &handler::S3Gateway::bucketsBind);
    r->registerPayload("s3.gateway.buckets.unbind", &handler::S3Gateway::bucketsUnbind);
    r->registerPayload("s3.gateway.buckets.createLocal", &handler::S3Gateway::bucketsCreateLocal);
    r->registerPayload("s3.gateway.buckets.createRemoteCache", &handler::S3Gateway::bucketsCreateRemoteCache);
    r->registerPayload("s3.gateway.budget.policy.list", &handler::S3Gateway::budgetPolicyList);
    r->registerPayload("s3.gateway.budget.policy.upsert", &handler::S3Gateway::budgetPolicyUpsert);
    r->registerPayload("s3.gateway.budget.policy.disable", &handler::S3Gateway::budgetPolicyDisable);
    r->registerPayload("s3.gateway.budget.ledger.list", &handler::S3Gateway::budgetLedgerList);
    r->registerPayload("s3.gateway.budget.status", &handler::S3Gateway::budgetStatus);
}

void Handler::registerGroupHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("group.add", &handler::Groups::add);
    r->registerPayload("group.update", &handler::Groups::update);
    r->registerPayload("group.remove", &handler::Groups::remove);
    r->registerPayload("group.member.add", &handler::Groups::addMember);
    r->registerPayload("group.member.remove", &handler::Groups::removeMember);
    r->registerPayload("group.get", &handler::Groups::get);
    r->registerPayload("group.get.byName", &handler::Groups::getByName);
    r->registerPayload("groups.list.byUser", &handler::Groups::listByUser);
    r->registerSessionOnlyHandler("groups.list", &handler::Groups::list);
}

void Handler::registerSyncConflictHandlers(const std::shared_ptr<Router>& r) {
    r->registerSessionOnlyHandler("sync.conflicts.summary", &handler::SyncConflicts::summary);
    r->registerPayload("sync.conflicts.list", &handler::SyncConflicts::list);
    r->registerPayload("sync.conflicts.resolve", &handler::SyncConflicts::resolve);
}

void Handler::registerStatHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("stats.vault", &handler::Stats::vault);
    r->registerPayload("stats.vault.sync", &handler::Stats::vaultSync);
    r->registerPayload("stats.vault.activity", &handler::Stats::vaultActivity);
    r->registerPayload("stats.vault.shares", &handler::Stats::vaultShares);
    r->registerPayload("stats.vault.recovery", &handler::Stats::vaultRecovery);
    r->registerPayload("stats.vault.operations", &handler::Stats::vaultOperations);
    r->registerPayload("stats.vault.storage", &handler::Stats::vaultStorage);
    r->registerPayload("stats.vault.retention", &handler::Stats::vaultRetention);
    r->registerPayload("stats.vault.trends", &handler::Stats::vaultTrends);
    r->registerPayload("stats.vault.security", &handler::Stats::vaultSecurity);
    r->registerPayload("stats.dashboard.overview", &handler::Stats::dashboardOverview);
    r->registerSessionOnlyHandler("stats.dashboard.severity", &handler::Stats::dashboardSeverity);
    r->registerSessionOnlyHandler("stats.system.health", &handler::Stats::systemHealth);
    r->registerSessionOnlyHandler("stats.system.threadpools", &handler::Stats::systemThreadPools);
    r->registerSessionOnlyHandler("stats.system.fuse", &handler::Stats::systemFuse);
    r->registerSessionOnlyHandler("stats.system.db", &handler::Stats::systemDb);
    r->registerSessionOnlyHandler("stats.system.operations", &handler::Stats::systemOperations);
    r->registerSessionOnlyHandler("stats.system.connections", &handler::Stats::systemConnections);
    r->registerSessionOnlyHandler("stats.system.storage", &handler::Stats::systemStorage);
    r->registerSessionOnlyHandler("stats.system.retention", &handler::Stats::systemRetention);
    r->registerPayload("stats.system.trends", &handler::Stats::systemTrends);
    r->registerPayload("stats.pricing.budget", &handler::Stats::pricingBudget);
    r->registerPayload("stats.vault.pricing", &handler::Stats::vaultPricing);
    r->registerSessionOnlyHandler("stats.system.pricing", &handler::Stats::systemPricing);
    r->registerSessionOnlyHandler("stats.fs.cache", &handler::Stats::fsCache);
    r->registerSessionOnlyHandler("stats.http.cache", &handler::Stats::httpCache);
}

void Handler::registerDashboardPreferenceHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("dashboard.preferences.get", &handler::dashboard::Preferences::get);
    r->registerPayload("dashboard.preferences.update", &handler::dashboard::Preferences::update);
    r->registerPayload("dashboard.preferences.reset", &handler::dashboard::Preferences::reset);
}

void Handler::registerShareManagementHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("share.link.create", &handler::share::Links::create);
    r->registerPayload("share.link.get", &handler::share::Links::get);
    r->registerPayload("share.link.list", &handler::share::Links::list);
    r->registerPayload("share.link.update", &handler::share::Links::update);
    r->registerPayload("share.link.revoke", &handler::share::Links::revoke);
    r->registerPayload("share.link.rotate_token", &handler::share::Links::rotateToken);
}

void Handler::registerShareSessionHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("share.session.open", &handler::share::Sessions::open);
    r->registerPayload("share.email.challenge.start", &handler::share::Sessions::startEmailChallenge);
    r->registerPayload("share.email.challenge.confirm", &handler::share::Sessions::confirmEmailChallenge);
}

void Handler::registerShareFilesystemHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("share.fs.metadata", &handler::share::Filesystem::metadata);
    r->registerPayload("share.fs.list", &handler::share::Filesystem::list);
}

void Handler::registerShareDownloadHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("share.download.start", &handler::share::Download::start);
    r->registerPayload("share.download.chunk", &handler::share::Download::chunk);
    r->registerPayload("share.download.cancel", &handler::share::Download::cancel);
}

void Handler::registerSharePreviewHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("share.preview.get", &handler::share::Preview::get);
}

void Handler::registerShareUploadHandlers(const std::shared_ptr<Router>& r) {
    r->registerPayload("share.upload.start", &handler::share::Upload::start);
    r->registerPayload("share.upload.finish", &handler::share::Upload::finish);
    r->registerPayload("share.upload.cancel", &handler::share::Upload::cancel);
}
