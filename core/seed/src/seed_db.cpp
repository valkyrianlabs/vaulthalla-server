#include "seed/include/seed_db.hpp"

// Database
#include "db/query/vault/Vault.hpp"
#include "db/query/rbac/Permission.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/identities/helpers.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/identities/Group.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/Transactions.hpp"

// Types
#include "rbac/permission/Permission.hpp"
#include "vault/model/S3Vault.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "identities/Group.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "vault/model/Vault.hpp"
#include "fs/model/Directory.hpp"
#include "vault/model/APIKey.hpp"

// Misc
#include "config/Registry.hpp"
#include "vault/APIKeyManager.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/s3/Controller.hpp"
#include "crypto/id/Generator.hpp"
#include "crypto/util/hash.hpp"
#include "auth/Bootstrap.hpp"
#include "auth/SystemUid.hpp"

// Libraries
#include <memory>
#include <version.h>
#include <optional>
#include <cstdlib>
#include <fstream>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <pugixml.hpp>
#include <spdlog/spdlog.h>
#include <paths.h>

using namespace vh::seed;
using namespace vh::config;
using namespace vh::crypto;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::rbac;
using namespace vh::vault::model;
using namespace vh::crypto;
using namespace vh::sync::model;
using namespace vh::fs::model;

namespace {

struct R2TestEnv {
    std::string access_key;
    std::string secret_access_key;
    std::string endpoint;
    std::string region;
    std::string bucket;
};

std::optional<std::string> readEnv(const std::string_view name) {
    if (const auto* value = std::getenv(std::string(name).c_str()); value && *value)
        return std::string(value);
    return std::nullopt;
}

std::optional<R2TestEnv> readR2TestEnv(const char* purpose) {
    constexpr std::string_view prefix = "VAULTHALLA_TEST_R2_";
    const auto accessKey = readEnv(std::string(prefix) + "ACCESS_KEY");
    const auto secretKey = readEnv(std::string(prefix) + "SECRET_ACCESS_KEY");
    const auto endpoint = readEnv(std::string(prefix) + "ENDPOINT");
    const auto region = readEnv(std::string(prefix) + "REGION");
    const auto bucket = readEnv(std::string(prefix) + "BUCKET");

    if (!accessKey) {
        vh::log::Registry::vaulthalla()->info("[initdb] Skipping {}; missing {}ACCESS_KEY", purpose, prefix);
        return std::nullopt;
    }
    if (!secretKey) {
        vh::log::Registry::vaulthalla()->info("[initdb] Skipping {}; missing {}SECRET_ACCESS_KEY", purpose, prefix);
        return std::nullopt;
    }
    if (!endpoint) {
        vh::log::Registry::vaulthalla()->info("[initdb] Skipping {}; missing {}ENDPOINT", purpose, prefix);
        return std::nullopt;
    }
    if (!region) {
        vh::log::Registry::vaulthalla()->info("[initdb] Skipping {}; missing {}REGION", purpose, prefix);
        return std::nullopt;
    }
    if (!bucket) {
        vh::log::Registry::vaulthalla()->info("[initdb] Skipping {}; missing {}BUCKET", purpose, prefix);
        return std::nullopt;
    }

    return R2TestEnv{
        .access_key = *accessKey,
        .secret_access_key = *secretKey,
        .endpoint = *endpoint,
        .region = *region,
        .bucket = *bucket
    };
}

bool shouldCleanDevR2TestBucket() {
    try {
        const auto& dev = Registry::get().dev;
        return dev.init_r2_test_vault && (dev.enabled || vh::paths::isTestMode());
    } catch (...) {
        return false;
    }
}

std::shared_ptr<APIKey> r2TestAPIKey(const R2TestEnv& env, const std::string& name) {
    auto key = std::make_shared<APIKey>();
    key->user_id = 1;
    key->name = name;
    key->provider = S3Provider::CloudflareR2;
    key->region = env.region;
    key->access_key = env.access_key;
    key->secret_access_key = env.secret_access_key;
    key->endpoint = env.endpoint;
    return key;
}

std::vector<std::filesystem::path> listObjectKeysIncludingManifests(const std::u8string& xml) {
    if (xml.empty()) return {};

    const std::string wrapped = "<VaulthallaListObjects>" +
        std::string(reinterpret_cast<const char*>(xml.data()), xml.size()) +
        "</VaulthallaListObjects>";

    pugi::xml_document doc;
    const pugi::xml_parse_result result = doc.load_string(wrapped.c_str());
    if (!result) {
        vh::log::Registry::vaulthalla()->warn("[initdb] Failed to parse R2 test bucket listing: {}", result.description());
        return {};
    }

    std::vector<std::filesystem::path> keys;
    const auto collectKeys = [&](const auto& self, const pugi::xml_node& node) -> void {
        for (const pugi::xml_node child : node.children()) {
            if (std::string_view(child.name()) == "Key" &&
                std::string_view(child.parent().name()) == "Contents") {
                if (const auto* value = child.text().get(); value && *value)
                    keys.emplace_back(value);
            }
            self(self, child);
        }
    };
    collectKeys(collectKeys, doc);
    return keys;
}

vh::rbac::role::Vault shareDownloadOnlyRole() {
    namespace role = vh::rbac::role;
    namespace permission = vh::rbac::permission;
    return role::Vault::Custom(
        "share_download_only",
        "Share-focused role template for downloading files without broader mutation privileges.",
        role::vault::Base::Custom(
            permission::vault::Roles::None(),
            permission::vault::Sync::None(),
            permission::vault::Filesystem::DownloadOnly()
        )
    );
}

vh::rbac::role::Vault uploadDropboxRoleTemplate() {
    namespace role = vh::rbac::role;
    namespace permission = vh::rbac::permission;
    namespace fs = vh::rbac::permission::vault::fs;

    // Upload-only: recipients of a dropbox link must not see each other's submissions, so no directory List (it
    // was granted before #151; installs seeded earlier keep their row, and their links are bounded by allowed_ops).
    // Share uploads need nothing but Upload: the parent resolves as Write (directory Upload), the file as Write
    // (file Upload). Touch stays for folder creation.
    auto files = fs::Files::Custom(
        static_cast<fs::Files::SetMask>(fs::FilePermissions::Upload),
        fs::Share::None(std::string{fs::Files::FLAG_PREFIX})
    );
    auto dirs = fs::Directories::Custom(
        static_cast<fs::Directories::SetMask>(
            static_cast<fs::Directories::SetMask>(fs::DirectoryPermissions::Upload) |
            static_cast<fs::Directories::SetMask>(fs::DirectoryPermissions::Touch)
        ),
        fs::Share::None(std::string{fs::Directories::FLAG_PREFIX})
    );

    return role::Vault::Custom(
        "share_upload_dropbox",
        "Share-focused role template for upload-only dropbox links: no listing, preview or download.",
        role::vault::Base::Custom(
            permission::vault::Roles::None(),
            permission::vault::Sync::None(),
            permission::vault::Filesystem::Custom(std::move(files), std::move(dirs))
        )
    );
}

std::optional<unsigned int> configuredSystemUid() {
    constexpr const char* systemUsername = "vaulthalla";
    const auto uid = vh::auth::uid_for_user(systemUsername);
    if (!uid) {
        vh::log::Registry::vaulthalla()->warn(
            "[initdb] OS user '{}' not found; system principal will not receive a Linux UID mapping",
            systemUsername);
        return std::nullopt;
    }

    if (*uid == 0) {
        vh::log::Registry::vaulthalla()->warn(
            "[initdb] OS user '{}' resolves to UID 0; UID 0 remains reserved for root",
            systemUsername);
        return std::nullopt;
    }

    return static_cast<unsigned int>(*uid);
}

unsigned int upsertBootstrapPrincipal(
    pqxx::work& txn,
    const std::string& name,
    const std::optional<std::string>& email,
    const std::string& passwordHash,
    const std::optional<unsigned int>& linuxUid,
    const bool isProtected,
    const bool systemOnly
) {
    const auto res = txn.exec(
        R"SQL(
            INSERT INTO users (
                name,
                email,
                password_hash,
                is_active,
                linux_uid,
                protected,
                system_only
            )
            VALUES ($1, $2, $3, TRUE, $4, $5, $6)
            ON CONFLICT (name) DO UPDATE SET
                email       = COALESCE(users.email, EXCLUDED.email),
                is_active   = TRUE,
                linux_uid   = EXCLUDED.linux_uid,
                protected   = EXCLUDED.protected,
                system_only = EXCLUDED.system_only,
                updated_at  = NOW()
            RETURNING id
        )SQL",
        pqxx::params{name, email, passwordHash, linuxUid, isProtected, systemOnly}
    );

    if (res.empty())
        throw std::runtime_error("Failed to upsert bootstrap principal: " + name);

    return res.one_row_ref()["id"].as<unsigned int>();
}

unsigned int upsertBootstrapAdmin(
    pqxx::work& txn,
    const std::string& passwordHash
) {
    const auto res = txn.exec(
        R"SQL(
            INSERT INTO users (
                name,
                email,
                password_hash,
                is_active,
                protected,
                system_only
            )
            VALUES ('admin', NULL, $1, TRUE, TRUE, FALSE)
            ON CONFLICT (name) DO UPDATE SET
                is_active   = TRUE,
                linux_uid   = CASE WHEN users.linux_uid = 0 THEN NULL ELSE users.linux_uid END,
                protected   = TRUE,
                system_only = FALSE,
                updated_at  = NOW()
            RETURNING id
        )SQL",
        pqxx::params{passwordHash}
    );

    if (res.empty())
        throw std::runtime_error("Failed to upsert bootstrap admin principal");

    return res.one_row_ref()["id"].as<unsigned int>();
}

void assignSuperAdminRole(pqxx::work& txn, const unsigned int userId, const unsigned int roleId) {
    txn.exec(
        R"SQL(
            INSERT INTO admin_role_assignments (user_id, role_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id) DO UPDATE SET
                role_id = EXCLUDED.role_id,
                assigned_at = CURRENT_TIMESTAMP
        )SQL",
        pqxx::params{userId, roleId}
    );
}

}

void vh::seed::seed_database() {
    log::Registry::audit()->info("Initializing database for Vaulthalla v{}", VH_VERSION);
    log::Registry::vaulthalla()->debug("Initializing database for Vaulthalla v{}", VH_VERSION);

    cleanupDevR2TestBucket();

    initPermissions();
    initRoles();
    initAdmin();
    initAdminGroup();
    initSystemUser();
    initRoot();
    initAdminDefaultVault();

    log::Registry::vaulthalla()->debug("[initdb] Database initialization complete");
    log::Registry::audit()->info("Database initialization complete for Vaulthalla v{}", VH_VERSION);
}

void vh::seed::initPermissions() {
    log::Registry::vaulthalla()->debug("[initdb] Initializing permissions...");

    db::Transactions::exec("initdb::initPermissions", [&](pqxx::work& txn) {
        for (const auto& p : role::Admin().toPermissions())
            txn.exec(pqxx::prepped{"insert_raw_permission"},
                pqxx::params{p.qualified_name, p.description, "admin", p.bit_position});

        for (const auto& p : role::Vault().toPermissions())
            txn.exec(pqxx::prepped{"insert_raw_permission"},
                pqxx::params{p.qualified_name, p.description, "vault", p.bit_position});
    });
}

void vh::seed::initRoles() {
    log::Registry::vaulthalla()->debug("[initdb] Initializing roles...");

    const std::vector adminRoles{
        role::Admin::None(),
        role::Admin::Auditor(),
        role::Admin::Support(),
        role::Admin::IdentityAdmin(),
        role::Admin::PlatformOperator(),
        role::Admin::VaultAdmin(),
        role::Admin::SecurityAdmin(),
        role::Admin::OrgAdmin(),
        role::Admin::SuperAdmin(),
        role::Admin::KeyCustodian()
    };

    const std::vector vaultRoles{
        role::Vault::ImplicitDeny(),
        role::Vault::Guest(),
        role::Vault::Reader(),
        role::Vault::Custom(
            "share_preview_read",
            "Share-focused role template for listing and previewing scoped content.",
            role::vault::Base::BrowseOnly()
        ),
        shareDownloadOnlyRole(),
        role::Vault::Custom(
            "share_browse_download",
            "Share-focused role template for browsing, previewing, and downloading scoped content.",
            role::vault::Base::Reader()
        ),
        uploadDropboxRoleTemplate(),
        role::Vault::Custom(
            "share_contributor_scoped",
            "Share-focused role template for scoped collaborative upload and download access.",
            role::vault::Base::Contributor()
        ),
        role::Vault::Contributor(),
        role::Vault::Editor(),
        role::Vault::Manager(),
        role::Vault::PowerUser()
    };

    db::Transactions::exec("initdb::initRoles", [&](pqxx::work& txn) {
        for (const auto& role : adminRoles)
            txn.exec(
            pqxx::prepped{"admin_role_upsert_by_name"},
            pqxx::params{
                role.name,
                role.description,
                role.identities.toBitString(),
                role.audits.toBitString(),
                role.settings.toBitString(),
                role.roles.toBitString(),
                role.vaults.toBitString(),
                role.keys.toBitString(),
                role.s3Gateway.toBitString(),
                role.stats.toBitString(),
                role.upstream.toBitString()
            }
        );

        for (const auto& role : vaultRoles)
            txn.exec(
                pqxx::prepped{"vault_role_upsert_by_name"},
                pqxx::params{
                    role.name,
                    role.description,
                    role.fs.files.toBitString(),
                    role.fs.directories.toBitString(),
                    role.sync.toBitString(),
                    role.roles.toBitString(),
                }
            );
    });
}

void vh::seed::initSystemUser() {
    log::Registry::vaulthalla()->debug("[initdb] Initializing system user...");

    const auto sysUid = configuredSystemUid();

    // 2) If a user already exists for this Linux UID, ensure it's marked as system + has super_admin
    auto& identities = vh::identities::manager();
    try {
        if (sysUid) {
            if (const auto existingByUid = identities.userByLinuxUid(*sysUid); existingByUid) {
                if (const auto name = existingByUid->name(); name != "system") {
                    log::Registry::vaulthalla()->warn(
                        "[initdb] linux_uid={} belongs to '{}'; clearing it so the system principal can claim it",
                        *sysUid,
                        name);
                    (void)identities.updateUser(existingByUid->id, [](vh::identities::UserState& s) {
                        s.meta.linux_uid = std::nullopt;
                    });
                } else {
                    log::Registry::vaulthalla()->info(
                        "[initdb] System user already exists for linux_uid={} (name='{}')",
                        *sysUid, name
                    );

                    auto role = db::query::rbac::role::Admin::get("super_admin");
                    role->user_id = existingByUid->id;
                    (void)identities.updateUser(existingByUid->id, [&](vh::identities::UserState& s) {
                        s.email = "no-reply@system";
                        s.meta.linux_uid = sysUid;
                        s.roles.admin = role;
                    });
                    return;
                }
            }
        }
    } catch (...) {
        // getUserByLinuxUid might throw if not found; ignore and proceed to create
    }

    // 3) If a user exists by name "system" but no UID match, align it
    try {
        if (const auto existingByName = identities.userByName("system"); existingByName) {
            log::Registry::vaulthalla()->info(
                "[initdb] Found existing 'system' user (id={}), updating linux_uid to {}",
                existingByName->id, sysUid ? std::to_string(*sysUid) : "none"
            );

            auto role = db::query::rbac::role::Admin::get("super_admin");
            role->user_id = existingByName->id;
            (void)identities.updateUser(existingByName->id, [&](vh::identities::UserState& s) {
                s.meta.linux_uid = sysUid;
                s.email = "";
                s.roles.admin = role;
            });
            return;
        }
    } catch (...) {
        // getUserByName might throw if not found; ignore and proceed to create
    }

    // 4) Create a fresh system user
    vh::identities::UserState user;
    user.name = "system";
    user.email = "no-reply@system";
    user.meta.linux_uid = sysUid;

    // System account shouldn't be used for interactive login.
    // Still set a password hash to satisfy NOT NULL / validation.
    // Generate a deterministic-ish strong password seed (or truly random if you prefer).
    const auto pwSeed = id::Generator({ .namespace_token = "vaulthalla-system-user" }).generate();

    auto role = db::query::rbac::role::Admin::get("super_admin");
    role->user_id = 0;
    role->vGlobals = role::Admin::builtin("super_admin", 0)->vGlobals;
    user.roles.admin = role;

    (void)identities.createUser(user, hash::password(pwSeed));

    log::Registry::vaulthalla()->info(
        "[initdb] Created system user with linux_uid={}",
        sysUid ? std::to_string(*sysUid) : "none"
    );
}

namespace vh::seed {

rbac::role::Vault shareUploadDropboxRole() { return uploadDropboxRoleTemplate(); }

static std::optional<unsigned int> loadPendingSuperAdminUid() {
    const std::filesystem::path uidFile{paths::getRuntimePath() / "superadmin_uid"};

    if (!std::filesystem::exists(uidFile)) {
        log::Registry::vaulthalla()->debug("[seed] No pending super-admin UID file at {}", uidFile.string());
        return std::nullopt;
    }

    std::ifstream in(uidFile);
    if (!in.is_open()) {
        log::Registry::vaulthalla()->warn("[seed] Failed to open super-admin UID file: {}", uidFile.string());
        return std::nullopt;
    }

    unsigned int uid{};
    if (!(in >> uid)) {
        log::Registry::vaulthalla()->warn("[seed] Invalid contents in {}", uidFile.string());
        return std::nullopt;
    }

    if (uid == 0) {
        log::Registry::vaulthalla()->warn("[seed] Refusing to assign UID 0 to admin from {}", uidFile.string());
        return std::nullopt;
    }

    if (!paths::testMode) {
        try {
            std::filesystem::remove(uidFile);
            log::Registry::vaulthalla()->info("[seed] Consumed and removed pending super-admin UID file (uid={})", uid);
        } catch (const std::exception& e) {
            log::Registry::vaulthalla()->warn("[seed] Failed to remove {}: {}", uidFile.string(), e.what());
        }
    }

    return uid;
}

void initAdmin() {
    log::Registry::vaulthalla()->debug("[initdb] Initializing admin user...");

    vh::identities::UserState user;
    user.name = "admin";
    user.email = "";
    user.meta.linux_uid = loadPendingSuperAdminUid();

    auto role = db::query::rbac::role::Admin::get("super_admin");
    role->user_id = 0;
    role->vGlobals = role::Admin::builtin("super_admin", 0)->vGlobals;
    user.roles.admin = role;

    // No universal default: a per-install password, written once for the operator (auth/Bootstrap.hpp).
    (void)vh::identities::manager().createUser(user, auth::bootstrap::issueInitialCredential());
}

}

void vh::seed::initAdminGroup() {
    log::Registry::vaulthalla()->debug("[initdb] Initializing admin group...");

    auto& identities = vh::identities::manager();
    vh::identities::GroupState draft;
    draft.name = "admin";
    draft.description = "Core administrative group for system management";
    const auto group = identities.createGroup(draft);

    identities.addMembers(group->id, {identities.userByName("admin")->id});

    const auto members = identities.members(group->id);
    if (members.empty() || members.front().user->name() != "admin")
        throw std::runtime_error("Admin user not added to admin group");
}

void vh::seed::initAdminDefaultVault() {
    log::Registry::vaulthalla()->debug("[initdb] Initializing admin default vault...");

    const auto vault = std::make_shared<Vault>();
    vault->name = ADMIN_DEFAULT_VAULT_NAME;
    vault->description = "Default vault for the admin user";
    vault->type = VaultType::Local;
    vault->owner_id = 1;
    vault->quota = 0; // No quota for admin vault
    vault->mount_point = id::Generator({ .namespace_token = vault->name }).generate();

    const auto sync = std::make_shared<LocalPolicy>();
    sync->interval = std::chrono::minutes(10);
    sync->conflict_policy = LocalPolicy::ConflictPolicy::Overwrite;

    db::query::vault::Vault::upsertVault(vault, sync);
}

void vh::seed::initRoot() {
    log::Registry::vaulthalla()->debug("[initdb] Initializing root directory...");

    const auto dir = std::make_shared<Directory>();
    dir->name = "/";
    dir->base32_alias = id::Generator( { .namespace_token = "absroot" }).generate();
    dir->created_by = dir->last_modified_by = 1;
    dir->path = "/";
    dir->fuse_path = "/";
    dir->inode = 1;
    dir->mode = 0755; // Standard directory permissions
    dir->is_hidden = false;
    dir->is_system = true;

    db::query::fs::Directory::upsertDirectory(dir);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    if (!db::query::fs::Entry::rootExists()) throw std::runtime_error("Failed to create root directory in database");
    log::Registry::vaulthalla()->info("[initdb] Root directory initialized successfully");
}

void vh::seed::initDevCloudVault() {
    log::Registry::vaulthalla()->debug("[initdb] Initializing development Cloudflare R2 vault...");

    try {
        cleanupDevR2TestBucket();

        const auto env = readR2TestEnv("R2 test vault seed");
        if (!env) return;

        auto key = r2TestAPIKey(*env, "R2 Test Key");

        key->id = runtime::Deps::get().apiKeyManager->addAPIKey(key);

        if (key->id == 0) {
            log::Registry::storage()->error("[StorageManager] Failed to create API key for Cloudflare R2");
            return;
        }

        const auto vault = std::make_shared<S3Vault>();
        vault->name = "R2 Test Vault";
        vault->description = "Test vault for Cloudflare R2 in development mode";
        vault->mount_point = id::Generator({ .namespace_token = vault->name }).generate();
        vault->api_key_id = key->id;
        vault->owner_id = 1;
        vault->bucket = env->bucket;
        vault->type = VaultType::S3;
        vault->quota = 10ull * 1024ull * 1024ull * 1024ull;

        const auto sync = std::make_shared<RemotePolicy>();
        sync->interval = std::chrono::minutes(10);
        sync->conflict_policy = RemotePolicy::ConflictPolicy::KeepLocal;
        sync->strategy = RemotePolicy::Strategy::Sync;

        vault->id = db::query::vault::Vault::upsertVault(vault, sync);

        log::Registry::vaulthalla()->info("[initdb] Created R2 test vault");
    } catch (const std::exception& e) {
        log::Registry::storage()->error("[StorageManager] Error initializing dev Cloudflare R2 vault: {}", e.what());
    }
}

void vh::seed::cleanupDevR2TestBucket() {
    if (!shouldCleanDevR2TestBucket()) return;

    const auto env = readR2TestEnv("R2 test bucket cleanup");
    if (!env) return;

    try {
        vh::storage::s3::Controller controller(r2TestAPIKey(*env, "R2 Test Cleanup Key"), env->bucket);
        const auto keys = listObjectKeysIncludingManifests(controller.listObjects());

        if (keys.empty()) {
            log::Registry::vaulthalla()->info("[initdb] R2 test bucket cleanup found no objects");
            return;
        }

        uint64_t deleted = 0;
        for (const auto& key : keys) {
            try {
                controller.deleteObject(key);
                ++deleted;
            } catch (const std::exception& e) {
                log::Registry::vaulthalla()->warn(
                    "[initdb] Failed to delete R2 test bucket object '{}': {}",
                    key.string(),
                    e.what()
                );
            }
        }

        log::Registry::vaulthalla()->info(
            "[initdb] R2 test bucket cleanup deleted {}/{} object(s)",
            deleted,
            keys.size()
        );
    } catch (const std::exception& e) {
        log::Registry::vaulthalla()->warn("[initdb] R2 test bucket cleanup failed: {}", e.what());
    }
}

void vh::seed::reconcileSystemPrincipals() {
    log::Registry::vaulthalla()->debug("[initdb] Reconciling protected system principals...");

    const auto systemUid = configuredSystemUid();

    // The upserts below only use a password hash to insert a missing principal; an existing account's password is
    // never touched. Argon2 is deliberately slow (most of startup time when it ran three times per boot), so hash
    // only for the principals that don't exist yet: after the first boot, none.
    const auto existing = db::Transactions::exec("initdb::existingSystemPrincipals", [](pqxx::work& txn) {
        std::set<std::string> names;
        for (const auto row : txn.exec("SELECT name FROM users WHERE name IN ('root', 'system', 'admin')"))
            names.insert(row[0].as<std::string>());
        return names;
    });
    const auto unusableHash = [&](const std::string& name, const char* token) {
        return existing.contains(name) ? std::string{} : hash::password(id::Generator({ .namespace_token = token }).generate());
    };
    const auto rootHash = unusableHash("root", "vaulthalla-root-user");
    const auto systemHash = unusableHash("system", "vaulthalla-system-user");
    const auto adminHash = existing.contains("admin") ? std::string{} : auth::bootstrap::issueInitialCredential();

    // Bootstrap-only writes (protected flags) the Manager's write API refuses; it still republishes what they touched.
    vh::identities::manager().mutate({.everyone = true}, [&] {
    db::Transactions::exec("initdb::reconcileSystemPrincipals", [&](pqxx::work& txn) {
        txn.exec("SELECT set_config('vaulthalla.bootstrap', 'on', true)");

        const auto roleRes = txn.exec("SELECT id FROM admin_role WHERE name = 'super_admin'");
        if (roleRes.empty())
            throw std::runtime_error("super_admin role is missing; cannot reconcile protected principals");

        const auto superAdminRoleId = roleRes.one_row_ref()["id"].as<unsigned int>();

        txn.exec("UPDATE users SET linux_uid = NULL WHERE linux_uid = 0 AND name <> 'root'");

        if (systemUid) {
            txn.exec(
                "UPDATE users SET linux_uid = NULL WHERE linux_uid = $1 AND name <> 'system'",
                pqxx::params{*systemUid}
            );
        }

        txn.exec("UPDATE users SET linux_uid = NULL WHERE name = 'admin' AND linux_uid = 0");

        const auto rootId = upsertBootstrapPrincipal(
            txn,
            "root",
            std::nullopt,
            rootHash,
            0u,
            true,
            true
        );

        const auto systemId = upsertBootstrapPrincipal(
            txn,
            "system",
            std::make_optional<std::string>("no-reply@system"),
            systemHash,
            systemUid,
            true,
            true
        );

        const auto adminId = upsertBootstrapAdmin(txn, adminHash);

        assignSuperAdminRole(txn, rootId, superAdminRoleId);
        assignSuperAdminRole(txn, systemId, superAdminRoleId);
        assignSuperAdminRole(txn, adminId, superAdminRoleId);
    });
    });

    log::Registry::vaulthalla()->info("[initdb] Protected system principals reconciled");
}

void vh::seed::reconcileGlobalVaultPolicies() {
    std::size_t repaired = 0;
    db::Transactions::exec("initdb::reconcileGlobalVaultPolicies", [&](pqxx::work& txn) {
        const auto rows = txn.exec(
            "SELECT u.id, r.name FROM users u "
            "JOIN admin_role_assignments a ON a.user_id = u.id JOIN admin_role r ON r.id = a.role_id "
            "WHERE NOT EXISTS (SELECT 1 FROM user_global_vault_policy p "
            "                  WHERE p.user_id = u.id AND p.scope IN ('admin', 'user'))");
        for (const auto& row : rows) {
            const auto userId = row[0].as<uint32_t>();
            const auto preset = role::Admin::builtin(row[1].as<std::string>(), userId);
            const auto policy = preset ? preset->vGlobals : permission::admin::VaultGlobals{};
            txn.exec(pqxx::prepped{"user_global_vault_policy_delete_all_for_user"}, pqxx::params{userId});
            db::query::identities::upsertGlobalVRoles(txn, policy, userId);
            ++repaired;
        }
        if (repaired)
            log::Registry::vaulthalla()->info("[initdb] Wrote the role's global vault policy for {} account(s)", repaired);
    });
    if (repaired) vh::identities::manager().refresh({.everyone = true});
}
