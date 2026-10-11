// ops::groups invariants that hold independently of either frontend: a missing actor is a refusal (never a
// dereference), groups resolve the same by id or by name, and every refusal is a typed ops::Error.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Groups.hpp"
#include "rbac/role/Admin.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

namespace vh::test_ops_groups {

namespace groups = ops::groups;

TEST(OpsGroups, MissingActorIsDeniedBeforeAnyLookup) {
    const ops::Actor none;
    EXPECT_THROW((void)groups::create(none, {.name = "anything"}), ops::Denied);
    EXPECT_THROW((void)groups::update(none, {.group = 1u, .name = std::string("x")}), ops::Denied);
    EXPECT_THROW((void)groups::remove(none, 1u), ops::Denied);
    EXPECT_THROW((void)groups::get(none, std::string("anything")), ops::Denied);
    EXPECT_THROW((void)groups::list(none), ops::Denied);
    EXPECT_THROW((void)groups::listForUser(none, 1), ops::Denied);
    EXPECT_THROW((void)groups::addMember(none, {.group = 1u, .user = 1u}), ops::Denied);
    EXPECT_THROW((void)groups::removeMember(none, {.group = 1u, .user = 1u}), ops::Denied);
    EXPECT_THROW((void)groups::members(none, 1u), ops::Denied);
}

TEST(OpsGroups, PermissionlessActorIsDeniedBeforeAnyLookup) {
    // No DB needed: the permission check runs before the group is looked up.
    const auto actor = test::identities::detachedUser(4242, "ops_permissionless",
                                                      std::make_shared<rbac::role::Admin>(rbac::role::Admin::None()));
    EXPECT_THROW((void)groups::create(actor, {.name = "anything"}), ops::Denied);
    EXPECT_THROW((void)groups::remove(actor, std::string("nosuch")), ops::Denied);
    EXPECT_THROW((void)groups::get(actor, std::string("nosuch")), ops::Denied);
    EXPECT_THROW((void)groups::listForUser(actor, 1), ops::Denied);
}

class OpsGroupsDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> superAdmin;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_ops_groups] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::seed::init_tables_if_not_exists();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::initPermissions();
        seed::initRoles();

        const auto name = unique("ops_super_");
        superAdmin = test::identities::createUser(name, db::query::rbac::role::Admin::get("super_admin"),
                                                  name + "@vaulthalla.test");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static std::string unique(const std::string& label) {
        return label + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 1000000000);
    }
};

TEST_F(OpsGroupsDbTest, IdAndNameRefsResolveTheSameGroup) {
    const auto created = groups::create(superAdmin, {.name = unique("ops_ref_"), .description = "d"});
    EXPECT_EQ(groups::get(superAdmin, created->id)->id, created->id);
    EXPECT_EQ(groups::get(superAdmin, created->name())->id, created->id);
    EXPECT_EQ(groups::get(superAdmin, created->name())->description().value_or(""), "d");
}

TEST_F(OpsGroupsDbTest, RefusalsAreTyped) {
    const auto created = groups::create(superAdmin, {.name = unique("ops_typed_"), .linux_gid = 770001u});

    EXPECT_THROW((void)groups::get(superAdmin, 0u), ops::Invalid);
    EXPECT_THROW((void)groups::get(superAdmin, std::string("ops-no-such-group")), ops::NotFound);
    EXPECT_THROW((void)groups::create(superAdmin, {.name = "ab"}), ops::Invalid);
    EXPECT_THROW((void)groups::create(superAdmin, {.name = created->name()}), ops::Conflict);
    EXPECT_THROW((void)groups::create(superAdmin, {.name = unique("ops_gid_"), .linux_gid = 770001u}), ops::Conflict);
    EXPECT_THROW((void)groups::create(superAdmin, {.name = unique("ops_gid0_"), .linux_gid = 0u}), ops::Invalid);
    EXPECT_THROW((void)groups::addMember(superAdmin, {.group = created->id, .user = std::string("ops-no-such-user")}),
                 ops::NotFound);
}

TEST_F(OpsGroupsDbTest, UpdateIsAPatch) {
    const auto created = groups::create(superAdmin, {.name = unique("ops_patch_"), .description = "keep", .linux_gid = 770101u});
    const auto originalName = created->name();
    const auto renamed = groups::update(superAdmin, {.group = created->id, .name = unique("ops_patched_")});
    EXPECT_NE(renamed->name(), originalName);
    // One canonical object: the reference taken before the update sees the new name too.
    EXPECT_EQ(created.get(), renamed.get());
    EXPECT_EQ(created->name(), renamed->name());
    EXPECT_EQ(renamed->description().value_or(""), "keep");
    ASSERT_TRUE(renamed->linuxGid().has_value());
    EXPECT_EQ(*renamed->linuxGid(), 770101u);

    // Renaming to its own current name is not a conflict.
    EXPECT_NO_THROW((void)groups::update(superAdmin, {.group = renamed->id, .name = renamed->name()}));
}

}
