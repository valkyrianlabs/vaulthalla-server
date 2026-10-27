// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// CLI <-> WebSocket parity for the group command family (Stage 1 of the ops:: consolidation).
//
// Every case runs one logical operation twice, each time against a fresh, uniquely named world: once through the
// CLI router (`vh group ...`) and once through the ws handler (`group.*`). It runs for a caller holding each
// seeded admin role. The two runs must agree on whether the operation was allowed, that verdict must match the
// oracle computed from the caller's admin identities.groups permission bits, and the observed database state
// afterwards must be identical. State is compared, never output text.
//
// The suite only touches the two surfaces' entry points and db::query, so it also builds against code from before
// the ops::groups migration; that is how the pre-migration divergences were recorded.

#include "db/Transactions.hpp"
#include "db/query/identities/Group.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Groups.hpp"
#include "rbac/permission/admin/identities/Groups.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "UsageManager.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include "../helpers/identities.hpp"

namespace vh::test_ops_parity_groups {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using GroupPtr = std::shared_ptr<identities::Group>;
using GroupPerms = rbac::permission::admin::identities::Groups;
using SessionPtr = std::shared_ptr<protocols::ws::Session>;

std::string uniqueTag() {
    static std::atomic<unsigned> counter{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(counter.fetch_add(1));
}

UserPtr createUser(const std::string& name, const std::shared_ptr<rbac::role::Admin>& role) {
    return test::identities::createUser(name, role, name + "@vaulthalla.test");
}

// Fresh objects for one run of one case. Names are short so they survive the CLI's table rendering.
struct World {
    std::string tag;
    GroupPtr group;       // existing group, `member` already in it
    std::string groupName; // its name when the world was made (the canonical group follows renames)
    UserPtr member;
    UserPtr outsider;     // not in the group
    std::string freeName; // a group name nobody holds
    unsigned int freeGid = 0;
};

GroupPtr groupByName(const std::string& name) { return vh::identities::manager().groupByName(name); }

bool isMember(const GroupPtr& group, const unsigned int userId) {
    return group && test::identities::isMember(group->id, userId);
}

json groupFacts(const GroupPtr& group) {
    if (!group) return json{{"exists", false}};
    const auto gid = group->linuxGid();
    return json{
        {"exists", true},
        {"description", group->description().value_or("")},
        {"gid", gid ? json(*gid) : json(nullptr)},
        {"members", vh::identities::manager().memberCount(group->id)}
    };
}

struct Case {
    std::string name;
    std::function<bool(const GroupPerms&)> allowed;  // oracle, from the caller's permission bits
    std::function<std::string(const World&)> cli;
    std::function<json(const World&, const SessionPtr&)> ws;
    std::function<json(const World&)> observe;
    // Facts about what the caller was shown (read operations), derived from each surface's result.
    std::function<json(const World&, const std::string& cliOut)> cliShown{};
    std::function<json(const World&, const json& wsData)> wsShown{};
    std::function<void(World&, const UserPtr& caller)> prepare{};
};

struct Outcome {
    bool ok = false;
    json state;
    json shown;
    std::string detail;
};

class GroupParityTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static std::vector<std::pair<std::string, UserPtr>> callers; // one per seeded admin role

    static bool hasDbEnv() {
        return std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
               std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME");
    }

    static void SetUpTestSuite() {
        if (!hasDbEnv()) {
            skipTests = true;
            std::cout << "[test_ops_parity_groups] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }

        paths::enableTestMode();
        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::seed::init_tables_if_not_exists();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::initPermissions();
        seed::initRoles();

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerGroupCommands(router);

        callers.clear();
        std::string roleNames;
        for (const auto& role : db::query::rbac::role::Admin::list()) {
            callers.emplace_back(role->name, createUser("gp_caller_" + uniqueTag(), role));
            roleNames += " " + role->name;
        }
        std::cout << "[test_ops_parity_groups] callers:" << roleNames << std::endl;
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        ASSERT_GE(callers.size(), 2u) << "expected the seeded admin roles";
    }

    static World makeWorld() {
        World w;
        w.tag = uniqueTag();
        const auto unprivileged = db::query::rbac::role::Admin::get("unprivileged");
        w.member = createUser("gpm_" + w.tag, unprivileged);
        w.outsider = createUser("gpo_" + w.tag, unprivileged);

        w.group = test::identities::createGroup("gp_" + w.tag, "orig");
        w.groupName = w.group->name();
        test::identities::addMember(w.group->id, w.member->id);

        w.freeName = "gpn_" + w.tag;
        static std::atomic<unsigned int> gid{610000 + static_cast<unsigned int>(std::rand() % 100000)};
        w.freeGid = gid.fetch_add(1);
        return w;
    }

    static Outcome runCli(const Case& c, World& w, const UserPtr& caller) {
        if (c.prepare) c.prepare(w, caller);
        Outcome out;
        std::string text;
        try {
            const auto res = router->executeLine(c.cli(w), caller, nullptr);
            out.ok = res.exit_code == 0;
            text = res.stdout_text;
            out.detail = "exit " + std::to_string(res.exit_code) + ": " + res.stderr_text;
        } catch (const std::exception& e) {
            out.detail = std::string("threw: ") + e.what();
        }
        out.state = c.observe(w);
        if (c.cliShown && out.ok) out.shown = c.cliShown(w, text);
        return out;
    }

    static Outcome runWs(const Case& c, World& w, const UserPtr& caller) {
        if (c.prepare) c.prepare(w, caller);
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->user = caller;
        Outcome out;
        json data;
        try {
            data = c.ws(w, session);
            out.ok = true;
        } catch (const std::exception& e) {
            out.detail = std::string("threw: ") + e.what();
        }
        out.state = c.observe(w);
        if (c.wsShown && out.ok) out.shown = c.wsShown(w, data);
        return out;
    }

    // Runs `c` for every seeded role through both surfaces and checks verdict, oracle and state.
    static void expectParity(const Case& c) {
        for (const auto& [roleName, caller] : callers) {
            const bool expected = c.allowed(caller->groupPerms());
            World a = makeWorld();
            World b = makeWorld();
            const auto cli = runCli(c, a, caller);
            const auto ws = runWs(c, b, caller);
            const auto where = c.name + " as " + roleName;

            EXPECT_EQ(cli.ok, ws.ok) << where << ": surfaces disagree. cli: " << cli.detail << " | ws: " << ws.detail;
            EXPECT_EQ(cli.ok, expected) << where << ": cli verdict vs permission oracle. " << cli.detail;
            EXPECT_EQ(ws.ok, expected) << where << ": ws verdict vs permission oracle. " << ws.detail;
            EXPECT_EQ(cli.state, ws.state) << where << ": resulting state differs.\n cli: " << cli.state.dump()
                                           << "\n ws:  " << ws.state.dump();
            if (cli.ok && ws.ok) {
                EXPECT_EQ(cli.shown, ws.shown) << where << ": surfaces showed different results.\n cli: "
                                               << cli.shown.dump() << "\n ws:  " << ws.shown.dump();
            }
        }
    }
};

const auto always = [](const GroupPerms&) { return true; };
const auto never = [](const GroupPerms&) { return false; };

TEST_F(GroupParityTest, Create) {
    expectParity({
        .name = "create",
        .allowed = [](const GroupPerms& p) { return p.canAdd(); },
        .cli = [](const World& w) {
            return "group create " + w.freeName + " --desc made --linux-gid " + std::to_string(w.freeGid);
        },
        .ws = [](const World& w, const SessionPtr& s) {
            return protocols::ws::handler::Groups::add(
                json{{"name", w.freeName}, {"description", "made"}, {"linux_gid", w.freeGid}}, s);
        },
        .observe = [](const World& w) {
            auto facts = groupFacts(groupByName(w.freeName));
            if (facts.contains("gid") && !facts["gid"].is_null()) facts["gid"] = facts["gid"] == w.freeGid;
            return facts;
        }
    });
}

// A two-character name, unique per world (base-36 counter), so a surface that skips isValidGroup (3..50 chars)
// really creates it instead of tripping over a duplicate or the VARCHAR(50) column limit.
std::string tooShortName() {
    static std::atomic<unsigned> next{0};
    constexpr std::string_view digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    const auto n = next.fetch_add(1) % (36 * 36);
    return {digits[n / 36], digits[n % 36]};
}

TEST_F(GroupParityTest, CreateRejectsInvalidName) {
    // Both surfaces must refuse, whoever asks; the world carries the name so observe() checks the same one.
    expectParity({
        .name = "create-invalid-name",
        .allowed = never,
        .cli = [](const World& w) { return "group create " + w.freeName; },
        .ws = [](const World& w, const SessionPtr& s) {
            return protocols::ws::handler::Groups::add(json{{"name", w.freeName}}, s);
        },
        .observe = [](const World& w) { return groupFacts(groupByName(w.freeName)); },
        .prepare = [](World& w, const UserPtr&) { w.freeName = tooShortName(); }
    });
}

TEST_F(GroupParityTest, CreateRejectsDuplicateName) {
    expectParity({
        .name = "create-duplicate",
        .allowed = never,
        .cli = [](const World& w) { return "group create " + w.groupName + " --desc dup"; },
        .ws = [](const World& w, const SessionPtr& s) {
            return protocols::ws::handler::Groups::add(json{{"name", w.groupName}, {"description", "dup"}}, s);
        },
        .observe = [](const World& w) { return groupFacts(groupByName(w.groupName)); }
    });
}

TEST_F(GroupParityTest, UpdateRenamesAndEditsDescription) {
    expectParity({
        .name = "update",
        .allowed = [](const GroupPerms& p) { return p.canEdit(); },
        .cli = [](const World& w) { return "group update " + w.groupName + " --name " + w.freeName + " --desc edited"; },
        .ws = [](const World& w, const SessionPtr& s) {
            return protocols::ws::handler::Groups::update(
                json{{"id", w.group->id}, {"name", w.freeName}, {"description", "edited"}}, s);
        },
        .observe = [](const World& w) {
            return json{{"old", groupFacts(groupByName(w.groupName))}, {"new", groupFacts(groupByName(w.freeName))}};
        }
    });
}

TEST_F(GroupParityTest, Delete) {
    expectParity({
        .name = "delete",
        .allowed = [](const GroupPerms& p) { return p.canDelete(); },
        .cli = [](const World& w) { return "group delete " + w.groupName; },
        .ws = [](const World& w, const SessionPtr& s) {
            return protocols::ws::handler::Groups::remove(json{{"id", w.group->id}}, s);
        },
        .observe = [](const World& w) { return groupFacts(vh::identities::manager().group(w.group->id)); }
    });
}

TEST_F(GroupParityTest, DeleteMissingIsRejected) {
    expectParity({
        .name = "delete-missing",
        .allowed = never,
        .cli = [](const World& w) { return "group delete " + w.freeName; },
        .ws = [](const World&, const SessionPtr& s) {
            return protocols::ws::handler::Groups::remove(json{{"id", 2147483000u}}, s);
        },
        .observe = [](const World& w) { return groupFacts(groupByName(w.groupName)); }
    });
}

TEST_F(GroupParityTest, Info) {
    expectParity({
        .name = "info",
        .allowed = [](const GroupPerms& p) { return p.canView(); },
        .cli = [](const World& w) { return "group info " + std::to_string(w.group->id); },
        .ws = [](const World& w, const SessionPtr& s) {
            return protocols::ws::handler::Groups::get(json{{"id", w.group->id}}, s);
        },
        .observe = [](const World& w) { return groupFacts(groupByName(w.groupName)); },
        .cliShown = [](const World& w, const std::string& out) { return json{{"named", out.contains(w.groupName)}}; },
        .wsShown = [](const World& w, const json& data) {
            return json{{"named", data.at("group").at("name") == w.groupName}};
        }
    });
}

TEST_F(GroupParityTest, ListShowsAllGroupsOnlyToViewers) {
    // The caller is not in the world's group: viewers see it, everyone else gets a (possibly empty) own-groups list.
    expectParity({
        .name = "list",
        .allowed = always,
        .cli = [](const World&) { return std::string("group list"); },
        .ws = [](const World&, const SessionPtr& s) { return protocols::ws::handler::Groups::list(s); },
        .observe = [](const World& w) { return groupFacts(groupByName(w.groupName)); },
        .cliShown = [](const World& w, const std::string& out) { return json{{"sees_group", out.contains(w.groupName)}}; },
        .wsShown = [](const World& w, const json& data) {
            return json{{"sees_group", std::ranges::any_of(data.at("groups"), [&](const json& g) {
                return g.at("name") == w.groupName;
            })}};
        }
    });
}

TEST_F(GroupParityTest, ListAlwaysShowsCallersOwnGroups) {
    expectParity({
        .name = "list-own",
        .allowed = always,
        .cli = [](const World&) { return std::string("group list"); },
        .ws = [](const World&, const SessionPtr& s) { return protocols::ws::handler::Groups::list(s); },
        .observe = [](const World& w) { return groupFacts(groupByName(w.groupName)); },
        .cliShown = [](const World& w, const std::string& out) { return json{{"sees_group", out.contains(w.groupName)}}; },
        .wsShown = [](const World& w, const json& data) {
            return json{{"sees_group", std::ranges::any_of(data.at("groups"), [&](const json& g) {
                return g.at("name") == w.groupName;
            })}};
        },
        .prepare = [](World& w, const UserPtr& caller) {
            test::identities::addMember(w.group->id, caller->id);
        }
    });
}

TEST_F(GroupParityTest, AddMember) {
    // ws payload per WebSocketCommandMap: {group_id, user_id}.
    expectParity({
        .name = "member-add",
        .allowed = [](const GroupPerms& p) { return p.canAddMember(); },
        .cli = [](const World& w) { return "group user add " + w.groupName + " " + w.outsider->name(); },
        .ws = [](const World& w, const SessionPtr& s) {
            return protocols::ws::handler::Groups::addMember(json{{"group_id", w.group->id}, {"user_id", w.outsider->id}}, s);
        },
        .observe = [](const World& w) {
            const auto group = vh::identities::manager().group(w.group->id);
            return json{{"outsider_member", isMember(group, w.outsider->id)}, {"member_member", isMember(group, w.member->id)}};
        }
    });
}

TEST_F(GroupParityTest, RemoveMember) {
    expectParity({
        .name = "member-remove",
        .allowed = [](const GroupPerms& p) { return p.canRemoveMember(); },
        .cli = [](const World& w) { return "group user remove " + w.groupName + " " + w.member->name(); },
        .ws = [](const World& w, const SessionPtr& s) {
            return protocols::ws::handler::Groups::removeMember(json{{"group_id", w.group->id}, {"user_id", w.member->id}}, s);
        },
        .observe = [](const World& w) {
            return json{{"member_member", isMember(vh::identities::manager().group(w.group->id), w.member->id)}};
        }
    });
}

TEST_F(GroupParityTest, AddMemberToMissingGroupIsRejected) {
    expectParity({
        .name = "member-add-missing-group",
        .allowed = never,
        .cli = [](const World& w) { return "group user add " + w.freeName + " " + w.outsider->name(); },
        .ws = [](const World& w, const SessionPtr& s) {
            return protocols::ws::handler::Groups::addMember(json{{"group_id", 2147483000u}, {"user_id", w.outsider->id}}, s);
        },
        .observe = [](const World& w) { return json{{"groups_of_outsider", vh::identities::manager().groupsOf(w.outsider->id).size()}}; }
    });
}

}

namespace vh::test_ops_parity_groups {

// Payload compatibility: the pre-migration member keys ({groupId, memberName} for add, {groupId, userId} for remove)
// keep working next to the WebSocketCommandMap shape, and are echoed back in the response.
TEST_F(GroupParityTest, WsLegacyMemberPayloadsStillAccepted) {
    const auto it = std::ranges::find_if(callers, [](const auto& c) { return c.first == "super_admin"; });
    ASSERT_NE(it, callers.end());
    auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    session->user = it->second;
    const auto w = makeWorld();

    const auto added = protocols::ws::handler::Groups::addMember(
        json{{"groupId", w.group->id}, {"memberName", w.outsider->name()}}, session);
    EXPECT_EQ(added.at("groupId"), w.group->id);
    EXPECT_EQ(added.at("memberName"), w.outsider->name());
    EXPECT_TRUE(isMember(vh::identities::manager().group(w.group->id), w.outsider->id));

    const auto removed = protocols::ws::handler::Groups::removeMember(
        json{{"groupId", w.group->id}, {"userId", w.outsider->id}}, session);
    EXPECT_EQ(removed.at("userId"), w.outsider->id);
    EXPECT_FALSE(isMember(vh::identities::manager().group(w.group->id), w.outsider->id));
}

}
