// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Sync conflicts through both surfaces (#187): `vh sync resolve` / `vh resolve` and the ws sync.conflicts.*
// commands run the same ops::conflicts operations. For every seeded admin role, on a vault owned by an unprivileged
// account (so admins reach it through their vault globals' "user" scope), both surfaces must agree on what the
// caller sees and whether a resolution is allowed, the verdict must match the role's bits (resolve_conflicts +
// Overwrite), and the resulting DB state must be the same.

#include "../helpers/sync_conflict_harness.hpp"

#include "db/query/rbac/role/Admin.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/SyncConflicts.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/vault/Global.hpp"
#include "UsageManager.hpp"

#include <nlohmann/json.hpp>

#include <set>

namespace vh::test_ops_parity_conflicts {

using namespace test_support::sync_conflicts;
using json = nlohmann::json;

class ConflictParityTest : public Harness {
protected:
    inline static std::shared_ptr<protocols::shell::Router> router;

    static void SetUpTestSuite() {
        Harness::SetUpTestSuite();
        if (skipTests) return;
        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerSyncCommands(router);
    }

    static std::pair<int, std::string> cli(const std::string& line, const UserPtr& user) {
        try {
            const auto res = router->executeLine(line, user, nullptr);
            return {res.exit_code, res.stdout_text + res.stderr_text};
        } catch (const std::exception& e) {
            return {1, e.what()};
        }
    }

    static std::shared_ptr<protocols::ws::Session> ws(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    static std::set<uint32_t> ids(const json& conflicts) {
        std::set<uint32_t> out;
        for (const auto& c : conflicts) out.insert(c.at("id").get<uint32_t>());
        return out;
    }

    // What the role's bits say about a vault owned by a non-admin account.
    static bool oracle(const UserPtr& user) {
        if (user->isSuperAdmin()) return true;
        const auto& g = user->state()->roles.admin->vGlobals.user;
        return g.sync.action.canResolveConflicts() && g.fs.files.canOverwrite();
    }
};

TEST_F(ConflictParityTest, ListAndResolveAgreeForEverySeededAdminRole) {
    const auto owner = createUser("cp_owner", "unprivileged");
    unsigned checked = 0;
    for (const auto& role : db::query::rbac::role::Admin::list()) {
        SCOPED_TRACE(role->name);
        // super_admin cannot be assigned through ops::users; the seeded admin account holds it.
        const auto caller = role->name == "super_admin" ? superUser : createUser("cp_" + role->name, role->name);
        const auto f = remoteVault(owner);
        const auto viaCli = conflicted(f, "/cli.txt");
        const auto viaWs = conflicted(f, "/ws.txt");
        const bool allowed = oracle(caller);

        // Listing: the same ids, or the same refusal.
        const auto [listCode, listOut] = cli("sync resolve --list --vault " + std::to_string(f.vault->id) + " --json", caller);
        std::optional<json> wsList;
        try {
            wsList = protocols::ws::handler::SyncConflicts::list(json{{"vault_id", f.vault->id}}, ws(caller));
        } catch (const ops::Denied&) {
        }
        EXPECT_EQ(listCode == 0, wsList.has_value()) << listOut;
        if (listCode == 0 && wsList) {
            EXPECT_EQ(ids(json::parse(listOut).at("conflicts")), ids(wsList->at("conflicts")));
            EXPECT_EQ(ids(wsList->at("conflicts")), (std::set<uint32_t>{viaCli.id, viaWs.id}));
        }

        // The summary (badge) and the `vh resolve` shortcut agree with them.
        const auto summary = protocols::ws::handler::SyncConflicts::summary(ws(caller));
        const bool sees = std::ranges::any_of(summary.at("vaults"), [&](const json& v) {
            return v.at("vault_id").get<uint32_t>() == f.vault->id && v.at("count").get<uint64_t>() == 2;
        });
        EXPECT_EQ(sees, wsList.has_value());
        const auto [aliasCode, aliasOut] = cli("resolve --list --vault " + std::to_string(f.vault->id) + " --json", caller);
        EXPECT_EQ(aliasCode, listCode) << aliasOut;

        // Resolving: one conflict per surface, the same verdict, the same resulting state.
        const auto [code, out] = cli("sync resolve " + std::to_string(viaCli.id) + " --keep-local --json", caller);
        const auto wsResult = protocols::ws::handler::SyncConflicts::resolve(
            json{{"resolution", "keep_local"}, {"conflict_ids", json::array({viaWs.id})}}, ws(caller));
        const bool cliOk = code == 0;
        const bool wsOk = wsResult.at("results").at(0).at("ok").get<bool>();
        EXPECT_EQ(cliOk, wsOk) << out << "\n" << wsResult.dump();
        EXPECT_EQ(cliOk, allowed) << "oracle: resolve_conflicts + Overwrite in the role's vault globals\n" << out;
        EXPECT_EQ(resolutionOf(viaCli.id), resolutionOf(viaWs.id));
        EXPECT_EQ(resolutionOf(viaCli.id), allowed ? "kept_local" : "unresolved");
        if (!cliOk) {
            EXPECT_EQ(json::parse(out).at("results").at(0).at("status"), wsResult.at("results").at(0).at("status"));
        }
        ++checked;
    }
    EXPECT_GE(checked, 2u) << "expected the seeded admin roles";
}

TEST_F(ConflictParityTest, BadRequestsAreRefusedTheSameWay) {
    const auto [noDecision, out1] = cli("sync resolve 1", superUser);
    EXPECT_EQ(noDecision, 2) << out1;
    EXPECT_THROW((void)protocols::ws::handler::SyncConflicts::resolve(json{{"conflict_ids", json::array({1})}}, ws(superUser)),
                 ops::Invalid);

    const auto [both, out2] = cli("sync resolve 1 --keep-local --keep-remote", superUser);
    EXPECT_EQ(both, 2) << out2;
    EXPECT_THROW((void)protocols::ws::handler::SyncConflicts::resolve(
                     json{{"resolution", "keep_both"}, {"conflict_ids", json::array({1})}}, ws(superUser)),
                 ops::Invalid);

    const auto [none, out3] = cli("sync resolve --all --keep-local", superUser);
    EXPECT_EQ(none, 2) << out3 << " (--all needs --vault)";
    EXPECT_THROW((void)protocols::ws::handler::SyncConflicts::resolve(
                     json{{"resolution", "keep_local"}, {"conflict_ids", json::array()}}, ws(superUser)),
                 ops::Invalid);

    // Without a terminal, --all needs --yes; with it, every conflict in the vault is resolved.
    const auto f = remoteVault(superUser);
    const auto a = conflicted(f, "/all-a.txt");
    const auto b = conflicted(f, "/all-b.txt");
    const auto vault = std::to_string(f.vault->id);
    const auto [noYes, out4] = cli("sync resolve --vault " + vault + " --all --keep-remote", superUser);
    EXPECT_EQ(noYes, 2) << out4;
    EXPECT_EQ(resolutionOf(a.id), "unresolved");
    const auto [yes, out5] = cli("sync resolve --vault " + vault + " --all --keep-remote --yes", superUser);
    EXPECT_EQ(yes, 0) << out5;
    EXPECT_EQ(resolutionOf(a.id), "kept_remote");
    EXPECT_EQ(resolutionOf(b.id), "kept_remote");
}

}
