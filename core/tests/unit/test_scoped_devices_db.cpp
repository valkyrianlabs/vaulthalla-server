// vh-test-tier: db-only
// Scoped devices (design/core/mcp-remote-signin.md, "Scoped devices"; migration 152), DB-backed:
//   - a pairing request may ask for a scope; the approver decides, equal or narrower, and a narrower scope is part of
//     the device.trust target, so an approval for read-only never pairs with more; an unscoped approval's target is
//     exactly what it was before scopes;
//   - device.list shows the scope; pending requests show what was asked, and nothing when nothing was;
//   - the router holds a scoped device to its scope over every ws command (table-driven), refuses what a scoped device
//     never runs whatever its scope, and answers device_scope with {scope, effect};
//   - a scoped device never steps up (the Agent channel), may unpair only itself, and can't change any scope;
//   - device.scope.set: narrowing without a step-up, widening by the owner only with one bound to the device and the
//     scope, never from the device itself; the device's live sessions close; audited;
//   - an unscoped device is classified exactly as before.
#include "../helpers/db_suite.hpp"
#include "../helpers/web_session.hpp"
#include "Contract.hpp"
#include "audit/Trail.hpp"
#include "device/ScopeAudit.hpp"
#include "ops/Audit.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "device/Pairing.hpp"
#include "device/ServerIdentity.hpp"
#include "ops/Devices.hpp"
#include "ops/Error.hpp"
#include "protocols/device/Endpoints.hpp"
#include "protocols/device/Scope.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/handler/Devices.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <algorithm>
#include <chrono>
#include <map>
#include <set>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_scoped_devices_db {

using namespace vh::test::web;
namespace crypto = vh::device::crypto;
namespace h = protocols::ws::handler;
using auth::stepup::Family;
using protocols::ws::Router;
using Decision = Router::CommandAuthDecision;
using SysClock = std::chrono::system_clock;

class ScopedDevicesDb : public vh::test::db::Suite {
protected:
    AuthRuntime auth_{{.level = auth::mfa::policy::Level::Optional, .webauthn = false}};
    std::shared_ptr<const vh::device::ServerIdentity> previousIdentity;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("scoped_devices")) return;
        protocols::device::endpoints::clearNodeIdForTesting();
        audit::Trail::instance()->resetForTesting();
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        previousIdentity = vh::device::currentServerIdentity();
        vh::device::setCurrentServerIdentity(vh::device::ServerIdentity::generate());
        vh::device::Pairing::instance().resetForTesting();
        vh::device::scope_audit::resetForTesting();
    }

    void TearDown() override {
        if (skipTests) return;
        vh::device::Pairing::instance().resetForTesting();
        vh::device::setCurrentServerIdentity(previousIdentity);
    }

    static SessionPtr console(const UserPtr& user) {
        auto s = connect({}, "scoped-browser");
        s->setAuthenticatedUser(user);
        sessions().promote(s);
        s->tokens->refreshToken->authTime = SysClock::now() - std::chrono::hours(2);
        return s;
    }

    static void grant(const SessionPtr& s, const Answer& refused) {
        ASSERT_EQ(refused.code, "step_up_required") << refused.message;
        s->stepUp().addGrant({.user_id = s->user->id, .refresh_jti = s->tokens->refreshToken->jti,
                              .family = Family::DeviceTrust, .target = refused.data.at("target").get<std::string>(),
                              .method = "webauthn", .expires_at = SysClock::now() + std::chrono::minutes(5)});
    }

    struct Request {
        std::shared_ptr<vh::device::Peer> peer;
        std::string request_id;
        std::string code;
    };
    static Request request(const std::optional<std::string>& scope) {
        auto peer = std::make_shared<vh::device::Peer>();
        peer->spki = crypto::randomNonce();
        peer->spkiHex = crypto::toHex(peer->spki);
        peer->address = "192.0.2.30";
        const auto nonce = crypto::randomNonce();
        const auto receipt = ops::devices::pairRequest(
            *peer, {.name = "Claude Code on Mac", .platform = "macOS", .app_version = "1.0",
                    .commitment = crypto::toHex(crypto::commitment(peer->spki, nonce)), .scope = scope});
        (void)ops::devices::pairConfirm(*peer, receipt.request_id, crypto::toHex(nonce));
        return {.peer = peer, .request_id = receipt.request_id,
                .code = *vh::device::Pairing::instance().codeForTesting(receipt.request_id)};
    }

    // A paired device of `user` with `scope` on its row and its session's peer (as the handshake reads it).
    static Paired scopedDevice(const UserPtr& user, const std::string& scope) {
        auto d = pairedDevice(user);
        if (scope != "destructive") {
            d.row = *db::query::device::Devices::setScope(d.row.id, scope);
            d.peer->scope = scope;
        }
        return d;
    }

    static std::vector<std::string> auditFor(const std::string& action, const uint32_t deviceId) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("scope audit", [&](pqxx::work& txn) {
            std::vector<std::string> out;
            for (const auto& r : txn.exec("SELECT details::jsonb->>'from', details::jsonb->>'to' FROM audit_event "
                                          "WHERE action = $1 AND (details::jsonb->>'device')::BIGINT = $2 ORDER BY seq",
                                          pqxx::params{action, deviceId}))
                out.push_back(r[0].as<std::string>() + ">" + r[1].as<std::string>());
            return out;
        });
    }
};

TEST_F(ScopedDevicesDb, TheRequesterAsksTheApproverDecidesAndTheStepUpBindsTheScope) {
    const auto owner = newUser("unprivileged");
    const auto web = console(owner);

    // Asked read: shown; approving wider is refused; approving as asked gives read (the default is what was asked).
    (void)ops::devices::openWindow(owner);
    const auto asked = request(std::string("read"));
    const auto pending = run(web, [&] { return h::Devices::pairingPending(web); });
    ASSERT_TRUE(pending.ok) << pending.message;
    ASSERT_EQ(pending.data.at("requests").size(), 1u);
    EXPECT_EQ(pending.data.at("requests")[0].at("requested_scope"), "read");
    EXPECT_EQ(run(web, [&] {
                  return h::Devices::pairingApprove(
                      json{{"request_id", asked.request_id}, {"code", asked.code}, {"scope", "write"}}, web);
              }).code,
              "invalid");
    const auto approveAsked = [&] {
        return h::Devices::pairingApprove(json{{"request_id", asked.request_id}, {"code", asked.code}}, web);
    };
    const auto refused = run(web, approveAsked);
    ASSERT_EQ(refused.code, "step_up_required");
    EXPECT_TRUE(refused.data.at("target").get<std::string>().ends_with(":read")) << refused.data.dump();
    grant(web, refused);
    const auto approved = run(web, approveAsked);
    ASSERT_TRUE(approved.ok) << approved.message;
    EXPECT_EQ(approved.data.at("device").at("scope"), "read");

    // Asked nothing: unscoped by default, with exactly the target pairings always had (no scope part).
    (void)ops::devices::openWindow(owner);
    const auto plain = request(std::nullopt);
    const auto plainPending = run(web, [&] { return h::Devices::pairingPending(web); });
    ASSERT_TRUE(plainPending.ok);
    EXPECT_FALSE(plainPending.data.at("requests")[0].contains("requested_scope")) << "absent when nothing was asked";
    const auto unscopedRefusal = run(web, [&] {
        return h::Devices::pairingApprove(json{{"request_id", plain.request_id}, {"code", plain.code}}, web);
    });
    ASSERT_EQ(unscopedRefusal.code, "step_up_required");
    const auto unscopedTarget = unscopedRefusal.data.at("target").get<std::string>();
    EXPECT_EQ(std::ranges::count(unscopedTarget, ':'), 3) << unscopedTarget;

    // The approver narrows it to read: an approval for read never pairs it unscoped.
    const auto approveRead = [&] {
        return h::Devices::pairingApprove(json{{"request_id", plain.request_id}, {"code", plain.code}, {"scope", "read"}},
                                          web);
    };
    const auto readRefusal = run(web, approveRead);
    ASSERT_EQ(readRefusal.code, "step_up_required");
    EXPECT_EQ(readRefusal.data.at("target").get<std::string>(), unscopedTarget + ":read");
    grant(web, readRefusal);
    EXPECT_EQ(run(web, [&] {
                  return h::Devices::pairingApprove(json{{"request_id", plain.request_id}, {"code", plain.code}}, web);
              }).code,
              "step_up_required")
        << "a read-only approval replayed for full access";
    const auto narrowed = run(web, approveRead);
    ASSERT_TRUE(narrowed.ok) << narrowed.message;
    EXPECT_EQ(narrowed.data.at("device").at("scope"), "read");
    EXPECT_EQ(db::query::device::Devices::byId(narrowed.data.at("device").at("id").get<uint32_t>())->scope, "read");

    // device.list shows it; an unscoped device says destructive.
    const auto full = pairedDevice(owner);
    const auto list = run(web, [&] { return h::Devices::list(json::object(), web); });
    ASSERT_TRUE(list.ok);
    std::map<uint32_t, std::string> scopes;
    for (const auto& d : list.data.at("devices")) scopes[d.at("id").get<uint32_t>()] = d.at("scope").get<std::string>();
    EXPECT_EQ(scopes.at(full.row.id), "destructive");
    EXPECT_EQ(scopes.at(narrowed.data.at("device").at("id").get<uint32_t>()), "read");

    // A request may only ask for a scope the server knows.
    (void)ops::devices::openWindow(owner);
    EXPECT_THROW((void)request(std::string("admin")), ops::Invalid);
}

TEST_F(ScopedDevicesDb, TheRouterHoldsAScopedDeviceToItsScopeOverEveryCommand) {
    const auto admin = newUser("super_admin");
    const auto unscoped = pairedDevice(admin);
    const auto read = scopedDevice(admin, "read");
    const auto write = scopedDevice(admin, "write");

    std::size_t allowedRead = 0, deniedRead = 0;
    for (const auto& c : contract::ws::commands()) {
        const auto base = Router::classifyCommand(c.command, *unscoped.session);
        for (const auto* d : {&read, &write}) {
            const auto got = Router::classifyCommand(c.command, *d->session);
            if (base != Decision::Allow) {
                // A scoped device is never allowed more than an unscoped one.
                EXPECT_NE(got, Decision::Allow) << c.command;
                continue;
            }
            const bool may = !Router::isScopedDeviceForbidden(c.command) &&
                             protocols::device::scope::allows(d->peer->scope, c.effect);
            EXPECT_EQ(got, may ? Decision::Allow : Decision::DenyScope) << d->peer->scope << " " << c.command;
            if (d == &read) (may ? allowedRead : deniedRead)++;
        }
    }
    EXPECT_GT(allowedRead, 50u);
    EXPECT_GT(deniedRead, 50u);

    // The refusal on the wire: typed, with the scope and the effect, and a plain message.
    auto router = std::make_shared<Router>();
    protocols::ws::Handler::registerAllHandlers(router);
    std::vector<json> answers;
    read.session->setSendSinkForTesting([&](const json& frame) { answers.push_back(frame); });
    router->routeMessage(json{{"command", "fs.dir.create"}, {"requestId", "x"},
                              {"payload", {{"vault_id", 1}, {"path", "/x"}}}},
                         read.session);
    ASSERT_FALSE(answers.empty());
    EXPECT_EQ(answers.back().at("data").at("code"), "device_scope");
    EXPECT_EQ(answers.back().at("data").at("scope"), "read");
    EXPECT_EQ(answers.back().at("data").at("effect"), "write");
    EXPECT_NE(answers.back().dump().find("limited to read access"), std::string::npos) << answers.back().dump();
    answers.clear();
    write.session->setSendSinkForTesting([&](const json& frame) { answers.push_back(frame); });
    router->routeMessage(json{{"command", "device.backup.grant.list"}, {"requestId", "y"}}, write.session);
    ASSERT_FALSE(answers.empty());
    EXPECT_EQ(answers.back().at("data").at("code"), "device_scope") << "never, whatever the scope";
}

TEST_F(ScopedDevicesDb, AScopedDeviceNeverStepsUpUnpairsOnlyItselfAndChangesNoScope) {
    const auto owner = newUser("unprivileged");
    const auto unscoped = pairedDevice(owner);
    const auto agent = scopedDevice(owner, "write");
    const auto other = pairedDevice(owner);
    {
        const auth::stepup::Scope s(agent.session);
        EXPECT_EQ(s.channel(), auth::stepup::Channel::Agent);
    }
    {
        const auth::stepup::Scope s(unscoped.session);
        EXPECT_EQ(s.channel(), auth::stepup::Channel::Device) << "an unscoped device as before";
    }
    EXPECT_EQ(run(agent.session, [&] {
                  return h::Devices::revoke(json{{"device_id", std::to_string(other.row.id)}}, agent.session);
              }).code,
              "device_scope");
    EXPECT_FALSE(db::query::device::Devices::byId(other.row.id)->revoked());
    EXPECT_EQ(run(agent.session, [&] {
                  return h::Devices::scopeSet(json{{"device_id", std::to_string(other.row.id)}, {"scope", "read"}},
                                              agent.session);
              }).code,
              "device_scope");
    const auto self = run(agent.session, [&] {
        return h::Devices::revoke(json{{"device_id", std::to_string(agent.row.id)}}, agent.session);
    });
    ASSERT_TRUE(self.ok) << self.message;
    EXPECT_TRUE(db::query::device::Devices::byId(agent.row.id)->revoked());
}

TEST_F(ScopedDevicesDb, ScopeSetNarrowsFreelyWidensOnlyWithTheOwnersStepUpAndNeverFromTheDevice) {
    const auto owner = newUser("unprivileged");
    const auto admin = newUser("super_admin");
    const auto web = console(owner);
    const auto adminWeb = console(admin);
    const auto d = pairedDevice(owner);
    const auto id = std::to_string(d.row.id);
    const auto live = reconnect(d, owner);

    // Narrowing: no step-up; the device's live sessions close (it reconnects under the new scope).
    const auto narrowed = run(web, [&] { return h::Devices::scopeSet(json{{"device_id", id}, {"scope", "read"}}, web); });
    ASSERT_TRUE(narrowed.ok) << narrowed.message;
    EXPECT_EQ(narrowed.data.at("device").at("scope"), "read");
    EXPECT_TRUE(live->closing());

    // Widening: a super admin can't do it for someone else's device; the owner can, with a step-up for this device and
    // this scope only.
    EXPECT_EQ(run(adminWeb, [&] {
                  return h::Devices::scopeSet(json{{"device_id", id}, {"scope", "write"}}, adminWeb);
              }).code,
              "denied");
    const auto refused = run(web, [&] { return h::Devices::scopeSet(json{{"device_id", id}, {"scope", "write"}}, web); });
    ASSERT_EQ(refused.code, "step_up_required");
    EXPECT_EQ(refused.data.at("target"), "device.scope.set:" + id + ":write");
    grant(web, refused);
    EXPECT_EQ(run(web, [&] {
                  return h::Devices::scopeSet(json{{"device_id", id}, {"scope", "destructive"}}, web);
              }).code,
              "step_up_required")
        << "an approval for write never widens to destructive";
    const auto widened = run(web, [&] { return h::Devices::scopeSet(json{{"device_id", id}, {"scope", "write"}}, web); });
    ASSERT_TRUE(widened.ok) << widened.message;
    EXPECT_EQ(widened.data.at("device").at("scope"), "write");

    // A super admin may narrow anyone's; nobody changes a device's scope from that device itself.
    EXPECT_TRUE(run(adminWeb, [&] {
                    return h::Devices::scopeSet(json{{"device_id", id}, {"scope", "read"}}, adminWeb);
                }).ok);
    const auto unscopedSelf = pairedDevice(owner);
    EXPECT_EQ(run(unscopedSelf.session, [&] {
                  return h::Devices::scopeSet(
                      json{{"device_id", std::to_string(unscopedSelf.row.id)}, {"scope", "read"}}, unscopedSelf.session);
              }).code,
              "device_scope");
    EXPECT_EQ(run(web, [&] { return h::Devices::scopeSet(json{{"device_id", id}, {"scope", "all"}}, web); }).code,
              "invalid");
    EXPECT_EQ(auditFor("device.scope.set", d.row.id),
              (std::vector<std::string>{"destructive>read", "read>write", "write>read"}));
}

// ---- accountable at audit time ---------------------------------------------------------------------------------------

struct AuditRow {
    std::string action, origin, outcome;
    json details;
};

std::vector<AuditRow> auditSince(const int64_t afterSeq) {
    EXPECT_TRUE(audit::Trail::instance()->flushNow());
    return db::Transactions::exec("scoped audit rows", [&](pqxx::work& txn) {
        std::vector<AuditRow> out;
        for (const auto& r : txn.exec("SELECT action, origin, outcome, details FROM audit_event WHERE seq > $1 ORDER BY seq",
                                      pqxx::params{afterSeq}))
            out.push_back({r[0].as<std::string>(), r[1].as<std::string>(), r[2].as<std::string>(),
                           json::parse(r[3].as<std::string>())});
        return out;
    });
}

int64_t auditHead() {
    EXPECT_TRUE(audit::Trail::instance()->flushNow());
    return db::Transactions::exec("scoped audit head", [](pqxx::work& txn) {
        return txn.exec("SELECT COALESCE(MAX(seq), 0) FROM audit_event").one_field_ref().as<int64_t>();
    });
}

TEST_F(ScopedDevicesDb, TheApprovalRecordsWhoWhichDeviceAndTheScopeAskedAndGiven) {
    const auto owner = newUser("unprivileged");
    (void)ops::devices::openWindow(owner);
    const auto asked = request(std::string("write"));
    const auto head = auditHead();
    const auto device = [&] {
        const auth::stepup::Scope host(auth::stepup::Channel::Host);
        return ops::devices::approve(owner, asked.request_id, asked.code, std::string("read"));
    }();
    bool found = false;
    for (const auto& r : auditSince(head))
        if (r.action == "device.pairing.approve") {
            found = true;
            EXPECT_EQ(r.details.at("device"), device.id);
            EXPECT_EQ(r.details.at("requested_scope"), "write");
            EXPECT_EQ(r.details.at("scope"), "read");
        }
    EXPECT_TRUE(found);
}

TEST_F(ScopedDevicesDb, RefusalsAreRecordedThrottledAndCountedAndActionsCarryTheScope) {
    const auto admin = newUser("super_admin");
    const auto read = scopedDevice(admin, "read");
    const auto write = scopedDevice(admin, "write");
    auto router = std::make_shared<Router>();
    protocols::ws::Handler::registerAllHandlers(router);
    read.session->setSendSinkForTesting([](const json&) {});
    write.session->setSendSinkForTesting([](const json&) {});
    const auto send = [&](const Paired& d, const std::string& command, json payload = json::object()) {
        router->routeMessage(json{{"command", command}, {"requestId", "a"}, {"payload", std::move(payload)}}, d.session);
    };

    const auto head = auditHead();
    for (int i = 0; i < 8; ++i) send(read, "fs.dir.create", {{"vault_id", 1}, {"path", "/x" + std::to_string(i)}});
    send(read, "made.up.command");
    auto rows = auditSince(head);
    std::vector<AuditRow> refused;
    for (const auto& r : rows)
        if (r.action == "device.scope.refused") refused.push_back(r);
    ASSERT_EQ(refused.size(), static_cast<std::size_t>(vh::device::scope_audit::kPerWindow)) << "throttled per device";
    const auto expectedOrigin = "device " + read.peer->shortId() + " scope read";
    for (const auto& r : refused) {
        EXPECT_EQ(r.outcome, "denied");
        EXPECT_EQ(r.origin, expectedOrigin);
        EXPECT_EQ(r.details.at("device"), read.row.id);
        EXPECT_EQ(r.details.at("surface"), "ws");
        EXPECT_EQ(r.details.at("command"), "fs.dir.create");
        EXPECT_EQ(r.details.at("effect"), "write");
        EXPECT_EQ(r.details.at("scope"), "read");
    }
    // The next window reports what was skipped (3 more creates and the unknown command), and an unknown command is
    // never recorded as sent.
    vh::device::scope_audit::expireWindowsForTesting();
    const auto head2 = auditHead();
    send(read, "another.made.up.command");
    rows = auditSince(head2);
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].details.at("suppressed"), 4);
    EXPECT_EQ(rows[0].details.at("command"), "(unknown)");
    EXPECT_TRUE(rows[0].details.at("effect").is_null());

    // Another device has its own window.
    const auto head3 = auditHead();
    send(write, "fs.entry.delete", {{"vault_id", 1}, {"path", "/x"}});
    rows = auditSince(head3);
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].origin, "device " + write.peer->shortId() + " scope write");

    // What a scoped device does is attributed to it with its scope; an unscoped device's origin is as before.
    const auto head4 = auditHead();
    send(write, "device.rename", {{"device_id", std::to_string(write.row.id)}, {"name", "Renamed"}});
    const auto unscoped = pairedDevice(admin);
    unscoped.session->setSendSinkForTesting([](const json&) {});
    send(unscoped, "device.rename", {{"device_id", std::to_string(unscoped.row.id)}, {"name", "Renamed too"}});
    std::set<std::string> origins;
    for (const auto& r : auditSince(head4)) origins.insert(r.origin);
    EXPECT_TRUE(origins.contains("device " + write.peer->shortId() + " scope write"));
    EXPECT_TRUE(origins.contains("device " + unscoped.peer->shortId()));

    // One device's history on its own: what it did and what was done to it, never another's.
    ops::audit::Filter filter;
    ops::audit::forDevice(filter, read.row.id);
    const auto page = ops::audit::list(admin, filter, 1000);
    ASSERT_FALSE(page.events.empty());
    for (const auto& e : page.events) {
        const auto details = json::parse(e.details);
        EXPECT_TRUE(e.origin.starts_with("device " + read.peer->shortId()) ||
                    (details.contains("device") && details.at("device") == read.row.id))
            << e.action << " " << e.origin;
    }
    EXPECT_THROW(ops::audit::forDevice(filter, 999999), ops::NotFound);

    // The chain holds with the new events.
    const auto verification = ops::audit::verify(admin);
    EXPECT_TRUE(verification.ok) << verification.problem;
}

TEST_F(ScopedDevicesDb, AnAuditorAsksTheNodeWhatAScopeAllowsFromTheContractItEnforces) {
    const auto admin = newUser("super_admin");
    auto shell = std::make_shared<protocols::shell::Router>();
    protocols::shell::commands::registerAllCommands(shell);
    const auto res = shell->executeLine("device scopes --json", admin, nullptr);
    ASSERT_EQ(res.exit_code, 0) << res.stderr_text;
    const auto out = json::parse(res.stdout_text);
    ASSERT_EQ(out.at("scopes").size(), 2u);
    for (const auto& s : out.at("scopes")) {
        const auto scope = s.at("scope").get<std::string>();
        std::set<std::string> ws;
        for (const auto& c : s.at("ws_commands")) ws.insert(c.get<std::string>());
        for (const auto& c : contract::ws::commands())
            EXPECT_EQ(ws.contains(c.command), Router::scopedDeviceMayRun(c.command, scope)) << scope << " " << c.command;
        std::set<std::string> tools;
        for (const auto& t : s.at("mcp_tools")) tools.insert(t.get<std::string>());
        EXPECT_EQ(tools.contains("vh_run"), scope == "write");
        EXPECT_TRUE(tools.contains("vh_read"));
    }
    const auto read = shell->executeLine("device scopes --scope read", admin, nullptr);
    ASSERT_EQ(read.exit_code, 0) << read.stderr_text;
    EXPECT_NE(read.stdout_text.find("only narrows"), std::string::npos);
    EXPECT_NE(shell->executeLine("device scopes --scope destructive", admin, nullptr).exit_code, 0);
}

}
