// Step-up (#359; MFA design note section 5.4, decisions D3 and D6), DB-free: the families and what may satisfy them;
// grants bound to their session's user and refresh token, family, target and window, single use where target-bound;
// the request scope (the host exempt, agents refused, no scope internal, a covered operation, one request spending a
// single-use grant once); a fresh aal 2 sign-in standing in for family-wide grants; the ws refusal's shape; the router
// setting the scope; and the contract annotations (every annotated command booked with the refusal, no other command
// declaring it, Desktop's routine commands unannotated). The DB-backed half is test_mfa_stepup_db.cpp.
#include "Contract.hpp"
#include "WsProtocol.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/stepup/StepUp.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/Refusal.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>

namespace vh::auth::stepup::test_stepup {

using json = nlohmann::json;
using SessionPtr = std::shared_ptr<protocols::ws::Session>;
using SysClock = std::chrono::system_clock;

struct Answer {
    bool ok{false};
    json data{};
    std::string code{};
    std::string message{};
};

Answer call(const std::function<json()>& fn) {
    try {
        return {.ok = true, .data = fn()};
    } catch (...) {
        auto reply = protocols::ws::core::describeCurrentError();
        const auto code = reply.data.is_object() ? reply.data.value("code", std::string{}) : std::string{};
        return {.ok = false, .data = reply.data, .code = code, .message = reply.message};
    }
}

// A signed-in web socket without a database: a detached user and a refresh row in memory.
SessionPtr detachedWebSession(const uint32_t userId, const uint8_t aal = 1,
                              std::vector<std::string> amr = {"pwd"},
                              const SysClock::time_point authTime = SysClock::now() - std::chrono::hours(1)) {
    auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    identities::UserState state;
    state.name = "stepup-" + std::to_string(userId);
    s->user = identities::User::detached(userId, std::move(state));
    s->tokens->refreshToken = std::make_shared<model::RefreshToken>();
    s->tokens->refreshToken->jti = "jti-" + std::to_string(userId);
    s->tokens->refreshToken->aal = aal;
    s->tokens->refreshToken->amr = std::move(amr);
    s->tokens->refreshToken->authTime = authTime;
    return s;
}

Grant grantFor(const SessionPtr& s, const Family family, std::optional<std::string> target = std::nullopt,
               const std::chrono::seconds ttl = std::chrono::seconds(300)) {
    return {.user_id = s->user->id, .refresh_jti = s->tokens->refreshToken->jti, .family = family,
            .target = targetBound(family) ? std::move(target) : std::nullopt, .method = "test",
            .expires_at = SysClock::now() + ttl};
}

// ── DB-free ───────────────────────────────────────────────────────────────────────────────────────────────────────────

TEST(StepUpFamilies, NamesTargetsAndWhatMaySatisfyThem) {
    std::set<std::string> names;
    for (const auto f : kFamilies) {
        const auto name = std::string(to_string(f));
        EXPECT_TRUE(names.insert(name).second) << name;
        EXPECT_EQ(parseFamily(name), f) << name;
    }
    EXPECT_EQ(names, (std::set<std::string>{"keys", "device.trust", "account.credentials", "identity.admin", "secrets",
                                             "settings", "data.destroy"}));
    EXPECT_FALSE(parseFamily("everything"));
    for (const auto f : {Family::Keys, Family::DeviceTrust, Family::DataDestroy}) {
        EXPECT_TRUE(targetBound(f)) << to_string(f);
        EXPECT_FALSE(passwordMaySatisfy(f)) << "D3: never the password alone for " << to_string(f);
    }
    for (const auto f : {Family::AccountCredentials, Family::IdentityAdmin, Family::Secrets, Family::Settings}) {
        EXPECT_FALSE(targetBound(f)) << to_string(f);
        EXPECT_TRUE(passwordMaySatisfy(f)) << to_string(f);
        EXPECT_FALSE(deviceApprovalMaySatisfy(f)) << "D6: other families need console WebAuthn: " << to_string(f);
    }
    EXPECT_TRUE(deviceApprovalMaySatisfy(Family::Keys));
    EXPECT_TRUE(deviceApprovalMaySatisfy(Family::DeviceTrust));
    EXPECT_FALSE(deviceApprovalMaySatisfy(Family::DataDestroy));
}

TEST(StepUpGrants, AGrantServesOnlyItsBindingFamilyTargetAndWindow) {
    SessionState state;
    const auto now = SysClock::now();
    state.addGrant({.user_id = 1, .refresh_jti = "a", .family = Family::Settings, .method = "webauthn",
                    .expires_at = now + std::chrono::minutes(5)});
    EXPECT_FALSE(state.use(2, "a", Family::Settings, std::nullopt, now)) << "another account";
    state.addGrant({.user_id = 1, .refresh_jti = "a", .family = Family::Settings, .method = "webauthn",
                    .expires_at = now + std::chrono::minutes(5)});
    EXPECT_FALSE(state.use(1, "b", Family::Settings, std::nullopt, now)) << "another refresh token";
    state.addGrant({.user_id = 1, .refresh_jti = "a", .family = Family::Settings, .method = "webauthn",
                    .expires_at = now + std::chrono::minutes(5)});
    EXPECT_FALSE(state.use(1, "a", Family::Secrets, std::nullopt, now)) << "another family";
    EXPECT_TRUE(state.use(1, "a", Family::Settings, std::nullopt, now));
    EXPECT_TRUE(state.use(1, "a", Family::Settings, std::nullopt, now)) << "a family grant serves its window";
    EXPECT_FALSE(state.use(1, "a", Family::Settings, std::nullopt, now + std::chrono::minutes(6))) << "expired";

    state.addGrant({.user_id = 1, .refresh_jti = "a", .family = Family::DataDestroy, .target = "vault:7",
                    .method = "webauthn", .expires_at = now + std::chrono::minutes(5)});
    EXPECT_FALSE(state.use(1, "a", Family::DataDestroy, std::string("vault:8"), now)) << "another target";
    EXPECT_FALSE(state.use(1, "a", Family::Keys, std::string("vault:7"), now)) << "another family, same target";
    EXPECT_TRUE(state.use(1, "a", Family::DataDestroy, std::string("vault:7"), now));
    EXPECT_FALSE(state.use(1, "a", Family::DataDestroy, std::string("vault:7"), now)) << "single use: consumed";

    state.addGrant({.user_id = 1, .refresh_jti = "a", .family = Family::Secrets, .method = "webauthn",
                    .expires_at = now + std::chrono::minutes(5)});
    state.clear();
    EXPECT_TRUE(state.grants(now).empty()) << "sign-out and invalidation drop every grant";
}

TEST(StepUpGrants, FailuresCountWithinTheirWindow) {
    SessionState state;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 1; i <= 4; ++i) EXPECT_EQ(state.recordFailure(t0 + std::chrono::minutes(i)), i);
    EXPECT_EQ(state.failures(t0 + std::chrono::minutes(16)), 3) << "the first failure left the 15 minute window";
}

TEST(StepUpScope, TheHostIsExemptAgentsAreRefusedAndNoScopeIsTheDaemonsOwn) {
    ASSERT_EQ(Scope::current(), nullptr);
    EXPECT_NO_THROW(require(Family::IdentityAdmin)) << "no request: internal callers and tests";
    {
        const Scope host(Channel::Host);
        EXPECT_EQ(Scope::current(), &host);
        for (const auto f : kFamilies)
            EXPECT_NO_THROW(require(f, std::string("t"))) << "the CLI over the unix socket: " << to_string(f);
        {
            const Scope agent(Channel::Agent);
            try {
                require(Family::Settings);
                ADD_FAILURE() << "an agent stepped up";
            } catch (const ops::StepUpRequired& e) {
                EXPECT_EQ(e.code, "step_up_required");
                EXPECT_EQ(e.family, "settings");
                EXPECT_TRUE(e.methods.empty()) << "agents can't produce a step-up";
            }
            EXPECT_FALSE(keyBackupGrantCovers(1));
        }
        EXPECT_EQ(Scope::current(), &host) << "scopes nest";
    }
    EXPECT_EQ(Scope::current(), nullptr);
    EXPECT_FALSE(keyBackupGrantCovers(1)) << "only a paired device's export is inside its backup grant";
}

TEST(StepUpScope, ACoveredOperationNeedsNoSecondStepUp) {
    const Scope agent(Channel::Agent);
    {
        const Covered covered;
        EXPECT_NO_THROW(require(Family::DataDestroy, std::string("storage.vault.remove:1")));
    }
    EXPECT_THROW(require(Family::DataDestroy, std::string("storage.vault.remove:1")), ops::StepUpRequired);
}

TEST(StepUpScope, OneRequestSpendsASingleUseGrantOnce) {
    const auto s = detachedWebSession(41);
    s->stepUp().addGrant(grantFor(s, Family::Keys, "vault.keys.import:3"));
    {
        const Scope scope(s);
        EXPECT_EQ(scope.channel(), Channel::Web);
        EXPECT_NO_THROW(require(Family::Keys, std::string("vault.keys.import:3")));
        EXPECT_NO_THROW(require(Family::Keys, std::string("vault.keys.import:3"))) << "the same request, checked twice";
    }
    EXPECT_TRUE(s->stepUp().grants().empty()) << "and the grant is gone for the next one";
}

TEST(StepUpScope, AFreshAal2SignInStandsInForFamilyGrants) {
    const auto fresh = detachedWebSession(42, 2, {"pwd", "hwk"}, SysClock::now() - std::chrono::seconds(30));
    const Scope scope(fresh);
    for (const auto f : {Family::AccountCredentials, Family::IdentityAdmin, Family::Secrets, Family::Settings})
        EXPECT_NO_THROW(require(f)) << to_string(f);
}

TEST(StepUpRefusal, TheWsAnswerCarriesFamilyTargetMethodsAndMaxAge) {
    const auto answer = call([]() -> json {
        throw ops::StepUpRequired("data.destroy", std::string("storage.vault.remove:9"), {"webauthn"}, 300,
                                  "Confirm it's you");
    });
    EXPECT_FALSE(answer.ok);
    EXPECT_EQ(answer.code, "step_up_required");
    EXPECT_EQ(answer.data.at("family"), "data.destroy");
    EXPECT_EQ(answer.data.at("target"), "storage.vault.remove:9");
    EXPECT_EQ(answer.data.at("methods"), json::array({"webauthn"}));
    EXPECT_EQ(answer.data.at("max_age_seconds"), 300);
    const auto family = call([]() -> json { throw ops::StepUpRequired("settings", std::nullopt, {}, 120, "x"); });
    EXPECT_TRUE(family.data.at("target").is_null());
}

TEST(StepUpRouter, TheRouterSetsTheScopeForEveryRoutedCommand) {
    auto router = std::make_shared<protocols::ws::Router>();
    std::optional<Channel> seen;
    const protocols::ws::Session* seenSession = nullptr;
    // A session-lifecycle name, so an anonymous (closed, answer-less) socket may route it.
    router->registerHandler("auth.logout", [&](json&&, const SessionPtr& session) {
        if (const auto* scope = Scope::current()) {
            seen = scope->channel();
            seenSession = scope->session().get();
        }
        (void)session;
    });
    auto session = std::make_shared<protocols::ws::Session>(router);
    session->close();
    router->routeMessage(json{{"command", "auth.logout"}}, session);
    ASSERT_TRUE(seen) << "no step-up scope while a command ran";
    EXPECT_EQ(*seen, Channel::Web);
    EXPECT_EQ(seenSession, session.get());
    EXPECT_EQ(Scope::current(), nullptr) << "the scope ends with the command";
}

// The contract: one table, booked commands, the refusal declared exactly where a family is.
TEST(StepUpContract, EveryAnnotatedCommandIsBookedAndDeclaresTheRefusal) {
    const auto table = contract::stepUpTable();
    ASSERT_GE(table.size(), 50u);
    std::map<std::string, contract::WsStepUp> byCommand;
    for (const auto& row : table) {
        const auto family = parseFamily(row.family);
        ASSERT_TRUE(family) << row.command << ": " << row.family;
        EXPECT_EQ(row.target_bound, targetBound(*family)) << row.command;
        byCommand.emplace(row.command, row);
    }
    std::set<std::string> booked;
    for (const auto& c : contract::ws::commands()) {
        booked.insert(c.command);
        const bool declares = std::ranges::find(c.refusal_codes, "step_up_required") != c.refusal_codes.end();
        if (const auto it = byCommand.find(c.command); it != byCommand.end()) {
            EXPECT_EQ(c.step_up, it->second.family) << c.command;
            EXPECT_TRUE(declares) << c.command << " is annotated but doesn't declare step_up_required";
        } else {
            EXPECT_FALSE(c.step_up) << c.command;
            EXPECT_FALSE(declares) << c.command << " declares step_up_required without a family";
        }
    }
    for (const auto& row : table) EXPECT_TRUE(booked.contains(row.command)) << row.command;
    for (const auto* cmd : {"auth.stepup.begin", "auth.stepup.finish", "auth.mfa.factor.remove"})
        EXPECT_TRUE(booked.contains(cmd)) << cmd;
    const auto capabilities = contract::capabilityNames();
    EXPECT_TRUE(std::ranges::find(capabilities, "auth.step_up") != capabilities.end());
}

// Design 5.4/6.1: routine Desktop traffic never prompts. The commands Vaulthalla Desktop runs routinely over its
// device session carry no family (vault.keys.export is inside the key-backup grant on a device: see the DB test).
TEST(StepUpContract, DesktopsRoutineCommandsAreNeverAnnotated) {
    const auto table = contract::stepUpTable();
    const auto annotated = [&](const std::string_view command) {
        return std::ranges::any_of(table, [&](const contract::WsStepUp& r) { return r.command == command; });
    };
    for (const auto* cmd : {"meta.hello", "meta.contract.get", "auth.isAuthenticated", "device.server.identity",
                            "device.endpoints", "device.identity.rotate", "device.list", "device.remote.status",
                            "device.revoke", "device.pairing.open", "storage.vault.list",
                            "storage.vault.accessible.list", "storage.vault.get", "storage.vault.sync", "fs.list",
                            "fs.dir.list", "fs.metadata", "fs.dir.create", "fs.entry.delete", "fs.entry.move",
                            "fs.entry.rename", "fs.entry.copy", "fs.upload.start", "fs.upload.finish",
                            "fs.download.start", "fs.download.chunk", "fs.changes.list", "fs.changes.subscribe",
                            "vault.keys.status", "vault.keys.export.confirm", "recovery.list", "recovery.inspect",
                            "recovery.restore", "recovery.snapshot.create", "share.link.create", "share.link.revoke",
                            "sync.conflicts.list", "sync.conflicts.resolve", "auth.user.get", "auth.users.list"})
        EXPECT_FALSE(annotated(cmd)) << cmd << " would prompt a device or a person on routine use";
}

}
