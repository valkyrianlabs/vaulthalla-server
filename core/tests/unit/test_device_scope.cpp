// Scoped devices (design/core/mcp-remote-signin.md, "Scoped devices"), DB-free: the scope order, what each HTTP lane of
// the device listener does, and which ws commands a scoped device may never run whatever its scope.

#include "Contract.hpp"
#include "connector/Grants.hpp"
#include "device/ScopeAudit.hpp"
#include "protocols/device/Scope.hpp"
#include "protocols/ws/Router.hpp"

#include <gtest/gtest.h>

#include <string>

namespace vh::test_device_scope {

namespace scope = protocols::device::scope;
using protocols::ws::Router;
using boost::beast::http::verb;

TEST(DeviceScope, OrderAndAllows) {
    EXPECT_LT(scope::rank("read"), scope::rank("write"));
    EXPECT_LT(scope::rank("write"), scope::rank("destructive"));
    EXPECT_EQ(scope::rank("admin"), 0);
    EXPECT_TRUE(scope::allows("read", "read"));
    EXPECT_FALSE(scope::allows("read", "write"));
    EXPECT_TRUE(scope::allows("write", "write"));
    EXPECT_FALSE(scope::allows("write", "destructive"));
    EXPECT_TRUE(scope::allows("destructive", "destructive"));
    EXPECT_FALSE(scope::allows("destructive", "")) << "an unknown effect is never allowed";
    EXPECT_FALSE(scope::allows("", "read")) << "an unknown scope allows nothing";
}

TEST(DeviceScope, EveryHttpLaneIsClassified) {
    struct Case {
        verb method;
        const char* target;
        const char* effect;
    };
    for (const auto& c : std::initializer_list<Case>{
             {verb::get, "/preview?vault_id=1&path=/a.jpg", "read"},
             {verb::head, "/download/content?vault_id=1&path=/a", "read"},
             {verb::get, "/download?vault_id=1&path=/dir", "read"},
             {verb::get, "/download/conflict?conflict_id=1&side=local", "read"},
             {verb::get, "/preview/derived?kind=x", "read"},
             {verb::post, "/preview/batch", "read"},
             {verb::get, "/transfer/probe", "read"},
             {verb::post, "/transfer/sink", "read"},
             {verb::get, "/transfer/source?bytes=10", "read"},
             {verb::post, "/mcp", "read"},
             {verb::put, "/upload/content?vault_id=1&path=/a", "write"},
             {verb::put, "/upload/text?vault_id=1&path=/a", "write"},
             {verb::post, "/upload/session", "write"},
             {verb::post, "/upload/sessions", "write"},
             {verb::delete_, "/upload/sessions/abc", "write"},
             {verb::get, "/upload/sessions/abc", "write"},
             {verb::post, "/preview", "write"},
             {verb::put, "/download/content", "write"},
             {verb::get, "/previewx", "write"},
             {verb::get, "/somewhere-else", "write"},
         })
        EXPECT_EQ(scope::laneEffect(c.method, c.target), c.effect) << c.target;
}

TEST(DeviceScope, WhatAScopedDeviceNeverRuns) {
    for (const auto* cmd : {"device.pairing.open", "device.pairing.approve", "device.pairing.pending", "device.pair.request",
                            "device.approval.challenge", "device.approval.submit", "device.approval.request",
                            "device.approval.key.register", "device.backup.grant.list", "device.backup.grant.create",
                            "vault.keys.export", "vault.keys.export.confirm", "vault.keys.import", "connector.status",
                            "connector.grants.revoke", "device.scope.set"}) {
        EXPECT_TRUE(Router::isScopedDeviceForbidden(cmd)) << cmd;
        EXPECT_FALSE(Router::scopedDeviceMayRun(cmd, "destructive")) << cmd;
    }
    // Everything else follows its effect.
    EXPECT_TRUE(Router::scopedDeviceMayRun("fs.dir.list", "read"));
    EXPECT_TRUE(Router::scopedDeviceMayRun("device.list", "read"));
    EXPECT_TRUE(Router::scopedDeviceMayRun("vault.keys.status", "read"));
    EXPECT_FALSE(Router::scopedDeviceMayRun("fs.upload.start", "read"));
    EXPECT_TRUE(Router::scopedDeviceMayRun("fs.upload.start", "write"));
    EXPECT_FALSE(Router::scopedDeviceMayRun("fs.entry.delete", "write"));
    EXPECT_TRUE(Router::scopedDeviceMayRun("fs.entry.delete", "destructive"));
    EXPECT_FALSE(Router::scopedDeviceMayRun("no.such.command", "destructive")) << "fail closed";
    // device.revoke is allowed by the router (destructive scope) and held to the device itself by ops::devices.
    EXPECT_FALSE(Router::isScopedDeviceForbidden("device.revoke"));
    for (const auto& c : contract::ws::commands()) {
        if (Router::isScopedDeviceForbidden(c.command)) {
            EXPECT_FALSE(Router::scopedDeviceMayRun(c.command, "destructive")) << c.command;
        }
    }
}

TEST(DeviceScope, TheLaneTableIsWhatLaneEffectDoes) {
    ASSERT_FALSE(scope::laneClasses().empty());
    for (const auto& lane : scope::laneClasses())
        EXPECT_EQ(scope::laneEffect(lane.sample_method, lane.sample_target), lane.effect) << lane.lanes;
}

TEST(DeviceScope, AuditOriginsNameTheDeviceOrGrantAndTheScopeInForce) {
    vh::device::Peer peer;
    peer.spkiHex = std::string(16, 'a') + std::string(48, 'b');
    EXPECT_EQ(vh::device::auditOrigin(peer), "device aaaaaaaaaaaaaaaa") << "an unscoped device as before";
    EXPECT_EQ(vh::device::auditOrigin(peer, "mcp"), "device aaaaaaaaaaaaaaaa mcp");
    peer.scope = "read";
    EXPECT_EQ(vh::device::auditOrigin(peer), "device aaaaaaaaaaaaaaaa scope read");
    EXPECT_EQ(vh::device::auditOrigin(peer, "mcp"), "device aaaaaaaaaaaaaaaa mcp scope read");
    connector::Grant g;
    g.row.id = "0b3a8d2e-5d1f-4e8a-9c0b-5a1d2e3f4a5b";
    g.scope = connector::Scope::Write;
    EXPECT_EQ(connector::auditOrigin(g), "connector 0b3a8d2e scope write");
}

}
