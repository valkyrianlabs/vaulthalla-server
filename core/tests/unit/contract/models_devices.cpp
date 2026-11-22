// Contract models: paired devices against their declared shape (see model_suites.hpp): device::to_json(Device).

#include "model_suites.hpp"

#include "device/Device.hpp"
#include "ops/BackupGrants.hpp"
#include "ops/CloudRelay.hpp"
#include "ops/Connector.hpp"

#include <string>

namespace vh::test_contract_models_devices {

// A device that rotated its key, was seen, and was revoked: every member non-null.
device::Device rotatedRevokedDevice() {
    device::Device d;
    d.id = 7;
    d.user_id = 3;
    d.user_name = "alice";
    d.name = "Alice's MacBook";
    d.platform = "macOS";
    d.app_version = "1.0.3";
    d.spki_sha256 = std::string(64, 'a');
    d.previous_spki_sha256 = std::string(64, 'b');
    d.approved_by = 3;
    d.created_at = 1760000000;
    d.last_seen_at = 1760000600;
    d.last_ip = "10.0.0.42";
    d.revoked_at = 1760001200;
    d.paired_via = "relay";
    return d;
}

// Just approved: never connected since, no rotation, approver gone (ON DELETE SET NULL), no app version.
device::Device freshDevice() {
    device::Device d;
    d.id = 8;
    d.user_id = 4;
    d.name = "Mac mini";
    d.platform = "macOS";
    d.spki_sha256 = std::string(64, 'c');
    d.created_at = 1760000000;
    return d;
}

// A migrated grant that was confirmed, used, suspended and revoked: every member non-null.
db::query::device::BackupGrant revokedGrant() {
    db::query::device::BackupGrant g;
    g.id = 4;
    g.device_id = 7;
    g.user_id = 3;
    g.origin = "approved";
    g.approved_via = "device_approval";
    g.vault_ids = {1, 5, 9};
    g.created_at = 1760000000;
    g.confirmed_at = 1760000100;
    g.last_used_at = 1760000200;
    g.suspended_at = 1760000300;
    g.revoked_at = 1760000400;
    g.revoked_reason = "recovery_code";
    return g;
}

// Just migrated (D1): never confirmed or used, no vaults yet; its device row gone.
db::query::device::BackupGrant migratedGrant() {
    db::query::device::BackupGrant g;
    g.id = 5;
    g.device_id = 8;
    g.user_id = 4;
    g.origin = "migrated";
    g.created_at = 1760000000;
    return g;
}

}

namespace vh::test::contract_models {

void checkDeviceModels(Checker& c) {
    using json = nlohmann::json;
    c.check(json(test_contract_models_devices::rotatedRevokedDevice()), "Device", "device.list devices[] (revoked)");
    c.check(json(test_contract_models_devices::freshDevice()), "Device", "device.pairing.approve device");
    c.check(ops::backup_grants::toJson(test_contract_models_devices::revokedGrant(),
                                       test_contract_models_devices::rotatedRevokedDevice()),
            "KeyBackupGrant", "device.backup.grant.list grants[] (revoked)");
    c.check(ops::backup_grants::toJson(test_contract_models_devices::migratedGrant(), std::nullopt), "KeyBackupGrant",
            "device.backup.grant.create grant (migrated, device gone)");

    ::vh::cloud::RelayStatus connected;
    connected.state = "connected";
    connected.enabled = true;
    connected.enabled_by = "admin";
    connected.enabled_at = 1760000000;
    connected.relay_url = "wss://relay.vaulthalla.test";
    connected.connected_since = 1760000100;
    connected.renew_by = 1760000700;
    connected.last_ticket_at = 1760000100;
    connected.next_attempt_at = 1760000101;
    connected.last_error = "the relay closed the connection (4003 renew)";
    connected.streams = 2;
    connected.streams_accepted = 9;
    connected.streams_refused = 1;
    c.check(ops::cloud_relay::toJson(connected), "CloudRelayStatus", "cloud.relay.status (connected)");
    c.check(ops::cloud_relay::toJson(::vh::cloud::RelayStatus{}), "CloudRelayStatus", "cloud.relay.status (off)");

    // Remote connectors (design/core/mcp-remote-signin.md): every member set, then the defaults.
    ops::connector::Status on;
    on.settings = {.enabled = true, .public_origin = "https://vault.example.com", .max_scope = "write",
                   .dcr_enabled = false, .client_hosts = {"claude.ai"}, .changed_by = 1, .changed_at = 1760000000};
    on.live_grants = 2;
    on.clients = 3;
    c.check(ops::connector::toJson(on), "ConnectorStatus", "connector.status (on)");
    c.check(ops::connector::toJson(ops::connector::Status{}), "ConnectorStatus", "connector.status (off, never set)");

    ::vh::connector::Grant ended;
    ended.row = {.id = "0b3a8d2e-5d1f-4e8a-9c0b-5a1d2e3f4a5b", .user_id = 1, .client_row = "c", .client_id =
                     "https://claude.ai/oauth/mcp-oauth-client-metadata", .client_name = "Claude",
                 .redirect_uri = "https://claude.ai/api/mcp/auth_callback", .scope = "read", .resource =
                     "https://vault.example.com/mcp", .label = "phone", .approved_via = "webauthn",
                 .created_at = 1760000000, .expires_at = 1767776000, .last_used_at = 1760000600,
                 .last_ip = "160.79.104.10", .revoked_at = 1760001200, .revoked_reason = "manual", .revoked_by = 1};
    c.check(ops::connector::toJson(ended), "ConnectorGrant", "connector.grants.list grants[] (revoked)");
    ::vh::connector::Grant fresh;
    fresh.row = {.id = "1b3a8d2e-5d1f-4e8a-9c0b-5a1d2e3f4a5b", .user_id = 1, .client_row = "c", .client_id = "vhc_x",
                 .client_name = "Codex", .redirect_uri = "http://127.0.0.1/callback", .scope = "write",
                 .resource = "https://vault.example.com/mcp", .approved_via = "password_totp", .created_at = 1760000000,
                 .expires_at = 1767776000};
    c.check(ops::connector::toJson(fresh), "ConnectorGrant", "connector.grants.list grants[] (live)");

    db::query::connector::ClientRow registered{.id = "2b3a8d2e-5d1f-4e8a-9c0b-5a1d2e3f4a5b", .client_id = "vhc_abc",
                                               .kind = "registered", .name = "Codex on laptop",
                                               .redirect_uris = {"http://127.0.0.1/callback"}, .created_by = 1,
                                               .created_at = 1760000000, .last_used_at = 1760000100,
                                               .disabled_at = 1760000200};
    c.check(ops::connector::toJson(registered), "ConnectorClient", "connector.clients.add");
    c.check(ops::connector::toJson(db::query::connector::ClientRow{.id = "x", .client_id = "https://a.example/c.json",
                                                                   .kind = "cimd", .name = "A",
                                                                   .redirect_uris = {"https://a.example/cb"}}),
            "ConnectorClient", "connector.clients.list clients[] (fetched, never used)");
}

}
