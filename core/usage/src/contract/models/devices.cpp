// ws models: paired devices (Vaulthalla Desktop). device::to_json(Device) (core/src/device/Device.cpp). Checked
// against its serializer by core/tests/unit/contract/models_devices.cpp.

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField deviceSpki(std::string name) {
    return str(std::move(name)).desc("SHA-256 of the device certificate's SubjectPublicKeyInfo (64 lowercase hex).");
}

WsField deviceTime(std::string name) { return integer(std::move(name)).desc("Unix seconds."); }

}

std::vector<WsModel> deviceModels() {
    std::vector<WsModel> out;

    out.push_back(model("Device",
        "A paired device (a devices row, migration 112): device::to_json(Device), core/src/device/Device.cpp.",
        {uinteger("id").desc("The row id: stable across key rotations."),
         deviceSpki("device_id").desc("The device id: the SHA-256 of its current certificate's SubjectPublicKeyInfo "
                                      "(64 lowercase hex digits)."),
         uinteger("user_id").desc("The account the device acts as."),
         str("user_name").desc("That account's name (empty when unknown)."),
         str("name"),
         str("platform").desc("\"macOS\"."),
         str("app_version").desc("Empty when the device didn't say."),
         deviceSpki("previous_device_id").nullable().desc(
             "The key before the last rotation, until the device first connects with the new one."),
         uinteger("approved_by").nullable().desc("The user who approved the pairing; null once that account is gone."),
         deviceTime("created_at"),
         deviceTime("last_seen_at").nullable(),
         str("last_ip").nullable().desc("The address of the device's last connection."),
         deviceTime("revoked_at").nullable(),
         boolean("revoked").desc("Revoked devices stay listed; their key never pairs again."),
         str("paired_via").oneOf({"listener", "relay"}).desc(
             "listener: paired on the device listener (Desktop); relay: a web browser paired through the cloud "
             "relay, held to the read-only capability set (migration 144)."),
         str("scope").oneOf({"read", "write", "destructive"}).desc(
             "Scoped devices (migration 152): what the device may do at most, within its user's rights. destructive: "
             "no limit beyond the account's own (every pairing before scopes).")}));

    out.push_back(model("CloudRelayStatus",
        "The cloud relay (design/cloud/relay.md): ops::cloud_relay::toJson(RelayStatus).",
        {str("state").oneOf({"off", "not_linked", "listener_off", "connecting", "connected", "backoff", "waiting",
                             "stopped"})
             .desc("off: the local switch; listener_off: device_server.enabled is false; backoff: retrying after a "
                   "failure; waiting: the cloud refused for a reason that may clear (off at the cloud, no plan, no "
                   "relay), retried every 5 minutes; stopped: the cloud no longer knows this installation (toggle the "
                   "switch to try again)."),
         boolean("enabled").desc("The local switch, for this linked installation."),
         str("enabled_by").nullable(), deviceTime("enabled_at").nullable(),
         str("relay_url").nullable().desc("From the latest ticket."),
         deviceTime("connected_since").nullable().desc("Since the relay admitted this server (WELCOME)."),
         deviceTime("renew_by").nullable(), deviceTime("last_ticket_at").nullable(),
         deviceTime("next_attempt_at").nullable(), str("last_error").nullable(),
         uinteger("streams").desc("Relayed streams open now."),
         uinteger("streams_accepted").desc("Since the daemon started."),
         uinteger("streams_refused").desc("Since the daemon started: bad tickets, failed key proofs, limits.")}));

    out.push_back(model("ConnectorStatus",
        "Remote connectors (design/core/mcp-remote-signin.md): ops::connector::toJson(Status).",
        {boolean("enabled").desc("The switch."),
         str("public_origin").nullable().desc("https://<host>, where hosted AI clients reach this server."),
         str("resource").nullable().desc("The MCP endpoint grants are bound to: public_origin + /mcp."),
         str("max_scope").oneOf({"read", "write", "destructive"}).desc("The widest scope a grant may be given."),
         boolean("dcr_enabled").desc("Dynamic client registration (off by default)."),
         strArray("client_hosts").desc("The only hosts a client-id metadata document may come from; empty: any."),
         uinteger("changed_by").nullable().desc("The user id of the last change."), integer("changed_at").nullable().desc("Unix seconds; null: never changed."),
         uinteger("live_grants"), uinteger("clients").desc("Live clients.")}));

    out.push_back(model("ConnectorGrant",
        "A remote connector grant, a connected app (migration 151): ops::connector::toJson(Grant).",
        {str("id").desc("uuid"), uinteger("user_id"),
         str("client_id").desc("A client-id metadata document URL, or vhc_… for a registered or dynamic client."),
         str("client_name").desc("As the client named itself (verified only for registered clients)."),
         str("client_host").desc("The client id's host (empty for vhc_… ids)."),
         str("redirect_host").desc("Where the grant's authorization code went."),
         boolean("loopback").desc("The redirect goes to a program on the approver's computer."),
         str("scope").oneOf({"read", "write", "destructive"}), str("label").nullable(),
         integer("created_at"), integer("expires_at").desc("At most 90 days after created_at."),
         integer("last_used_at").nullable(), str("last_ip").nullable(),
         integer("revoked_at").nullable(),
         str("revoked_reason").oneOf({"manual", "user_inactive", "grantor_policy", "refresh_reuse", "code_reuse",
                                      "switch_off", "expired", "client_removed", "sessions_revoked", "mfa_recovery"})
             .nullable()}));

    out.push_back(model("ConnectorClient",
        "A remote connector client (migration 151): ops::connector::toJson(ClientRow).",
        {str("id").desc("uuid"), str("client_id"), str("kind").oneOf({"cimd", "registered", "dcr"}), str("name"),
         strArray("redirect_uris"), uinteger("created_by").nullable().desc("The registering user's id."),
         integer("created_at"),
         integer("last_used_at").nullable(), integer("disabled_at").nullable()}));

    out.push_back(model("KeyBackupGrant",
        "A paired device's key-backup grant (#362, migration 130; MFA design note section 6.4): "
        "ops::backup_grants::toJson, core/src/ops/BackupGrants.cpp.",
        {uinteger("id"),
         deviceSpki("device_id").nullable().desc("The device the grant is bound to (null once the device row is gone)."),
         str("device_name").nullable(),
         str("origin").oneOf({"approved", "migrated"})
             .desc("approved: made or confirmed by a person's approval; migrated: carried over from before grants "
                   "existed (D1), with exactly the authority the device had then. Confirm or revoke it."),
         str("approved_via").oneOf({"webauthn", "password_totp", "device_approval", "console_approval"}).nullable()
             .desc("How the latest approval was given; null for a migrated grant never confirmed."),
         intArray("vault_ids").desc("The vaults whose keys the device may export without a prompt, ascending."),
         deviceTime("created_at"),
         deviceTime("confirmed_at").nullable(),
         deviceTime("last_used_at").nullable().desc("The latest export under the grant."),
         deviceTime("suspended_at").nullable()
             .desc("Set when more than 60 vault keys were exported in an hour; exports then need a person's approval "
                   "until the grant is confirmed again."),
         deviceTime("revoked_at").nullable(),
         str("revoked_reason").oneOf({"manual", "device_revoked", "user_inactive", "export_permission", "recovery_code",
                                      "admin_reset", "cli_reset", "device_idle"}).nullable(),
         boolean("active").desc("Live and not suspended: exports of its vaults need no prompt.")}));

    return out;
}

}
