// ws book: mirror.* and peer.mirror.* (core/src/protocols/ws/handler/Mirrors.cpp; design/peers/mirror.md "Starting a
// mirror", "As built: starting a mirror"). Experimental and off by default (peers.experimental): every command answers
// peers_experimental while it is off.
//
// Auth levels: the management commands are "human" (a signed-in person, or a full-access paired device's session:
// never a scoped device, a relayed one, an agent or a share session; ops answers peer_forbidden, the router and the
// MCP catalog refuse first). "peer": only on a linked server's own Peer session.

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

std::vector<std::string> mcMirrorRefusals(const std::vector<std::string>& extra = {}) {
    auto out = opsRefusals();
    out.emplace_back("peers_experimental");
    out.emplace_back("peer_forbidden");
    for (const auto& e : extra) out.push_back(e);
    return out;
}

std::vector<std::string> mcWireRefusals(const std::vector<std::string>& extra = {}) {
    std::vector<std::string> out{"denied", "invalid", "not_found", "conflict", "unauthorized", "peers_experimental",
                                 "peer_revoked"};
    for (const auto& e : extra) out.push_back(e);
    return out;
}

std::vector<WsField> mcRoleFields() {
    return {str("role_name").desc("1-50 characters: the role's name on the core, never matched to a role here."),
            uinteger("files"), uinteger("directories"), uinteger("sync"), uinteger("roles")};
}

WsField mcRoleObject(std::string name, std::string desc) {
    return object(std::move(name), "", mcRoleFields()).nullable().desc(std::move(desc));
}

std::vector<WsField> mcOfferFields() {
    return {uinteger("id").desc("The offer's number on this server."),
            str("offer_uid").desc("The start's id, the same on both servers (UUID)."),
            str("side").oneOf({"core", "mirror"}).desc("This server's part in it."),
            uinteger("peer_id"),
            str("vault_uid").desc("26 base32 symbols."),
            integer("vault_id").nullable().desc("core: the vault; mirror: the vault created for it, once installed."),
            uinteger("core_vault_id").desc("The vault's id on the core (its key attestations bind it)."),
            uinteger("term"), str("name"), str("description"), uinteger("quota"), uinteger("size_bytes"),
            uinteger("file_count"), boolean("history").desc("Always false in this version."),
            object("owner", "", {str("node"), uinteger("id"), str("name")})
                .desc("The vault's owner on the core: its home server's node id and its id there."),
            mcRoleObject("role", "The role the core proposes for the mirror server; null: none."),
            str("state").oneOf({"offered", "pending", "accepted", "keys_acked", "installed", "started", "declined",
                                "cancelled", "expired", "failed"}),
            str("step").desc("What the start is doing, in words: offering, waiting_for_answer, delivering_keys, "
                             "beginning, waiting_for_a_super_admin, answering, waiting_for_keys, waiting_for_begin, or "
                             "the state once it finished."),
            boolean("told").desc("The other server was told this state."),
            str("reason").nullable().desc("A decline's, cancel's or failure's code."), str("detail").nullable(),
            uinteger("attempts"), str("last_error").nullable(), uinteger("created_at"), uinteger("updated_at"),
            uinteger("expires_at").desc("An offer nobody answered expires (7 days)."),
            integer("finished_at").nullable()};
}

WsField mcOfferObject(std::string name = "offer") { return object(std::move(name), "", mcOfferFields()); }

std::vector<WsField> mcMirroredFields() {
    return {uinteger("vault_id"), str("vault_name"),
            str("role").oneOf({"core", "mirror", "orphaned", "starting", "none"}),
            object("peer", "", {uinteger("id"), str("node_id"), str("name"), boolean("revoked")}).nullable(),
            integer("term").nullable(), integer("last_seq").nullable(),
            str("state").oneOf({"live", "paused", "diverged"}).nullable(),
            object("grant", "", {str("role_name"), uinteger("files"), uinteger("directories"), uinteger("sync"),
                                 uinteger("roles"), str("granted_by_node"), uinteger("granted_at")})
                .nullable()
                .desc("mirror: what the core granted this server (its super admins get exactly that); null: nothing."),
            object("acked", "", {uinteger("term"), uinteger("seq")}).nullable(), integer("created_at").nullable(),
            object("start", "", mcOfferFields()).nullable().desc("The latest start of the vault on this side.")};
}

WsField mcVaultIdField() { return vaultId(); }

// A linked server's payloads: every field names what generates it (the contract's generated clients and tests).
std::vector<WsField> mcGenerated(const std::string& scope, std::vector<WsField> fields) {
    for (auto& f : fields)
        if (!f.generator && f.enum_values.empty()) f = f.gen(gen::ref(scope, {f.name}));
    return fields;
}

WsField mcOfferRef() {
    return anyOf("offer", {"integer", "string"})
        .alternatives({alt({"integer"}).desc("The offer's number here."), alt({"string"}).desc("Its offer uid.")})
        .gen(gen::ref("mirror.offer", {"id"}))
        .desc("An offer (vh mirror pending).");
}

}

std::vector<WsCommandUsage> mirrorCommands() {
    std::vector<WsCommandUsage> out;

    // ---- a person (ops/Mirrors.hpp)

    out.push_back({
        .command = "mirror.add",
        .description = "Start mirroring one of this server's vaults to a linked server (this server stays its core). "
                       "Every precondition refuses with its own code: mirror_already, mirror_start_running, "
                       "vault_replicated, vault_attach_running, vault_detach_running, layout_migration_running, "
                       "key_rotation_running, key_salvage_running, vault_pending_deletion, vault_unavailable, "
                       "legacy_content, key_version_missing, key_version_unattested, trashed_without_uid, "
                       "contents_not_held, peer_not_linked, peer_link_down. Then the offer goes to the linked server. "
                       "A super admin, or someone with the vault's admin Edit and vault.roles.assign on it.",
        .payload = {mcVaultIdField(), str("peer").gen(gen::ref("peer", {"id"})).desc("The linked server.")},
        .response = {mcOfferObject()},
        .refusal_codes = mcMirrorRefusals({"mirror_already", "mirror_start_running", "vault_replicated",
                                           "vault_attach_running", "vault_detach_running", "layout_migration_running",
                                           "key_rotation_running", "key_salvage_running", "vault_pending_deletion",
                                           "vault_unavailable", "legacy_content", "key_version_missing",
                                           "key_version_unattested", "trashed_without_uid", "contents_not_held",
                                           "peer_not_linked", "peer_link_down"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.pending",
        .description = "Offers linked servers made this server that wait for a super admin's answer.",
        .input = "none",
        .response = {objectArray("offers", "", mcOfferFields())},
        .refusal_codes = mcMirrorRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.accept",
        .description = "Accept an offer (super admins): checked again (mirror_vault_exists, mirror_name_taken, "
                       "mirror_no_space, history_not_supported), then the core is told and sends the keys.",
        .payload = {mcOfferRef()},
        .response = {mcOfferObject()},
        .refusal_codes = mcMirrorRefusals({"mirror_offer_not_pending", "mirror_vault_exists", "mirror_name_taken",
                                           "mirror_no_space", "history_not_supported"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.decline",
        .description = "Decline an offer (super admins); the core is told.",
        .payload = {mcOfferRef()},
        .response = {mcOfferObject()},
        .refusal_codes = mcMirrorRefusals({"mirror_offer_not_pending"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.cancel",
        .description = "Cancel a vault's mirror at any step. On the core: the core row and the log go and the mirror is "
                       "told (it removes its copy). On the mirror (super admins): a start that has not completed is "
                       "removed here and the core is told; a completed one is refused (mirror_detach_required). Name "
                       "the vault, or the offer when its vault doesn't exist here yet.",
        .payload = {uinteger("vault_id").opt().gen(gen::ref("vault", {"id"})), mcOfferRef().opt()},
        .response = {str("side").oneOf({"core", "mirror"}), integer("vault_id").nullable(),
                     boolean("removed").desc("mirror: the vault this server was given went."),
                     object("offer", "", mcOfferFields()).nullable()},
        .refusal_codes = mcMirrorRefusals({"mirror_detach_required", "mirror_offer_finished"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.list",
        .description = "Every mirrored vault here (this server's role, the linked server, the grant) and every start in "
                       "progress (role starting). Super admins.",
        .input = "none",
        .response = {objectArray("vaults", "", mcMirroredFields())},
        .refusal_codes = mcMirrorRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.get",
        .description = "One vault's mirror: role, linked server, state, grant, and what step a start is at. Super "
                       "admins; on the core also the vault's admin View.",
        .payload = {mcVaultIdField()},
        .response = {object("vault", "", mcMirroredFields())},
        .refusal_codes = mcMirrorRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.accept_all.set",
        .description = "Whether this server accepts every vault a linked server offers without asking (default off). "
                       "Super admins; audited mirror.accept_all.set.",
        .payload = {str("peer").gen(gen::ref("peer", {"id"})), boolean("enabled").gen(gen::boolean())},
        .response = {object("peer", "", {uinteger("id"), str("node_id"), str("name")}), boolean("enabled"),
                     integer("set_by").nullable(), integer("set_at").nullable()},
        .refusal_codes = mcMirrorRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- a linked server's own session (mirror/start/Start.hpp)

    out.push_back({
        .command = "peer.mirror.offer",
        .description = "The core offers a vault: its uid (base32), its id on the core, its root folder's uid, the term, "
                       "name, description, quota, size, file count, history (false), its owner (home node, id there, "
                       "name) and the role it proposes. The receiver stores it (pending, or accepted when its link "
                       "accepts every vault from the sender, or declined at once with a reason) and answers its state; "
                       "the decision follows as peer.mirror.answer.",
        .auth = "peer",
        .payload = mcGenerated("peer.mirror.offer", {str("offer_uid"), str("vault_uid"), uinteger("core_vault_id"), str("root_uid"), uinteger("term"),
                    str("name"), str("description").opt(), uinteger("quota"), uinteger("size_bytes"),
                    uinteger("file_count"), boolean("history"),
                    object("owner", "", {str("node"), uinteger("id"), str("name").opt()}),
                    mcRoleObject("role", "The proposed role; null: none."), integer("expires_at").opt()}),
        .response = {str("offer_uid"), str("state").oneOf({"pending", "accepted", "declined", "installed", "started",
                                                           "cancelled", "expired", "failed"})},
        .refusal_codes = mcWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.answer",
        .description = "The mirror's decision on an offer: accepted (the core then sends the keys) or declined with a "
                       "reason. Answers the core's state of the offer.",
        .auth = "peer",
        .payload = mcGenerated("peer.mirror.answer", {str("offer_uid"), str("decision").oneOf({"accepted", "declined"}), str("reason").opt(),
                    str("detail").opt()}),
        .response = {str("state")},
        .refusal_codes = mcWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.keys",
        .description = "Every key version the vault needs: each a KEV1 envelope (suite X25519) to the receiver's peer "
                       "wrap key, the core's key check over its vault id, and the core's attestation. The receiver "
                       "proves every version against the attestation keys it pinned at pairing (vault::recover::prove); "
                       "one unprovable version refuses the start (mirror_keys_refused) and nothing is written. Else it "
                       "creates the vault (the core's uid and root uid), seals the keys under its own vault master with "
                       "their origin, writes its mirror row, and answers (the acknowledgement). Again after that: the "
                       "same answer.",
        .auth = "peer",
        .payload = mcGenerated("peer.mirror.keys", {str("offer_uid"), str("vault_uid"), uinteger("core_vault_id"),
                    objectArray("versions", "",
                                {uinteger("version").min(1), boolean("current"),
                                 str("envelope").desc("KEV1, standard base64."),
                                 str("key_check").desc("32 hex digits, over the core's vault id."),
                                 object("attestation", "", {uinteger("key_id"), str("signature"),
                                                            str("public_key").opt()})})}),
        .response = {str("vault_uid"), boolean("installed")},
        .refusal_codes = mcWireRefusals({"mirror_keys_refused", "mirror_offer_not_accepted", "mirror_vault_exists",
                                         "mirror_name_taken", "mirror_no_space", "history_not_supported"}),
        .client_timeout = std::chrono::milliseconds(60'000),
    });

    out.push_back({
        .command = "peer.mirror.begin",
        .description = "The core started following the vault (its core row exists): the mirror's start is complete, "
                       "and the grant comes with it (null: nothing granted).",
        .auth = "peer",
        .payload = mcGenerated("peer.mirror.begin", {str("offer_uid"), str("vault_uid"), uinteger("term"), mcRoleObject("grant", "The core's grant.")}),
        .response = {boolean("started")},
        .refusal_codes = mcWireRefusals({"mirror_offer_not_installed"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.grant",
        .description = "What the core grants the mirror server for a vault now (its role's name and actual "
                       "permissions; null: nothing). Sent at begin, on every link-up and whenever it changes. Kept only "
                       "for a vault the sender is the core of (else not_found).",
        .auth = "peer",
        .payload = mcGenerated("peer.mirror.grant", {str("vault_uid"), mcRoleObject("grant", "null: the core grants nothing now.")}),
        .response = {boolean("recorded")},
        .refusal_codes = mcWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.cancel",
        .description = "Either side cancels a start, or the core ends a completed mirror: the core drops its core row "
                       "and log; the mirror removes the vault it was given, its keys and its rows. Answers whether "
                       "anything was cancelled.",
        .auth = "peer",
        .payload = mcGenerated("peer.mirror.cancel", {str("offer_uid").opt().nullable(), str("vault_uid"), str("reason").opt()}),
        .response = {boolean("cancelled")},
        .refusal_codes = mcWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
