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
                                "cancelled", "expired", "failed", "orphaned", "detached"}),
            str("step").desc("What the start is doing, in words: offering, waiting_for_answer, delivering_keys, "
                             "beginning, waiting_for_a_super_admin, answering, waiting_for_keys, waiting_for_begin, or "
                             "the state once it finished."),
            boolean("told").desc("The other server was told this state."),
            boolean("remove_copy").desc("core: its cancel asked the mirror to remove its copy."),
            str("copy").oneOf({"removed", "kept", "none", "detached"}).nullable().desc(
                "core: what the mirror said it did with its copy when it was told of the cancel."),
            str("reason").nullable().desc("A decline's, cancel's or failure's code."), str("detail").nullable(),
            uinteger("attempts"), str("last_error").nullable(), uinteger("created_at"), uinteger("updated_at"),
            uinteger("expires_at").desc("An offer nobody answered expires (7 days)."),
            integer("finished_at").nullable()};
}

WsField mcOfferObject(std::string name = "offer") { return object(std::move(name), "", mcOfferFields()); }

std::vector<WsField> mcMirroredFields() {
    return {uinteger("vault_id"), str("vault_name"),
            str("role").oneOf({"core", "mirror", "orphaned", "starting", "detached", "none"}).desc(
                "orphaned: a copy whose core ended the mirror, kept here read-only (detach it, or remove it with "
                "mirror.cancel); detached: a former copy, standalone here now."),
            object("peer", "", {uinteger("id"), str("node_id"), str("name"), boolean("revoked")}).nullable(),
            integer("term").nullable(), integer("last_seq").nullable(),
            str("state").oneOf({"starting", "live", "paused", "diverged", "expired", "stopped", "switching", "rejoining",
                                "forked"})
                .nullable(),
            object("grant", "", {str("role_name"), uinteger("files"), uinteger("directories"), uinteger("sync"),
                                 uinteger("roles"), str("granted_by_node"), uinteger("granted_at")})
                .nullable()
                .desc("mirror: what the core granted this server (its super admins get exactly that); null: nothing."),
            object("acked", "", {uinteger("term"), uinteger("seq")}).nullable(), integer("created_at").nullable(),
            object("start", "", mcOfferFields()).nullable().desc("The latest start of the vault on this side."),
            object("switch", "", {str("switch_id"), str("side").oneOf({"core", "mirror"}),
                                  str("phase").oneOf({"requested", "draining", "preparing", "prepared", "switched",
                                                      "abandoned"}),
                                  uinteger("term"), str("reason").nullable(), uinteger("created_at"),
                                  integer("ended_at").nullable()})
                .nullable().desc("The vault's latest planned switch here."),
            object("takeover", "", {uinteger("term"), object("fork", "", {uinteger("term"), uinteger("seq")}),
                                    uinteger("peer_id"), uinteger("contents_missing"), uinteger("created_at")})
                .nullable().desc("A take over here still waiting for its old core to return."),
            str("advice").nullable().desc("What a person does next when the vault waits on the other server."),
            object("detached", "", {uinteger("id"), str("side").oneOf({"mirror", "core"}), uinteger("vault_id"),
                                    uinteger("peer_id"), object("fork", "", {uinteger("term"), uinteger("seq")}),
                                    boolean("digest_matched").nullable(), str("was_state").nullable(),
                                    uinteger("missing"), integer("owner_id").nullable(),
                                    integer("detached_by").nullable(), integer("detached_at"),
                                    integer("rekeyed_at").nullable(), boolean("rekey_recommended")})
                .nullable()
                .desc("Wave 5: the vault's detach not followed by a re-key (side mirror: detached here; side core: "
                      "its mirror left with a copy)."),
            boolean("rekey_recommended").desc("The vault was detached here and shares its uid and keys with the "
                                              "original: the re-key pass is recommended."),
            object("deleting", "", {boolean("deleting"), integer("purge_after"), str("copy").oneOf({"remove", "leave"}),
                                    str("here").opt()})
                .nullable()
                .desc("The vault's core is deleting it (its retention window): when the purge is due and what it does "
                      "to the copy (mirror: `here`, what this server will do by its keep setting). null: not deleting."),
            str("stop_reason").nullable().desc("Why the copy is not live (mirror_core_deleting while its core deletes "
                                               "the vault).")};
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
                                           "peer_not_linked", "peer_link_down", "mirror_detached_copy"}),
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
                                           "mirror_no_space", "history_not_supported", "mirror_detached_copy"}),
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
        .description = "End a vault's mirror at any step. On the core: the core row and the log go at once and the "
                       "mirror is told (queued while the link is down; dropped if the servers are unlinked first), "
                       "with remove_copy. On the mirror (super admins): a start that has not completed is removed here "
                       "and the core is told; a completed one is refused (mirror_detach_required); an orphaned copy "
                       "is removed. Name the vault, or the offer when its vault doesn't exist here yet.",
        .payload = {uinteger("vault_id").opt().gen(gen::ref("vault", {"id"})), mcOfferRef().opt(),
                    boolean("remove_copy").opt().gen(gen::boolean()).desc(
                        "On the core: ask the mirror to remove its copy (default false: it keeps it, orphaned). The "
                        "mirror removes it unless its link keeps the vaults this server removes; a copy whose first "
                        "copy isn't finished is removed anyway. The data-destroy step-up for a mirror that has begun.")},
        .response = {str("side").oneOf({"core", "mirror"}), integer("vault_id").nullable(),
                     boolean("removed").desc("mirror: the vault this server was given, or an orphaned copy, went."),
                     boolean("remove_copy").desc("core: what was asked; what the mirror did comes later (mirror.get: "
                                                 "start.copy)."),
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
        .command = "mirror.keep_removed.set",
        .description = "Whether this server keeps the vaults a linked server (their core) removes: a cancel that asks "
                       "to remove a finished copy leaves it here as an orphaned copy instead (default off). Super "
                       "admins; audited mirror.keep_removed.set.",
        .payload = {str("peer").gen(gen::ref("peer", {"id"})), boolean("enabled").gen(gen::boolean())},
        .response = {object("peer", "", {uinteger("id"), str("node_id"), str("name")}), boolean("enabled"),
                     integer("set_by").nullable(), integer("set_at").nullable()},
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

    out.push_back({
        .command = "mirror.mirror_all.set",
        .description = "On the core: whether this server mirrors every vault it owns to a linked server, new ones "
                       "included (default off). When on, the start service offers each vault that is not mirrored yet "
                       "and each new one as it is created (an offer the other server declined, or that ended, is not "
                       "made again until the setting is turned on again); with the other server's accept_all on it is "
                       "fully automatic. A vault whose preconditions refuse it waits until they pass. Super admins, a "
                       "person only; turning it on asks the keys step-up in the console (every vault's keys go "
                       "there). Audited mirror.mirror_all.set.",
        .payload = {str("peer").gen(gen::ref("peer", {"id"})), boolean("enabled").gen(gen::boolean())},
        .response = {object("peer", "", {uinteger("id"), str("node_id"), str("name")}), boolean("enabled"),
                     integer("set_by").nullable(), integer("set_at").nullable()},
        .refusal_codes = mcMirrorRefusals({"peer_not_linked"}),
        .client_timeout = kDefaultTimeout,
    });

    // ---- a change made on the mirror that the core refused (mirror::submit; ops::mirrors::held*)

    const auto heldFields = [] {
        return std::vector<WsField>{
            uinteger("id"), uinteger("vault_id"), str("kind").oneOf({"held", "conflict"}),
            str("op").oneOf({"mkdir", "move", "rename", "remove", "copy", "write"}), str("entry_uid").nullable(),
            str("path").nullable().desc("Where the person's version was (vault path)."),
            str("name").desc("The name the change gave the entry."),
            str("copy_name").nullable().desc("kind conflict: the name the person's version took."),
            object("person", "", {str("node"), uinteger("id")}).desc("Who made the change ({node, id})."),
            str("reason_code").desc("The core's refusal code (denied, not_found, conflict, ...)."), str("reason"),
            str("state").oneOf({"open", "retried", "discarded"}), integer("created_at"),
            integer("resolved_at").nullable()};
    };

    out.push_back({
        .command = "mirror.held.list",
        .description = "Changes made on this server to a vault it mirrors that the core refused (held: the entry came "
                       "back to the core's state, the change is kept with the reason) or turned into a conflict copy. "
                       "Super admins.",
        .payload = {uinteger("vault_id").opt().gen(gen::ref("vault", {"id"})).desc("One vault only."),
                    boolean("all").opt().gen(gen::boolean()).desc("Include discarded and retried ones.")},
        .response = {objectArray("held", "", heldFields())},
        .refusal_codes = mcMirrorRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.held.discard",
        .description = "Drops a held change (or dismisses a conflict record); nothing in the vault changes. Super "
                       "admins; audited mirror.held.discard.",
        .payload = {uinteger("id").gen(gen::ref("mirror.held", {"id"}))},
        .response = {object("held", "", heldFields())},
        .refusal_codes = mcMirrorRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.held.retry",
        .description = "Submits a held change to the core again as it was, as the person who made it; its result "
                       "comes back in the log (a new refusal is held again). The vault must be live here. Super "
                       "admins; audited mirror.held.retry.",
        .payload = {uinteger("id").gen(gen::ref("mirror.held", {"id"}))},
        .response = {object("held", "", heldFields())},
        .refusal_codes = [] {
            auto r = mcMirrorRefusals();
            r.push_back("mirror_read_only");
            return r;
        }(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.resync",
        .description = "Starts a copy that stopped (diverged, expired or stopped) over from its core's tree without "
                       "making it again: the core takes its baseline again in the next term and this server runs the "
                       "first copy over the entries it has (files whose bytes are here already are not fetched). "
                       "Changes still pending, this server's version of a file the core's replaces and anything the "
                       "core's tree does not hold are kept as held changes. The link must be up. Super admins; "
                       "audited mirror.resync.",
        .payload = {mcVaultIdField()},
        .response = {uinteger("vault_id"), str("state"), boolean("copy_finished"), uinteger("term"),
                     uinteger("held").desc("Changes that were pending, now held."),
                     integer("entries").desc("Entries in the core's new baseline.")},
        .refusal_codes = mcMirrorRefusals({"mirror_not_stopped", "mirror_core_unreachable", "mirror_core_gone",
                                           "mirror_paused", "mirror_resync_failed", "mirror_resync_refused"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.switch",
        .description = "A planned switch of the core role between the two servers of a mirrored vault, asked on "
                       "either server: the core stops taking changes (the vault is read-only on both servers, reason "
                       "mirror_switching), numbers its last change, waits for the mirror to apply it with the same "
                       "digest and nothing pending, then both record the next term with the roles swapped. The old "
                       "core keeps the vault only through the new core's role for it; with none the switch is "
                       "abandoned (mirror_switch_no_role) unless accept_no_access. Anything "
                       "that stops it before the core decides (a timeout, a refusal, a dropped link) changes nothing. "
                       "Local vaults only. Waits for the outcome: switched, abandoned (with the reason) or running. "
                       "Super admins of this server; audited mirror.switch.",
        .payload = {mcVaultIdField(),
                    boolean("accept_no_access").opt().desc("Go ahead even though the old core would hold no role on the "
                                                           "vault on its new core (refused otherwise, "
                                                           "mirror_switch_no_role).")},
        .response = {uinteger("vault_id"), str("switch_id"),
                     str("outcome").oneOf({"switched", "abandoned", "running"}),
                     str("role").nullable().desc("This server's role for the vault now."),
                     integer("role_term").nullable().desc("This server's term for the vault now."),
                     str("side").oneOf({"core", "mirror"}).desc("This server's role when the switch began."),
                     str("phase").oneOf({"requested", "draining", "preparing", "prepared", "switched", "abandoned"}),
                     uinteger("term").desc("The term the switch leaves."), integer("seq").nullable(),
                     str("digest").nullable(), integer("entries").nullable(),
                     boolean("told").desc("core: the mirror was told the decision."),
                     str("asked_on").oneOf({"core", "mirror"}),
                     object("asked_by", "", {str("node"), uinteger("id"), str("name")}).nullable(),
                     str("reason").nullable().desc("abandoned: why (mirror_switch_timeout, a refusal's code, ...)."),
                     object("detail").desc("What the other server last said, or why it ended."),
                     uinteger("deadline"), uinteger("created_at"), integer("ended_at").nullable(),
                     mcRoleObject("peer_role", "The role the old core holds on the vault on its new core (the new "
                                               "core's policy for it); null: none."),
                     str("peer_access").oneOf({"read-only", "read-write", "none"})
                         .desc("What that role allows, in a word.")},
        .refusal_codes = mcMirrorRefusals({"mirror_switch_no_role", "mirror_not_live", "mirror_first_copy",
                                           "mirror_switch_running",
                                           "mirror_submissions_queued", "mirror_has_remote", "mirror_pending_changes",
                                           "mirror_contents_missing", "mirror_core_unreachable", "mirror_core_gone",
                                           "mirror_switch_refused", "mirror_orphaned", "peer_link_down",
                                           "mirror_vault_deleting"}),
        .client_timeout = std::chrono::milliseconds(60'000),
    });

    out.push_back({
        .command = "peer.mirror.key",
        .description = "A key rotation on the core of a mirrored vault, before anything is sealed under the new "
                       "version: that version as a KEV1 envelope (suite X25519) to the receiver's peer wrap key, the "
                       "core's key check over its vault id and its attestation. The receiver (the vault's mirror for "
                       "this very server) proves it against the attestation keys it pinned at pairing and holds it "
                       "sealed under its own vault master with its origin; it becomes the current version there when "
                       "the core's log names it. The same key again: the same answer. Refused (mirror_key_refused) "
                       "when unprovable or when this server holds that version with another key; nothing is written.",
        .auth = "peer",
        .payload = mcGenerated("peer.mirror.key", {str("vault_uid"), uinteger("core_vault_id"),
                    uinteger("version").min(1), str("envelope").desc("KEV1, standard base64."),
                    str("key_check").desc("32 hex digits, over the core's vault id."),
                    object("attestation", "", {uinteger("key_id"), str("signature"), str("public_key").opt()})}),
        .response = {str("vault_uid"), uinteger("version"), boolean("installed")},
        .refusal_codes = mcWireRefusals({"mirror_key_refused"}),
        .client_timeout = std::chrono::milliseconds(30'000),
    });

    out.push_back({
        .command = "mirror.takeover",
        .description = "On a mirror whose core is gone or cannot be reached: take over as the vault's core. This server "
                       "records the next term with itself as the core, the last change it applied from the old core as "
                       "the fork point and its tree as the old core last confirmed it as the fork base (kept for the "
                       "old core's return); changes made here and still pending become ordinary changes, held ones stay "
                       "listed. Refused while the core answers (mirror_core_reachable: use mirror.switch). Also the way "
                       "out of a planned switch whose core never came back. `confirm` is the vault's name, typed. "
                       "Super admins, or holders of admin.mirror.takeover (Take over as core); the data.destroy "
                       "step-up in the console; audited mirror.takeover.",
        .payload = {mcVaultIdField(),
                    str("confirm").gen(gen::ref("vault", {"name"})).desc("The vault's name, typed exactly.")},
        .response = {uinteger("id"), uinteger("vault_id"), uinteger("peer_id").desc("The old core."),
                     uinteger("from_term"), uinteger("term").desc("This server's term as the core."),
                     object("fork", "", {uinteger("term"), uinteger("seq"), str("digest"), integer("entries")})
                         .desc("The fork point: the last change applied from the old core, and the digest there."),
                     uinteger("fork_rows").desc("Entries in the fork base."),
                     uinteger("pending_made_local"), uinteger("held"),
                     uinteger("contents_missing").desc("Files whose contents never arrived here."),
                     object("by", "", {integer("id").nullable(), str("name")}), uinteger("created_at"),
                     integer("settled_at").nullable(), str("settled_how").nullable(),
                     object("detail").desc("The fork base's own digest and whether it is the fork point's."),
                     str("warning"), boolean("fork_base_matches")},
        .refusal_codes = mcMirrorRefusals({"mirror_not_mirror", "mirror_orphaned", "mirror_first_copy", "mirror_diverged",
                                           "mirror_core_reachable", "mirror_name_mismatch"}),
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
                                         "mirror_name_taken", "mirror_no_space", "history_not_supported",
                                         "mirror_detached_copy"}),
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
        .description = "Either side cancels a start, or the core ends a mirror (remove_copy: it asks the mirror to "
                       "remove its copy). The core drops its core row and log. The mirror removes a copy whose first "
                       "copy isn't finished; a finished one it removes when asked and its keep setting is off, and "
                       "otherwise keeps orphaned (read-only, the last grant kept). Answers what it did.",
        .auth = "peer",
        .payload = mcGenerated("peer.mirror.cancel", {str("offer_uid").opt().nullable(), str("vault_uid"), str("reason").opt(),
                                                       boolean("remove_copy").opt()}),
        .response = {boolean("cancelled"),
                     str("copy").oneOf({"removed", "kept", "none"}).desc(
                         "What the mirror did with its copy: removed (the first copy wasn't finished, or removal was "
                         "asked and its link keeps nothing), kept (orphaned), or none (it held none).")},
        .refusal_codes = mcWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
