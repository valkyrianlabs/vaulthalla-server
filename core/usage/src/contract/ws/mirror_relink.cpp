// ws book: relinking a vault two linked servers once mirrored (core/src/protocols/ws/handler/Mirrors.cpp and
// MirrorFollow.cpp; mirror/relink/Relink.hpp; design/peers/mirror.md "As built: relink"; migration 171).
//
// mirror.relink.* are "human" (a signed-in person, or a full-access paired device's session: never a scoped device, a
// relayed one, an agent or a share session: peer_forbidden), for super admins of this server. peer.mirror.relink.* are
// "peer": only on a linked server's own Peer session. Both servers agree, each by a super admin: the responder accepts
// the request before its tree is served, and approves the outcome before anything changes on it.

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

std::vector<std::string> mrRefusals(const std::vector<std::string>& extra = {}) {
    auto out = opsRefusals();
    out.emplace_back("peer_forbidden");
    for (const auto& e : extra) out.push_back(e);
    return out;
}

std::vector<std::string> mrWireRefusals(const std::vector<std::string>& extra = {}) {
    std::vector<std::string> out{"denied", "invalid", "not_found", "conflict", "unauthorized", "peer_revoked"};
    for (const auto& e : extra) out.push_back(e);
    return out;
}

const std::vector<std::string>& mrBlockerCodes() {
    static const std::vector<std::string> codes{"mirror_relink_mirrored", "mirror_relink_pending", "mirror_relink_switch",
                                                "mirror_relink_busy", "mirror_relink_deleting", "mirror_relink_keys"};
    return codes;
}

WsField mrPosition(std::string name, std::string desc) {
    return object(std::move(name), "", {uinteger("term"), uinteger("seq")}).nullable().desc(std::move(desc));
}

// One entry's version, as both servers describe it.
std::vector<WsField> mrVersionFields() {
    return {str("kind").oneOf({"file", "directory", "symlink"}), boolean("trashed"),
            str("path").desc("Vault-relative (a trashed file's: where it was)."), str("hash").desc("Its entry hash."),
            str("name"), str("parent").nullable().desc("Its folder's uid (the vault's uid at the top); null when trashed."),
            str("generation").opt(), uinteger("size").opt(), uinteger("key_version").opt(), str("content_hash").opt(),
            str("mime").opt(), str("target").opt(), integer("mode").opt()};
}

WsField mrVersion(std::string name, std::string desc) {
    return object(std::move(name), "", mrVersionFields()).nullable().desc(std::move(desc));
}

std::vector<WsField> mrBaseFields() {
    return {boolean("available"), str("source").desc("fork_base | rejoin | agreed | acknowledged | entry_hashes | kept"),
            object("at", "", {uinteger("term"), uinteger("seq")}).nullable()};
}

std::vector<WsField> mrSideFields() {
    return {uinteger("vault_id").desc("The vault's id on that server."), str("vault_uid"), str("vault_name"),
            str("node").desc("That server's node id."),
            str("status").oneOf({"detached", "ended", "orphaned", "rejoining", "forked", "core", "mirror", "unrelated"})
                .desc("What it holds of the vault: detached (it or its mirror detached), ended (its core ended the mirror "
                      "or the servers were unlinked), orphaned (the copy its core left), rejoining or forked (an old core "
                      "after a take over), core, mirror."),
            str("row_state").nullable(), uinteger("term").desc("The highest term its records of the vault reached."),
            mrPosition("agreed", "The last position it agreed on with the other server, when it knows one."),
            uinteger("pending").desc("Changes not yet confirmed or numbered there."), boolean("switch_running"),
            boolean("start_running"), boolean("deleting"), uinteger("contents_missing"), boolean("mirrored_elsewhere"),
            str("digest").desc("Its tree's digest now."), integer("entries")};
}

std::vector<WsField> mrGainsFields() {
    return {uinteger("takes").desc("Entries it takes from the other server's version."),
            uinteger("keeps_held").desc("Its versions that leave its tree, kept as held changes (with their bytes) or in "
                                        "the core's trash."),
            uinteger("conflict_copies").desc("Conflict copies it gains (keep both).")};
}

const std::vector<std::string>& mrPhases() {
    static const std::vector<std::string> phases{"requested", "accepted", "open", "proposed", "approved", "prepared",
                                                 "bring", "copying", "done", "failed", "stale", "cancelled", "declined",
                                                 "expired"};
    return phases;
}

// The outcome a responder's super admin approves (seen from the server that holds it).
WsField mrProposal() {
    return object("proposal", "", {str("plan_hash").desc("The plan's hash, as both servers compute it."),
                                   str("core").oneOf({"this", "theirs"}).desc("Which server becomes the core."),
                                   str("mode").oneOf({"plan", "override"}), object("this", "", mrGainsFields()),
                                   object("theirs", "", mrGainsFields()),
                                   object("chosen", "", {uinteger("core"), uinteger("mirror"), uinteger("both")}),
                                   uinteger("entries").desc("Drifted entries the plan decides.")})
        .nullable()
        .desc("The outcome proposed (null: none yet).");
}

WsField mrHandshake() {
    return object("handshake", "",
                  {str("waiting_for").oneOf({"other_admin", "this_admin", "this_compare", "other_compare"}).nullable()
                       .desc("other_admin: the other server's super admin is to accept the request or approve the "
                             "outcome; this_admin: this server's is; this_compare: accepted, compare now; null: nobody."),
                   integer("expires_at").nullable().desc("Until when the request (then its acceptance) holds."),
                   integer("accepted_at").nullable(), str("accepted_by").nullable(), integer("approved_at").nullable(),
                   str("approved_by").nullable(), mrProposal(),
                   str("outcome").nullable().desc("The responder: the outcome to approve, in plain words."),
                   str("discloses").nullable().desc("The responder: what accepting lets the other server see.")})
        .opt()
        .desc("Both servers agree, each by a super admin: to compare (the responder accepts the request), then to the "
              "outcome (it approves it).");
}

std::vector<WsField> mrRequestFields() {
    return {uinteger("vault_id"), str("vault_name"), str("relink_uid"),
            str("phase").oneOf({"requested", "accepted", "proposed", "approved", "declined", "cancelled", "expired"}),
            object("peer", "", {uinteger("id"), str("name"), str("node")}).desc("The linked server asking."),
            str("asked_by").desc("Who asked, on that server."), str("status").desc("What this server holds of the vault."),
            integer("created_at"), mrHandshake()};
}

std::vector<WsField> mrAnswerFields() {
    return {str("relink_uid"), str("phase").oneOf(mrPhases()), integer("expires_at").nullable(),
            str("accepted_by").nullable(), str("approved_by").nullable(),
            str("plan_hash").nullable().desc("Approved: the hash of the plan approved.")};
}

std::vector<WsField> mrStatusFields() {
    const auto gains = [] { return mrGainsFields(); };
    return {uinteger("vault_id"),
            object("relink", "", {uinteger("id"), str("relink_uid"), str("side").oneOf({"initiator", "responder"}),
                                  str("phase").oneOf(mrPhases()),
                                  str("mode").oneOf({"plan", "override"}), str("core").oneOf({"this", "theirs"}),
                                  str("default_choice").oneOf({"this", "theirs", "both"}).nullable(),
                                  str("role").oneOf({"core", "mirror"}).nullable(), integer("term").nullable(),
                                  str("error").nullable(),
                                  object("by", "", {str("node"), integer("id").nullable(), str("name")}),
                                  integer("created_at"), integer("applied_at").nullable(),
                                  integer("finished_at").nullable()})
                .nullable()
                .desc("The vault's open relink here, else its last; null: none."),
            object("peer", "", {uinteger("id"), str("name"), str("node")}).nullable().opt(),
            object("this", "", mrSideFields()).nullable().opt().desc("This server, when compared."),
            object("theirs", "", mrSideFields()).nullable().opt().desc("The other server, when compared."),
            object("counts", "", {uinteger("only_this").opt(), uinteger("only_theirs").opt(),
                                  uinteger("changed_this").opt(), uinteger("changed_theirs").opt(),
                                  uinteger("changed_both").opt(), uinteger("differs").opt(), uinteger("total").opt(),
                                  uinteger("same").opt()})
                .opt()
                .desc("Drifted entries by kind (changed_*: on both and changed on that side since the last position both "
                      "agreed on; differs: that cannot be told), and the entries that are the same."),
            object("keys", "", {boolean("match"), object("current", "", {uinteger("this"), uinteger("theirs")}),
                                intArray("mismatched")})
                .nullable()
                .opt()
                .desc("Whether both servers hold the same keys (by key check and origin; no key moves)."),
            object("base", "", {object("this", "", mrBaseFields()), object("theirs", "", mrBaseFields()), boolean("both")})
                .nullable()
                .opt()
                .desc("Each side's base (what it last agreed with the other), and whether both have one."),
            objectArray("blockers", "", {str("code"), str("side").oneOf({"this", "theirs", "both"}), str("message")})
                .opt()
                .desc("What refuses applying now."),
            object("plan", "", {object("this", "", gains()), object("theirs", "", gains()),
                                object("chosen", "", {uinteger("core"), uinteger("mirror"), uinteger("both")}),
                                str("core").oneOf({"this", "theirs"}),
                                str("default_choice").oneOf({"this", "theirs", "both"}).nullable()})
                .opt()
                .desc("What each server will gain and lose as the plan stands."),
            object("progress", "", {uinteger("bring_total"), uinteger("bring_done"), uinteger("executed"),
                                    uinteger("refused"), uinteger("kept"),
                                    object("row", "", {str("role"), str("state"), boolean("copy_finished"),
                                                       uinteger("copy_cursor"), uinteger("term"),
                                                       str("stop_reason").nullable()})
                                        .opt()
                                        .desc("The vault's mirror row here once applied.")})
                .opt()
                .desc("Applying: the versions brought onto the core, and the vault's mirror row."),
            mrHandshake()};
}

std::vector<WsField> mrEntryFields() {
    return {str("uid"),
            str("kind").oneOf({"only_this", "only_theirs", "changed_this", "changed_theirs", "changed_both", "differs"}),
            strArray("aspects").desc("place, contents, trashed, target, attributes; for an entry on one server only: "
                                     "created or removed, and by_this, by_theirs or by_both when known."),
            str("path").desc("Vault-relative: this server's, else the other's."),
            mrVersion("this", "This server's version; null: not here."),
            mrVersion("theirs", "The other server's version; null: not there."),
            str("choice").oneOf({"this", "theirs", "both"}).nullable().desc("null: the plan's default."),
            str("resolution").oneOf({"core", "mirror", "both"})
                .desc("What the plan does: the core's version stays, the future mirror's is brought onto the core, or "
                      "both (the mirror's as a conflict copy)."),
            str("outcome").nullable().desc("Applying: copied, executed, refused, kept."), str("outcome_note").nullable()};
}

}

std::vector<WsCommandUsage> mirrorRelinkCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "mirror.relink.compare",
        .description = "Compares a vault this server and a linked server both hold since a mirror between them ended "
                       "(detached, the core ended it or the servers were unlinked, an old core rejoining or forked after "
                       "a take over) with the other server's, by entry uid: what is only on one server, and what both "
                       "hold and changed on this side, the other or both since the last position both agreed on (differs "
                       "where that cannot be told). Entry hashes only: no file's contents are read. Kept as the vault's "
                       "open plan (replacing an open one): every entry the default (the core's), this server the core. "
                       "The first call asks the other server (relink phase requested): nothing of its tree is read until "
                       "a super admin there accepts; call again once they have. Super admins.",
        .payload = {vaultId(), str("peer").gen(gen::ref("peer", {"id"})).desc("The linked server.")},
        .response = mrStatusFields(),
        .refusal_codes = mrRefusals({"peer_not_linked", "peer_link_down", "mirror_core_unreachable", "mirror_relink_no_vault",
                                     "mirror_relink_unrelated", "mirror_relink_running", "mirror_relink_refused",
                                     "mirror_relink_asked", "mirror_relink_not_accepted"}),
        .client_timeout = std::chrono::milliseconds(120'000),
    });

    out.push_back({
        .command = "mirror.relink.get",
        .description = "The vault's open relink here (else its last): both sides, the drift counts, the keys, what "
                       "refuses applying, the plan with what each server gains and loses, and the progress of one being "
                       "applied. relink null: none. Super admins.",
        .payload = {vaultId()},
        .response = mrStatusFields(),
        .refusal_codes = mrRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.relink.entries",
        .description = "A page of the relink's drifted entries, by path, with both versions and the plan's choice and "
                       "resolution for each. Super admins.",
        .payload = {vaultId(),
                    str("kind").opt().oneOf({"only_this", "only_theirs", "changed_this", "changed_theirs",
                                             "changed_both", "differs"}),
                    uinteger("offset").opt(), uinteger("limit").opt().desc("1-500 (default 100).")},
        .response = {uinteger("vault_id"), uinteger("relink_id"), uinteger("total"), uinteger("offset"),
                     objectArray("entries", "", mrEntryFields())},
        .refusal_codes = mrRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.relink.plan",
        .description = "Changes the open plan: which server becomes the core (core), the choice for entries left unset "
                       "(default; \"\" is the core's), choices one at a time (set: {uid, choice}) or by kind (by_kind: "
                       "{kind, choice}; kind \"\" is every entry); a choice is this, theirs, both (files only: the future "
                       "mirror's version becomes a conflict copy beside the core's) or null (the default). A change to a "
                       "proposed plan withdraws it (the other server's approval is void). discard ends the relink at any "
                       "step before it is applied, the request included (the other server is told). Answers "
                       "mirror.relink.get. Super admins.",
        .payload = {vaultId(), str("core").opt().oneOf({"this", "theirs"}),
                    str("default").opt().oneOf({"", "this", "theirs", "both"}),
                    objectArray("set", "", {str("uid"), str("choice").nullable().oneOf({"this", "theirs", "both"})})
                        .opt(),
                    objectArray("by_kind", "", {str("kind"), str("choice").nullable().oneOf({"this", "theirs", "both"})})
                        .opt(),
                    boolean("discard").opt()},
        .response = mrStatusFields(),
        .refusal_codes = mrRefusals({"mirror_relink_no_plan"}),
        .client_timeout = kDefaultTimeout,
    });

    auto applyRefusals = mrRefusals({"mirror_name_mismatch", "mirror_relink_no_plan", "mirror_relink_stale",
                                     "mirror_relink_running", "mirror_relink_no_vault", "mirror_relink_unrelated",
                                     "mirror_relink_no_person", "mirror_relink_refused", "mirror_core_unreachable",
                                     "peer_not_linked", "peer_link_down", "mirror_relink_asked",
                                     "mirror_relink_not_accepted", "mirror_relink_not_approved"});
    for (const auto& c : mrBlockerCodes()) applyRefusals.push_back(c);
    out.push_back({
        .command = "mirror.relink.apply",
        .description = "Carries the open plan out, or with keep (this | theirs) compares again and keeps that server's "
                       "tree everywhere (the hard override). The chosen server becomes the vault's core in a term above "
                       "any either used, the other its mirror: the mirror first brings each entry whose chosen version "
                       "is its own onto the core as its own changes (contents over the sealed lane), then starts its "
                       "copy over from the core's tree. Nothing is dropped: what leaves a tree is a held change with its "
                       "bytes, a conflict copy, or in the core's trash. The detach, take over and rejoin records it "
                       "resolves settle. Refused when either tree changed since it was compared (mirror_relink_stale), "
                       "and while either server has pending changes, a switch, a start or a copy running, or is "
                       "deleting the vault. `confirm` is the vault's name, typed. Nothing changes before the other "
                       "server's super admin approved the outcome: the first call proposes it (relink phase proposed, "
                       "awaiting the other server's approval) and it is carried out once approved (this server's "
                       "follower, or this command again); with keep, each step waits as mirror.relink.compare does. "
                       "Answers mirror.relink.get; follow its progress there. Super admins; the keys step-up in the "
                       "console; audited mirror.relink on both servers.",
        .payload = {vaultId(), str("confirm").gen(gen::ref("vault", {"name"})).desc("The vault's name, typed exactly."),
                    str("keep").opt().oneOf({"this", "theirs"}),
                    str("peer").opt().gen(gen::ref("peer", {"id"})).desc("With keep: the linked server.")},
        .response = mrStatusFields(),
        .refusal_codes = applyRefusals,
        .client_timeout = std::chrono::milliseconds(180'000),
    });

    // ---- the other side of the handshake: this server's super admin, asked

    out.push_back({
        .command = "mirror.relink.pending",
        .description = "The relinks linked servers ask of this server's vaults that wait for an answer here (requested: "
                       "accept or decline; proposed: approve or decline the outcome), and those accepted or approved "
                       "and not carried out yet: who asks, which vault, what accepting lets them see, the outcome in "
                       "plain words. Super admins.",
        .payload = {},
        .response = {objectArray("requests", "", mrRequestFields())},
        .refusal_codes = mrRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.relink.accept",
        .description = "Accepts a linked server's request to relink the vault: it may compare its copy with this "
                       "vault's tree (file and folder names, places, sizes, hashes; never contents). Nothing changes "
                       "here until an outcome it proposes is approved (mirror.relink.approve). The acceptance holds a "
                       "day. Super admins, people only; audited on both servers.",
        .payload = {vaultId()},
        .response = mrRequestFields(),
        .refusal_codes = mrRefusals({"mirror_relink_no_request"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.relink.decline",
        .description = "Declines a linked server's relink of the vault: its request or the outcome it proposed. The "
                       "relink ends on both servers; neither vault changes. Super admins, people only; audited on both "
                       "servers.",
        .payload = {vaultId()},
        .response = mrRequestFields(),
        .refusal_codes = mrRefusals({"mirror_relink_no_request"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.relink.approve",
        .description = "Approves the outcome a linked server proposed for its relink of the vault: which server becomes "
                       "the core, the mode, and what this vault gains and loses (entries replaced or removed here, kept "
                       "as held changes or conflict copies). The other server then carries it out; this server prepares "
                       "only that plan (the same hash and counts, its tree unchanged): a changed plan or tree voids the "
                       "approval. `confirm` is the vault's name, typed. Super admins, people only; the keys step-up in "
                       "the console; audited on both servers.",
        .payload = {vaultId(), str("confirm").gen(gen::ref("vault", {"name"})).desc("The vault's name, typed exactly.")},
        .response = mrRequestFields(),
        .refusal_codes = mrRefusals({"mirror_relink_no_request", "mirror_relink_stale", "mirror_name_mismatch"}),
        .client_timeout = kDefaultTimeout,
    });

    // ---- a linked server's own session

    out.push_back({
        .command = "peer.mirror.relink.request",
        .description = "The other server asks to relink the vault with this uid: recorded here as waiting for a super "
                       "admin of this server (a day), answered with the request's phase and nothing of this server's "
                       "tree. Asked again, it answers how it stands (accepted, proposed, approved, declined, cancelled, "
                       "expired). not_found unless this server has a record of mirroring the vault with the asking "
                       "server.",
        .auth = "peer",
        .payload = {str("vault_uid").gen(gen::ref("mirror.relink", {"vault_uid"})),
                    str("relink_uid").gen(gen::ref("mirror.relink", {"relink_uid"})),
                    object("by", "", {str("node"), uinteger("id"), str("name")})
                        .gen(gen::ref("mirror.person", {"node", "id", "name"}))},
        .response = mrAnswerFields(),
        .refusal_codes = mrWireRefusals({"mirror_relink_running"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.relink.answer",
        .description = "The other server's super admin answered this server's relink: accepted (this server may compare), "
                       "approved (with the plan's hash: this server carries it out), declined (it ends), or voided (its "
                       "tree changed: propose again). Informational: each side checks its own records before acting.",
        .auth = "peer",
        .payload = {str("vault_uid").gen(gen::ref("mirror.relink", {"vault_uid"})),
                    str("relink_uid").gen(gen::ref("mirror.relink", {"relink_uid"})),
                    str("answer").oneOf({"accepted", "approved", "declined", "voided"}), str("by").opt(),
                    str("plan_hash").opt(), str("why").opt()},
        .response = {str("phase").oneOf(mrPhases())},
        .refusal_codes = mrWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.relink.propose",
        .description = "The other server proposes the outcome of a relink this server accepted, for a super admin here "
                       "to approve: which server becomes the core and the mode (seen from this server), what each "
                       "server gains and loses, both digests and the plan's hash. The same outcome again keeps an "
                       "approval; another one voids it. withdraw: the proposal (and an approval) is void. Refused when "
                       "this server's tree changed since it was compared.",
        .auth = "peer",
        .payload = {str("vault_uid").gen(gen::ref("mirror.relink", {"vault_uid"})),
                    str("relink_uid").gen(gen::ref("mirror.relink", {"relink_uid"})),
                    object("proposal", "", {str("plan_hash"), str("core").oneOf({"this", "theirs"}),
                                            str("mode").oneOf({"plan", "override"}), object("this", "", mrGainsFields()),
                                            object("theirs", "", mrGainsFields()),
                                            object("chosen", "", {uinteger("core"), uinteger("mirror"), uinteger("both")}),
                                            uinteger("entries"), object("digest", "", {str("digest"), integer("entries")}),
                                            object("their_digest", "", {str("digest"), integer("entries")}),
                                            object("by", "", {str("node"), uinteger("id"), str("name")})})
                        .opt()
                        .gen(gen::ref("mirror.relink", {"proposal"})),
                    boolean("withdraw").opt(), str("why").opt()},
        .response = mrAnswerFields(),
        .refusal_codes = mrWireRefusals({"mirror_relink_not_accepted", "mirror_relink_stale"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.relink.cancel",
        .description = "The other server ended its relink before it was applied (discarded, or replaced by a new "
                       "request): its request here ends; this vault did not change.",
        .auth = "peer",
        .payload = {str("vault_uid").gen(gen::ref("mirror.relink", {"vault_uid"})),
                    str("relink_uid").gen(gen::ref("mirror.relink", {"relink_uid"})), str("why").opt()},
        .response = {str("phase").oneOf(mrPhases())},
        .refusal_codes = mrWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.relink.state",
        .description = "A relink's other server asks what this server holds of the vault with this uid. Until a super "
                       "admin here accepted that relink (relink_uid): only its status (accepted false). Once accepted: "
                       "the highest term, the last position it agreed on with the asking server, what refuses a relink "
                       "here, its tree's digest and its key versions (key checks and origins, never a key). not_found "
                       "unless this server has a record of mirroring the vault with the asking server.",
        .auth = "peer",
        .payload = {str("vault_uid").gen(gen::ref("mirror.relink", {"vault_uid"})),
                    str("relink_uid").opt().gen(gen::ref("mirror.relink", {"relink_uid"}))},
        .response = [] {
            std::vector<WsField> f{boolean("accepted").desc("Whether this server's super admin accepted the relink.")};
            for (auto& x : mrSideFields()) {
                const bool always = x.name == "vault_uid" || x.name == "status";
                f.push_back(always ? std::move(x) : std::move(x).opt());
            }
            f.push_back(objectArray("keys", "", {uinteger("version"), boolean("current"), str("check").nullable(),
                                                 object("origin", "", {str("node"), uinteger("vault_id"), str("check")})
                                                     .nullable()})
                            .opt());
            return f;
        }(),
        .refusal_codes = mrWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.relink.tree",
        .description = "A page of this server's tree of the vault for a relink's comparison, by uid: each entry's "
                       "version (or null when only its base holds it) and its base hash (what this server last agreed "
                       "with the asking server). The tree is read at the first page (after 0) and paged from that read. "
                       "Refused (mirror_relink_not_accepted) unless a super admin here accepted the relink.",
        .auth = "peer",
        .payload = {str("vault_uid").gen(gen::ref("mirror.relink", {"vault_uid"})),
                    str("relink_uid").gen(gen::ref("mirror.relink", {"relink_uid"})),
                    mrPosition("since", "The asking server's agreed position.").opt()
                        .gen(gen::ref("mirror.relink", {"since"})),
                    uinteger("after").gen(gen::ref("mirror.relink", {"after"})),
                    uinteger("limit").gen(gen::ref("mirror.relink", {"limit"}))},
        .response = {objectArray("entries", "", {str("uid"), mrVersion("state", "null: only its base holds it."),
                                                 str("base").nullable()}),
                     boolean("more"), uinteger("next"), uinteger("total"),
                     object("base", "", mrBaseFields()).opt().desc("The first page: this server's base.")},
        .refusal_codes = mrWireRefusals({"mirror_relink_not_accepted"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.relink.prepare",
        .description = "A relink's plan for this server, in parts: its role (core or mirror), the term, and every "
                       "drifted entry with both versions and the choice seen from this server. The last part prepares it "
                       "here: the records the relink resolves settle; a future core keeps the versions the plan replaces "
                       "as held changes and starts the pair; a future mirror keeps what the core's tree replaces without "
                       "a trace, makes its conflict copies and holds a mirror row (stopped, mirror_relinking) until it "
                       "is told to go. Refused unless a super admin here approved the outcome (mirror_relink_not_"
                       "accepted, mirror_relink_not_approved), and when this server's tree changed since it was compared "
                       "or the plan is not the one approved (both void the approval).",
        .auth = "peer",
        .payload = {str("vault_uid").gen(gen::ref("mirror.relink", {"vault_uid"})),
                    str("relink_uid").gen(gen::ref("mirror.relink", {"relink_uid"})),
                    str("role").oneOf({"core", "mirror"}), uinteger("term").gen(gen::ref("mirror.relink", {"term"})),
                    str("mode").oneOf({"plan", "override"}), uinteger("part").gen(gen::ref("mirror.relink", {"part"})),
                    boolean("more").gen(gen::ref("mirror.relink", {"more"})),
                    objectArray("entries", "", {str("uid"), str("kind"), strArray("aspects"), str("path"),
                                                mrVersion("yours", "The receiving server's version."),
                                                mrVersion("mine", "The asking server's version."),
                                                str("choice").oneOf({"this", "theirs", "both"})})
                        .gen(gen::ref("mirror.relink", {"entries"})),
                    object("by", "", {str("node"), uinteger("id"), str("name")})
                        .gen(gen::ref("mirror.person", {"node", "id", "name"})),
                    object("digest", "", {str("digest"), integer("entries")})
                        .gen(gen::ref("mirror.digest", {"digest", "entries"}))},
        .response = {boolean("prepared"), uinteger("part"), str("phase").opt()},
        .refusal_codes = [] {
            auto r = mrWireRefusals({"mirror_relink_stale", "mirror_relink_running", "mirror_relink_no_person",
                                     "mirror_relink_not_accepted", "mirror_relink_not_approved"});
            for (const auto& c : mrBlockerCodes()) r.push_back(c);
            return r;
        }(),
        .client_timeout = std::chrono::milliseconds(120'000),
    });

    out.push_back({
        .command = "peer.mirror.relink.go",
        .description = "The relink's core is ready: this server, its future mirror, starts its copy over from the core's "
                       "tree at once, or first brings its chosen versions onto the core (the follower's pass). Told "
                       "again, it answers its phase. Refused unless a super admin here approved the relink.",
        .auth = "peer",
        .payload = {str("vault_uid").gen(gen::ref("mirror.relink", {"vault_uid"})),
                    str("relink_uid").gen(gen::ref("mirror.relink", {"relink_uid"}))},
        .response = {str("phase")},
        .refusal_codes = mrWireRefusals({"mirror_relink_not_accepted"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.relink.abort",
        .description = "The other server could not prepare its side: this server's prepared side ends (its new mirror "
                       "row goes; the vault is this server's own; what it settled stays settled).",
        .auth = "peer",
        .payload = {str("vault_uid").gen(gen::ref("mirror.relink", {"vault_uid"})),
                    str("relink_uid").gen(gen::ref("mirror.relink", {"relink_uid"})),
                    str("why").gen(gen::ref("mirror.relink", {"why"}))},
        .response = {str("phase")},
        .refusal_codes = mrWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
