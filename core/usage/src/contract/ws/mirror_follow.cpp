// ws book: peer.mirror.tree, peer.mirror.log, peer.mirror.ack, peer.mirror.notify, peer.mirror.submit,
// peer.mirror.resync, peer.mirror.switch.request|prepare|commit (mirror::switching)
// (core/src/protocols/ws/handler/MirrorFollow.cpp; mirror::follow::Protocol; design/peers/mirror.md "As built: following the core"). The server
// mirror's data plane, between the two linked servers of a mirrored vault only ("peer": a linked server's own Peer
// session). Experimental: refused with peers_experimental while peers.experimental is off. A vault the caller is not
// the linked server of (or no such vault) answers not_found, exactly as the sealed lane does. Every answer stays under
// 768 KiB (the link's websocket takes at most 1 MiB a message).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

std::vector<std::string> mfRefusals() { return {"denied", "invalid", "not_found", "unauthorized", "peers_experimental"}; }

WsField mfVaultUid() {
    return str("vault_uid").gen(gen::ref("mirror.vault", {"uid"}))
        .desc("The mirrored vault's uid (UUID text): the same on both servers.");
}

WsField mfTerm() { return uinteger("term").gen(gen::ref("mirror.position", {"term"})); }
WsField mfSeq() { return uinteger("seq").gen(gen::ref("mirror.position", {"seq"})); }

WsField mfPosition(std::string name) {
    return object(std::move(name), "", {uinteger("term"), uinteger("seq")}).desc("A place in the vault's log.");
}

WsField mfCoreState() {
    return str("core_state").oneOf({"live", "paused", "diverged", "expired", "stopped", "switching", "rejoining", "forked"}).opt()
        .desc("The vault's state on the core: diverged stops the mirror too.");
}

std::vector<WsField> mfGroupFields() {
    return {uinteger("term"), uinteger("txid"), uinteger("first_seq"), uinteger("last_seq"),
            arrayOf("rows", object("", "", {uinteger("seq"),
                                             str("op").oneOf({"upsert", "move", "trash", "restore", "purge", "delete",
                                                              "vault", "key", "history"}),
                                             str("uid").nullable(), str("type").nullable(), object("state"),
                                             str("entry_hash").nullable(), str("prev_hash").nullable(),
                                             object("actor", "", {str("node"), uinteger("id")}).nullable(),
                                             str("origin").nullable().desc(
                                                 "The mirror's request id when the change was one it submitted "
                                                 "(peer.mirror.submit).")}))
                .desc("The group's log rows in order (vault_replication_log: state documents, 64-hex hashes).")};
}

}

std::vector<WsCommandUsage> mirrorFollowCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "peer.mirror.tree",
        .description = "The mirror's first copy: a page of the core's tree as of its baseline (the state documents of "
                       "the replication log, a folder before what is under it, trashed files last), after `after`. "
                       "expired once the baseline is gone (the mirror acknowledged it).",
        .auth = "peer",
        .payload = {mfVaultUid(), uinteger("after").opt().gen(gen::intRange(0, 1000))
                                      .desc("The last baseline entry the mirror holds (0 first).")},
        .response = {boolean("expired").opt(), mfPosition("baseline").opt(),
                     str("digest").opt().desc("The baseline's digest (64 hex)."), integer("entries").opt(),
                     uinteger("rows").opt().desc("Entries the baseline serves."),
                     object("vault").opt().desc("The vault's document then (the first page only)."),
                     arrayOf("items", object("", "", {uinteger("ord"), object("state")})).opt(),
                     boolean("more").opt(), mfCoreState()},
        .refusal_codes = mfRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.log",
        .description = "Whole groups of the core's log after (term, seq), at most 2,000 rows and 768 KiB; a single "
                       "group larger than that comes in parts (part, asked again with the group's txid and the last "
                       "seq held) and is applied whole. expired below retention or when the vault is no longer the "
                       "core's.",
        .auth = "peer",
        .payload = {mfVaultUid(), mfTerm(), mfSeq(),
                    object("part", "", {uinteger("txid").gen(gen::ref("mirror.group", {"txid"})),
                                        uinteger("after_seq").gen(gen::ref("mirror.group", {"after_seq"}))})
                        .opt()},
        .response = {boolean("expired").opt(), arrayOf("groups", object("", "", mfGroupFields())).opt(),
                     mfPosition("last").opt(), boolean("more").opt(),
                     object("part", "", [] {
                         auto f = mfGroupFields();
                         f.push_back(boolean("complete"));
                         return f;
                     }()).opt(),
                     mfCoreState()},
        .refusal_codes = mfRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.ack",
        .description = "The mirror applied everything through (term, seq) and its digest there is `digest`. The core "
                       "compares it with its own: equal, the acknowledgement is recorded (retention may pass it, the "
                       "baseline is dropped); different, the vault stops as diverged on both servers.",
        .auth = "peer",
        .payload = {mfVaultUid(), mfTerm(), mfSeq(),
                    str("digest").gen(gen::ref("mirror.digest", {"digest"})).desc("64 hex digits."),
                    integer("entries").gen(gen::ref("mirror.digest", {"entries"}))},
        .response = {boolean("known").desc("The core can say its digest at that position."), boolean("match"),
                     boolean("recorded"), str("core_digest").nullable(), integer("core_entries").nullable()},
        .refusal_codes = mfRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.notify",
        .description = "The core numbered groups of the vault through (term, seq): the mirror's follower looks now. "
                       "Coalesced, never waited for; a lost one is harmless (the follower also polls).",
        .auth = "peer",
        .payload = {mfVaultUid(), mfTerm(), mfSeq()},
        .response = {},
        .refusal_codes = mfRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.resync",
        .description = "The mirror starts its copy over (mirror.resync on the mirror): the core takes its baseline "
                       "again in the next term (its log, entry hashes, submissions and baseline for the vault start "
                       "again) and answers the new term and baseline. The caller must be the vault's mirror; a paused "
                       "vault is refused.",
        .auth = "peer",
        .payload = {mfVaultUid()},
        .response = {uinteger("term"), object("baseline", "", {mfTerm(), mfSeq()}).desc("The new baseline's position."),
                     integer("entries")},
        .refusal_codes = [] {
            auto r = mfRefusals();
            r.push_back("mirror_paused");
            r.push_back("mirror_resync_failed");
            r.push_back("peer_revoked");
            return r;
        }(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- the planned switch (mirror/switching/Switch.hpp)

    const auto switchId = [] {
        return str("switch_id").gen(gen::ref("mirror.switch", {"switch_id"})).desc("The switch's id (UUID), the same on "
                                                                                   "both servers.");
    };
    out.push_back({
        .command = "peer.mirror.switch.request",
        .description = "A super admin of the mirror asked for a planned switch (mirror.switch there): the core begins "
                       "one (it freezes the vault, numbers its last change and prepares the mirror) and answers at "
                       "once with the switch's id; the decision comes later as peer.mirror.switch.commit. The caller "
                       "must be the vault's mirror.",
        .auth = "peer",
        .payload = {mfVaultUid(),
                    object("by", "", {uinteger("id").desc("The person's account id on the mirror."),
                                      str("name").opt().desc("Their display name (attribution only).")})
                        .gen(gen::ref("mirror.person", {"id", "name"}))
                        .desc("Who asked."),
                    boolean("accept_no_access").opt().desc("The person accepted that the core may hold no role on the "
                                                           "vault on the mirror afterwards.")},
        .response = {switchId(), uinteger("term").desc("The term the switch leaves.")},
        .refusal_codes = [] {
            auto r = mfRefusals();
            for (const auto* c : {"peer_revoked", "conflict", "mirror_not_live", "mirror_switch_running",
                                  "mirror_submissions_queued", "mirror_has_remote"})
                r.emplace_back(c);
            return r;
        }(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.switch.prepare",
        .description = "The core froze the vault for a planned switch: its last change is (term, seq) with `digest`. "
                       "The mirror becomes read-only too and catches up; it answers ready once it is there with the "
                       "same digest, nothing pending or dirty and every file's contents held, and then waits for the "
                       "decision (it never decides on its own). Asked again until ready or the core's deadline; a "
                       "refusal ends the switch on both servers with nothing changed.",
        .auth = "peer",
        .payload = {mfVaultUid(), switchId(), mfTerm(), mfSeq(),
                    str("digest").gen(gen::ref("mirror.digest", {"digest"})).desc("64 hex digits."),
                    integer("entries").gen(gen::ref("mirror.digest", {"entries"})),
                    object("by", "", {str("node"), uinteger("id"), str("name"), str("on").oneOf({"core", "mirror"})})
                        .nullable().opt().gen(gen::ref("mirror.person", {"node", "id", "name", "on"}))
                        .desc("Who asked, and on which server.")},
        .response = {boolean("ready"),
                     str("waiting").oneOf({"busy", "applying"}).opt()
                         .desc("Not ready yet: a change here holds the vault (busy), or the mirror is applying."),
                     mfPosition("at").nullable().desc("Where the mirror stands."),
                     str("digest").nullable(), integer("entries").nullable(),
                     object("peer_role", "", {str("role_name"), uinteger("files"), uinteger("directories"),
                                              uinteger("sync"), uinteger("roles")})
                         .nullable().opt()
                         .desc("The role the core will hold on the vault here once this server is its core (this "
                               "server's policy for it); null: none, and the core abandons the switch "
                               "(mirror_switch_no_role) unless the person accepted that.")},
        .refusal_codes = [] {
            auto r = mfRefusals();
            for (const auto* c : {"peer_revoked", "mirror_not_live", "mirror_first_copy", "mirror_term_mismatch",
                                  "mirror_switch_ended", "mirror_pending_changes", "mirror_contents_missing",
                                  "mirror_ahead", "mirror_digest_mismatch"})
                r.emplace_back(c);
            return r;
        }(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.switch.commit",
        .description = "The core's decision on a planned switch, told until answered. switched: the core is the "
                       "vault's mirror in term + 1 now and the mirror becomes its core (its log starts at (term + 1, "
                       "1)); abandoned: nothing changed, and a mirror that prepared goes live again. Told again, it "
                       "answers the same.",
        .auth = "peer",
        .payload = {mfVaultUid(), switchId(), str("outcome").oneOf({"switched", "abandoned"}),
                    str("reason").opt().gen(gen::ref("mirror.switch", {"reason"})).desc("abandoned: why.")},
        .response = {str("outcome").oneOf({"switched", "abandoned"}),
                     uinteger("term").opt().desc("switched: the new term."),
                     object("peer_role", "", {str("role_name"), uinteger("files"), uinteger("directories"),
                                              uinteger("sync"), uinteger("roles")})
                         .nullable().opt()
                         .desc("switched: the role the old core holds on the vault on the new core (its ceiling); "
                               "null: none.")},
        .refusal_codes = [] {
            auto r = mfRefusals();
            r.emplace_back("peer_revoked");
            r.emplace_back("mirror_not_prepared");
            return r;
        }(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.promoted",
        .description = "The new core tells its old core it took over (mirror.takeover), on every pass while the link is "
                       "up until answered: the new term, the fork point and its digest, and the new core's digest at "
                       "(term, 0). The old core stops taking changes for the vault at once (read-only) and answers "
                       "pending until it decided: following (it committed nothing after the fork point: the vault's "
                       "mirror in the new term), rejoining (it did: read-only with them until the merge; changes is "
                       "their count) or forced (it had taken over too: both read-only until an operator picks one).",
        .auth = "peer",
        .payload = {mfVaultUid(), uinteger("term").gen(gen::ref("mirror.position", {"term"})).desc("The new term."),
                    object("fork", "", {uinteger("term"), uinteger("seq"), str("digest"), integer("entries")})
                        .gen(gen::ref("mirror.takeover", {"fork"}))
                        .desc("The last position the new core applied from the old one, and its digest there."),
                    object("baseline", "", {str("digest"), integer("entries")})
                        .opt().gen(gen::ref("mirror.takeover", {"baseline"}))
                        .desc("The new core's digest at (term, 0).")},
        .response = {str("outcome").oneOf({"pending", "following", "rejoining", "forced"}),
                     uinteger("changes").opt().desc("rejoining: the old core's changes past the fork point.")},
        .refusal_codes = [] {
            auto r = mfRefusals();
            r.emplace_back("peer_revoked");
            r.emplace_back("mirror_term_stale");
            return r;
        }(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.submit",
        .description = "A change made on the mirror, submitted to the core, which executes it as that person (the "
                       "linked server's vault role is the ceiling) and logs it with the request id in `origin`. "
                       "Answered at once: a new request is queued and executed in order on the core; asked again with "
                       "the same request id, the core answers what it did the first time (never twice): running, "
                       "executed with the number of groups it logged, or refused with the code (conflict: the name "
                       "was taken; anything else is kept on the mirror as a held change).",
        .auth = "peer",
        .payload = {mfVaultUid(),
                    str("request_id").gen(gen::ref("mirror.submit", {"request_id"}))
                        .desc("The mirror's id for the change (8-64 lower-case letters, digits or -)."),
                    object("person", "", {str("node").desc("The mirror's node id."),
                                          uinteger("id").desc("The person's account id on the mirror.")})
                        .gen(gen::ref("mirror.person", {"node", "id"})),
                    mfPosition("at").gen(gen::ref("mirror.position", {"term", "seq"}))
                        .desc("The position the mirror had applied when it submitted."),
                    str("op").oneOf({"mkdir", "move", "rename", "remove", "copy", "write", "setattr"}),
                    str("entry_uid").gen(gen::ref("mirror.entry", {"uid"}))
                        .desc("The entry the change is on (UUID text); a created folder's uid, chosen by the mirror."),
                    object("args", "", {str("uid").opt().desc("The entry's uid, as entry_uid."),
                                        str("parent_uid").opt().desc("The destination folder's uid (the vault's uid "
                                                                     "for its root)."),
                                        str("name").opt().desc("The entry's name there."),
                                        boolean("replace").opt().desc("move, rename: an entry at the destination goes "
                                                                      "first (rename(2) over it)."),
                                        str("base").opt().desc("write: the generation a replacement was based on "
                                                               "(absent: a create)."),
                                        str("generation").opt().desc("write: the new generation (its sealed bytes "
                                                                     "were PUT on the sealed lane first)."),
                                        uinteger("key_version").opt(), uinteger("size").opt().desc("write: plaintext."),
                                        str("content_hash").opt().desc("write: BLAKE2b of the sealed bytes."),
                                        str("mime").opt(),
                                        uinteger("mode").opt().desc("setattr: the permission bits."),
                                        integer("mtime_us").opt().desc("setattr: the modification time.")})
                        .opt().desc("Where the entry goes (mkdir, move, rename, copy), a write's contents, "
                                    "setattr's values."),
                    str("base_generation").opt().desc("The generation the change was based on (contents).")},
        .response = {str("status").oneOf({"queued", "running", "executed", "refused"}),
                     uinteger("groups").opt().desc("executed: the groups the core logged for it."),
                     str("code").opt().desc("refused (or executed in part): the refusal's code."),
                     str("error").opt(), mfCoreState()},
        .refusal_codes = {"denied", "invalid", "not_found", "unauthorized", "peers_experimental", "peer_revoked",
                          "mirror_not_live", "contents_missing"},
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
