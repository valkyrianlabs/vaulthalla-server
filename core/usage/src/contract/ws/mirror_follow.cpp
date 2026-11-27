// ws book: peer.mirror.tree, peer.mirror.log, peer.mirror.ack, peer.mirror.notify, peer.mirror.submit
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
    return str("core_state").oneOf({"live", "paused", "diverged", "expired", "stopped"}).opt()
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
