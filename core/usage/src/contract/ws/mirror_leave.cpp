// ws book: leaving a mirror (core/src/protocols/ws/handler/MirrorLeave.cpp; ops/MirrorLeave.hpp, mirror/leave/Leave.hpp;
// design/peers/mirror.md "Leaving a mirror", "As built: leaving a mirror"). Server mirror phase 2, wave 5, piece A.
//
// mirror.detach.preview and mirror.detach are "human" (a signed-in person, or a full-access paired device's session:
// never a scoped device, a relayed one, an agent or a share session: peer_forbidden), for a super admin of this server
// or a holder of admin.mirror.detach. peer.mirror.detached is "peer": only on a linked server's own Peer session.

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

std::vector<std::string> mlRefusals(const std::vector<std::string>& extra = {}) {
    auto out = opsRefusals();
    out.emplace_back("peer_forbidden");
    for (const auto& e : extra) out.push_back(e);
    return out;
}

WsField mlPosition(std::string name, std::string desc) {
    return object(std::move(name), "", {uinteger("term"), uinteger("seq")}).desc(std::move(desc));
}

std::vector<WsField> mlPreviewFields() {
    return {uinteger("vault_id"), str("vault_name"),
            str("role").oneOf({"mirror", "orphaned"}),
            str("state").desc("live | paused | diverged | expired | stopped"),
            str("stop_reason").nullable(),
            object("peer", "", {uinteger("id"), str("node_id"), str("name"), boolean("revoked")}).nullable()
                .desc("The vault's core."),
            boolean("link_up"),
            object("first_copy", "", {boolean("finished"), uinteger("entries_copied"), uinteger("entries_total")})
                .desc("An unfinished first copy holds only the entries copied so far."),
            mlPosition("applied", "The last (term, seq) applied here: the fork point."),
            mlPosition("confirmed", "The last (term, seq) the core acknowledged with an equal digest.").nullable(),
            boolean("digest_matched").nullable().desc("At `confirmed`; false once the copy diverged; null: nothing "
                                                     "compared yet."),
            uinteger("pending_changes").desc("Changes made here not yet confirmed by the core: they become ordinary "
                                             "local changes."),
            uinteger("held_changes").desc("Held changes: they stay listed until discarded."),
            uinteger("missing_count"),
            objectArray("missing", "", {uinteger("file_id"), str("uid"), str("path"), uinteger("size_bytes"),
                                        str("state").oneOf({"waiting", "failed", "missing"}),
                                        str("last_error").nullable()})
                .desc("Every file whose contents are not on this server (vault-relative paths, shown only to someone "
                      "who may detach): after the detach each stays listed, marked missing, and an open fails with "
                      "mirror_contents_missing."),
            uinteger("owner_id").desc("The vault's owner here now (the core's owner, as a remote account).")};
}

std::vector<WsField> mlRecordFields() {
    return {uinteger("id"), str("side").oneOf({"mirror", "core"}), uinteger("vault_id"), uinteger("peer_id"),
            mlPosition("fork", "Where the copy left the core's log."), boolean("digest_matched").nullable(),
            str("was_state").nullable(), uinteger("missing"), integer("owner_id").nullable(),
            integer("detached_by").nullable(), integer("detached_at"), integer("rekeyed_at").nullable(),
            boolean("rekey_recommended").desc("The vault shares its uid and keys with the original until the re-key "
                                              "pass runs.")};
}

std::vector<WsField> mlCopyFields() {
    return {uinteger("id"), integer("source_vault_id").nullable().desc("The held vault it reads (null once it is gone)."),
            integer("vault_id").nullable().desc("The new vault: while it is written (read-only to everything but the "
                                                "copy) and once it is complete; null before it exists and after a "
                                                "failed or cancelled copy removed it."),
            str("name"), uinteger("owner_id"),
            str("state").oneOf({"running", "finished", "failed", "cancelled"}),
            uinteger("entries_total"), uinteger("entries_done"), uinteger("bytes_total"), uinteger("bytes_done"),
            uinteger("skipped_count"),
            objectArray("skipped", "", {str("path"), uinteger("size_bytes"),
                                        str("reason").oneOf({"contents_missing", "removed", "unreadable"})})
                .desc("The files left out, by path: contents that never arrived here (the detach preview's missing "
                      "list), and any removed or unreadable while the copy ran."),
            str("error").nullable(), integer("requested_by").nullable(), boolean("cancel_requested"),
            uinteger("attempts").desc("How often the copy started: a daemon restart removes the partial vault and "
                                      "starts again."),
            integer("created_at"), integer("updated_at"), integer("finished_at").nullable()};
}

}

std::vector<WsCommandUsage> mirrorLeaveCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "mirror.detach.preview",
        .description = "What detaching a vault this server holds as another server's copy would give, before anything "
                       "happens: the fork point, whether the digest matched there, the pending and held changes, and "
                       "every file whose contents are not here (the list to export). Changes nothing. Super admins, or "
                       "holders of admin.mirror.detach.",
        .payload = {vaultId()},
        .response = {object("preview", "", mlPreviewFields())},
        .refusal_codes = mlRefusals({"mirror_not_held"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.detach",
        .description = "Leave a mirror with its files: the held copy (live, stopped, diverged, expired or orphaned; the "
                       "link up, down or gone) becomes a standalone vault here, owned by `owner` (default: the caller), "
                       "without asking the core, which is told when it is reachable. One transaction: the mirror "
                       "record goes (no gate, no backstop), pending changes become ordinary local changes, held "
                       "changes stay listed, files whose contents never arrived stay marked missing, the linked "
                       "server's role goes. Nothing is deleted on either server; no bucket is touched. The vault keeps "
                       "the original's uid and keys until the re-key pass. No step-up; the console asks for the "
                       "vault's name (confirm_name). Super admins, or holders of admin.mirror.detach; audited "
                       "mirror.detach.",
        .payload = {vaultId(),
                    str("owner").opt().nullable().gen(gen::ref("user", {"name"}))
                        .desc("The new owner: a sign-in account here, by number or name."),
                    str("confirm_name").opt().nullable().gen(gen::ref("vault", {"name"}))
                        .desc("When given, it must be the vault's name exactly.")},
        .response = {object("detached", "",
                            {uinteger("vault_id"), uinteger("owner_id"), uinteger("missing"), uinteger("pending_kept"),
                             uinteger("pending_held").desc("Pending writes the file no longer held, kept as held "
                                                           "changes with their bytes."),
                             str("core_told").oneOf({"when_reachable", "no"}),
                             object("record", "", mlRecordFields()), object("before", "", mlPreviewFields())})},
        .refusal_codes = mlRefusals({"mirror_not_held"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.detach.copy",
        .description = "Detach a copy: write a new, separate local vault from a vault held here as another server's copy "
                       "(a mirror in any state, or orphaned; the link up, down or gone; nothing is asked of the core), "
                       "which stays exactly as it is. The new vault gets a new uid, new entry uids and its own new key, "
                       "is owned by `owner` (default: the caller) with the owner's ordinary access, and holds every "
                       "folder, file and symlink with its name, place, mode and modification time; not the trash, "
                       "versions, shares or access rules. Files whose contents never arrived here are left out and "
                       "listed. A background job: mirror.detach.copy.get shows its progress; while it runs the new vault "
                       "is read-only to everything else (mirror_copy_writing); a failure or a cancel removes it. Refused "
                       "when the volume's free space or the quota the new vault takes (the held vault's) can't hold "
                       "the copy (mirror_copy_no_space). Super admins, or holders of admin.mirror.detach; audited "
                       "mirror.detach.copy.",
        .payload = {vaultId(),
                    str("name").opt().nullable().desc("The new vault's name (default: \"<name> copy\")."),
                    str("owner").opt().nullable().gen(gen::ref("user", {"name"}))
                        .desc("The new owner: a sign-in account here, by number or name.")},
        .response = {object("copy", "", mlCopyFields())},
        .refusal_codes = mlRefusals({"mirror_not_held", "mirror_copy_no_space"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.detach.copy.get",
        .description = "The newest copy of a held vault (mirror.detach.copy): its state and progress (entries and "
                       "bytes done of the totals), the files it left out, its error; null when none was written here. "
                       "Super admins, or holders of admin.mirror.detach.",
        .payload = {vaultId()},
        .response = {object("copy", "", mlCopyFields()).nullable()},
        .refusal_codes = mlRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.detach.copy.cancel",
        .description = "Stop the running copy of a held vault: it removes its partial vault and ends cancelled (a "
                       "complete vault or none). Super admins, or holders of admin.mirror.detach; audited "
                       "mirror.detach.copy.cancel.",
        .payload = {vaultId()},
        .response = {object("copy", "", mlCopyFields())},
        .refusal_codes = mlRefusals({"mirror_copy_not_running"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.versions.set",
        .description = "Keep versions of what the core replaces or deletes, for a vault this server holds as another "
                       "server's mirror (default off): before the core's replacement, trash or delete of a file is "
                       "applied here, its prior generation is kept as a local version, bounded by keep_last, "
                       "max_age_days and quota_bytes (unset ones default to 10 versions and 30 days when turning it "
                       "on; 0 is no limit of that kind; at least one stays). This server's own state: never logged, "
                       "hashed or submitted. Read them with recovery.list|inspect (whoever may read the file here); "
                       "restoring one is a change made here (Live only). Super admins; audited mirror.versions.set.",
        .payload = {vaultId(), boolean("enabled").gen(gen::boolean()),
                    uinteger("keep_last").opt().nullable(), uinteger("max_age_days").opt().nullable(),
                    uinteger("quota_bytes").opt().nullable()},
        .response = {object("versions", "",
                            {boolean("enabled"), integer("keep_last").nullable(), integer("max_age_days").nullable(),
                             integer("quota_bytes").nullable(), integer("set_by").nullable(),
                             integer("set_at").nullable()})},
        .refusal_codes = mlRefusals({"mirror_not_held"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "mirror.held.get",
        .description = "A held write's bytes: the person's version, decrypted, inline (base64) up to 8 MiB; a larger "
                       "one is refused too_large (vh mirror save streams it). Nothing in the vault changes. Super "
                       "admins (whoever may list held changes).",
        .payload = {uinteger("id").gen(gen::ref("mirror.held", {"id"}))},
        .response = {object("held", "", {uinteger("id"), uinteger("vault_id"), str("kind"), str("op"),
                                         str("entry_uid").nullable(), str("path").nullable(), str("name"),
                                         str("copy_name").nullable(), object("person", "", {str("node"), uinteger("id")}),
                                         str("reason_code"), str("reason"), str("state"), integer("created_at"),
                                         integer("resolved_at").nullable()}),
                     str("name"), uinteger("size"), str("content_b64")},
        .refusal_codes = mlRefusals({"too_large"}),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.deleting",
        .description = "The core says whether it is deleting a mirrored vault (its retention window): deleting with the "
                       "date the purge is due and what it does to the copy (remove | leave, the mirror's keep setting "
                       "deciding on its side), or not (restored). The mirror pauses its copy (read-only, reason "
                       "mirror_core_deleting) or follows again where it was. Sent again on every link-up and whenever it "
                       "changes. Only from the vault's core (not_found otherwise).",
        .auth = "peer",
        .payload = {str("vault_uid").gen(gen::ref("peer.mirror.deleting", {"vault_uid"})),
                    boolean("deleting").gen(gen::boolean()),
                    integer("purge_after").opt().gen(gen::ref("peer.mirror.deleting", {"purge_after"})),
                    str("copy").opt().oneOf({"remove", "leave"})},
        .response = {boolean("recorded"), str("state")},
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized",
                          "peer_revoked"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.mirror.detached",
        .description = "The mirror detached its copy of a vault (told, not asked): the core ends the mirror on its "
                       "side as a cancel does (its core row, log, submissions and staged bytes go), records it (its "
                       "offer's copy becomes detached), audits mirror.detached, and leaves its own vault as it is. "
                       "Answers whether it recorded anything (a vault it holds no record of: false).",
        .auth = "peer",
        .payload = {str("offer_uid").opt().gen(gen::ref("peer.mirror.detached", {"offer_uid"})),
                    str("vault_uid").gen(gen::ref("peer.mirror.detached", {"vault_uid"})),
                    object("at", "", {uinteger("term"), uinteger("seq")}).opt()
                        .gen(gen::ref("peer.mirror.detached", {"at"})),
                    uinteger("missing").opt().gen(gen::ref("peer.mirror.detached", {"missing"}))},
        .response = {boolean("recorded"), uinteger("record").opt()},
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized",
                          "peer_revoked"},
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
