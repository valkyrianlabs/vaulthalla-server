#include "mirror/submit/Submit.hpp"

#include "concurrency/ThreadPool.hpp"
#include "concurrency/ThreadPoolManager.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/SessionSettings.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/fs/AssignedUid.hpp"
#include "db/query/mirror/Apply.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Pending.hpp"
#include "db/query/peer/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/ops/file.hpp"
#include "fs/tree_apply/TreeApply.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "mirror/apply/Applier.hpp"
#include "mirror/submit/Contents.hpp"
#include "mirror/submit/Local.hpp"
#include "ops/Error.hpp"
#include "ops/Fs.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/Content.hpp"

#include <pqxx/pqxx>

#include <paths.h>

#include <atomic>
#include <cstdlib>
#include <mutex>
#include <regex>
#include <set>
#include <thread>
#include <utility>

namespace vh::mirror::submit {

namespace mq = vh::db::query::mirror;
namespace ta = vh::fs::tree_apply;
using json = nlohmann::json;

namespace {

std::atomic<bool>& submitInline() {
    static std::atomic<bool> v{false};
    return v;
}

std::atomic<int64_t>& submitPollPauseMs() {
    static std::atomic<int64_t> v{100};
    return v;
}

[[noreturn]] void submitNotFound() { throw vh::ops::NotFound("Not found"); }

std::string submitText(const json& j, const char* key) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_string() || it->get<std::string>().empty())
        throw vh::ops::Invalid(std::string(key) + " is required");
    return it->get<std::string>();
}

bool submitValidRequestId(const std::string& id) {
    static const std::regex re("^[a-z0-9-]{8,64}$");
    return std::regex_match(id, re);
}

bool submitValidUuid(const std::string& s) {
    static const std::regex re("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    return std::regex_match(s, re);
}

const std::set<std::string>& submitOps() {
    static const std::set<std::string> ops{"mkdir", "move", "rename", "remove", "copy", "write", "setattr"};
    return ops;
}

json submitAnswerOf(const mq::Submission& s) {
    json out{{"status", s.state}};
    if (s.groups) out["groups"] = *s.groups;
    if (s.code) out["code"] = *s.code;
    if (s.error) out["error"] = *s.error;
    return out;
}

// ---- executing on the core ----------------------------------------------------------------------------------------------

std::string submitEntryName(const json& args) {
    const auto name = submitText(args, "name");
    if (name == "." || name == ".." || name.find('/') != std::string::npos || name.find('\0') != std::string::npos ||
        name.size() > 255)
        throw vh::ops::Invalid("not a name: " + name);
    return name;
}

std::string submitJoin(const std::string& folder, const std::string& name) {
    return folder == "/" ? "/" + name : folder + "/" + name;
}

// The live entry with this uid in the vault: its vault path. NotFound when it is not live there.
std::string submitPathOf(const uint32_t vaultId, const std::string& uid) {
    const auto at = ta::locate(vaultId, uid);
    if (!at || at->trashed) throw vh::ops::NotFound("the entry is not in this vault (any more)");
    return at->path;
}

std::string submitFolderOf(const uint32_t vaultId, const std::string& vaultUid, const std::string& uid) {
    if (uid == vaultUid) return "/";
    const auto at = ta::locate(vaultId, uid);
    if (!at || at->trashed || at->kind != ta::Located::Kind::Directory)
        throw vh::ops::NotFound("destination folder does not exist");
    return at->path;
}

// A write: the file committed from the sealed bytes the mirror sent first (mirror::submit::contents::staged), never
// re-encrypted, so both servers hold the same bytes under the same generation. A create takes the mirror's uid and
// never replaces what is there (a conflict); a replacement is a compare-and-swap on the generation it was based on
// (content_conflict when the file moved on, or is gone).
void submitExecuteWrite(const vh::ops::Actor& actor, const uint32_t vaultId, const std::string& vaultUid,
                        const std::string& uid, const json& args) {
    const auto generation = args.value("generation", std::string{});
    const auto size = args.value("size", uint64_t{0});
    const auto keyVersion = args.value("key_version", 0u);
    const auto contentHash = args.value("content_hash", std::string{});
    const std::optional<std::string> mime =
        args.contains("mime") && args["mime"].is_string() ? std::optional<std::string>(args["mime"].get<std::string>())
                                                          : std::nullopt;
    std::optional<contents::StagedBytes> bytes;
    if (size > 0) {
        bytes = contents::staged(vaultId, uid, generation);
        if (!bytes) throw vh::ops::Refused("contents_missing", "the change's sealed bytes are not here");
        // Invariant 6: the row describes the bytes the core verified, never what the submit claims of them. A change
        // whose facts are not those of the bytes it sent is refused (the mirror keeps it as held).
        if (bytes->facts.key_version != keyVersion || bytes->facts.size != size ||
            bytes->facts.content_hash != contentHash)
            throw vh::ops::Refused("invalid_contents", "the change's facts are not those of the bytes it sent");
    }
    const std::optional<std::string> base =
        args.contains("base") && args["base"].is_string() ? std::optional<std::string>(args["base"].get<std::string>())
                                                          : std::nullopt;
    std::string path;
    std::optional<vh::db::query::fs::AssignedUid> assigned;
    if (base) {
        const auto at = ta::locate(vaultId, uid);
        if (!at || at->trashed) throw vh::ops::fs::ContentConflict("the file is not in this vault (any more)");
        path = at->path;
    } else {
        if (ta::locate(vaultId, uid)) throw vh::ops::Invalid("an entry with that uid exists already");
        path = submitJoin(submitFolderOf(vaultId, vaultUid, submitText(args, "parent_uid")), submitEntryName(args));
        assigned.emplace(vaultId, path, vh::crypto::id::fromUuid(uid));
    }
    vh::ops::fs::SealedCommit commit{.vault_id = vaultId, .path = path, .base = base};
    commit.sealed = [&](const std::filesystem::path& dst) {
        if (bytes) {
            contents::keep(bytes->path, dst);
        } else {
            vh::fs::ops::writeFileExclusive(dst, {}, 0600);
        }
        if (!bytes) return vh::fs::SealedContent{.plaintext_size = 0, .mime_type = mime};
        return vh::fs::SealedContent{.encryption_iv = bytes->facts.generation,
                                     .key_version = bytes->facts.key_version,
                                     .plaintext_size = bytes->facts.size,
                                     .mime_type = mime,
                                     .content_hash = bytes->facts.content_hash};
    };
    (void)vh::ops::fs::commitSealed(actor, commit);
    if (bytes) contents::dropStaged(*bytes);
}

void submitExecute(const mq::Submission& sub) {
    const auto vaultId = sub.vault_id;
    const auto& rid = sub.request_id;
    const auto mv = mq::MirrorVaults::get(vaultId);
    const auto vaultUid = mq::MirrorVaults::vaultUidOf(vaultId);
    const auto peer = vh::db::query::peer::Peers::byId(sub.peer_id);
    if (!mv || mv->role != "core" || mv->peer_id != sub.peer_id || !vaultUid || !peer) {
        mq::Pending::finish(vaultId, rid, "refused", std::nullopt, std::string("not_found"),
                            std::string("this server no longer holds the vault as mirrored with that server"));
        return;
    }
    if (peer->revoked()) {
        mq::Pending::finish(vaultId, rid, "refused", std::nullopt, std::string("peer_revoked"),
                            std::string("this link is unlinked"));
        return;
    }
    const auto& p = sub.payload;
    try {
        const auto& person = p.at("person");
        const auto node = person.at("node").get<std::string>();
        const auto id = person.at("id").get<uint32_t>();
        // The remote account for (the mirror's node id, the person's id there), never matched by name.
        const auto ownNode = vh::db::query::device::Devices::nodeId();
        const auto accountId = vh::db::Transactions::exec("mirror::submit account", [&](pqxx::work& txn) {
            return mq::ApplyRows::account(txn, ownNode, node, id);
        });
        if (!accountId) throw vh::ops::Invalid("the person has no account here");
        vh::ops::Actor actor;
        if (const auto& manager = vh::runtime::Deps::get().identityManager) actor = manager->user(*accountId);
        if (!actor) throw vh::ops::Invalid("the person has no account here");

        const vh::db::SessionSettings::Scope settings(mq::Pending::originSettings(rid, *accountId));
        const vh::ops::fs::PeerSubmission scope({.peer_id = sub.peer_id, .vault_id = vaultId, .request_id = rid,
                                                 .peer_node = peer->node_id});
        const auto op = p.at("op").get<std::string>();
        const auto uid = p.at("entry_uid").get<std::string>();
        const auto& args = p.contains("args") && p["args"].is_object() ? p["args"] : json::object();
        if (op == "mkdir") {
            if (ta::locate(vaultId, uid)) throw vh::ops::Invalid("an entry with that uid exists already");
            const auto path = submitJoin(submitFolderOf(vaultId, *vaultUid, submitText(args, "parent_uid")),
                                         submitEntryName(args));
            const vh::db::query::fs::AssignedUid assigned(vaultId, path, vh::crypto::id::fromUuid(uid));
            vh::ops::fs::mkdir(actor, vaultId, path);
        } else if (op == "move" || op == "rename" || op == "copy") {
            const auto from = submitPathOf(vaultId, uid);
            const auto to = submitJoin(submitFolderOf(vaultId, *vaultUid, submitText(args, "parent_uid")),
                                       submitEntryName(args));
            // rename(2) over an entry on the mirror: what is at the destination goes first (as the person's delete).
            if (op != "copy" && args.value("replace", false))
                if (const auto& manager = vh::runtime::Deps::get().storageManager)
                    if (const auto engine = manager->getEngine(vaultId);
                        engine && vh::fs::Filesystem::exists(engine->vaultPathToFusePath(to)))
                        vh::ops::fs::remove(actor, vaultId, to);
            if (op == "move") vh::ops::fs::move(actor, vaultId, from, to);
            else if (op == "rename") vh::ops::fs::rename(actor, vaultId, from, to);
            else vh::ops::fs::copy(actor, vaultId, from, to);
        } else if (op == "remove") {
            vh::ops::fs::remove(actor, vaultId, submitPathOf(vaultId, uid));
        } else if (op == "write") {
            submitExecuteWrite(actor, vaultId, *vaultUid, uid, args);
        } else if (op == "setattr") {
            vh::ops::fs::Attributes attrs;
            if (args.contains("mode") && args["mode"].is_number_unsigned()) attrs.mode = args["mode"].get<uint32_t>();
            if (args.contains("mtime_us") && args["mtime_us"].is_number_integer())
                attrs.mtime_us = args["mtime_us"].get<int64_t>();
            vh::ops::fs::setAttributes(actor, vaultId, submitPathOf(vaultId, uid), attrs);
        } else {
            throw vh::ops::Invalid("this server cannot execute " + op);
        }
        mq::Pending::finish(vaultId, rid, "executed", mq::Pending::originGroups(vaultId, rid), std::nullopt, std::nullopt);
        return;
    } catch (const std::exception& e) {
        std::string code = "error";
        if (dynamic_cast<const vh::ops::fs::ContentConflict*>(&e)) code = "content_conflict";
        else if (dynamic_cast<const vh::ops::Conflict*>(&e)) code = "conflict";
        else if (dynamic_cast<const vh::ops::NotFound*>(&e)) code = "not_found";
        else if (dynamic_cast<const vh::ops::Denied*>(&e)) code = "denied";
        else if (dynamic_cast<const vh::ops::Invalid*>(&e)) code = "invalid";
        else if (const auto* r = dynamic_cast<const vh::ops::Refused*>(&e)) code = r->code;
        else if (dynamic_cast<const vh::ops::Error*>(&e)) code = "refused";
        else if (dynamic_cast<const nlohmann::json::exception*>(&e)) code = "invalid";
        // Something of it was logged before it failed: what happened is the core's state, and its groups confirm it.
        if (const auto groups = mq::Pending::originGroups(vaultId, rid); groups > 0) {
            vh::log::Registry::sync()->warn("[MirrorSubmit] Vault {}: request {} failed after {} group(s): {}", vaultId,
                                            rid, groups, e.what());
            mq::Pending::finish(vaultId, rid, "executed", groups, code, std::string(e.what()));
            return;
        }
        vh::log::Registry::sync()->info("[MirrorSubmit] Vault {}: request {} refused ({}): {}", vaultId, rid, code,
                                        e.what());
        mq::Pending::finish(vaultId, rid, "refused", std::nullopt, code, std::string(e.what()));
    }
}

class SubmitDrainTask final : public vh::concurrency::Task {
public:
    explicit SubmitDrainTask(const uint32_t vaultId) : vaultId_(vaultId) {}
    void operator()() override;

private:
    uint32_t vaultId_;
};

std::mutex& submitDrainMutex() {
    static std::mutex m;
    return m;
}

std::set<uint32_t>& submitDraining() {
    static std::set<uint32_t> s;
    return s;
}

std::set<uint32_t>& submitAgain() {
    static std::set<uint32_t> s;
    return s;
}

void SubmitDrainTask::operator()() {
    for (;;) {
        {
            std::scoped_lock lock(submitDrainMutex());
            submitAgain().erase(vaultId_);
        }
        try {
            (void)drain(vaultId_);
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->warn("[MirrorSubmit] Vault {}: draining submissions failed: {}", vaultId_,
                                            e.what());
        }
        std::scoped_lock lock(submitDrainMutex());
        if (!submitAgain().contains(vaultId_)) {
            submitDraining().erase(vaultId_);
            return;
        }
    }
}

// ---- the mirror ------------------------------------------------------------------------------------------------------------

json submitPayload(const std::string& vaultUid, const mq::MirrorVault& mv, const mq::PendingChange& p) {
    json out{{"vault_uid", vaultUid},
             {"request_id", p.request_id},
             {"person", {{"node", p.actor.node}, {"id", p.actor.id}}},
             {"at", {{"term", mv.term}, {"seq", mv.last_seq}}},
             {"op", p.op},
             {"entry_uid", p.entry_uid},
             {"args", p.args}};
    if (p.base_generation) out["base_generation"] = *p.base_generation;
    return out;
}

// The entries of a change settle (confirmed, or executed with nothing to apply here): its row goes.
void submitSettleConfirmed(const mq::PendingChange& p) {
    const std::function<void(pqxx::work&)> also = [&](pqxx::work& txn) { mq::Pending::remove(txn, p.id); };
    const auto r = vh::mirror::apply::settle(p.vault_id, p.uids, also);
    if (r.status != vh::mirror::apply::Status::Applied)
        vh::log::Registry::sync()->warn("[MirrorSubmit] Vault {}: request {} confirmed, its entries not settled: {}",
                                        p.vault_id, p.request_id, r.reason);
    contents::dropBlob(contents::pendingBlob(p.vault_id, p.id));
}

mq::HeldChange submitHeldOf(const mq::PendingChange& p, const std::string& kind, const std::string& code,
                            const std::string& error) {
    mq::HeldChange h;
    h.vault_id = p.vault_id;
    h.kind = kind;
    h.request_id = p.request_id;
    h.op = p.op;
    h.entry_uid = p.entry_uid;
    h.args = p.args;
    h.actor = p.actor;
    h.reason_code = code;
    h.reason = error.empty() ? code : error;
    if (const auto at = ta::locate(p.vault_id, p.entry_uid)) h.path = at->path;
    return h;
}

// Refused for anything a copy would be refused for too: the entries settle back to the core's state and the person's
// version is kept as a held change.
void submitHold(const mq::PendingChange& p, const std::string& code, const std::string& error) {
    const auto held = submitHeldOf(p, "held", code, error);
    uint64_t heldId = 0;
    const std::function<void(pqxx::work&)> also = [&](pqxx::work& txn) {
        mq::Pending::remove(txn, p.id);
        heldId = mq::Pending::hold(txn, held);
    };
    // The person's sealed bytes stay with the held change (never dropped without their action).
    const auto keepBytes = [&] {
        if (heldId) contents::moveBlob(contents::pendingBlob(p.vault_id, p.id), contents::heldBlob(p.vault_id, heldId));
    };
    const auto r = vh::mirror::apply::settle(p.vault_id, p.uids, also);
    keepBytes();
    if (r.status == vh::mirror::apply::Status::Applied) {
        vh::log::Registry::sync()->info("[MirrorSubmit] Vault {}: request {} ({}) refused by the core ({}): held",
                                        p.vault_id, p.request_id, p.op, code);
        return;
    }
    // The vault is not live here: the change is kept all the same (its entries stay as they are until it is).
    vh::db::Transactions::exec("mirror::submit hold", [&](pqxx::work& txn) { also(txn); });
    keepBytes();
    vh::log::Registry::sync()->warn("[MirrorSubmit] Vault {}: request {} held; its entries not settled: {}", p.vault_id,
                                    p.request_id, r.reason);
}

// The name was taken on the core meanwhile: the entry takes its conflict name here and the change goes again under it.
// False when that is not possible (the entry is gone here, or this already was the conflict name).
bool submitConflictCopy(const mq::PendingChange& p, const std::string& code, const std::string& error) {
    const bool createdFile = p.op == "write" && !p.args.contains("base");
    if (p.op != "mkdir" && p.op != "move" && p.op != "rename" && !createdFile) return false;
    std::scoped_lock local(vaultMutex(p.vault_id));
    const auto at = ta::locate(p.vault_id, p.entry_uid);
    if (!at || at->trashed) return false;
    const auto name = p.args.value("name", std::string{});
    const auto copyName = conflictName(name, p.entry_uid, at->kind == ta::Located::Kind::Directory);
    if (name.empty() || name == copyName) return false;
    const auto& manager = vh::runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(p.vault_id) : nullptr;
    if (!engine) return false;
    const auto requestId = newRequestId();
    if (at->name != copyName) {
        const auto parent = std::filesystem::path(at->path).parent_path();
        const auto target = (parent.empty() ? std::filesystem::path("/") : parent) / copyName;
        if (vh::fs::Filesystem::exists(engine->vaultPathToFusePath(target.string()))) return false;
        std::shared_ptr<vh::identities::User> person;
        if (const auto& ids = vh::runtime::Deps::get().identityManager) person = ids->user(p.actor.id);
        const Local::Suppress suppress(p.vault_id);   // this server's own bringing-into-line: no new pending change
        const vh::db::SessionSettings::Scope settings(mq::Pending::localSettings(requestId));
        if (const auto err = vh::fs::Filesystem::rename(engine->vaultPathToFusePath(at->path),
                                                        engine->vaultPathToFusePath(target.string()), person, engine);
            err)
            return false;
    }
    auto args = p.args;
    args["name"] = copyName;
    auto record = submitHeldOf(p, "conflict", code, error);
    record.copy_name = copyName;
    vh::db::Transactions::exec("mirror::submit conflict", [&](pqxx::work& txn) {
        mq::Pending::resubmit(txn, p.id, requestId, args);
        (void)mq::Pending::hold(txn, record);
    });
    vh::log::Registry::sync()->info("[MirrorSubmit] Vault {}: request {} ({}): the name was taken on the core; "
                                    "resubmitted as {}",
                                    p.vault_id, p.request_id, p.op, copyName);
    return true;
}

// A replacement the core refused because the file moved on there (content_conflict): the file comes back to the
// core's state and the person's version becomes a new file beside it, "name (conflict <its uid>)", made here from the
// pending store and submitted as a create. False when that is not possible (held instead).
bool submitContentConflictCopy(const mq::PendingChange& p, const std::string& code, const std::string& error) {
    if (p.op != "write" || !p.args.contains("base")) return false;
    const auto blob = contents::pendingBlob(p.vault_id, p.id);
    const auto size = p.args.value("size", uint64_t{0});
    std::error_code ec;
    if (size > 0 && !std::filesystem::exists(blob, ec)) return false;
    const auto& manager = vh::runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(p.vault_id) : nullptr;
    if (!engine) return false;
    std::shared_ptr<vh::identities::User> person;
    if (const auto& ids = vh::runtime::Deps::get().identityManager) person = ids->user(p.actor.id);
    if (!person) return false;

    std::scoped_lock local(vaultMutex(p.vault_id));
    const auto newUid = vh::crypto::id::toUuid(vh::crypto::id::newObjectUid());
    const auto requestId = newRequestId();
    // Back to the core's state first; the row becomes the copy's create (dirty: nothing confirmed for it yet).
    std::optional<std::string> name, parentUid;
    if (const auto at = ta::locate(p.vault_id, p.entry_uid); at && !at->trashed) {
        name = at->name;
        parentUid = at->parent_uid;
    }
    if (!name || !parentUid) return false;
    const auto copyName = conflictName(*name, newUid, false);
    auto args = p.args;
    args.erase("base");
    args["uid"] = newUid;
    args["parent_uid"] = *parentUid;
    args["name"] = copyName;
    const std::function<void(pqxx::work&)> also = [&](pqxx::work& txn) {
        mq::Pending::resubmitAs(txn, p.id, requestId, newUid, args);
    };
    if (vh::mirror::apply::settle(p.vault_id, p.uids, also).status != vh::mirror::apply::Status::Applied) return false;

    // The person's bytes, as they are (the same generation and key version), under the copy's name and uid.
    const auto now = ta::locate(p.vault_id, p.entry_uid);
    const auto folder = now ? std::filesystem::path(now->path).parent_path() : std::filesystem::path("/");
    const auto path = (folder.empty() ? std::filesystem::path("/") : folder) / copyName;
    try {
        const Local::Suppress suppress(p.vault_id);
        const vh::db::SessionSettings::Scope settings(mq::Pending::localSettings(requestId));
        const vh::db::query::fs::AssignedUid assigned(p.vault_id, path, vh::crypto::id::fromUuid(newUid));
        vh::fs::NewFileContext ctx{.path = path, .fuse_path = engine->vaultPathToFusePath(path), .engine = engine,
                                   .user = person, .overwrite = true, .expected_source_id = std::string{}};
        ctx.sealed = [&](const std::filesystem::path& dst) {
            if (size > 0) contents::keep(blob, dst);
            else vh::fs::ops::writeFileExclusive(dst, {}, 0600);
            return vh::fs::SealedContent{
                .encryption_iv = p.args.value("generation", std::string{}),
                .key_version = p.args.value("key_version", 0u), .plaintext_size = size,
                .mime_type = p.args.contains("mime") ? std::optional<std::string>(p.args.value("mime", std::string{}))
                                                     : std::nullopt,
                .content_hash = size > 0 ? std::optional<std::string>(p.args.value("content_hash", std::string{}))
                                         : std::nullopt};
        };
        (void)vh::fs::Filesystem::createFile(ctx);
    } catch (const std::exception& e) {
        vh::log::Registry::sync()->warn("[MirrorSubmit] Vault {}: the conflict copy of request {} could not be made here "
                                        "({}); it is submitted all the same",
                                        p.vault_id, p.request_id, e.what());
    }
    auto record = submitHeldOf(p, "conflict", code, error);
    record.copy_name = copyName;
    vh::db::Transactions::exec("mirror::submit conflict", [&](pqxx::work& txn) { (void)mq::Pending::hold(txn, record); });
    vh::log::Registry::sync()->info("[MirrorSubmit] Vault {}: request {} (write): the file changed on the core; the "
                                    "person's version is resubmitted as {}",
                                    p.vault_id, p.request_id, copyName);
    return true;
}

void submitRefused(const mq::PendingChange& p, const std::string& code, const std::string& error) {
    if (code == "conflict" && submitConflictCopy(p, code, error)) return;
    if (code == "content_conflict" && submitContentConflictCopy(p, code, error)) return;
    submitHold(p, code, error);
    // A refused creation: the later changes of the entry it would have made (its contents written afterwards, a
    // rename) cannot succeed either; they are held with it, for the same reason, their bytes kept.
    const bool creation = p.op == "mkdir" || (p.op == "write" && !p.args.contains("base"));
    if (!creation) return;
    for (const auto& later : mq::Pending::list(p.vault_id))
        if (later.id > p.id && later.entry_uid == p.entry_uid && later.state != "executed")
            submitHold(later, code, "the change that would have made this entry was refused: " + error);
}

}

json serveSubmit(const uint32_t callerPeerId, const json& payload) {
    if (!payload.is_object()) throw vh::ops::Invalid("the payload is an object");
    const auto mv = mq::MirrorVaults::byVaultUid(submitText(payload, "vault_uid"));
    if (!mv || mv->peer_id != callerPeerId || mv->role != "core" || mv->state == "starting") submitNotFound();
    const auto rid = submitText(payload, "request_id");
    if (!submitValidRequestId(rid)) throw vh::ops::Invalid("request_id is 8 to 64 lower-case letters, digits or -");

    if (const auto known = mq::Pending::submission(mv->vault_id, rid)) {
        if (known->state == "queued" || known->state == "running") schedule(mv->vault_id);
        auto out = submitAnswerOf(*known);
        out["core_state"] = mv->state;
        return out;
    }

    const auto peer = vh::db::query::peer::Peers::byId(callerPeerId);
    if (!peer) submitNotFound();
    const auto person = payload.find("person");
    if (person == payload.end() || !person->is_object() || !person->contains("node") || !(*person)["node"].is_string() ||
        !person->contains("id") || !(*person)["id"].is_number_unsigned())
        throw vh::ops::Invalid("person is {node, id}");
    if ((*person)["node"].get<std::string>() != peer->node_id)
        throw vh::ops::Invalid("the person is one of the submitting server's own accounts");
    const auto op = submitText(payload, "op");
    if (!submitOps().contains(op)) throw vh::ops::Invalid("op is one of mkdir, move, rename, remove, copy");
    if (!submitValidUuid(submitText(payload, "entry_uid"))) throw vh::ops::Invalid("entry_uid is a uuid");
    if (payload.contains("args") && !payload["args"].is_object()) throw vh::ops::Invalid("args is an object");
    if (mv->state != "live") throw vh::ops::Refused("mirror_not_live", "the core holds this vault as " + mv->state);
    if (op == "write") {
        const auto& args = payload.contains("args") && payload["args"].is_object() ? payload["args"] : json::object();
        const auto size = args.contains("size") && args["size"].is_number_unsigned() ? args["size"].get<uint64_t>() : 0;
        const auto generation = args.contains("generation") && args["generation"].is_string()
                                    ? args["generation"].get<std::string>()
                                    : std::string{};
        // Contents travel sealed (VHF1, a 32-byte salt), as the sealed lane takes them; an empty file has none.
        if (size > 0 ? !vh::vault::content::isVhf1(generation) : !generation.empty())
            throw vh::ops::Invalid("a write's generation is a VHF1 salt (none for an empty file)");
        // The sealed bytes come first (PUT on the sealed lane): without them nothing is queued, and the mirror sends
        // them again (not an answer kept for the request).
        if (size > 0 && !contents::staged(mv->vault_id, payload.at("entry_uid").get<std::string>(), generation))
            throw vh::ops::Refused("contents_missing", "the change's sealed bytes are not here: send them first");
    }

    (void)mq::Pending::enqueue(mv->vault_id, callerPeerId, rid, payload);
    schedule(mv->vault_id);
    auto out = submitAnswerOf(mq::Pending::submission(mv->vault_id, rid).value_or(mq::Submission{.state = "queued"}));
    out["core_state"] = mv->state;
    return out;
}

std::size_t drain(const uint32_t vaultId) {
    // A running row is one a stop interrupted (this process runs one drain of a vault at a time).
    (void)mq::Pending::recoverRunning(vaultId);
    // What the core did with a request is kept as long as the log keeps its rows (30 days), then forgotten.
    (void)mq::Pending::sweep(std::chrono::hours(24 * 30));
    std::size_t n = 0;
    while (const auto sub = mq::Pending::claimNext(vaultId)) {
        submitExecute(*sub);
        ++n;
    }
    return n;
}

void schedule(const uint32_t vaultId) {
    if (submitInline().load()) {
        (void)drain(vaultId);
        return;
    }
    {
        std::scoped_lock lock(submitDrainMutex());
        if (submitDraining().contains(vaultId)) {
            submitAgain().insert(vaultId);
            return;
        }
        submitDraining().insert(vaultId);
    }
    try {
        vh::concurrency::ThreadPoolManager::instance().syncPool()->submit(std::make_shared<SubmitDrainTask>(vaultId));
    } catch (const std::exception& e) {
        std::scoped_lock lock(submitDrainMutex());
        submitDraining().erase(vaultId);
        vh::log::Registry::sync()->warn("[MirrorSubmit] Vault {}: submissions not scheduled: {}", vaultId, e.what());
    }
}

void setInlineForTesting(const bool inlineDrain) { submitInline().store(inlineDrain); }

void setPollPauseForTesting(const std::chrono::milliseconds pause) { submitPollPauseMs().store(pause.count()); }

SubmitStep submitPending(const uint32_t vaultId, vh::mirror::follow::Transport& transport,
                         const std::chrono::steady_clock::time_point deadline) {
    SubmitStep out;
    const auto mv = mq::MirrorVaults::get(vaultId);
    if (!mv || mv->role != "mirror" || mv->state != "live" || !mv->copy_finished) return out;
    const auto vaultUid = mq::MirrorVaults::vaultUidOf(vaultId);
    if (!vaultUid) return out;
    // Test instances only (VH_TEST_FAULT_DIR/mirror-submit-hold): nothing is submitted, so `vhh drill peers` can make
    // the core refuse a change, clash with it, or restart this server while changes wait. Never in a packaged daemon.
    if (vh::paths::testMode)
        if (const char* dir = std::getenv("VH_TEST_FAULT_DIR")) {
            std::error_code ec;
            if (std::filesystem::exists(std::filesystem::path(dir) / "mirror-submit-hold", ec)) {
                out.waiting = true;
                out.detail = "submit_held_for_testing";
                return out;
            }
        }
    {
        // A local row with no change running is one a stop left: submit it (the core decides, its answer settles).
        std::scoped_lock local(vaultMutex(vaultId));
        (void)mq::Pending::promoteLocal(vaultId);
    }
    while (std::chrono::steady_clock::now() < deadline) {
        std::optional<mq::PendingChange> next;
        for (const auto& p : mq::Pending::list(vaultId)) {
            if (p.state == "executed") {
                // Its answer came after its groups (or it logged none): settled here.
                if (p.confirmed()) submitSettleConfirmed(p);
                continue;
            }
            if (p.state == "pending" || p.state == "submitted") {
                next = p;
                break;
            }
            break;   // a change still being applied here: it and everything after it wait
        }
        if (!next) break;
        // A write's sealed bytes go first (the core never commits a mirror's file without its verified contents).
        if (next->op == "write" && next->state == "pending" && next->args.value("size", uint64_t{0}) > 0) {
            const auto blob = contents::pendingBlob(vaultId, next->id);
            const vh::mirror::follow::Transport::Content content{
                .vault_uid = *vaultUid, .object_uid = next->entry_uid,
                .generation = next->args.value("generation", std::string{}),
                .key_version = next->args.value("key_version", 0u), .size = next->args.value("size", uint64_t{0}),
                .content_hash = next->args.value("content_hash", std::string{}), .path = blob.string()};
            const auto sent = transport.sendContent(mv->peer_id, content);
            if (!sent.ok) {
                if (sent.retry) {
                    mq::Pending::noteError(next->id, "contents not sent: " + sent.error);
                    out.waiting = true;
                    out.detail = "contents_not_sent";
                    return out;
                }
                submitRefused(*next, sent.code.empty() ? std::string("invalid_contents") : sent.code, sent.error);
                ++out.submitted;
                continue;
            }
        }
        const auto a = transport.request(mv->peer_id, "peer.mirror.submit", submitPayload(*vaultUid, *mv, *next));
        if (!a) {
            mq::Pending::noteError(next->id, "no answer from the core");
            out.waiting = true;
            out.detail = "no_answer";
            return out;
        }
        if (!a->ok) {
            if (a->code == "not_found" || a->code == "peers_experimental" || a->code == "mirror_not_live" ||
                a->code == "peer_revoked" || a->code == "contents_missing") {
                mq::Pending::noteError(next->id, a->code + ": " + a->error);
                out.waiting = true;
                out.detail = a->code;
                return out;
            }
            // The core refused the request itself (malformed, not allowed at the wire): kept for the person.
            submitRefused(*next, a->code.empty() ? std::string("refused") : a->code, a->error);
            ++out.submitted;
            continue;
        }
        const auto status = a->data.value("status", std::string{});
        if (status == "queued" || status == "running") {
            mq::Pending::markSubmitted(next->id);
            const auto pause = std::chrono::milliseconds(submitPollPauseMs().load());
            if (std::chrono::steady_clock::now() + pause >= deadline) {
                out.waiting = true;
                out.detail = "with_the_core";
                return out;
            }
            if (pause.count() > 0) std::this_thread::sleep_for(pause);
            continue;
        }
        if (status == "executed") {
            const auto now = mq::Pending::markExecuted(next->id, a->data.value("groups", 0u));
            if (now && now->confirmed()) submitSettleConfirmed(*now);
            ++out.submitted;
            continue;
        }
        if (status == "refused") {
            submitRefused(*next, a->data.value("code", std::string("refused")), a->data.value("error", std::string{}));
            ++out.submitted;
            continue;
        }
        mq::Pending::noteError(next->id, "unknown answer: " + status);
        out.waiting = true;
        out.detail = "unknown_answer";
        return out;
    }
    return out;
}

}
