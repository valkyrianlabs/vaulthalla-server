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
#include "fs/tree_apply/TreeApply.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "mirror/apply/Applier.hpp"
#include "mirror/submit/Local.hpp"
#include "ops/Error.hpp"
#include "ops/Fs.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"

#include <pqxx/pqxx>

#include <atomic>
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
    static const std::set<std::string> ops{"mkdir", "move", "rename", "remove", "copy"};
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
            if (op == "move") vh::ops::fs::move(actor, vaultId, from, to);
            else if (op == "rename") vh::ops::fs::rename(actor, vaultId, from, to);
            else vh::ops::fs::copy(actor, vaultId, from, to);
        } else if (op == "remove") {
            vh::ops::fs::remove(actor, vaultId, submitPathOf(vaultId, uid));
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
    const std::function<void(pqxx::work&)> also = [&](pqxx::work& txn) {
        mq::Pending::remove(txn, p.id);
        (void)mq::Pending::hold(txn, held);
    };
    const auto r = vh::mirror::apply::settle(p.vault_id, p.uids, also);
    if (r.status == vh::mirror::apply::Status::Applied) {
        vh::log::Registry::sync()->info("[MirrorSubmit] Vault {}: request {} ({}) refused by the core ({}): held",
                                        p.vault_id, p.request_id, p.op, code);
        return;
    }
    // The vault is not live here: the change is kept all the same (its entries stay as they are until it is).
    vh::db::Transactions::exec("mirror::submit hold", [&](pqxx::work& txn) { also(txn); });
    vh::log::Registry::sync()->warn("[MirrorSubmit] Vault {}: request {} held; its entries not settled: {}", p.vault_id,
                                    p.request_id, r.reason);
}

// The name was taken on the core meanwhile: the entry takes its conflict name here and the change goes again under it.
// False when that is not possible (the entry is gone here, or this already was the conflict name).
bool submitConflictCopy(const mq::PendingChange& p, const std::string& code, const std::string& error) {
    if (p.op != "mkdir" && p.op != "move" && p.op != "rename") return false;
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

void submitRefused(const mq::PendingChange& p, const std::string& code, const std::string& error) {
    if (code == "conflict" && submitConflictCopy(p, code, error)) return;
    submitHold(p, code, error);
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

    (void)mq::Pending::enqueue(mv->vault_id, callerPeerId, rid, payload);
    schedule(mv->vault_id);
    auto out = submitAnswerOf(mq::Pending::submission(mv->vault_id, rid).value_or(mq::Submission{.state = "queued"}));
    out["core_state"] = mv->state;
    return out;
}

std::size_t drain(const uint32_t vaultId) {
    // A running row is one a stop interrupted (this process runs one drain of a vault at a time).
    (void)mq::Pending::recoverRunning(vaultId);
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
        const auto a = transport.request(mv->peer_id, "peer.mirror.submit", submitPayload(*vaultUid, *mv, *next));
        if (!a) {
            mq::Pending::noteError(next->id, "no answer from the core");
            out.waiting = true;
            out.detail = "no_answer";
            return out;
        }
        if (!a->ok) {
            if (a->code == "not_found" || a->code == "peers_experimental" || a->code == "mirror_not_live" ||
                a->code == "peer_revoked") {
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
