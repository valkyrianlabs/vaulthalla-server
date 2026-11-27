#include "mirror/submit/Local.hpp"

#include "crypto/id/ObjectUid.hpp"
#include "db/SessionSettings.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/fs/AssignedUid.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "mirror/access/Access.hpp"
#include "mirror/follow/Follower.hpp"
#include "mirror/submit/Contents.hpp"
#include "fs/model/File.hpp"
#include "ops/Error.hpp"
#include "rbac/Mirrored.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <map>
#include <utility>

namespace vh::mirror::submit {

namespace mq = vh::db::query::mirror;

struct Local::Scope {
    vh::db::SessionSettings::Scope settings;
    std::optional<vh::db::query::fs::AssignedUid> assigned;
    explicit Scope(std::vector<std::pair<std::string, std::string>> s) : settings(std::move(s)) {}
};

namespace {

std::shared_ptr<vh::storage::Engine> submitLocalEngine(const uint32_t vaultId) {
    const auto& manager = vh::runtime::Deps::get().storageManager;
    auto engine = manager ? manager->getEngine(vaultId) : nullptr;
    if (!engine) throw vh::ops::NotFound("No storage engine found for vault with ID: " + std::to_string(vaultId));
    return engine;
}

std::optional<uint32_t> submitLocalEntryId(const std::shared_ptr<vh::storage::Engine>& engine,
                                           const std::filesystem::path& vaultPath) {
    const auto entry = vh::runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(vaultPath));
    if (!entry) return std::nullopt;
    return entry->id;
}

// The folder a vault path is in ("/" for a top-level entry).
std::filesystem::path submitLocalParent(const std::filesystem::path& vaultPath) {
    auto normal = vaultPath.lexically_normal();
    if (!normal.has_filename() && normal.has_relative_path()) normal = normal.parent_path();
    const auto parent = normal.parent_path();
    return parent.empty() || parent == normal ? std::filesystem::path("/") : parent;
}

}

std::recursive_mutex& vaultMutex(const uint32_t vaultId) {
    static std::mutex guard;
    static std::map<uint32_t, std::unique_ptr<std::recursive_mutex>> locks;
    std::scoped_lock lock(guard);
    auto& m = locks[vaultId];
    if (!m) m = std::make_unique<std::recursive_mutex>();
    return *m;
}

std::string newRequestId() {
    std::array<unsigned char, 16> bytes{};
    randombytes_buf(bytes.data(), bytes.size());
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (const auto b : bytes) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

std::string conflictName(const std::string& name, const std::string& uid, const bool directory) {
    std::string shortUid;
    for (const char c : uid) {
        if (c == '-') continue;
        shortUid.push_back(c);
        if (shortUid.size() == 8) break;
    }
    const auto tag = " (conflict " + shortUid + ")";
    const auto dot = name.rfind('.');
    if (directory || dot == std::string::npos || dot == 0) return name + tag;
    return name.substr(0, dot) + tag + name.substr(dot);
}

namespace {

// The vaults a Local runs for (or is suppressed for) on this thread, innermost last.
std::vector<uint32_t>& submitLocalRunning() {
    thread_local std::vector<uint32_t> running;
    return running;
}

bool submitLocalRunningFor(const uint32_t vaultId) {
    const auto& r = submitLocalRunning();
    return std::ranges::find(r, vaultId) != r.end();
}

void submitLocalPop(const uint32_t vaultId) {
    auto& r = submitLocalRunning();
    if (const auto it = std::ranges::find(r.rbegin(), r.rend(), vaultId); it != r.rend()) r.erase(std::next(it).base());
}

}

Scratch::Scratch(const uint32_t vaultId) {
    if (vaultId == 0 || !vh::mirror::access::held(vaultId)) return;
    settings_.emplace(mq::Pending::scratchSettings());
}

Local::Suppress::Suppress(const uint32_t vaultId) : vault_(vaultId) { submitLocalRunning().push_back(vaultId); }

Local::Suppress::~Suppress() { submitLocalPop(vault_); }

Local::Local(const vh::ops::Actor& actor, const uint32_t vaultId, std::string op, const Mode mode)
    : actor_(actor), vaultId_(vaultId), op_(std::move(op)) {
    // A change is a local person's (a remote account names someone of another server: never this server's person).
    if (!actor_ || actor_->remote() || !vh::mirror::access::held(vaultId) || submitLocalRunningFor(vaultId)) return;
    if (!vh::mirror::access::acceptsLocalChanges()) return;
    const auto state = vh::mirror::access::state(vaultId);
    const bool sealWhileDown = mode == Mode::Seal && state == vh::mirror::access::State::ReadOnly &&
                               vh::mirror::access::reason(vaultId) == vh::mirror::access::kLinkDown;
    if (state != vh::mirror::access::State::Live && !sealWhileDown)
        return;   // the gate's line before this one refused already; nothing here changes that
    lock_ = std::unique_lock(vaultMutex(vaultId));
    active_ = true;
    submitLocalRunning().push_back(vaultId);
    pushed_ = true;
    requestId_ = newRequestId();
}

Local::~Local() {
    if (pushed_) submitLocalPop(vaultId_);
}

void Local::base(const std::string& generation) {
    if (!active_) return;
    base_ = generation;
    args_["base"] = generation;
}

void Local::content(const vh::fs::model::File& file) {
    if (!active_) return;
    args_["generation"] = file.encryption_iv;
    args_["key_version"] = file.encrypted_with_key_version;
    args_["size"] = file.size_bytes;
    args_["content_hash"] = file.content_hash.value_or(std::string{});
    if (file.mime_type) args_["mime"] = *file.mime_type;
    newGeneration_ = file.encryption_iv;
    if (file.size_bytes > 0) contentBacking_ = file.backing_path;
}

void Local::arg(const std::string& key, nlohmann::json value) {
    if (!active_) return;
    args_[key] = std::move(value);
}

void Local::on(const std::filesystem::path& vaultPath, const bool subtree) {
    if (!active_) return;
    const auto engine = submitLocalEngine(vaultId_);
    const auto id = submitLocalEntryId(engine, vaultPath);
    if (!id) throw vh::ops::NotFound("source does not exist: " + vaultPath.string());
    auto entries = mq::Pending::capture(*id, subtree);
    if (entries.empty()) throw vh::ops::NotFound("source does not exist: " + vaultPath.string());
    if (entryUid_.empty()) entryUid_ = entries.front().uid;
    if (!args_.contains("uid")) args_["uid"] = entries.front().uid;
    for (auto& e : entries) captured_.push_back(std::move(e));
}

std::string Local::creates(const std::filesystem::path& vaultPath) {
    if (!active_) return {};
    const auto uid = vh::crypto::id::toUuid(vh::crypto::id::newObjectUid());
    created_.push_back(uid);
    createdPath_ = vaultPath.lexically_normal();
    if (entryUid_.empty()) entryUid_ = uid;
    if (!args_.contains("uid")) args_["uid"] = uid;
    into(vaultPath);
    return uid;
}

void Local::into(const std::filesystem::path& vaultPath) {
    if (!active_) return;
    const auto parent = submitLocalParent(vaultPath);
    std::optional<std::string> parentUid;
    if (parent == "/") {
        parentUid = mq::MirrorVaults::vaultUidOf(vaultId_);
    } else {
        const auto engine = submitLocalEngine(vaultId_);
        if (const auto pid = submitLocalEntryId(engine, parent))
            parentUid = vh::db::Transactions::exec("mirror::submit parent uid", [&](pqxx::work& txn) {
                return mq::Pending::uidOfEntry(txn, *pid);
            });
    }
    if (!parentUid) throw vh::ops::NotFound("destination folder does not exist: " + parent.string());
    args_["parent_uid"] = *parentUid;
    args_["name"] = vaultPath.lexically_normal().filename().string();
}

void Local::submitOnly() { submitOnly_ = true; }

std::shared_ptr<Local::Scope> Local::scope() {
    auto s = std::make_shared<Scope>(mq::Pending::localSettings(requestId_));
    if (createdPath_ && !created_.empty())
        s->assigned.emplace(vaultId_, *createdPath_, vh::crypto::id::fromUuid(created_.front()));
    return s;
}

void Local::begin() {
    if (entryUid_.empty()) throw vh::ops::Invalid("a pending change names its entry");
    mq::NewPending change;
    change.vault_id = vaultId_;
    change.request_id = requestId_;
    change.entry_uid = entryUid_;
    change.op = op_;
    change.args = args_;
    change.actor = mq::Account{.node = vh::db::query::device::Devices::nodeId(), .id = actor_->id};
    // A change submitted without being applied here holds nothing dirty: its result comes back in the log.
    const auto row = submitOnly_ ? mq::Pending::open(change, {}, {}) : mq::Pending::open(change, captured_, created_);
    row_ = row.id;
}

void Local::failed() {
    if (!row_) return;
    try {
        if (submitOnly_ || mq::Pending::unchanged(vaultId_, captured_, created_)) {
            mq::Pending::abandon(*row_);
        } else {
            // Something of it happened here: the core decides, and its answer settles every entry it touched.
            mq::Pending::ready(*row_);
            vh::mirror::follow::Follower::instance()->wake(vaultId_);
        }
    } catch (const std::exception& e) {
        vh::log::Registry::sync()->warn("[MirrorSubmit] Vault {}: a failed change could not be settled: {}", vaultId_,
                                        e.what());
    }
}

void Local::succeeded() {
    // The sealed bytes go to the pending store first: nothing later done to the file here can take them before the
    // core has them.
    if (contentBacking_) vh::mirror::submit::contents::keep(*contentBacking_, contents::pendingBlob(vaultId_, *row_));
    mq::Pending::ready(*row_, args_, base_, newGeneration_);
    vh::mirror::follow::Follower::instance()->wake(vaultId_);
}

}
