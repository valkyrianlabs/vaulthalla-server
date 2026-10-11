#include "identities/Manager.hpp"

#include "db/query/identities/Group.hpp"
#include "db/query/identities/Loader.hpp"
#include "db/query/identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"

#include <algorithm>
#include <stdexcept>

namespace vh::identities {

namespace {

using db::query::identities::IdentitySelection;
using db::query::identities::IdentitySnapshot;
using db::query::identities::Loader;

constexpr auto kPruneEvery = std::chrono::hours(1);
constexpr auto kChangeLogRetention = std::chrono::hours(24);

// One publication: odd while states are being stored, even once they all are (see detail::publicationSeq).
// Every operation on the sequence and on the published states is sequentially consistent (no fences: they are not
// modelled by ThreadSanitizer, and publications are rare).
struct Publication {
    Publication() { detail::publicationSeq.fetch_add(1); }
    ~Publication() { detail::publicationSeq.fetch_add(1); }
    Publication(const Publication&) = delete;
    Publication& operator=(const Publication&) = delete;
};

void sortUnique(std::vector<uint32_t>& v) {
    std::ranges::sort(v);
    v.erase(std::unique(v.begin(), v.end()), v.end());
}

std::shared_ptr<const UserState> tombstone(const UserState& last, const uint64_t revision) {
    auto t = std::make_shared<UserState>(last);
    t->deleted = true;
    t->meta.is_active = false;
    t->roles = {};
    t->groups.clear();
    t->joinedAt.clear();
    t->revision = revision;
    return t;
}

std::shared_ptr<const GroupState> tombstone(const GroupState& last, const uint64_t revision) {
    auto t = std::make_shared<GroupState>(last);
    t->deleted = true;
    t->roles = {};
    t->revision = revision;
    return t;
}

}

// ------------------------------------------------------------------------------------------------ reads

template <typename T>
std::shared_ptr<T> Manager::lookupOrLoad(const Key key, const uint32_t number, const std::string& text) {
    const auto find = [&](const Index& idx) -> std::shared_ptr<T> {
        const auto pick = [](const auto& map, const auto& k) -> std::shared_ptr<T> {
            const auto it = map.find(k);
            return it == map.end() ? nullptr : it->second;
        };
        if constexpr (std::is_same_v<T, User>) {
            switch (key) {
                case Key::UserId: return pick(idx.users, number);
                case Key::UserName: return pick(idx.byName, text);
                case Key::Uid: return pick(idx.byUid, number);
                default: return nullptr;
            }
        } else {
            switch (key) {
                case Key::GroupId: return pick(idx.groups, number);
                case Key::GroupName: return pick(idx.groupsByName, text);
                case Key::Gid: return pick(idx.byGid, number);
                default: return nullptr;
            }
        }
    };
    // Answered from memory: a hit, or a remembered miss.
    const auto answer = [&](const Index& idx, std::shared_ptr<T>& out) {
        out = find(idx);
        if (out) return true;
        switch (key) {
            case Key::UserId: return idx.missingUserIds.contains(number);
            case Key::UserName: return idx.missingUserNames.contains(text);
            case Key::Uid: return idx.missingUids.contains(number);
            case Key::GroupId: return idx.missingGroupIds.contains(number);
            case Key::GroupName: return idx.missingGroupNames.contains(text);
            case Key::Gid: return idx.missingGids.contains(number);
        }
        return false;
    };

    std::shared_ptr<T> hit;
    if (answer(*index(), hit)) return hit;

    // Cold miss: load once (concurrent misses wait for it), publish, answer from the index.
    std::scoped_lock load(loadMutex_);
    if (answer(*index(), hit)) return hit;

    IdentitySelection sel;
    switch (key) {
        case Key::UserId: sel.userIds = {number}; break;
        case Key::UserName: sel.userName = text; break;
        case Key::Uid: sel.linuxUid = number; break;
        case Key::GroupId: sel.groupIds = {number}; break;
        case Key::GroupName: sel.groupName = text; break;
        case Key::Gid: sel.linuxGid = number; break;
    }
    apply(Loader::load(sel), false);

    hit = find(*index());
    if (!hit) {
        std::scoped_lock lock(publishMutex_);
        auto next = std::make_shared<Index>(*index());
        switch (key) {
            case Key::UserId: next->missingUserIds.insert(number); break;
            case Key::UserName: next->missingUserNames.insert(text); break;
            case Key::Uid: next->missingUids.insert(number); break;
            case Key::GroupId: next->missingGroupIds.insert(number); break;
            case Key::GroupName: next->missingGroupNames.insert(text); break;
            case Key::Gid: next->missingGids.insert(number); break;
        }
        index_.store(std::move(next), std::memory_order_release);
    }
    return hit;
}

std::shared_ptr<User> Manager::user(const uint32_t id) {
    if (id == 0) return nullptr;
    return lookupOrLoad<User>(Key::UserId, id, {});
}

std::shared_ptr<User> Manager::userByName(const std::string& name) {
    if (name.empty()) return nullptr;
    return lookupOrLoad<User>(Key::UserName, 0, name);
}

std::shared_ptr<User> Manager::userByLinuxUid(const uint32_t uid) { return lookupOrLoad<User>(Key::Uid, uid, {}); }

std::shared_ptr<Group> Manager::group(const uint32_t id) {
    if (id == 0) return nullptr;
    return lookupOrLoad<Group>(Key::GroupId, id, {});
}

std::shared_ptr<Group> Manager::groupByName(const std::string& name) {
    if (name.empty()) return nullptr;
    return lookupOrLoad<Group>(Key::GroupName, 0, name);
}

std::shared_ptr<Group> Manager::groupByLinuxGid(const uint32_t gid) { return lookupOrLoad<Group>(Key::Gid, gid, {}); }

void Manager::ensureComplete() {
    if (index()->complete) return;
    std::scoped_lock load(loadMutex_);
    if (index()->complete) return;
    auto snap = Loader::load({.all = true});
    const auto revision = snap.revision;
    apply(std::move(snap), true);
    auto seen = seenRevision_.load();
    while (seen < revision && !seenRevision_.compare_exchange_weak(seen, revision)) {}
}

void Manager::preload() {
    // Always a full reload: startup reconcilers may have written rows behind identities the seed already loaded.
    std::scoped_lock load(loadMutex_);
    auto snap = Loader::load({.all = true});
    const auto revision = snap.revision;
    apply(std::move(snap), true);
    auto seen = seenRevision_.load();
    while (seen < revision && !seenRevision_.compare_exchange_weak(seen, revision)) {}
}

std::vector<std::shared_ptr<User>> Manager::users() {
    ensureComplete();
    const auto idx = index();
    std::vector<std::shared_ptr<User>> out;
    out.reserve(idx->users.size());
    for (const auto& [_, u] : idx->users) out.push_back(u);
    std::ranges::sort(out, {}, [](const auto& u) { return u->id; });
    return out;
}

std::vector<std::shared_ptr<Group>> Manager::groups() {
    ensureComplete();
    const auto idx = index();
    std::vector<std::shared_ptr<Group>> out;
    out.reserve(idx->groups.size());
    for (const auto& [_, g] : idx->groups) out.push_back(g);
    std::ranges::sort(out, [](const auto& a, const auto& b) {
        const auto an = a->name(), bn = b->name();
        return an != bn ? an < bn : a->id < b->id;
    });
    return out;
}

std::vector<std::shared_ptr<Group>> Manager::groupsOf(const uint32_t userId) {
    const auto u = user(userId);
    if (!u) return {};
    const auto s = u->state();
    std::vector<std::shared_ptr<Group>> out;
    for (const auto& g : s->groups)
        if (g && !g->deleted()) out.push_back(g);
    std::ranges::sort(out, [](const auto& a, const auto& b) {
        const auto an = a->name(), bn = b->name();
        return an != bn ? an < bn : a->id < b->id;
    });
    return out;
}

std::vector<GroupMember> Manager::members(const uint32_t groupId) {
    ensureComplete();
    std::vector<GroupMember> out;
    for (const auto& [_, u] : index()->users) {
        const auto s = u->state();
        if (s->deleted) continue;
        if (const auto it = s->joinedAt.find(groupId); it != s->joinedAt.end()) out.push_back({u, it->second});
    }
    std::ranges::sort(out, [](const GroupMember& a, const GroupMember& b) {
        const auto an = a.user->name(), bn = b.user->name();
        return an != bn ? an < bn : a.user->id < b.user->id;
    });
    return out;
}

std::size_t Manager::memberCount(const uint32_t groupId) {
    ensureComplete();
    std::size_t n = 0;
    for (const auto& [_, u] : index()->users) {
        const auto s = u->state();
        if (!s->deleted && s->joinedAt.contains(groupId)) ++n;
    }
    return n;
}

bool Manager::isAdmin(const uint32_t userId) {
    const auto u = user(userId);
    return u && u->isAdmin();
}

// ------------------------------------------------------------------------------------------------ publication

void Manager::apply(IdentitySnapshot&& snap, const bool loadedAll) {
    std::scoped_lock lock(publishMutex_);
    auto next = std::make_shared<Index>(*index());
    const auto rev = snap.revision;

    {
        Publication publication;

        // Groups first: users resolve their memberships to canonical groups.
        std::unordered_set<uint32_t> seenGroups;
        for (auto& rec : snap.groups) {
            seenGroups.insert(rec.id);
            auto state = std::make_shared<const GroupState>(std::move(rec.state));
            auto& slot = next->groups[rec.id];
            if (!slot) slot = std::shared_ptr<Group>(new Group(rec.id, std::move(state), false));
            else if (slot->state()->revision <= state->revision) slot->publish(std::move(state));
        }
        const auto dropGroup = [&](const uint32_t id) {
            const auto it = next->groups.find(id);
            if (it == next->groups.end()) return;
            if (const auto last = it->second->state(); last->revision <= rev && !last->deleted)
                it->second->publish(tombstone(*last, rev));
            next->groups.erase(it);
        };
        if (loadedAll) {
            std::vector<uint32_t> gone;
            for (const auto& [id, _] : next->groups)
                if (!seenGroups.contains(id)) gone.push_back(id);
            for (const auto id : gone) dropGroup(id);
        } else {
            for (const auto id : snap.requestedGroupIds)
                if (!seenGroups.contains(id)) dropGroup(id);
        }

        std::unordered_set<uint32_t> seenUsers;
        for (auto& rec : snap.users) {
            seenUsers.insert(rec.id);
            auto state = std::make_shared<UserState>(std::move(rec.state));
            state->groups.reserve(rec.memberships.size());
            for (const auto& [gid, _] : rec.memberships)
                if (const auto it = next->groups.find(gid); it != next->groups.end())
                    state->groups.push_back(it->second);
            auto& slot = next->users[rec.id];
            if (!slot) slot = std::shared_ptr<User>(new User(rec.id, std::move(state), false));
            else if (slot->state()->revision <= state->revision) slot->publish(std::move(state));
        }
        const auto dropUser = [&](const uint32_t id) {
            const auto it = next->users.find(id);
            if (it == next->users.end()) return;
            if (const auto last = it->second->state(); last->revision <= rev && !last->deleted)
                it->second->publish(tombstone(*last, rev));
            next->users.erase(it);
        };
        if (loadedAll) {
            std::vector<uint32_t> gone;
            for (const auto& [id, _] : next->users)
                if (!seenUsers.contains(id)) gone.push_back(id);
            for (const auto id : gone) dropUser(id);
        } else {
            for (const auto id : snap.requestedUserIds)
                if (!seenUsers.contains(id)) dropUser(id);
        }
    }

    // Secondary indexes follow the published states.
    next->byUid.clear();
    next->byName.clear();
    for (const auto& [_, u] : next->users) {
        const auto s = u->state();
        if (s->deleted) continue;
        next->byName[s->name] = u;
        if (s->meta.linux_uid) next->byUid[*s->meta.linux_uid] = u;
    }
    next->byGid.clear();
    next->groupsByName.clear();
    for (const auto& [_, g] : next->groups) {
        const auto s = g->state();
        if (s->deleted) continue;
        next->groupsByName[s->name] = g;
        if (s->linux_gid) next->byGid[*s->linux_gid] = g;
    }
    // A negative entry is only as good as the snapshot it came from.
    next->missingUserIds.clear();
    next->missingUserNames.clear();
    next->missingUids.clear();
    next->missingGroupIds.clear();
    next->missingGroupNames.clear();
    next->missingGids.clear();
    if (loadedAll) next->complete = true;

    index_.store(std::move(next), std::memory_order_release);
    loads_.fetch_add(1, std::memory_order_relaxed);
    publications_.fetch_add(1, std::memory_order_relaxed);
}

void Manager::refresh(const Touched& touched) {
    if (touched.empty()) return;
    if (touched.everyone) {
        std::scoped_lock load(loadMutex_);
        auto snap = Loader::load({.all = true});
        apply(std::move(snap), true);
        return;
    }
    IdentitySelection sel;
    sel.userIds = touched.users;
    sel.groupIds = touched.groups;
    sortUnique(sel.userIds);
    sortUnique(sel.groupIds);
    std::erase(sel.userIds, 0u);
    std::erase(sel.groupIds, 0u);
    if (sel.userIds.empty() && sel.groupIds.empty()) return;
    std::scoped_lock load(loadMutex_);
    apply(Loader::load(sel), false);
}

void Manager::refreshNoThrow(const Touched& touched) noexcept {
    try {
        refresh(touched);
    } catch (const std::exception& e) {
        // The watcher republishes from the change log once the database answers again.
        log::Registry::auth()->error("[identities::Manager] Could not republish after a write: {}", e.what());
    } catch (...) {
        log::Registry::auth()->error("[identities::Manager] Could not republish after a write");
    }
}

bool Manager::reconcile() {
    std::scoped_lock serial(reconcileMutex_);
    const auto since = seenRevision_.load();
    uint64_t upTo = since;
    const auto changes = Loader::changesSince(since, upTo);

    bool published = false;
    if (!changes) {
        // The log no longer reaches back to what we saw (or this is the first round): reload everything we hold.
        refresh({.everyone = true});
        published = true;
    } else if (!changes->empty()) {
        Touched t;
        const auto idx = index();
        for (const auto& c : *changes) {
            // Held and older than the change: reload. Not held: only a complete index must learn about it (a new
            // account); otherwise it is loaded when first asked for.
            if (c.entity == "user") {
                const auto it = idx->users.find(c.id);
                if (it != idx->users.end() ? it->second->state()->revision < c.revision : idx->complete)
                    t.users.push_back(c.id);
            } else if (c.entity == "group") {
                const auto it = idx->groups.find(c.id);
                if (it != idx->groups.end() ? it->second->state()->revision < c.revision : idx->complete)
                    t.groups.push_back(c.id);
            } else {
                // A role template: whoever holds it. Template edits are rare; reload everything we hold.
                t.everyone = true;
            }
        }
        if (t.everyone && !idx->complete && idx->users.empty() && idx->groups.empty()) t.everyone = false;
        if (!t.empty()) {
            refresh(t);
            published = true;
        } else {
            // Something changed that we hold nothing for (e.g. a new account): a negative entry may no longer hold.
            std::scoped_lock lock(publishMutex_);
            auto next = std::make_shared<Index>(*index());
            next->missingUserIds.clear();
            next->missingUserNames.clear();
            next->missingUids.clear();
            next->missingGroupIds.clear();
            next->missingGroupNames.clear();
            next->missingGids.clear();
            index_.store(std::move(next), std::memory_order_release);
        }
    }
    auto seen = seenRevision_.load();
    while (seen < upTo && !seenRevision_.compare_exchange_weak(seen, upTo)) {}
    if (published) reconciliations_.fetch_add(1, std::memory_order_relaxed);

    if (const auto now = std::chrono::steady_clock::now(); now - lastPrune_ > kPruneEvery) {
        lastPrune_ = now;
        try {
            Loader::pruneChangeLog(kChangeLogRetention);
        } catch (const std::exception& e) {
            log::Registry::auth()->debug("[identities::Manager] Change log prune failed: {}", e.what());
        }
    }
    return published;
}

void Manager::reset() {
    std::scoped_lock load(loadMutex_);
    std::scoped_lock lock(publishMutex_);
    index_.store(std::make_shared<const Index>(), std::memory_order_release);
    seenRevision_.store(0);
}

ManagerStats Manager::stats() const {
    const auto idx = index();
    return {
        .revision = seenRevision_.load(),
        .users = idx->users.size(),
        .groups = idx->groups.size(),
        .complete = idx->complete,
        .loads = loads_.load(),
        .publications = publications_.load(),
        .reconciliations = reconciliations_.load()
    };
}

// ------------------------------------------------------------------------------------------------ writes

std::shared_ptr<User> Manager::createUser(const UserState& draft, const std::string& passwordHash) {
    uint32_t id = 0;
    mutate({}, [&] { id = db::query::identities::User::createUser(draft, passwordHash); });
    refresh({.users = {id}});
    auto created = user(id);
    if (!created) throw std::runtime_error("user " + std::to_string(id) + " could not be read back");
    return created;
}

std::shared_ptr<User> Manager::updateUser(const uint32_t id, const std::function<void(UserState&)>& edit) {
    const auto target = user(id);
    if (!target) throw std::runtime_error("User not found: " + std::to_string(id));
    UserState next = *target->state();
    edit(next);
    mutate({.users = {id}}, [&] { db::query::identities::User::updateUser(id, next); });
    return target;
}

void Manager::setPasswordHash(const uint32_t id, const std::string& passwordHash) {
    mutate({.users = {id}}, [&] { db::query::identities::User::updateUserPassword(id, passwordHash); });
}

void Manager::recordLogin(const uint32_t id) {
    mutate({.users = {id}}, [&] { db::query::identities::User::updateLastLoggedInUser(id); });
}

void Manager::bindLinuxUid(const uint32_t id, const uint32_t linuxUid, const std::optional<uint32_t> updatedBy) {
    // The previous holder of the uid (if any) changes too.
    std::vector<uint32_t> touched{id};
    if (const auto holder = userByLinuxUid(linuxUid)) touched.push_back(holder->id);
    mutate({.users = touched}, [&] { db::query::identities::User::bootstrapSetAdminLinuxUID(linuxUid, updatedBy); });
}

void Manager::deleteUser(const uint32_t id) {
    mutate({.users = {id}}, [&] { db::query::identities::User::deleteUser(id); });
}

std::shared_ptr<Group> Manager::createGroup(const GroupState& draft) {
    uint32_t id = 0;
    mutate({}, [&] { id = db::query::identities::Group::createGroup(draft); });
    refresh({.groups = {id}});
    auto created = group(id);
    if (!created) throw std::runtime_error("group " + std::to_string(id) + " could not be read back");
    return created;
}

std::shared_ptr<Group> Manager::updateGroup(const uint32_t id, const std::function<void(GroupState&)>& edit) {
    const auto target = group(id);
    if (!target) throw std::runtime_error("Group not found: " + std::to_string(id));
    GroupState next = *target->state();
    edit(next);
    mutate({.groups = {id}}, [&] { db::query::identities::Group::updateGroup(id, next); });
    return target;
}

void Manager::deleteGroup(const uint32_t id) {
    Touched t{.groups = {id}};
    for (const auto& m : members(id)) t.users.push_back(m.user->id);
    mutate(std::move(t), [&] { db::query::identities::Group::deleteGroup(id); });
}

void Manager::addMembers(const uint32_t groupId, const std::vector<uint32_t>& userIds) {
    mutate({.users = userIds, .groups = {groupId}},
           [&] { db::query::identities::Group::addMembersToGroup(groupId, userIds); });
}

void Manager::removeMembers(const uint32_t groupId, const std::vector<uint32_t>& userIds) {
    mutate({.users = userIds, .groups = {groupId}},
           [&] { db::query::identities::Group::removeMembersFromGroup(groupId, userIds); });
}

// ------------------------------------------------------------------------------------------------ watcher

RevisionWatcher::RevisionWatcher() : AsyncService("IdentityRevisionWatcher") {}

void RevisionWatcher::runLoop() {
    auto backoff = Manager::kWatchInterval;
    while (!shouldStop()) {
        try {
            (void)manager().reconcile();
            backoff = Manager::kWatchInterval;
        } catch (const std::exception& e) {
            log::Registry::auth()->debug("[identities::RevisionWatcher] Reconcile failed: {}", e.what());
            backoff = std::min<std::chrono::milliseconds>(backoff * 2, std::chrono::seconds(30));
        }
        if (!lazySleep(backoff)) break;
    }
}

Manager& manager() {
    static std::mutex m;
    auto& deps = runtime::Deps::get();
    if (const auto& existing = deps.identityManager) return *existing;
    std::scoped_lock lock(m);
    if (!deps.identityManager) deps.identityManager = std::make_shared<Manager>();
    return *deps.identityManager;
}

}
