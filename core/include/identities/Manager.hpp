#pragma once

#include "concurrency/AsyncService.hpp"
#include "db/query/identities/Loader.hpp"
#include "identities/Group.hpp"
#include "identities/User.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace vh::identities {

namespace detail {
// Seqlock over publications. A publication (one Manager refresh, possibly touching several users and groups) makes it
// odd while it stores new states and even again when done; User::authz() retries while it is odd or moved, so an
// authorization view never mixes states from two publications.
inline std::atomic<uint64_t> publicationSeq{0};
}

// Which identities a change touched. `everyone`: reload all (role template edits, reconciliation gaps).
struct Touched {
    std::vector<uint32_t> users{};
    std::vector<uint32_t> groups{};
    bool everyone = false;

    [[nodiscard]] bool empty() const noexcept { return !everyone && users.empty() && groups.empty(); }
};

struct ManagerStats {
    uint64_t revision = 0;
    std::size_t users = 0;
    std::size_t groups = 0;
    bool complete = false;
    uint64_t loads = 0;           // DB load rounds (each: one snapshot, ~8 statements)
    uint64_t publications = 0;
    uint64_t reconciliations = 0; // rounds that applied out-of-band changes
};

// The in-process owner of every identity (users, groups) and the only supported way their rows change.
//
// Reads return the canonical object for an id; the same shared_ptr every time. Once preload() has run, the index
// holds every account and group, and lookups by id/name/Linux uid/gid are answered from memory. A miss (an unknown
// uid, an account created outside the daemon a moment ago) loads from the database once (single-flight) and is
// remembered, negatively too, until the next publication.
//
// Writes run their statements, then reload what they touched from one database snapshot and publish it into the
// existing canonical objects before returning. Publication never goes backwards: every state carries the
// identity_revision it was read at (migration 108; bumped by triggers, so commit order), and an older read never
// replaces a newer state. Out-of-band changes (psql, anything that bypasses the Manager) are picked up by the
// identities::RevisionWatcher from identity_change_log, within ~1 s, and published the same way.
class Manager {
public:
    static constexpr std::chrono::milliseconds kWatchInterval{1000};

    Manager() = default;

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    // ---------------------------------------------------------------- reads
    [[nodiscard]] std::shared_ptr<User> user(uint32_t id);
    [[nodiscard]] std::shared_ptr<User> userByName(const std::string& name);
    [[nodiscard]] std::shared_ptr<User> userByLinuxUid(uint32_t uid);
    [[nodiscard]] std::shared_ptr<Group> group(uint32_t id);
    [[nodiscard]] std::shared_ptr<Group> groupByName(const std::string& name);
    [[nodiscard]] std::shared_ptr<Group> groupByLinuxGid(uint32_t gid);

    // Every live account by id / every live group by name. Loads everything first when the index is not complete.
    [[nodiscard]] std::vector<std::shared_ptr<User>> users();
    [[nodiscard]] std::vector<std::shared_ptr<Group>> groups();
    [[nodiscard]] std::vector<std::shared_ptr<Group>> groupsOf(uint32_t userId);
    [[nodiscard]] std::vector<GroupMember> members(uint32_t groupId);
    [[nodiscard]] std::size_t memberCount(uint32_t groupId);

    // Whether `userId` currently holds an admin role (used for vault-owner checks; no DB on a warm index).
    [[nodiscard]] bool isAdmin(uint32_t userId);

    // ---------------------------------------------------------------- lifecycle
    // Loads every identity in one snapshot; afterwards the index is complete.
    void preload();

    // Applies out-of-band changes recorded since the last call (identities::RevisionWatcher calls it every
    // kWatchInterval). Returns true if anything was published.
    bool reconcile();

    // Forgets every index entry (test schema resets). Objects already handed out keep their last state.
    void reset();

    [[nodiscard]] ManagerStats stats() const;

    // ---------------------------------------------------------------- writes
    // Creates an account (the draft's roles must name an admin role) and returns its canonical object.
    std::shared_ptr<User> createUser(const UserState& draft, const std::string& passwordHash);

    // Persists `edit` applied to a copy of the current state (name, email, active, Linux uid, admin role and its
    // global vault policy, direct vault roles), then publishes. Returns the canonical object.
    std::shared_ptr<User> updateUser(uint32_t id, const std::function<void(UserState&)>& edit);

    void setPasswordHash(uint32_t id, const std::string& passwordHash);
    void recordLogin(uint32_t id);
    void bindLinuxUid(uint32_t id, uint32_t linuxUid, std::optional<uint32_t> updatedBy);
    void deleteUser(uint32_t id);

    std::shared_ptr<Group> createGroup(const GroupState& draft);
    std::shared_ptr<Group> updateGroup(uint32_t id, const std::function<void(GroupState&)>& edit);
    void deleteGroup(uint32_t id);
    void addMembers(uint32_t groupId, const std::vector<uint32_t>& userIds);
    void removeMembers(uint32_t groupId, const std::vector<uint32_t>& userIds);

    // Any other authorization write (vault role assignments and overrides, role templates, ...): runs `fn`, then
    // reloads and publishes what it touched, also when `fn` throws (a partial multi-step write is published as
    // committed).
    template <typename Fn>
    decltype(auto) mutate(Touched touched, Fn&& fn) {
        struct Republish {
            Manager* self;
            Touched* t;
            ~Republish() { self->refreshNoThrow(*t); }
        } republish{this, &touched};
        return std::forward<Fn>(fn)();
    }

    // Reloads and publishes `touched` now.
    void refresh(const Touched& touched);

    // Publishes a snapshot read earlier (tests: a slow cold load finishing after a newer write).
    void publishSnapshotForTesting(db::query::identities::IdentitySnapshot snap) { apply(std::move(snap), false); }

private:
    struct Index {
        std::unordered_map<uint32_t, std::shared_ptr<User>> users;
        std::unordered_map<uint32_t, std::shared_ptr<User>> byUid;
        std::unordered_map<std::string, std::shared_ptr<User>> byName;
        std::unordered_map<uint32_t, std::shared_ptr<Group>> groups;
        std::unordered_map<uint32_t, std::shared_ptr<Group>> byGid;
        std::unordered_map<std::string, std::shared_ptr<Group>> groupsByName;
        // Negative entries: keys a database read found nothing for. Every publication clears them (any change may
        // have created the identity), so a miss costs one query until something changes, then one more.
        std::unordered_set<uint32_t> missingUserIds, missingUids, missingGroupIds, missingGids;
        std::unordered_set<std::string> missingUserNames, missingGroupNames;
        bool complete = false;   // holds every identity (users()/groups()/members() need no load)
    };

    enum class Key { UserId, UserName, Uid, GroupId, GroupName, Gid };

    [[nodiscard]] std::shared_ptr<const Index> index() const { return index_.load(std::memory_order_acquire); }

    template <typename T>
    std::shared_ptr<T> lookupOrLoad(Key key, uint32_t number, const std::string& text);

    void refreshNoThrow(const Touched& touched) noexcept;
    void ensureComplete();
    void apply(db::query::identities::IdentitySnapshot&& snap, bool loadedAll);

    std::atomic<std::shared_ptr<const Index>> index_{std::make_shared<const Index>()};
    mutable std::mutex publishMutex_;   // index and publication changes; never held across database I/O
    std::mutex loadMutex_;              // single-flight cold loads

    std::mutex reconcileMutex_;
    std::atomic<uint64_t> seenRevision_{0};
    std::atomic<uint64_t> loads_{0}, publications_{0}, reconciliations_{0};
    std::chrono::steady_clock::time_point lastPrune_{};
};

// Polls identity_revision and applies out-of-band identity changes (see Manager::reconcile).
class RevisionWatcher final : public concurrency::AsyncService {
public:
    RevisionWatcher();

protected:
    void runLoop() override;
};

// The process-wide Manager (runtime::Deps::get().identities, created on first use).
[[nodiscard]] Manager& manager();

}
