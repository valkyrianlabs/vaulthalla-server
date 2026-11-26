#pragma once

#include "concurrency/AsyncService.hpp"
#include "rbac/Fwd.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>

// The vaults this server holds as another server's copy, and the one rule every resolver applies to them
// (design/peers/identity.md "Decided and given", Cooper 2026-11-25; migration 162).
//
// A vault whose mirror_vault row here has the role `mirror` (or `orphaned`: a copy the core stopped following, still
// another server's vault until it is detached) is resolved from what its core granted this server, and from nothing
// else: a local account's effective permissions on it are exactly the granted role's if the account is a super admin
// of this server, and none otherwise. No other local source applies: not a vault role assignment (the account's or a
// group's), not an admin role's vault powers, not a global vault policy, not ownership. No grant recorded: nobody has
// access. The core's role arrives by name with its permissions and is never matched to a role of this server.
//
// The resolvers ask find() on every check. While no vault is held here (every server today) that is one atomic load;
// otherwise one more atomic load of an immutable snapshot and a hash lookup. The snapshot is published:
//   - at startup, before any engine serves a request (reload(); a failure stops the daemon, as for upstream locks);
//   - by every db::query::mirror::MirrorVaults write that adds, removes or changes a held row or its grant, before
//     that write returns;
//   - within kWatchInterval of an out-of-band change (psql by hand), by the Watcher service.
// Every publication that changes something bumps rbac::policyEpoch(), so short-lived authorization caches miss.
namespace vh::rbac::mirrored {

struct Grant {
    std::string role_name{};
    std::shared_ptr<const role::Vault> role{};  // the permissions as told: no overrides, never a local role's row
    std::string granted_by_node{};              // the core's node id
    std::time_t granted_at{};
};

struct Held {
    uint32_t vault_id{};
    uint32_t peer_id{};          // the linked server whose vault this is
    std::string role{};          // mirror | orphaned
    std::optional<Grant> grant{};  // none: nobody here has access
};

// nullptr: this server does not hold the vault as another server's copy; it resolves as it always has.
[[nodiscard]] std::shared_ptr<const Held> find(uint32_t vaultId) noexcept;

// Whether any vault is held here (the hot path's first, and while nothing is mirrored only, question).
[[nodiscard]] bool any() noexcept;

// Reads mirror_vault and publishes it. Throws when the database can't be read; what was published stays.
void reload();

// reload() when the rows differ from what is published (the Watcher's pass). True when it published a change.
bool reconcile();

// Forgets everything (test schema resets: nothing is held in a fresh schema).
void resetForTesting();

// Applies out-of-band changes to mirror_vault (registered with runtime::Manager as "MirrorAccessWatcher").
class Watcher final : public concurrency::AsyncService {
public:
    static constexpr std::chrono::milliseconds kWatchInterval{1000};

    Watcher();
    static const std::shared_ptr<Watcher>& instance();

protected:
    void runLoop() override;
};

}
