#pragma once

#include "db/query/mirror/MirrorVault.hpp"
#include "mirror/Hash.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// The old core of a vault another server took over (migration 168, mirror_rejoin; design/peers/mirror.md "As built: the
// old core learns"). The rows mirror::rejoin reads and writes; callers authorize. Every write that changes the vault's
// role or state republishes rbac::mirrored and mirror::access before it returns.
namespace vh::db::query::mirror {

struct Rejoin {
    uint64_t id{};
    uint32_t vault_id{};
    uint32_t peer_id{};
    uint64_t new_term{};
    Position fork{};
    vh::mirror::Digest fork_digest{};
    std::optional<vh::mirror::Digest> baseline_digest{};   // the new core's digest at (new_term, 0)
    std::string phase{};   // draining | following | rejoining | forked | resynced | ended (the mirror ended first)
    uint32_t changes{};    // rejoining: this server's numbered changes past the fork point
    std::vector<std::string> writers{};
    nlohmann::json detail{};
    std::time_t created_at{};
    std::optional<std::time_t> decided_at{};
};

class Rejoins {
public:
    [[nodiscard]] static std::optional<Rejoin> get(uint64_t id);
    // The vault's rejoin still open here (draining, rejoining or forked), and its newest whatever it is.
    [[nodiscard]] static std::optional<Rejoin> openOf(uint32_t vaultId);
    [[nodiscard]] static std::optional<Rejoin> latestOf(uint32_t vaultId);
    // Draining ones (the follower's pass decides them).
    [[nodiscard]] static std::vector<Rejoin> draining();

    // The telling arrived: this server's `core` row for the vault (in a lower term than `newTerm`) becomes `rejoining`
    // (read-only) and a rejoin begins (draining), in one transaction under the row's lock. An open rejoin of the same
    // term is returned as it is (told again).
    static Rejoin begin(uint32_t vaultId, uint32_t peerId, uint64_t newTerm, Position fork, const vh::mirror::Digest& forkDigest,
                        const std::optional<vh::mirror::Digest>& baselineDigest);
    static void recordWriters(uint64_t id, const std::vector<std::string>& writers);

    // Both servers took over: this server's core row (with its own take over open) is `forked`, read-only, and the
    // record says the other's term and fork point. An open rejoin of the vault is returned as it is.
    static Rejoin forked(uint32_t vaultId, uint32_t peerId, uint64_t otherTerm, Position otherFork,
                         const vh::mirror::Digest& otherForkDigest);

    // The decision once the writers ended and the sequencer numbered what they logged, in one transaction under the
    // row's lock. "" and the phase it took, or the reason it waits (a row still waits for its number):
    //   following   nothing numbered past the fork point and the digest is the fork point's: the row is the vault's
    //               mirror in the new term at (new_term, 0), live, first copy complete (its log, baseline and
    //               submissions go, the start offer changes side); when the new core's digest there is not the fork
    //               point's (it made its pending changes ordinary when it took over), its first copy starts again from
    //               the new core's baseline over the entries here (the resync copy, as `resyncBy`)
    //   rejoining   it numbered changes past the fork point: the row stays read-only with them, counted
    struct Decided {
        std::string waits{};
        std::string phase{};
        uint32_t changes{};
    };
    static Decided decide(uint64_t id, uint32_t resyncBy);

    // A person starts the copy of a rejoining or forked old core over from the other server (mirror.resync): the row
    // becomes the vault's `mirror` in the other's term, stopped (mirror_rejoin_resync), so the resync takes it from
    // there; the rejoin is `resynced` and a take over of this server's own (forked) settles. False without an open
    // rejoin.
    static bool toMirrorForResync(uint32_t vaultId);
    // This server stays the core and its forked other side starts over from it: its own forked rejoin ends (resynced).
    static bool closeForked(uint32_t vaultId);
};

}
