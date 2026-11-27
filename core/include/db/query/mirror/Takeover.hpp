#pragma once

#include "db/query/mirror/MirrorVault.hpp"
#include "mirror/Hash.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// Take over (forced promotion; migration 168, mirror_takeover and mirror_fork_base; design/peers/mirror.md "Forced
// promotion", "As built: take over"). The rows mirror::takeover reads and writes; callers authorize and hold the vault's
// local-change lock. Every write that changes the vault's role republishes rbac::mirrored and mirror::access before it
// returns.
namespace vh::db::query::mirror {

struct Takeover {
    uint64_t id{};
    uint32_t vault_id{};
    uint32_t peer_id{};
    uint64_t from_term{};
    uint64_t term{};
    uint64_t fork_seq{};
    vh::mirror::Digest fork_digest{};
    uint64_t fork_rows{};
    uint32_t pending_made_local{};
    uint32_t held{};
    uint32_t contents_missing{};
    std::optional<uint32_t> by_id{};
    std::string by_name{};
    nlohmann::json detail{};
    std::time_t created_at{};
    std::optional<std::time_t> settled_at{};
    std::optional<std::string> settled_how{};

    [[nodiscard]] Position fork() const { return {from_term, fork_seq}; }
    [[nodiscard]] bool open() const { return !settled_at.has_value(); }
};

class Takeovers {
public:
    // The promotion, in one transaction under the vault row's lock: only for a `mirror` row whose first copy finished
    // and that is not diverged (ops::Refused mirror_not_mirror, mirror_first_copy, mirror_diverged). A switch of the
    // vault still open here ends `abandoned` (mirror_taken_over). The record (fork point: the position applied, the
    // digest there) and the fork base (the tree as the core last confirmed it: an entry a change made here holds dirty
    // is its confirmed state, one made here is left out) are written; pending changes become ordinary local changes
    // (their rows and dirty entries go; held changes stay); the entry hashes and the digest are taken again from the
    // tables (the tree as it is now, the person's changes in it); the row becomes the vault's `core` in term + 1, live,
    // its log from (term + 1, 1), its baseline position (term + 1, 0) at that digest, the grant gone; the start's offer
    // changes side. Returns the record and the pending rows' ids (their sealed bytes are dropped after the commit).
    struct Taken {
        Takeover takeover{};
        std::vector<uint64_t> pending_ids{};
        bool fork_base_matches{false};   // the fork base's digest is the fork point's
    };
    static Taken take(uint32_t vaultId, std::optional<uint32_t> byId, const std::string& byName, uint32_t contentsMissing);

    [[nodiscard]] static std::optional<Takeover> get(uint64_t id);
    // The vault's take over not yet settled, and its newest whatever it is.
    [[nodiscard]] static std::optional<Takeover> openOf(uint32_t vaultId);
    [[nodiscard]] static std::optional<Takeover> latestOf(uint32_t vaultId);
    // The fork base's documents, in order (ord after `after`, at most `limit`).
    [[nodiscard]] static std::vector<nlohmann::json> forkBase(uint64_t id, uint64_t after, std::size_t limit);

    // The old core rejoined (`how`: switched, returned, merged) or the mirror ended (ended): settled, its fork base
    // dropped. False when it was settled already.
    static bool settle(uint64_t id, const std::string& how, const nlohmann::json& detail = nlohmann::json::object());
};

}
