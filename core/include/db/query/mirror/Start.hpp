#pragma once

#include "crypto/id/ObjectUid.hpp"
#include "db/query/vault/Key.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Starting a mirror, the database side (migration 163; design/peers/mirror.md "Starting a mirror", "As built: starting
// a mirror"): the offers each server keeps (mirror_offer), the per-link "accept every vault" setting (peer
// .accept_vaults), the facts about a core's vault an offer and its preconditions read, and the one transaction that
// creates a mirror's vault (the vault row with the core's uid, its root folder with the core's root uid, every key
// version sealed under this host's vault master with its origin, and the `mirror` row). Trusted primitives: callers
// (mirror::start, ops::mirrors) authorize. No key material is stored in mirror_offer.
namespace vh::db::query::mirror {

// The role the core proposes or grants, by name with its permissions (vault_role's bit layout).
struct OfferedRole {
    std::string name{};
    uint64_t files{}, directories{}, sync{}, roles{};
};

// An account named as (its home server's node id, its id there), with its name for display.
struct OfferOwner {
    std::string node{};
    uint32_t id{};
    std::string name{};
};

struct Offer {
    uint32_t id{};
    std::string offer_uid{};  // UUID text, the same on both servers
    std::string side{};       // core | mirror: this server's part in it
    uint32_t peer_id{};
    vh::crypto::id::ObjectUid vault_uid{};
    std::optional<uint32_t> vault_id{};  // core: the vault; mirror: the vault created for it
    uint64_t core_vault_id{};
    vh::crypto::id::ObjectUid root_uid{};
    uint64_t term{1};
    std::string name{}, description{};
    uint64_t quota{}, size_bytes{}, file_count{};
    bool history{false};
    OfferOwner owner{};
    std::optional<OfferedRole> role{};
    // core: offered | accepted | keys_acked | started | declined | cancelled | expired | failed
    // mirror: pending | accepted | installed | started | declined | cancelled | expired | failed | orphaned (the core
    // ended a finished mirror and the copy was kept here)
    std::string state{};
    bool notify{false};
    bool remove_copy{false};                 // core: what its cancel asked of the mirror's copy
    std::optional<std::string> copy_outcome{};  // core: what the mirror said it did (removed | kept | none)
    std::optional<std::string> reason{}, detail{};
    std::optional<uint32_t> started_by{}, decided_by{};
    uint32_t attempts{};
    std::optional<std::string> last_error{};
    std::time_t created_at{}, updated_at{}, expires_at{};
    std::optional<std::time_t> finished_at{};

    [[nodiscard]] bool finished() const noexcept { return finished_at.has_value(); }
};

// The facts about a vault an offer carries and its preconditions read (one snapshot).
struct VaultFacts {
    uint32_t vault_id{};
    vh::crypto::id::ObjectUid vault_uid{};
    std::optional<vh::crypto::id::ObjectUid> root_uid{};
    std::string name{}, description{};
    uint64_t quota{};
    bool deleted{false};
    std::string type{};                          // local | s3
    std::optional<std::string> strategy{};       // a remote's sync strategy (cache | sync | mirror)
    uint32_t owner_id{};
    OfferOwner owner{};
    uint64_t live_files{}, live_bytes{}, trashed_files{}, trashed_bytes{};
    uint64_t trashed_without_uid{};              // opaque_v1 rows from before 125 (the log cannot carry them)
    uint64_t gcm0_files{}, plain_files{};        // non-portable contents (plain: with bytes)
    std::vector<uint32_t> key_versions{};        // the versions live and trashed files use, and the current one
    std::optional<uint32_t> current_version{};
};

struct AcceptVaults {
    bool enabled{false};
    std::optional<uint32_t> set_by{};
    std::optional<std::time_t> set_at{};
};

// One key version as a mirror stores it: sealed under this host's vault master, this node's provenance over the new
// vault id, and where it came from (the core's node id, its vault id there, its key check over that id, and the core's
// attestation that was proven against the key pinned at pairing).
struct MirrorKeyRow {
    uint32_t version{};
    bool current{false};
    std::vector<uint8_t> encrypted_key{}, iv{};
    unsigned int master_version{1};
    vh::db::query::vault::Key::Provenance provenance{};
    std::string origin_node_id{};
    uint64_t origin_vault_id{};
    std::string origin_key_check{};
    unsigned int attestation_key_id{};
    std::vector<uint8_t> attestation_public_key{}, attestation{};
};

struct NewMirrorVault {
    uint32_t vault_id{};  // MirrorStart::reserveVaultId (the provenance binds it)
    uint32_t offer_id{};
    uint32_t peer_id{};
    uint64_t term{1};
    vh::crypto::id::ObjectUid vault_uid{}, root_uid{};
    std::string name{}, description{}, mount_point{};
    uint64_t quota{};
    OfferOwner owner{};
    std::vector<MirrorKeyRow> keys{};
};

class MirrorStart {
public:
    // ---- offers

    [[nodiscard]] static Offer insertOffer(const Offer& offer);
    [[nodiscard]] static std::optional<Offer> offer(uint32_t id);
    [[nodiscard]] static std::optional<Offer> offerByUid(const std::string& offerUid, const std::string& side);
    // The start of `vaultUid` on this side that has not finished, if any.
    [[nodiscard]] static std::optional<Offer> activeOffer(const vh::crypto::id::ObjectUid& vaultUid, const std::string& side);
    // The latest offer of a vault on this side (finished or not).
    [[nodiscard]] static std::optional<Offer> latestOffer(const vh::crypto::id::ObjectUid& vaultUid, const std::string& side);
    // Newest first. `side` empty: both; `open` only: the ones that have not finished.
    [[nodiscard]] static std::vector<Offer> offers(const std::string& side, bool openOnly);
    // What the start service looks at: rows not finished, or finished with the other server still to be told.
    [[nodiscard]] static std::vector<Offer> offersWithWork();

    struct Change {
        std::string to{};
        bool notify{false};
        std::optional<std::string> reason{}, detail{};
        std::optional<uint32_t> decided_by{};
        std::optional<uint32_t> vault_id{};
        std::optional<bool> remove_copy{};
    };
    // Compare-and-set: moves the offer from one of `from` to `change.to` (finished_at set for a finished state). The row
    // after the change, or nullopt when it was in none of them.
    static std::optional<Offer> transition(uint32_t id, const std::vector<std::string>& from, const Change& change);
    // The other server was told the offer's state `state` (nothing changes when it moved on meanwhile).
    static bool told(uint32_t id, const std::string& state);
    // What the mirror answered it did with its copy (removed | kept | none). False without such an offer.
    static bool recordCopyOutcome(uint32_t id, const std::string& outcome);
    // The other server can no longer be told (its link was unlinked): queued notices of its offers are dropped.
    static std::size_t dropNotices(uint32_t peerId);
    // A failed attempt to tell or ask the other server: counted, its error kept.
    static void noteAttempt(uint32_t id, const std::string& error);
    // Offers not answered by expires_at: the pre-key states become `expired`, the other server to be told. Returns them.
    static std::vector<Offer> expireOffers();
    // Finished rows older than `age` that have nothing left to tell. Returns how many went.
    static std::size_t sweepFinished(std::chrono::seconds age);

    // ---- the link's setting

    [[nodiscard]] static AcceptVaults acceptVaults(uint32_t peerId);
    static void setAcceptVaults(uint32_t peerId, bool enabled, std::optional<uint32_t> setBy);
    // Keep the vaults this linked server (their core) asks to remove: peer.keep_vaults (same shape).
    [[nodiscard]] static AcceptVaults keepVaults(uint32_t peerId);
    static void setKeepVaults(uint32_t peerId, bool enabled, std::optional<uint32_t> setBy);

    // ---- the core's vault

    // nullopt without such a vault (deleted ones included, flagged).
    [[nodiscard]] static std::optional<VaultFacts> facts(uint32_t vaultId);
    // A file of the vault whose sealed bytes are not on this server's disk at its generation's length (a cache vault
    // with evicted files): the first such path, or nullopt.
    [[nodiscard]] static std::optional<std::string> firstFileNotHeld(uint32_t vaultId);

    // ---- the mirror's vault

    // A live vault here with this uid (any vault, mirrored or not).
    [[nodiscard]] static std::optional<uint32_t> vaultWithUid(const vh::crypto::id::ObjectUid& vaultUid);
    // A live vault here whose name is `name`, compared without case and surrounding spaces.
    [[nodiscard]] static std::optional<uint32_t> vaultNamed(const std::string& name);
    [[nodiscard]] static uint32_t reserveVaultId();
    // One transaction: the owner's account (an existing local account when the owner's home is this server and it
    // exists here, else the remote account for (node, id), created when missing), the local vault (core's uid, name,
    // description, quota), its sync rows, its root folder (the core's root uid), every key row with its origin, the
    // `mirror` row (no grant: nobody has access until the core's grant is recorded) and the offer moved to `installed`
    // (from `accepted`) with the vault id. ops::Conflict when the offer moved on, a vault already has the uid, or the
    // vault is mirrored already. Republishes rbac::mirrored before it returns. Returns the vault id.
    static uint32_t createMirrorVault(const NewMirrorVault& in);
    // After the vault and its mirror row went (Manager::removeVault): the remote account made for its owner, when
    // nothing else names it as an owner. Never a local account. Best effort.
    static void dropOrphanedOwner(uint32_t ownerId);
};

}
