#pragma once

#include "db/query/mirror/MirrorVault.hpp"
#include "mirror/Hash.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/transaction>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <map>
#include <optional>
#include <string>
#include <vector>

// Relinking a vault two linked servers once mirrored, the database side (migration 171; design/peers/mirror.md "As
// built: relink"; mirror/relink/Relink.hpp is the protocol). Trusted primitives: callers authorize.
namespace vh::db::query::mirror {

// One entry of a vault's tree as a relink reads it (vh_mirror_tree_states, its hash, its path).
struct RelinkTreeRow {
    std::string uid{};
    bool trashed{false};
    nlohmann::json state{};   // the replication log's state document
    std::string hash{};       // hex
    std::string path{};       // live: its vault path; trashed: the trash row's path
    std::string generation{}; // a file's files.encryption_iv (live or trashed)
};

// The entry hashes this server last agreed with its peer, and where they come from.
struct RelinkBase {
    bool available{false};
    std::string source{};           // fork_base | rejoin | acknowledged | entry_hashes | kept
    std::optional<Position> at{};   // the last position both agreed on, when known
    std::map<std::string, std::string> hashes{};   // uid -> hex
};

// What a relink needs to know of this server's hold on the vault.
struct RelinkFacts {
    std::optional<MirrorVault> row{};
    std::optional<std::string> row_peer_node{};
    // Unsettled records of the vault with the peer whose node id is asked for.
    std::optional<uint32_t> detach_id{};
    std::optional<Position> detach_fork{};
    std::optional<uint64_t> takeover_id{};
    std::optional<Position> takeover_fork{};
    uint64_t takeover_term{};
    std::optional<uint64_t> rejoin_id{};
    std::optional<Position> rejoin_fork{};
    uint64_t rejoin_term{};
    uint64_t max_term{};
    // What refuses a relink now.
    uint64_t pending{};             // changes made here as a mirror and not confirmed
    uint64_t unnumbered{};          // log rows that wait for their number
    uint64_t submissions{};         // a core's queued or running submissions
    bool switch_running{false};
    bool start_running{false};      // an offer of the vault not finished
    bool copy_running{false};       // a "detach a copy" job reads it
    bool deleting{false};
    uint64_t contents_missing{};
    std::optional<Position> base_mark{};   // a kept base (mirror_base_mark) and its position
    std::optional<std::string> base_peer_node{};   // the server it was kept with
};

// One key version of the vault here, as two servers compare them without the key: the key check over this server's
// vault id, and where it came from when a linked server delivered it.
struct RelinkKey {
    uint32_t version{};
    bool current{false};
    std::optional<std::string> check{};
    std::optional<std::string> origin_node{};
    std::optional<uint64_t> origin_vault{};
    std::optional<std::string> origin_check{};
};

struct Relink {
    uint64_t id{};
    std::string relink_uid{};
    uint32_t vault_id{};
    uint32_t peer_id{};
    std::string side{};     // initiator | responder
    // requested | accepted | open | proposed | approved | prepared | bring | copying | done | failed | stale | cancelled |
    // declined | expired (migration 171)
    std::string phase{};
    std::string mode{};     // plan | override
    std::string core{};     // this | theirs
    std::optional<std::string> default_choice{};
    std::optional<std::string> role{};
    std::optional<uint64_t> term{};
    std::optional<std::string> this_status{}, theirs_status{};
    std::optional<vh::mirror::Digest> this_digest{}, theirs_digest{};
    nlohmann::json summary = nlohmann::json::object();
    std::optional<std::string> by_node{};
    std::optional<uint32_t> by_id{};
    std::optional<std::string> by_name{};
    std::optional<std::string> error{};
    std::time_t created_at{}, updated_at{};
    std::optional<std::time_t> applied_at{}, finished_at{};
    // The handshake: until when the request (then its acceptance) holds; the responder's super admin who accepted it;
    // the outcome proposed (null: none) and who approved it.
    std::optional<std::time_t> expires_at{}, accepted_at{}, approved_at{};
    std::optional<std::string> accepted_by{}, approved_by{};
    nlohmann::json proposal{};

    [[nodiscard]] bool open() const {
        return phase == "requested" || phase == "accepted" || phase == "open" || phase == "proposed" ||
               phase == "approved" || phase == "prepared" || phase == "bring" || phase == "copying";
    }
    // Asked and answered, nothing applied yet.
    [[nodiscard]] bool handshaking() const {
        return phase == "requested" || phase == "accepted" || phase == "open" || phase == "proposed" || phase == "approved";
    }
};

struct RelinkEntry {
    std::string uid{};
    std::string kind{};
    std::vector<std::string> aspects{};
    std::string path{};
    nlohmann::json this_state{};    // null: not on this server
    nlohmann::json theirs_state{};  // null: not on the other
    std::optional<std::string> choice{};
    std::optional<std::string> request_id{}, outcome{}, outcome_note{};
};

struct NewRelink {
    std::string relink_uid{};
    uint32_t vault_id{};
    uint32_t peer_id{};
    std::string side{"initiator"};
    std::string phase{"open"};
    std::string mode{"plan"};
    std::string core{"this"};
    std::optional<std::string> default_choice{};
    std::optional<std::string> this_status{}, theirs_status{};
    std::optional<vh::mirror::Digest> this_digest{}, theirs_digest{};
    nlohmann::json summary = nlohmann::json::object();
    std::optional<std::string> by_node{};
    std::optional<uint32_t> by_id{};
    std::optional<std::string> by_name{};
    // The handshake carried over from an earlier row of the same relink (a comparison made again).
    std::optional<std::time_t> expires_at{}, accepted_at{};
    std::optional<std::string> accepted_by{};
};

class Relinks {
public:
    // ---- the trees

    // Every entry of the vault (live and trashed) with its state document, hash and path, ordered by uid.
    [[nodiscard]] static std::vector<RelinkTreeRow> tree(uint32_t vaultId);
    // The vault's digest as its tables hold it now (Digests::recompute).
    [[nodiscard]] static vh::mirror::Digest digest(uint32_t vaultId);
    // The entry hashes this server last agreed with its peer: an open take over's fork base; a core's recorded hashes
    // with every entry changed since `since` (an old core's rejoin fork point, else the other side's agreed position,
    // else what its mirror acknowledged) taken back to the state it replaced; a mirror's or orphaned copy's recorded
    // hashes; the base kept when its mirror row ended. Unavailable otherwise.
    [[nodiscard]] static RelinkBase base(uint32_t vaultId, std::optional<Position> since);
    // In the caller's transaction, before the vault's mirror row goes (MirrorVaults::remove): its base is kept
    // (mirror_base, replacing an older one) when one is available, so a later relink can tell who changed what.
    static void keepBase(pqxx::work& txn, uint32_t vaultId);

    // ---- this server's hold on the vault

    // `peerNode`: the other server's node id (the records of the vault with it).
    [[nodiscard]] static RelinkFacts facts(uint32_t vaultId, const std::string& peerNode);
    [[nodiscard]] static std::vector<RelinkKey> keys(uint32_t vaultId);

    // ---- the relink rows

    // A new relink (an open one of the vault here is cancelled first: one open per vault).
    static Relink create(const NewRelink& in);
    [[nodiscard]] static std::optional<Relink> get(uint64_t id);
    [[nodiscard]] static std::optional<Relink> byUid(uint32_t vaultId, const std::string& relinkUid);
    // The vault's open relink here (open, prepared, bring, copying), and its newest whatever it is.
    [[nodiscard]] static std::optional<Relink> openOf(uint32_t vaultId);
    [[nodiscard]] static std::optional<Relink> latestOf(uint32_t vaultId);
    // Relinks in a phase (the follower's pass drives bring and copying on the future mirror).
    [[nodiscard]] static std::vector<Relink> inPhase(const std::string& phase);

    // Compare-and-set on the phase: false when it was in none of `from`. `error` is recorded when given.
    static bool setPhase(uint64_t id, const std::vector<std::string>& from, const std::string& to,
                         const std::optional<std::string>& error = std::nullopt);

    // ---- the handshake (both servers agree: first to compare, then to the outcome)

    // A person accepted the request (on the initiator: the other server said its super admin did): `from` -> accepted,
    // and the acceptance holds `holds` from now. False when the phase was in none of `from`.
    static bool accept(uint64_t id, const std::vector<std::string>& from, const std::string& by,
                       std::chrono::seconds holds);
    // The outcome proposed: `from` -> proposed, any approval void. False when the phase was in none of `from`.
    static bool propose(uint64_t id, const std::vector<std::string>& from, const nlohmann::json& proposal);
    // The outcome approved: proposed -> approved, only while the proposal's plan_hash is still `planHash`.
    static bool approve(uint64_t id, const std::string& by, const std::string& planHash);
    // The approval (and the proposal) void: `from` -> `to` (accepted on the responder, open on the initiator), with why.
    static bool unapprove(uint64_t id, const std::vector<std::string>& from, const std::string& to,
                          const std::string& why);
    static void setExpiry(uint64_t id, std::time_t at);
    // Requests and acceptances past their expiry end 'expired' (nothing was applied). The rows that did.
    static std::vector<Relink> expire();
    // The other servers' relinks this server is asked to answer or has answered and not applied yet (responder,
    // requested | accepted | proposed | approved), newest first.
    [[nodiscard]] static std::vector<Relink> requests();
    // The entries a prepare received in earlier parts go (a prepare told again from its first part).
    static void clearEntries(uint64_t id);
    static void setPlan(uint64_t id, const std::optional<std::string>& core, const std::optional<std::string>& defaultChoice,
                        bool clearDefault);
    static void setApplied(uint64_t id, const std::string& role, uint64_t term, const std::string& mode);
    static void setSummary(uint64_t id, const nlohmann::json& summary);

    // ---- the drifted entries

    static void addEntries(uint64_t id, const std::vector<RelinkEntry>& entries);
    [[nodiscard]] static std::vector<RelinkEntry> entries(uint64_t id);
    // A page by path (kind narrows; empty: every kind).
    [[nodiscard]] static std::vector<RelinkEntry> page(uint64_t id, const std::string& kind, uint64_t offset,
                                                       uint64_t limit, uint64_t& total);
    [[nodiscard]] static std::optional<RelinkEntry> entry(uint64_t id, const std::string& uid);
    // One entry's choice (nullopt: the default). False when the relink holds no such entry.
    static bool setChoice(uint64_t id, const std::string& uid, const std::optional<std::string>& choice);
    // Every entry of `kind` (empty: all) takes `choice`. How many.
    static uint64_t setChoiceByKind(uint64_t id, const std::string& kind, const std::optional<std::string>& choice);
    static void setOutcome(uint64_t id, const std::string& uid, const std::optional<std::string>& requestId,
                           const std::string& outcome, const std::string& note);

    // ---- applying

    // In the caller's transaction: what the vault's mirror records here end as the relink resolves them: the detach
    // records with the peer settle (relinked_at), an open take over settles 'relinked' (its fork base goes), an open
    // rejoin becomes 'relinked', the vault's mirror row (core or orphaned) goes with its log and hashes, and the kept
    // base goes. Files whose contents never arrived here wait to be fetched again (missing -> waiting) when this
    // server becomes the mirror.
    static void release(pqxx::work& txn, uint32_t vaultId, uint64_t relinkId, bool becomingMirror);
};

}
