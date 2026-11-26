#include "db/query/mirror/Start.hpp"

#include "crypto/id/Generator.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/Entry.hpp"
#include "fs/model/Entry.hpp"
#include "ops/Error.hpp"
#include "rbac/Mirrored.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "vault/Content.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <pqxx/subtransaction>

#include <sys/stat.h>

#include <stdexcept>

namespace vh::db::query::mirror {

namespace mirror_start_query {

using json = nlohmann::json;

constexpr const char* kOfferColumns = R"SQL(
    id, offer_uid::text AS offer_uid, side, peer_id, vault_uid::text AS vault_uid, vault_id, core_vault_id,
    root_uid::text AS root_uid, term, name, description, quota, size_bytes, file_count, history, owner::text AS owner,
    role::text AS role, state, notify, reason, detail, started_by, decided_by, attempts, last_error,
    EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at,
    EXTRACT(EPOCH FROM expires_at)::BIGINT AS expires_at, EXTRACT(EPOCH FROM finished_at)::BIGINT AS finished_at
)SQL";

constexpr const char* kFinishedStates = "('started', 'declined', 'cancelled', 'expired', 'failed')";

std::string selectOffers(const std::string& where) { return std::string("SELECT ") + kOfferColumns + " FROM mirror_offer " + where; }

bool finishedState(const std::string& s) {
    return s == "started" || s == "declined" || s == "cancelled" || s == "expired" || s == "failed";
}

json roleJson(const OfferedRole& r) {
    return {{"name", r.name}, {"files", r.files}, {"directories", r.directories}, {"sync", r.sync}, {"roles", r.roles}};
}

json ownerJson(const OfferOwner& o) { return {{"node", o.node}, {"id", o.id}, {"name", o.name}}; }

template <class T, class Field>
std::optional<T> opt(const Field& f) {
    if (f.is_null()) return std::nullopt;
    return f.template as<T>();
}

Offer offerFrom(const pqxx::row_ref row) {
    Offer o;
    o.id = row["id"].as<uint32_t>();
    o.offer_uid = row["offer_uid"].as<std::string>();
    o.side = row["side"].as<std::string>();
    o.peer_id = row["peer_id"].as<uint32_t>();
    o.vault_uid = vh::crypto::id::fromUuid(row["vault_uid"].as<std::string>());
    o.vault_id = opt<uint32_t>(row["vault_id"]);
    o.core_vault_id = row["core_vault_id"].as<uint64_t>();
    o.root_uid = vh::crypto::id::fromUuid(row["root_uid"].as<std::string>());
    o.term = row["term"].as<uint64_t>();
    o.name = row["name"].as<std::string>();
    o.description = row["description"].as<std::string>();
    o.quota = row["quota"].as<uint64_t>();
    o.size_bytes = row["size_bytes"].as<uint64_t>();
    o.file_count = row["file_count"].as<uint64_t>();
    o.history = row["history"].as<bool>();
    const auto owner = json::parse(row["owner"].as<std::string>());
    o.owner = {.node = owner.value("node", ""), .id = owner.value("id", 0u), .name = owner.value("name", "")};
    if (!row["role"].is_null()) {
        const auto r = json::parse(row["role"].as<std::string>());
        o.role = OfferedRole{.name = r.value("name", ""), .files = r.value("files", uint64_t{0}),
                             .directories = r.value("directories", uint64_t{0}), .sync = r.value("sync", uint64_t{0}),
                             .roles = r.value("roles", uint64_t{0})};
    }
    o.state = row["state"].as<std::string>();
    o.notify = row["notify"].as<bool>();
    o.reason = opt<std::string>(row["reason"]);
    o.detail = opt<std::string>(row["detail"]);
    o.started_by = opt<uint32_t>(row["started_by"]);
    o.decided_by = opt<uint32_t>(row["decided_by"]);
    o.attempts = row["attempts"].as<uint32_t>();
    o.last_error = opt<std::string>(row["last_error"]);
    o.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    o.updated_at = static_cast<std::time_t>(row["updated_at"].as<int64_t>());
    o.expires_at = static_cast<std::time_t>(row["expires_at"].as<int64_t>());
    if (!row["finished_at"].is_null()) o.finished_at = static_cast<std::time_t>(row["finished_at"].as<int64_t>());
    return o;
}

std::string clipped(std::string s, const std::size_t max) {
    if (s.size() > max) s.resize(max);
    return s;
}

std::optional<std::string> clipped(const std::optional<std::string>& s, const std::size_t max) {
    if (!s) return std::nullopt;
    return clipped(*s, max);
}

}

// ---- offers ---------------------------------------------------------------------------------------------------------

Offer MirrorStart::insertOffer(const Offer& in) {
    using namespace mirror_start_query;
    if (in.side != "core" && in.side != "mirror") throw ops::Invalid("an offer's side is core or mirror");
    return Transactions::exec("mirror::MirrorStart::insertOffer", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "INSERT INTO mirror_offer (offer_uid, side, peer_id, vault_uid, vault_id, core_vault_id, root_uid, term, "
            "  name, description, quota, size_bytes, file_count, history, owner, role, state, notify, reason, detail, "
            "  started_by, decided_by, expires_at, finished_at) "
            "VALUES ($1::uuid, $2, $3, $4::uuid, $5, $6, $7::uuid, $8, $9, $10, $11, $12, $13, $14, $15::jsonb, "
            "  $16::jsonb, $17, $18, $19, $20, $21, $22, to_timestamp($23::bigint), "
            "  CASE WHEN $24 THEN CURRENT_TIMESTAMP END) "
            "ON CONFLICT DO NOTHING RETURNING id",
            pqxx::params{in.offer_uid, in.side, in.peer_id, vh::crypto::id::toUuid(in.vault_uid), in.vault_id,
                         static_cast<int64_t>(in.core_vault_id), vh::crypto::id::toUuid(in.root_uid),
                         static_cast<int64_t>(in.term), in.name, in.description, static_cast<int64_t>(in.quota),
                         static_cast<int64_t>(in.size_bytes), static_cast<int64_t>(in.file_count), in.history,
                         ownerJson(in.owner).dump(), in.role ? std::optional<std::string>(roleJson(*in.role).dump())
                                                             : std::nullopt,
                         in.state, in.notify, clipped(in.reason, 64), clipped(in.detail, 2000), in.started_by,
                         in.decided_by, static_cast<int64_t>(in.expires_at), finishedState(in.state)});
        if (res.empty()) throw ops::Conflict("a start of this vault is in progress already");
        const auto id = res.one_field_ref().as<uint32_t>();
        return offerFrom(txn.exec(selectOffers("WHERE id = $1"), pqxx::params{id}).one_row_ref());
    });
}

std::optional<Offer> MirrorStart::offer(const uint32_t id) {
    using namespace mirror_start_query;
    return Transactions::exec("mirror::MirrorStart::offer", [&](pqxx::work& txn) -> std::optional<Offer> {
        const auto res = txn.exec(selectOffers("WHERE id = $1"), pqxx::params{id});
        if (res.empty()) return std::nullopt;
        return offerFrom(res.one_row_ref());
    });
}

std::optional<Offer> MirrorStart::offerByUid(const std::string& offerUid, const std::string& side) {
    using namespace mirror_start_query;
    return Transactions::exec("mirror::MirrorStart::offerByUid", [&](pqxx::work& txn) -> std::optional<Offer> {
        const auto res = txn.exec(selectOffers("WHERE offer_uid = $1::uuid AND side = $2"), pqxx::params{offerUid, side});
        if (res.empty()) return std::nullopt;
        return offerFrom(res.one_row_ref());
    });
}

std::optional<Offer> MirrorStart::activeOffer(const vh::crypto::id::ObjectUid& vaultUid, const std::string& side) {
    using namespace mirror_start_query;
    return Transactions::exec("mirror::MirrorStart::activeOffer", [&](pqxx::work& txn) -> std::optional<Offer> {
        const auto res = txn.exec(selectOffers("WHERE vault_uid = $1::uuid AND side = $2 AND finished_at IS NULL"),
                                  pqxx::params{vh::crypto::id::toUuid(vaultUid), side});
        if (res.empty()) return std::nullopt;
        return offerFrom(res.one_row_ref());
    });
}

std::optional<Offer> MirrorStart::latestOffer(const vh::crypto::id::ObjectUid& vaultUid, const std::string& side) {
    using namespace mirror_start_query;
    return Transactions::exec("mirror::MirrorStart::latestOffer", [&](pqxx::work& txn) -> std::optional<Offer> {
        const auto res = txn.exec(selectOffers("WHERE vault_uid = $1::uuid AND side = $2 ORDER BY id DESC LIMIT 1"),
                                  pqxx::params{vh::crypto::id::toUuid(vaultUid), side});
        if (res.empty()) return std::nullopt;
        return offerFrom(res.one_row_ref());
    });
}

std::vector<Offer> MirrorStart::offers(const std::string& side, const bool openOnly) {
    using namespace mirror_start_query;
    return Transactions::exec("mirror::MirrorStart::offers", [&](pqxx::work& txn) {
        std::vector<Offer> out;
        const auto res = txn.exec(selectOffers("WHERE ($1 = '' OR side = $1) AND (NOT $2 OR finished_at IS NULL) "
                                               "ORDER BY id DESC LIMIT 500"),
                                  pqxx::params{side, openOnly});
        for (const auto row : res) out.push_back(offerFrom(row));
        return out;
    });
}

std::vector<Offer> MirrorStart::offersWithWork() {
    using namespace mirror_start_query;
    return Transactions::exec("mirror::MirrorStart::offersWithWork", [&](pqxx::work& txn) {
        std::vector<Offer> out;
        for (const auto row : txn.exec(selectOffers("WHERE finished_at IS NULL OR notify ORDER BY id")))
            out.push_back(offerFrom(row));
        return out;
    });
}

std::optional<Offer> MirrorStart::transition(const uint32_t id, const std::vector<std::string>& from, const Change& c) {
    using namespace mirror_start_query;
    std::string states = "{";
    for (const auto& s : from) states += (states.size() > 1 ? "," : "") + s;
    states += "}";
    return Transactions::exec("mirror::MirrorStart::transition", [&](pqxx::work& txn) -> std::optional<Offer> {
        const auto res = txn.exec(
            "UPDATE mirror_offer SET state = $3, notify = $4, reason = COALESCE($5, reason), "
            "  detail = COALESCE($6, detail), decided_by = COALESCE($7, decided_by), vault_id = COALESCE($8, vault_id), "
            "  updated_at = CURRENT_TIMESTAMP, finished_at = CASE WHEN $9 THEN CURRENT_TIMESTAMP END, "
            "  attempts = 0, last_error = NULL "
            "WHERE id = $1 AND state = ANY($2::text[]) RETURNING id",
            pqxx::params{id, states, c.to, c.notify, clipped(c.reason, 64), clipped(c.detail, 2000), c.decided_by,
                         c.vault_id, finishedState(c.to)});
        if (res.empty()) return std::nullopt;
        return offerFrom(txn.exec(selectOffers("WHERE id = $1"), pqxx::params{id}).one_row_ref());
    });
}

bool MirrorStart::told(const uint32_t id, const std::string& state) {
    return Transactions::exec("mirror::MirrorStart::told", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_offer SET notify = FALSE, attempts = 0, last_error = NULL, "
                        "  updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND state = $2 AND notify",
                        pqxx::params{id, state})
                   .affected_rows() > 0;
    });
}

void MirrorStart::noteAttempt(const uint32_t id, const std::string& error) {
    using namespace mirror_start_query;
    Transactions::exec("mirror::MirrorStart::noteAttempt", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_offer SET attempts = attempts + 1, last_error = $2, updated_at = CURRENT_TIMESTAMP "
                 "WHERE id = $1",
                 pqxx::params{id, clipped(error, 2000)});
    });
}

std::vector<Offer> MirrorStart::expireOffers() {
    using namespace mirror_start_query;
    return Transactions::exec("mirror::MirrorStart::expireOffers", [&](pqxx::work& txn) {
        std::vector<Offer> out;
        const auto res = txn.exec(
            "UPDATE mirror_offer SET state = 'expired', notify = TRUE, reason = 'offer_expired', "
            "  detail = 'nobody answered the offer before it expired', updated_at = CURRENT_TIMESTAMP, "
            "  finished_at = CURRENT_TIMESTAMP "
            "WHERE state IN ('offered', 'pending', 'accepted') AND expires_at <= CURRENT_TIMESTAMP RETURNING id");
        for (const auto row : res)
            out.push_back(offerFrom(
                txn.exec(selectOffers("WHERE id = $1"), pqxx::params{row[0].as<uint32_t>()}).one_row_ref()));
        return out;
    });
}

std::size_t MirrorStart::sweepFinished(const std::chrono::seconds age) {
    using namespace mirror_start_query;
    return Transactions::exec("mirror::MirrorStart::sweepFinished", [&](pqxx::work& txn) {
        return static_cast<std::size_t>(
            // A started offer stays while its vault is mirrored: a later cancel tells the other server through it.
            txn.exec("DELETE FROM mirror_offer WHERE finished_at IS NOT NULL AND NOT notify "
                     "  AND finished_at < CURRENT_TIMESTAMP - make_interval(secs => $1::bigint) "
                     "  AND NOT (state = 'started' AND vault_id IS NOT NULL "
                     "           AND EXISTS (SELECT 1 FROM mirror_vault m WHERE m.vault_id = mirror_offer.vault_id))",
                     pqxx::params{static_cast<int64_t>(age.count())})
                .affected_rows());
    });
}

// ---- the link's setting ---------------------------------------------------------------------------------------------

AcceptVaults MirrorStart::acceptVaults(const uint32_t peerId) {
    return Transactions::exec("mirror::MirrorStart::acceptVaults", [&](pqxx::work& txn) {
        AcceptVaults out;
        const auto res = txn.exec("SELECT accept_vaults, accept_vaults_set_by, "
                                  "  EXTRACT(EPOCH FROM accept_vaults_set_at)::BIGINT FROM peer WHERE id = $1",
                                  pqxx::params{peerId});
        if (res.empty()) return out;
        out.enabled = res[0][0].as<bool>();
        if (!res[0][1].is_null()) out.set_by = res[0][1].as<uint32_t>();
        if (!res[0][2].is_null()) out.set_at = static_cast<std::time_t>(res[0][2].as<int64_t>());
        return out;
    });
}

void MirrorStart::setAcceptVaults(const uint32_t peerId, const bool enabled, const std::optional<uint32_t> setBy) {
    Transactions::exec("mirror::MirrorStart::setAcceptVaults", [&](pqxx::work& txn) {
        if (txn.exec("UPDATE peer SET accept_vaults = $2, accept_vaults_set_by = $3, "
                     "  accept_vaults_set_at = CURRENT_TIMESTAMP WHERE id = $1 AND revoked_at IS NULL",
                     pqxx::params{peerId, enabled, setBy})
                .affected_rows() == 0)
            throw ops::NotFound("no such linked server");
    });
}

// ---- the core's vault -----------------------------------------------------------------------------------------------

std::optional<VaultFacts> MirrorStart::facts(const uint32_t vaultId) {
    return Transactions::exec("mirror::MirrorStart::facts", [&](pqxx::work& txn) -> std::optional<VaultFacts> {
        const auto v = txn.exec(
            "SELECT v.id, v.uid::text, v.name, COALESCE(v.description, ''), COALESCE(v.quota, 0), "
            "  v.deleted_at IS NOT NULL, v.type, v.owner_id, u.name, u.remote, u.home_node, u.home_id, "
            "  (SELECT r.strategy::text FROM sync s JOIN rsync r ON r.sync_id = s.id WHERE s.vault_id = v.id LIMIT 1), "
            "  (SELECT version FROM vault_keys WHERE vault_id = v.id) "
            "FROM vault v JOIN users u ON u.id = v.owner_id WHERE v.id = $1",
            pqxx::params{vaultId});
        if (v.empty()) return std::nullopt;
        const auto r = v[0];
        VaultFacts f;
        f.vault_id = r[0].as<uint32_t>();
        f.vault_uid = vh::crypto::id::fromUuid(r[1].as<std::string>());
        f.name = r[2].as<std::string>();
        f.description = r[3].as<std::string>();
        f.quota = static_cast<uint64_t>(std::max<int64_t>(0, r[4].as<int64_t>()));
        f.deleted = r[5].as<bool>();
        f.type = r[6].as<std::string>();
        f.owner_id = r[7].as<uint32_t>();
        f.owner.name = r[8].as<std::string>();
        if (r[9].as<bool>()) {
            f.owner.node = r[10].as<std::string>();
            f.owner.id = r[11].as<uint32_t>();
        } else {
            f.owner.id = f.owner_id;  // the node is this server's (the caller fills it in)
        }
        if (!r[12].is_null()) f.strategy = r[12].as<std::string>();
        if (!r[13].is_null()) f.current_version = r[13].as<uint32_t>();

        const auto root = txn.exec("SELECT d.uid::text FROM fs_entry e JOIN directories d ON d.fs_entry_id = e.id "
                                   "WHERE e.vault_id = $1 AND e.path = '/' LIMIT 1",
                                   pqxx::params{vaultId});
        if (!root.empty()) f.root_uid = vh::crypto::id::fromUuid(root[0][0].as<std::string>());

        const auto live = txn.exec(
            "SELECT count(*), COALESCE(sum(f.size_bytes), 0), "
            "  count(*) FILTER (WHERE f.content_format = 'gcm0'), "
            "  count(*) FILTER (WHERE f.content_format = 'plain' AND COALESCE(f.size_bytes, 0) > 0) "
            "FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = $1",
            pqxx::params{vaultId});
        f.live_files = live[0][0].as<uint64_t>();
        f.live_bytes = live[0][1].as<uint64_t>();
        f.gcm0_files = live[0][2].as<uint64_t>();
        f.plain_files = live[0][3].as<uint64_t>();
        const auto trash = txn.exec("SELECT count(*), COALESCE(sum(size_bytes), 0), count(*) FILTER (WHERE object_uid "
                                    "IS NULL) FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL",
                                    pqxx::params{vaultId});
        f.trashed_files = trash[0][0].as<uint64_t>();
        f.trashed_bytes = trash[0][1].as<uint64_t>();
        f.trashed_without_uid = trash[0][2].as<uint64_t>();
        return f;
    });
}

std::optional<std::string> MirrorStart::firstFileNotHeld(const uint32_t vaultId) {
    struct Row {
        unsigned int id{};
        std::string path;
        uint64_t size{};
        std::string generation;
    };
    const auto rows = Transactions::exec("mirror::MirrorStart::firstFileNotHeld", [&](pqxx::work& txn) {
        std::vector<Row> out;
        for (const auto row : txn.exec("SELECT e.id, e.path, COALESCE(f.size_bytes, 0), COALESCE(f.encryption_iv, '') "
                                       "FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = $1 "
                                       "  AND COALESCE(f.size_bytes, 0) > 0 ORDER BY e.id",
                                       pqxx::params{vaultId}))
            out.push_back({.id = row[0].as<unsigned int>(), .path = row[1].as<std::string>(),
                           .size = row[2].as<uint64_t>(), .generation = row[3].as<std::string>()});
        return out;
    });
    // The backing path is the entry model's (backing root, vault alias, each ancestor's alias).
    for (const auto& r : rows) {
        const auto entry = query::fs::Entry::getFSEntryById(r.id);
        if (!entry) continue;
        uint64_t sealed = r.size;
        try {
            sealed = vh::vault::content::sealedSize(r.size, vh::vault::content::formatOf(r.generation));
        } catch (const std::exception&) {
        }
        struct stat st{};
        if (::stat(entry->backing_path.c_str(), &st) != 0 || !S_ISREG(st.st_mode) ||
            static_cast<uint64_t>(st.st_size) != sealed)
            return r.path;
    }
    return std::nullopt;
}

// ---- the mirror's vault ---------------------------------------------------------------------------------------------

std::optional<uint32_t> MirrorStart::vaultWithUid(const vh::crypto::id::ObjectUid& vaultUid) {
    return Transactions::exec("mirror::MirrorStart::vaultWithUid", [&](pqxx::work& txn) -> std::optional<uint32_t> {
        const auto res = txn.exec("SELECT id FROM vault WHERE uid = $1::uuid", pqxx::params{vh::crypto::id::toUuid(vaultUid)});
        if (res.empty()) return std::nullopt;
        return res[0][0].as<uint32_t>();
    });
}

std::optional<uint32_t> MirrorStart::vaultNamed(const std::string& name) {
    return Transactions::exec("mirror::MirrorStart::vaultNamed", [&](pqxx::work& txn) -> std::optional<uint32_t> {
        const auto res = txn.exec("SELECT id FROM vault WHERE deleted_at IS NULL AND lower(btrim(name)) = lower(btrim($1)) "
                                  "ORDER BY id LIMIT 1",
                                  pqxx::params{name});
        if (res.empty()) return std::nullopt;
        return res[0][0].as<uint32_t>();
    });
}

uint32_t MirrorStart::reserveVaultId() {
    return Transactions::exec("mirror::MirrorStart::reserveVaultId", [&](pqxx::work& txn) {
        return txn.exec("SELECT nextval('vault_id_seq')").one_field_ref().as<uint32_t>();
    });
}

uint32_t MirrorStart::createMirrorVault(const NewMirrorVault& in) {
    using encoding::to_hex_bytea;
    if (in.vault_id == 0) throw std::invalid_argument("a mirror's vault needs a reserved vault id");
    if (in.keys.empty()) throw std::invalid_argument("a mirror's vault needs its key versions");
    const auto fsRoot = query::fs::Entry::getRootEntry();
    if (!fsRoot) throw std::runtime_error("the filesystem root entry is missing");
    const vh::sync::model::LocalPolicy defaults;
    const auto id = Transactions::exec("mirror::MirrorStart::createMirrorVault", [&](pqxx::work& txn) {
        const auto offer = txn.exec("SELECT state FROM mirror_offer WHERE id = $1 AND side = 'mirror' FOR UPDATE",
                                    pqxx::params{in.offer_id});
        if (offer.empty() || offer[0][0].as<std::string>() != "accepted")
            throw ops::Conflict("the offer is no longer waiting for its keys");
        if (!txn.exec("SELECT 1 FROM vault WHERE uid = $1::uuid", pqxx::params{vh::crypto::id::toUuid(in.vault_uid)}).empty())
            throw ops::Conflict("a vault on this server already has that vault's uid");
        if (txn.exec("SELECT 1 FROM peer WHERE id = $1 AND revoked_at IS NULL", pqxx::params{in.peer_id}).empty())
            throw ops::NotFound("no such linked server");

        // ---- the owner: a local account only when its home is this server; otherwise the remote account for it
        std::optional<uint32_t> ownerId;
        if (!in.owner.node.empty()) {
            const auto here = txn.exec("SELECT node_id FROM device_node LIMIT 1");
            if (!here.empty() && here[0][0].as<std::string>() == in.owner.node) {
                const auto local = txn.exec("SELECT id FROM users WHERE id = $1 AND NOT remote", pqxx::params{in.owner.id});
                if (!local.empty()) ownerId = local[0][0].as<uint32_t>();
            }
        }
        if (!ownerId) {
            auto name = in.owner.name.empty() ? std::string("remote-") + std::to_string(in.owner.id) : in.owner.name;
            if (name.size() > 80) name.resize(80);
            ownerId = txn.exec("INSERT INTO users (name, password_hash, remote, home_node, home_id) "
                               "VALUES ($1, '', TRUE, $2, $3) "
                               "ON CONFLICT (home_node, home_id) WHERE remote DO UPDATE SET home_node = EXCLUDED.home_node "
                               "RETURNING id",
                               pqxx::params{name, in.owner.node, in.owner.id})
                          .one_field_ref()
                          .as<uint32_t>();
        }

        // ---- the vault (local, bucketless), its sync rows and its root folder with the core's root uid
        txn.exec("INSERT INTO vault (id, name, type, description, owner_id, mount_point, quota, is_active, slug, "
                 "fuse_name, uid) VALUES ($1, $2, 'local', $3, $4, $5, $6, true, NULL, NULL, $7::uuid)",
                 pqxx::params{in.vault_id, in.name, in.description, *ownerId, in.mount_point,
                              static_cast<int64_t>(in.quota), vh::crypto::id::toUuid(in.vault_uid)});
        txn.exec(pqxx::prepped{"insert_sync_and_fsync"},
                 pqxx::params{in.vault_id, vh::sync::model::Policy::clampInterval(defaults.interval).count(),
                              vh::sync::model::to_string(defaults.conflict_policy)});
        const auto rootName = txn.exec("SELECT COALESCE(fuse_name, slug) FROM vault WHERE id = $1", pqxx::params{in.vault_id})
                                  .one_field_ref()
                                  .as<std::string>();
        const auto rootId = txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, "
                                     "  last_modified_by, path, mode, is_hidden, is_system) "
                                     "VALUES ($1, $2, $3, $4, $5, $5, '/', 493, false, false) RETURNING id",
                                     pqxx::params{in.vault_id, fsRoot->id, rootName, in.mount_point, *ownerId})
                                .one_field_ref()
                                .as<unsigned int>();
        txn.exec("INSERT INTO directories (fs_entry_id, file_count, subdirectory_count, size_bytes, uid) "
                 "VALUES ($1, 0, 0, 0, $2::uuid)",
                 pqxx::params{rootId, vh::crypto::id::toUuid(in.root_uid)});
        vh::db::query::fs::Directory::addToAncestorStats(txn, fsRoot->id, 0, 0, 1);

        // ---- the keys, sealed under this host's vault master, with where each came from
        for (const auto& k : in.keys) {
            const auto& p = k.provenance;
            const std::optional<std::string> sig =
                p.attestation.empty() ? std::nullopt : std::make_optional(to_hex_bytea(p.attestation));
            if (k.current)
                txn.exec("INSERT INTO vault_keys (vault_id, encrypted_key, iv, version, key_check, attestation_key_id, "
                         "attestation, master_version) VALUES ($1, $2, $3, $4, $5, $6, $7::bytea, $8)",
                         pqxx::params{in.vault_id, to_hex_bytea(k.encrypted_key), to_hex_bytea(k.iv), k.version,
                                      p.key_check, p.attestation_key_id, sig, k.master_version});
            else
                txn.exec("INSERT INTO vault_keys_trashed (vault_id, version, encrypted_key, iv, created_at, trashed_at, "
                         "rotation_completed_at, key_check, attestation_key_id, attestation, master_version) VALUES ($1, "
                         "$2, $3, $4, NOW(), NOW(), NOW(), $5, $6, $7::bytea, $8)",
                         pqxx::params{in.vault_id, k.version, to_hex_bytea(k.encrypted_key), to_hex_bytea(k.iv),
                                      p.key_check, p.attestation_key_id, sig, k.master_version});
            txn.exec("INSERT INTO vault_key_origin (vault_id, version, origin_node_id, origin_vault_id, origin_key_check, "
                     "attestation_key_id, attestation_public_key, attestation, anchor) VALUES ($1, $2, $3, $4, $5, $6, "
                     "$7::bytea, $8::bytea, 'peer')",
                     pqxx::params{in.vault_id, k.version, k.origin_node_id, static_cast<int64_t>(k.origin_vault_id),
                                  k.origin_key_check, k.attestation_key_id, to_hex_bytea(k.attestation_public_key),
                                  to_hex_bytea(k.attestation)});
        }

        // ---- this server mirrors the vault (no grant yet: nobody has access), and the offer says so
        txn.exec("INSERT INTO mirror_vault (vault_id, peer_id, role, term) VALUES ($1, $2, 'mirror', $3)",
                 pqxx::params{in.vault_id, in.peer_id, static_cast<int64_t>(in.term)});
        txn.exec("UPDATE mirror_offer SET state = 'installed', notify = FALSE, vault_id = $2, attempts = 0, "
                 "  last_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{in.offer_id, in.vault_id});
        return in.vault_id;
    });
    vh::rbac::mirrored::reload();
    return id;
}

void MirrorStart::dropOrphanedOwner(const uint32_t ownerId) {
    try {
        Transactions::exec("mirror::MirrorStart::dropOrphanedOwner", [&](pqxx::work& txn) {
            pqxx::subtransaction sub(txn, "mirror_owner_drop");
            try {
                sub.exec("DELETE FROM users WHERE id = $1 AND remote AND NOT EXISTS (SELECT 1 FROM vault WHERE owner_id = $1)",
                         pqxx::params{ownerId});
                sub.commit();
            } catch (const pqxx::sql_error&) {
                sub.abort();  // still named elsewhere (an entry's creator, an audit line): it stays
            }
        });
    } catch (const std::exception&) {
    }
}

}
