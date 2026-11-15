#include "db/query/sync/Manifest.hpp"

#include "crypto/id/ObjectUid.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "db/query/device/Device.hpp"
#include "sync/manifest/Objects.hpp"
#include "vault/Content.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <version.h>

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>

namespace vh::db::query::sync {

namespace manifest_query_detail {

namespace mf = vh::sync::manifest;

constexpr const char* kRootStateKey = ".vaulthalla/root";

// A timestamptz column as the manifest writes times (UTC, seconds).
std::string iso(const std::string& column) {
    return fmt::format("to_char({} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')", column);
}

std::optional<std::string> optText(const pqxx::field_ref& f) {
    if (f.is_null()) return std::nullopt;
    return f.as<std::string>();
}

std::string hexOf(const std::vector<uint8_t>& bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out += kHex[b >> 4];
        out += kHex[b & 0x0f];
    }
    return out;
}

template <typename T>
std::optional<T> optNum(const pqxx::field_ref& f) {
    if (f.is_null()) return std::nullopt;
    return f.as<T>();
}

std::string uidFromUuid(const pqxx::field_ref& f) { return mf::uidText(crypto::id::fromUuid(f.as<std::string>())); }

// Gives every directory and symlink of the vault without a uid one (libsodium, never PostgreSQL), like
// SqlDeployer's assignUids does for files.
void assignTreeUids(pqxx::work& txn, const uint32_t vaultId, const std::string& table) {
    const auto rows = txn.exec(fmt::format("SELECT t.fs_entry_id FROM {} t JOIN fs_entry e ON e.id = t.fs_entry_id "
                                           "WHERE e.vault_id = $1 AND t.uid IS NULL",
                                           table),
                               pqxx::params{vaultId});
    if (rows.empty()) return;
    std::string ids = "{", uids = "{";
    for (pqxx::result::size_type i = 0; i < rows.size(); ++i) {
        if (i) {
            ids += ',';
            uids += ',';
        }
        ids += rows[i][0].c_str();
        uids += crypto::id::toUuid(crypto::id::newObjectUid());
    }
    ids += '}';
    uids += '}';
    txn.exec(fmt::format("UPDATE {} t SET uid = u.uid FROM unnest($1::int[], $2::uuid[]) AS u(id, uid) "
                         "WHERE t.fs_entry_id = u.id AND t.uid IS NULL",
                         table),
             pqxx::params{ids, uids});
}

std::string parentPath(const std::string& path) {
    const auto slash = path.find_last_of('/');
    if (slash == std::string::npos || slash == 0) return "/";
    return path.substr(0, slash);
}

std::string baseName(const std::string& path) {
    const auto slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

}

vh::sync::manifest::ChainState Manifest::state(const uint32_t vaultId) {
    using namespace manifest_query_detail;
    return Transactions::exec("Manifest::state", [&](pqxx::work& txn) {
        vh::sync::manifest::ChainState s;
        const auto res = txn.exec(
            "SELECT epoch, root_sha256, etag, refused_reason, refused_epoch, refused_root_sha256, "
            "       EXTRACT(EPOCH FROM refused_at)::bigint AS refused_at, EXTRACT(EPOCH FROM gc_at)::bigint AS gc_at, "
            "       root_version_id, base_version_id, array_to_json(settle_window)::text AS settle_window, own_epoch, "
            "       applying_epoch, applying_root_sha256, array_to_json(publishing_roots)::text AS publishing_roots, "
            "       array_to_json(writers)::text AS writers "
            "FROM remote_manifest_state WHERE vault_id = $1 AND manifest_key = $2",
            pqxx::params{vaultId, kRootStateKey});
        if (res.empty()) return s;
        const auto row = res[0];
        s.epoch = optNum<uint64_t>(row["epoch"]);
        s.root_sha256 = optText(row["root_sha256"]);
        s.etag = optText(row["etag"]);
        s.refused_reason = optText(row["refused_reason"]);
        s.refused_epoch = optNum<uint64_t>(row["refused_epoch"]);
        s.refused_root_sha256 = optText(row["refused_root_sha256"]);
        s.refused_at = optNum<std::time_t>(row["refused_at"]);
        s.gc_at = optNum<std::time_t>(row["gc_at"]);
        s.root_version_id = optText(row["root_version_id"]);
        s.base_version_id = optText(row["base_version_id"]);
        if (const auto w = optText(row["settle_window"]))
            for (const auto& id : nlohmann::json::parse(*w)) s.settle_window.push_back(id.get<std::string>());
        s.own_epoch = optNum<uint64_t>(row["own_epoch"]);
        s.applying_epoch = optNum<uint64_t>(row["applying_epoch"]);
        s.applying_root_sha256 = optText(row["applying_root_sha256"]);
        if (const auto p = optText(row["publishing_roots"]))
            for (const auto& sha : nlohmann::json::parse(*p)) s.publishing_roots.push_back(sha.get<std::string>());
        if (const auto w = optText(row["writers"]))
            for (const auto& node : nlohmann::json::parse(*w)) s.writers.push_back(node.get<std::string>());
        return s;
    });
}

void Manifest::recordRoot(const uint32_t vaultId, const vh::sync::manifest::RootRecord& rec) {
    Transactions::exec("Manifest::recordRoot", [&](pqxx::work& txn) { recordRoot(txn, vaultId, rec); });
}

void Manifest::recordRoot(pqxx::work& txn, const uint32_t vaultId, const vh::sync::manifest::RootRecord& rec) {
    using namespace manifest_query_detail;
    const auto epoch = rec.epoch;
    const auto& rootSha256 = rec.root_sha256;
    const auto& sids = rec.sids;
    {
        // The window travels as JSON: version ids may hold '+', '/' and '='.
        txn.exec("INSERT INTO remote_manifest_state (vault_id, manifest_key, etag, epoch, root_sha256, root_version_id, "
                 "  base_version_id, settle_window, own_epoch, base_root, publishing_roots, writers, updated_at) "
                 "VALUES ($1, $2, $3, $4::bigint, $5, $6, $7, ARRAY(SELECT json_array_elements_text($8::json)), "
                 "  CASE WHEN $9::boolean THEN $4::bigint END, $10::bytea, ARRAY[$5::text], "
                 "  ARRAY(SELECT json_array_elements_text($11::json)), CURRENT_TIMESTAMP) "
                 "ON CONFLICT (vault_id, manifest_key) DO UPDATE SET etag = EXCLUDED.etag, epoch = EXCLUDED.epoch, "
                 "  root_sha256 = EXCLUDED.root_sha256, root_version_id = EXCLUDED.root_version_id, "
                 "  base_version_id = EXCLUDED.base_version_id, settle_window = EXCLUDED.settle_window, "
                 "  own_epoch = COALESCE(EXCLUDED.own_epoch, remote_manifest_state.own_epoch), "
                 "  base_root = EXCLUDED.base_root, publishing_roots = ARRAY[EXCLUDED.root_sha256], "
                 "  writers = EXCLUDED.writers, "
                 "  applying_epoch = CASE WHEN remote_manifest_state.applying_root_sha256 = EXCLUDED.root_sha256 "
                 "    THEN NULL ELSE remote_manifest_state.applying_epoch END, "
                 "  applying_root_sha256 = CASE WHEN remote_manifest_state.applying_root_sha256 = EXCLUDED.root_sha256 "
                 "    THEN NULL ELSE remote_manifest_state.applying_root_sha256 END, "
                 "  refused_reason = NULL, refused_epoch = NULL, "
                 "  refused_root_sha256 = NULL, refused_at = NULL, updated_at = CURRENT_TIMESTAMP",
                 pqxx::params{vaultId, kRootStateKey, rec.etag, static_cast<int64_t>(epoch), rootSha256,
                              rec.version_id, rec.base_version_id,
                              nlohmann::json(rec.settle_window).dump(), rec.own,
                              rec.base ? std::optional<std::string>(encoding::to_hex_bytea(rec.base->root))
                                       : std::nullopt,
                              nlohmann::json(rec.writers).dump()});
        txn.exec("DELETE FROM remote_manifest_pending WHERE vault_id = $1", pqxx::params{vaultId});
        std::string array = "{";
        for (std::size_t i = 0; i < sids.size(); ++i) {
            if (i) array += ',';
            array += sids[i];  // base32: no quoting needed
        }
        array += '}';
        txn.exec("INSERT INTO remote_manifest_root (vault_id, epoch, root_sha256, sids) VALUES ($1, $2, $3, $4::text[]) "
                 "ON CONFLICT (vault_id, epoch) DO UPDATE SET root_sha256 = EXCLUDED.root_sha256, sids = EXCLUDED.sids, "
                 "  published_at = CURRENT_TIMESTAMP",
                 pqxx::params{vaultId, static_cast<int64_t>(epoch), rootSha256, array});
        txn.exec("DELETE FROM remote_manifest_root WHERE vault_id = $1 AND epoch NOT IN "
                 "(SELECT epoch FROM remote_manifest_root WHERE vault_id = $1 ORDER BY epoch DESC LIMIT $2)",
                 pqxx::params{vaultId, static_cast<int64_t>(kRetainedRoots)});

        // The base copy follows `known` (design/sync/manifest-applier.md, "The merge base"): the named sids' bytes,
        // nothing else. A sid's bytes never change (a fresh random name per object), so stored ones are kept.
        if (!rec.base) {
            txn.exec("DELETE FROM remote_manifest_base WHERE vault_id = $1", pqxx::params{vaultId});
        } else {
            txn.exec("DELETE FROM remote_manifest_base WHERE vault_id = $1 AND sid <> ALL ($2::text[])",
                     pqxx::params{vaultId, array});
            for (const auto& [sid, bytes] : rec.base->objects) {
                if (std::ranges::find(sids, sid) == sids.end()) continue;
                txn.exec("INSERT INTO remote_manifest_base (vault_id, sid, object_sha256, bytes) "
                         "VALUES ($1, $2, $3, $4::bytea) ON CONFLICT (vault_id, sid) DO NOTHING",
                         pqxx::params{vaultId, sid, mf::sha256Hex(bytes), encoding::to_hex_bytea(bytes)});
            }
        }
    }
}

std::optional<vh::sync::manifest::BaseCopy> Manifest::base(const uint32_t vaultId) {
    using namespace manifest_query_detail;
    return Transactions::exec("Manifest::base", [&](pqxx::work& txn) -> std::optional<mf::BaseCopy> {
        const auto root = txn.exec("SELECT base_root FROM remote_manifest_state WHERE vault_id = $1 AND manifest_key = $2 "
                                   "AND base_root IS NOT NULL",
                                   pqxx::params{vaultId, kRootStateKey});
        if (root.empty()) return std::nullopt;
        mf::BaseCopy copy;
        copy.root = encoding::from_hex_bytea(root[0][0].as<std::string>());
        for (const auto row : txn.exec("SELECT sid, bytes FROM remote_manifest_base WHERE vault_id = $1",
                                       pqxx::params{vaultId}))
            copy.objects[row[0].as<std::string>()] = encoding::from_hex_bytea(row[1].as<std::string>());
        return copy;
    });
}

void Manifest::notePublishing(const uint32_t vaultId, const std::string& rootSha256,
                              const vh::sync::manifest::BaseCopy& pending) {
    using namespace manifest_query_detail;
    Transactions::exec("Manifest::notePublishing", [&](pqxx::work& txn) {
        // The pending base copy first: the new objects by sid (kept until a record names or drops them) and the root.
        for (const auto& [sid, bytes] : pending.objects)
            txn.exec("INSERT INTO remote_manifest_base (vault_id, sid, object_sha256, bytes) VALUES ($1, $2, $3, $4::bytea) "
                     "ON CONFLICT (vault_id, sid) DO NOTHING",
                     pqxx::params{vaultId, sid, mf::sha256Hex(bytes), encoding::to_hex_bytea(bytes)});
        if (!pending.root.empty())
            txn.exec("INSERT INTO remote_manifest_pending (vault_id, root_sha256, bytes) VALUES ($1, $2, $3::bytea) "
                     "ON CONFLICT (vault_id, root_sha256) DO NOTHING",
                     pqxx::params{vaultId, rootSha256, encoding::to_hex_bytea(pending.root)});
        txn.exec("INSERT INTO remote_manifest_state (vault_id, manifest_key, publishing_roots, updated_at) "
                 "VALUES ($1, $2, ARRAY[$3::text], CURRENT_TIMESTAMP) ON CONFLICT (vault_id, manifest_key) DO UPDATE SET "
                 "  publishing_roots = (CASE WHEN cardinality(remote_manifest_state.publishing_roots) >= 256 "
                 "    THEN remote_manifest_state.publishing_roots[cardinality(remote_manifest_state.publishing_roots) - 254:] "
                 "    ELSE remote_manifest_state.publishing_roots END) || $3::text, updated_at = CURRENT_TIMESTAMP",
                 pqxx::params{vaultId, kRootStateKey, rootSha256});
        txn.exec("DELETE FROM remote_manifest_pending p USING remote_manifest_state s WHERE p.vault_id = $1 "
                 "AND s.vault_id = $1 AND s.manifest_key = $2 AND p.root_sha256 <> ALL (s.publishing_roots)",
                 pqxx::params{vaultId, kRootStateKey});
    });
}

std::optional<vh::sync::manifest::BaseCopy> Manifest::pendingBase(const uint32_t vaultId, const std::string& rootSha256) {
    using namespace manifest_query_detail;
    return Transactions::exec("Manifest::pendingBase", [&](pqxx::work& txn) -> std::optional<mf::BaseCopy> {
        const auto root = txn.exec("SELECT bytes FROM remote_manifest_pending WHERE vault_id = $1 AND root_sha256 = $2",
                                   pqxx::params{vaultId, rootSha256});
        if (root.empty()) return std::nullopt;
        mf::BaseCopy copy;
        copy.root = encoding::from_hex_bytea(root[0][0].as<std::string>());
        for (const auto row : txn.exec("SELECT sid, bytes FROM remote_manifest_base WHERE vault_id = $1",
                                       pqxx::params{vaultId}))
            copy.objects[row[0].as<std::string>()] = encoding::from_hex_bytea(row[1].as<std::string>());
        return copy;
    });
}

void Manifest::markApplying(const uint32_t vaultId, const uint64_t epoch, const std::string& rootSha256) {
    using namespace manifest_query_detail;
    Transactions::exec("Manifest::markApplying", [&](pqxx::work& txn) {
        txn.exec("UPDATE remote_manifest_state SET applying_epoch = $3, applying_root_sha256 = $4, "
                 "  updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1 AND manifest_key = $2",
                 pqxx::params{vaultId, kRootStateKey, static_cast<int64_t>(epoch), rootSha256});
    });
}

bool Manifest::recordRefused(const uint32_t vaultId, const std::string& reason, const uint64_t epoch,
                             const std::string& rootSha256) {
    using namespace manifest_query_detail;
    return Transactions::exec("Manifest::recordRefused", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "INSERT INTO remote_manifest_state (vault_id, manifest_key, refused_reason, refused_epoch, "
            "  refused_root_sha256, refused_at, updated_at) "
            "VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
            "ON CONFLICT (vault_id, manifest_key) DO UPDATE SET refused_reason = EXCLUDED.refused_reason, "
            "  refused_epoch = EXCLUDED.refused_epoch, refused_root_sha256 = EXCLUDED.refused_root_sha256, "
            "  refused_at = EXCLUDED.refused_at, updated_at = CURRENT_TIMESTAMP "
            "WHERE remote_manifest_state.refused_root_sha256 IS DISTINCT FROM EXCLUDED.refused_root_sha256 "
            "   OR remote_manifest_state.refused_reason IS DISTINCT FROM EXCLUDED.refused_reason "
            "RETURNING 1",
            pqxx::params{vaultId, kRootStateKey, reason, static_cast<int64_t>(epoch), rootSha256});
        return !res.empty();
    });
}

std::set<std::string> Manifest::retainedSids(const uint32_t vaultId) {
    return Transactions::exec("Manifest::retainedSids", [&](pqxx::work& txn) {
        std::set<std::string> out;
        for (const auto row : txn.exec("SELECT unnest(sids) FROM remote_manifest_root WHERE vault_id = $1",
                                       pqxx::params{vaultId}))
            out.insert(row[0].as<std::string>());
        return out;
    });
}

std::time_t Manifest::firstUnreferenced(const uint32_t vaultId, const std::string& sid) {
    return Transactions::exec("Manifest::firstUnreferenced", [&](pqxx::work& txn) {
        return txn.exec("INSERT INTO remote_manifest_gc (vault_id, sid) VALUES ($1, $2) "
                        "ON CONFLICT (vault_id, sid) DO UPDATE SET sid = EXCLUDED.sid "
                        "RETURNING EXTRACT(EPOCH FROM first_unreferenced_at)::bigint",
                        pqxx::params{vaultId, sid}).one_field_ref().as<std::time_t>();
    });
}

void Manifest::forgetUnreferenced(const uint32_t vaultId, const std::string& sid) {
    Transactions::exec("Manifest::forgetUnreferenced", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM remote_manifest_gc WHERE vault_id = $1 AND sid = $2", pqxx::params{vaultId, sid});
    });
}

void Manifest::markCollected(const uint32_t vaultId) {
    using namespace manifest_query_detail;
    Transactions::exec("Manifest::markCollected", [&](pqxx::work& txn) {
        txn.exec("UPDATE remote_manifest_state SET gc_at = CURRENT_TIMESTAMP WHERE vault_id = $1 AND manifest_key = $2",
                 pqxx::params{vaultId, kRootStateKey});
    });
}

vh::sync::manifest::Content Manifest::collect(const uint32_t vaultId) { return collect(vaultId, CollectOptions{}); }

vh::sync::manifest::Content Manifest::collect(const uint32_t vaultId, const CollectOptions& options) {
    using namespace manifest_query_detail;
    const auto nodeId = device::Devices::nodeId();
    return Transactions::exec("Manifest::collect", [&](pqxx::work& txn) {
        mf::Content c;
        c.producer = {nodeId, vaultId, std::string("vaulthalla ") + VH_VERSION};

        // ---- the vault
        const auto vrow = txn.exec(
            fmt::format("SELECT v.uid, v.name, {}, v.quota, r.strategy, p.mode AS recovery_mode, "
                        "       p.version_max_age_days "
                        "FROM vault v LEFT JOIN sync s ON s.vault_id = v.id LEFT JOIN rsync r ON r.sync_id = s.id "
                        "LEFT JOIN vault_recovery_policy p ON p.vault_id = v.id WHERE v.id = $1",
                        iso("v.created_at") + " AS created_at"),
            pqxx::params{vaultId});
        if (vrow.empty() || vrow[0]["uid"].is_null()) throw std::runtime_error("manifest: the vault has no uid");
        mf::VaultInfo info;
        info.name = vrow[0]["name"].as<std::string>();
        info.created_at = optText(vrow[0]["created_at"]);
        if (const auto quota = vrow[0]["quota"].as<int64_t>(); quota > 0) info.quota_bytes = static_cast<uint64_t>(quota);
        info.sync_strategy = options.sync_strategy ? options.sync_strategy : optText(vrow[0]["strategy"]);
        if (!vrow[0]["recovery_mode"].is_null())
            info.recovery_policy = mf::FileRecovery{vrow[0]["recovery_mode"].as<std::string>(),
                                                    optNum<uint32_t>(vrow[0]["version_max_age_days"])};
        c.vault = std::move(info);
        // Recovery recipients (#370, spec 03 §5.7): every grant, revoked ones too (with revoked_at), oldest first.
        mf::RecoveryPolicy policy;
        for (const auto row : txn.exec(
                 fmt::format("SELECT grant_id, recipient_id, class, suite, label, {}, authorized_by, {}, public_key, "
                             "account_key_generation "
                             "FROM vault_recovery_grant WHERE vault_id = $1 ORDER BY added_at, grant_id",
                             iso("added_at") + " AS added_at", iso("revoked_at") + " AS revoked_at"),
                 pqxx::params{vaultId})) {
            mf::Grant g;
            g.grant_id = row["grant_id"].as<std::string>();
            g.recipient_id = row["recipient_id"].as<std::string>();
            g.recipient_class = row["class"].as<std::string>();
            g.suite = row["suite"].as<uint32_t>();
            g.label = optText(row["label"]);
            g.added_at = optText(row["added_at"]);
            g.authorized_by = optText(row["authorized_by"]);
            g.revoked_at = optText(row["revoked_at"]);
            g.public_key = crypto::util::b64_encode(encoding::from_hex_bytea(row["public_key"].as<std::string>()));
            if (!row["account_key_generation"].is_null())
                g.account_key_generation = row["account_key_generation"].as<uint32_t>();
            policy.grants.push_back(std::move(g));
        }
        // The account's signed recovery policy (key-manager.md): carried for a vault the account key covers, as the
        // pinned row holds it. A reader verifies it against its own pin; nothing here vouches for it.
        if (!txn.exec("SELECT 1 FROM vault_recovery_grant WHERE vault_id = $1 AND account_key_generation IS NOT NULL AND "
                      "revoked_at IS NULL LIMIT 1", pqxx::params{vaultId}).empty()) {
            const auto ap = txn.exec("SELECT policy, encode(policy_signature, 'base64') FROM cloud_account_key WHERE state = "
                                     "'pinned' AND policy IS NOT NULL ORDER BY generation DESC LIMIT 1");
            if (!ap.empty()) {
                // base64url without padding, as the service serves it.
                auto sig = ap[0][1].as<std::string>();
                std::erase(sig, '\n');
                std::erase(sig, '=');
                for (auto& ch : sig) ch = ch == '+' ? '-' : ch == '/' ? '_' : ch;
                policy.account_policy = mf::AccountPolicyBytes{.policy = ap[0][0].as<std::string>(), .signature = sig};
            }
        }
        c.recovery_policy = std::move(policy);
        // KEV1 envelopes by key version (keys[].envelopes): every kid written, a revoked grant's too.
        std::map<uint32_t, std::vector<std::string>> envelopesByVersion;
        // And other writers' envelopes (manifest_foreign_envelope, migration 147) for a recipient one of this vault's
        // grants has, revoked or not, as this server lists its own: every writer names the same kids, so the root is
        // the same whoever publishes it.
        for (const auto row : txn.exec("SELECT key_version, kid FROM vault_key_envelope WHERE vault_id = $1 "
                                       "UNION SELECT f.key_version, f.kid FROM manifest_foreign_envelope f "
                                       "WHERE f.vault_id = $1 AND EXISTS (SELECT 1 FROM vault_recovery_grant g "
                                       "  WHERE g.vault_id = $1 AND g.recipient_id = f.recipient_id) "
                                       "ORDER BY 1, 2",
                                       pqxx::params{vaultId}))
            envelopesByVersion[row[0].as<uint32_t>()].push_back(row[1].as<std::string>());

        // ---- key history: the current version and every retired one still held
        const auto keyRows = txn.exec(
            fmt::format("SELECT k.version, k.key_check, k.attestation_key_id, k.attestation, a.public_key, {}, "
                        "       NULL::text AS retired_at "
                        "FROM vault_keys k LEFT JOIN key_attestation_keys a ON a.id = k.attestation_key_id "
                        "WHERE k.vault_id = $1 "
                        "UNION ALL "
                        "SELECT t.version, t.key_check, t.attestation_key_id, t.attestation, a.public_key, {}, {} "
                        "FROM vault_keys_trashed t LEFT JOIN key_attestation_keys a ON a.id = t.attestation_key_id "
                        "WHERE t.vault_id = $1 ORDER BY 1",
                        iso("k.created_at") + " AS created_at", iso("t.created_at"), iso("t.trashed_at")),
            pqxx::params{vaultId});
        // Versions a restore recovered (#371, migration 131): where they were minted and the original attestation.
        std::map<uint32_t, mf::KeyOrigin> origins;
        for (const auto row : txn.exec(
                 fmt::format("SELECT version, origin_node_id, origin_vault_id, origin_key_check, attestation_key_id, "
                             "       attestation_public_key, attestation, {} FROM vault_key_origin WHERE vault_id = $1",
                             iso("recovered_at") + " AS recovered_at"),
                 pqxx::params{vaultId})) {
            mf::KeyOrigin o;
            o.node_id = row["origin_node_id"].as<std::string>();
            o.vault_id = row["origin_vault_id"].as<uint64_t>();
            o.key_check = row["origin_key_check"].as<std::string>();
            o.attestation.key_id = row["attestation_key_id"].as<unsigned>();
            o.attestation.public_key =
                crypto::util::b64_encode(encoding::from_hex_bytea(row["attestation_public_key"].as<std::string>()));
            o.attestation.signature =
                crypto::util::b64_encode(encoding::from_hex_bytea(row["attestation"].as<std::string>()));
            o.recovered_at = optText(row["recovered_at"]);
            origins.emplace(row["version"].as<uint32_t>(), std::move(o));
        }
        for (const auto row : keyRows) {
            mf::KeyRecord k;
            k.version = row["version"].as<uint32_t>();
            k.key_check = optText(row["key_check"]);
            if (!row["attestation_key_id"].is_null() && !row["attestation"].is_null()) {
                mf::KeyAttestation a;
                a.key_id = row["attestation_key_id"].as<unsigned>();
                a.signature = crypto::util::b64_encode(encoding::from_hex_bytea(row["attestation"].as<std::string>()));
                if (!row["public_key"].is_null())
                    a.public_key = crypto::util::b64_encode(encoding::from_hex_bytea(row["public_key"].as<std::string>()));
                k.attestation = std::move(a);
            }
            k.created_at = optText(row["created_at"]);
            k.retired_at = optText(row["retired_at"]);
            if (!c.keys.empty() && c.keys.back().version == k.version) continue;  // a retired copy of the current row
            if (const auto it = envelopesByVersion.find(k.version); it != envelopesByVersion.end())
                k.envelopes = it->second;
            if (const auto it = origins.find(k.version); it != origins.end()) k.origin = it->second;
            c.keys.push_back(std::move(k));
        }

        // ---- provider versions of o/<uid> objects, by uid
        std::map<std::string, std::vector<mf::FileVersion>> versionsByUid;
        for (const auto row : txn.exec(
                 fmt::format("SELECT object_key, version_id, key_version, size_bytes, etag, is_delete_marker, "
                             "encryption_iv, {}, {} "
                             "FROM upstream_object_version WHERE vault_id = $1 AND gone_at IS NULL "
                             "  AND object_key LIKE 'o/%' ORDER BY object_key, last_modified DESC NULLS LAST, version_id",
                             iso("last_modified") + " AS last_modified",
                             iso("became_noncurrent_at") + " AS noncurrent_at"),
                 pqxx::params{vaultId})) {
            const auto uid = mf::uidOfObjectKey(row["object_key"].as<std::string>());
            if (!uid) continue;
            mf::FileVersion v;
            v.version_id = row["version_id"].as<std::string>();
            v.key_version = optNum<uint32_t>(row["key_version"]);
            v.size = optNum<uint64_t>(row["size_bytes"]);
            v.etag = optText(row["etag"]);
            v.delete_marker = row["is_delete_marker"].as<bool>();
            v.last_modified = optText(row["last_modified"]);
            v.noncurrent_at = optText(row["noncurrent_at"]);
            if (const auto iv = optText(row["encryption_iv"]); iv && vault::content::isVhf1(*iv))
                v.generation = manifest_query_detail::hexOf(crypto::util::b64_decode(*iv));
            versionsByUid[mf::uidText(*uid)].push_back(std::move(v));
        }

        // ---- the current object of each file (remote_object_index under its o/<uid> key). A row Vaulthalla's own
        //      upload wrote (#369) names the object's generation (its size is then the plaintext's: the object's is
        //      the sealed size of that generation); a listed row has the object's size and no generation.
        std::map<std::string, mf::ObjectRef> objects;
        std::map<std::string, std::string> objectGenerations;   // uid → hex salt of the current object (VHF1)
        for (const auto row : txn.exec("SELECT object_key, size_bytes, etag, version_id, storage_class, encryption_iv "
                                       "FROM remote_object_index WHERE vault_id = $1 AND object_key LIKE 'o/%'",
                                       pqxx::params{vaultId})) {
            const auto uid = mf::uidOfObjectKey(row["object_key"].as<std::string>());
            if (!uid) continue;
            auto size = row["size_bytes"].as<uint64_t>();
            if (const auto iv = optText(row["encryption_iv"]); iv && vault::content::isVhf1(*iv)) {
                size = vault::content::sealedSizeOf(size, *iv);
                objectGenerations[mf::uidText(*uid)] = manifest_query_detail::hexOf(crypto::util::b64_decode(*iv));
            }
            objects[mf::uidText(*uid)] = {optText(row["etag"]), size, optText(row["version_id"]),
                                          optText(row["storage_class"])};
        }
        // Attach-remote: what the bucket holds before the index names it (CollectOptions).
        for (const auto& staged : options.staged) {
            const auto uid = mf::uidOfObjectKey(staged.object_key);
            if (!uid || !vault::content::isVhf1(staged.generation)) continue;
            objectGenerations[mf::uidText(*uid)] = manifest_query_detail::hexOf(crypto::util::b64_decode(staged.generation));
            objects[mf::uidText(*uid)] = {staged.etag, vault::content::sealedSizeOf(staged.plaintext_bytes, staged.generation),
                                          staged.version_id, staged.storage_class};
        }

        // ---- the tree
        assignTreeUids(txn, vaultId, "directories");
        assignTreeUids(txn, vaultId, "symlinks");
        const auto rows = txn.exec(
            fmt::format("SELECT e.id, e.parent_id, e.name, e.path, e.mode, e.owner_uid, e.group_gid, {}, {}, "
                        "       (p.id IS NULL OR p.vault_id IS DISTINCT FROM e.vault_id) AS is_root, "
                        "       d.uid AS dir_uid, f.object_uid, f.size_bytes, f.mime_type, f.content_hash, "
                        "       f.encrypted_with_key_version, s.uid AS symlink_uid, s.target, "
                        "       (d.fs_entry_id IS NOT NULL) AS is_dir, (f.fs_entry_id IS NOT NULL) AS is_file, "
                        "       (s.fs_entry_id IS NOT NULL) AS is_symlink "
                        "FROM fs_entry e LEFT JOIN fs_entry p ON p.id = e.parent_id "
                        "LEFT JOIN directories d ON d.fs_entry_id = e.id LEFT JOIN files f ON f.fs_entry_id = e.id "
                        "LEFT JOIN symlinks s ON s.fs_entry_id = e.id WHERE e.vault_id = $1",
                        iso("e.updated_at") + " AS mtime", iso("e.created_at") + " AS ctime"),
            pqxx::params{vaultId});

        std::map<int64_t, std::string> uidById;
        std::map<std::string, std::string> dirUidByPath;
        for (const auto row : rows) {
            const auto id = row["id"].as<int64_t>();
            if (row["is_dir"].as<bool>()) {
                uidById[id] = uidFromUuid(row["dir_uid"]);
                dirUidByPath[row["path"].as<std::string>()] = uidById[id];
            } else if (row["is_file"].as<bool>()) {
                uidById[id] = uidFromUuid(row["object_uid"]);
            } else if (row["is_symlink"].as<bool>()) {
                uidById[id] = uidFromUuid(row["symlink_uid"]);
            }
        }

        std::set<std::string> liveUids;
        bool sawRoot = false;
        for (const auto row : rows) {
            const auto id = row["id"].as<int64_t>();
            const auto it = uidById.find(id);
            if (it == uidById.end()) continue;  // an fs_entry with no kind row: nothing to describe
            mf::Entry e;
            e.uid = it->second;
            if (row["is_root"].as<bool>()) {
                if (sawRoot) throw std::runtime_error("manifest: the vault's tree has more than one root");
                sawRoot = true;
                e.parent = std::nullopt;
                e.name = "";
            } else {
                const auto parent = uidById.find(row["parent_id"].as<int64_t>());
                if (parent == uidById.end()) continue;  // dangling (its parent is not a directory of this vault)
                e.parent = parent->second;
                e.name = row["name"].as<std::string>();
            }
            e.mode = optNum<uint32_t>(row["mode"]);
            if (!row["owner_uid"].is_null() || !row["group_gid"].is_null())
                e.owner = mf::Owner{optNum<int64_t>(row["owner_uid"]).value_or(0),
                                    optNum<int64_t>(row["group_gid"]).value_or(0)};
            e.mtime = optText(row["mtime"]);
            e.ctime = optText(row["ctime"]);
            if (row["is_dir"].as<bool>()) {
                e.kind = mf::EntryKind::Dir;
            } else if (row["is_file"].as<bool>()) {
                e.kind = mf::EntryKind::File;
                e.size = optNum<uint64_t>(row["size_bytes"]).value_or(0);
                e.mime = optText(row["mime_type"]);
                e.content_hash = optText(row["content_hash"]);
                if (const auto kv = optNum<uint32_t>(row["encrypted_with_key_version"]); kv && *kv > 0) e.key_version = kv;
                if (const auto o = objects.find(e.uid); o != objects.end()) e.object = o->second;
                if (const auto g = objectGenerations.find(e.uid); g != objectGenerations.end()) {
                    e.format = 1;
                    e.generation = g->second;
                }
                if (const auto v = versionsByUid.find(e.uid); v != versionsByUid.end()) e.versions = v->second;
            } else {
                e.kind = mf::EntryKind::Symlink;
                e.target = optText(row["target"]);
            }
            liveUids.insert(e.uid);
            c.entries.push_back(std::move(e));
        }
        if (!sawRoot && !c.entries.empty()) throw std::runtime_error("manifest: the vault's tree has no root");

        // ---- trash
        for (const auto row : txn.exec(
                 fmt::format("SELECT t.object_uid, t.path, t.size_bytes, {}, u.name AS trashed_by "
                             "FROM files_trashed t LEFT JOIN users u ON u.id = t.trashed_by "
                             "WHERE t.vault_id = $1 AND t.deleted_at IS NULL AND t.object_uid IS NOT NULL",
                             iso("t.trashed_at") + " AS trashed_at"),
                 pqxx::params{vaultId})) {
            mf::Entry e;
            e.uid = uidFromUuid(row["object_uid"]);
            if (liveUids.contains(e.uid)) continue;
            const auto path = row["path"].as<std::string>();
            e.kind = mf::EntryKind::File;
            if (const auto p = dirUidByPath.find(parentPath(path)); p != dirUidByPath.end()) e.parent = p->second;
            e.name = baseName(path);
            e.size = row["size_bytes"].as<uint64_t>();
            e.trashed = mf::Trashed{optText(row["trashed_at"]).value_or(""), optText(row["trashed_by"]), path};
            if (const auto o = objects.find(e.uid); o != objects.end()) e.object = o->second;
            if (const auto v = versionsByUid.find(e.uid); v != versionsByUid.end()) e.versions = v->second;
            liveUids.insert(e.uid);
            c.entries.push_back(std::move(e));
        }

        // ---- tombstones: provider versions of objects whose file is gone
        for (const auto& [uid, versions] : versionsByUid) {
            if (liveUids.contains(uid)) continue;
            mf::Entry e;
            e.uid = uid;
            e.kind = mf::EntryKind::Tombstone;
            e.versions = versions;  // a copy: the snapshot members below still look them up
            c.entries.push_back(std::move(e));
        }

        // ---- entries an apply deferred while their file was open (migration 146): the root's value until the apply
        // finishes them, so a publish never reverts what another writer did
        for (const auto row : txn.exec("SELECT uid::text, target::text FROM manifest_apply_deferred WHERE vault_id = $1",
                                       pqxx::params{vaultId})) {
            const auto uid = mf::uidText(crypto::id::fromUuid(row[0].as<std::string>()));
            std::erase_if(c.entries, [&](const mf::Entry& e) { return e.uid == uid; });
            if (!row[1].is_null()) c.entries.push_back(mf::entryFromJson(nlohmann::json::parse(row[1].as<std::string>())));
        }

        // ---- snapshots, by uid (migration 145): one is given here the first time it is listed (libsodium), like
        // directories; recovery_snapshot.id is this server's and stays out of the manifest.
        {
            const auto missing = txn.exec("SELECT id FROM recovery_snapshot WHERE vault_id = $1 AND state = 'ready' "
                                          "AND uid IS NULL",
                                          pqxx::params{vaultId});
            for (const auto row : missing)
                txn.exec("UPDATE recovery_snapshot SET uid = $2::uuid WHERE id = $1 AND uid IS NULL",
                         pqxx::params{row[0].as<int64_t>(), crypto::id::toUuid(crypto::id::newObjectUid())});
        }
        std::map<uint64_t, mf::SnapshotRecord> snapshots;
        for (const auto row : txn.exec(
                 fmt::format("SELECT id, uid, name, root_path, {} FROM recovery_snapshot WHERE vault_id = $1 AND "
                             "state = 'ready'",
                             iso("created_at") + " AS created_at"),
                 pqxx::params{vaultId})) {
            mf::SnapshotRecord s;
            s.uid = uidFromUuid(row["uid"]);
            s.name = optText(row["name"]);
            s.created_at = optText(row["created_at"]).value_or("");
            s.root_path = row["root_path"].as<std::string>();
            snapshots.emplace(row["id"].as<uint64_t>(), std::move(s));
        }
        for (const auto row : txn.exec(
                 "SELECT fv.snapshot_id, fv.path, f.object_uid, b.key_version, b.encryption_iv, fv.upstream_version_id "
                 "FROM file_versions fv JOIN recovery_snapshot rs ON rs.id = fv.snapshot_id "
                 "LEFT JOIN files f ON f.fs_entry_id = fv.file_id LEFT JOIN recovery_blob b ON b.id = fv.blob_id "
                 "WHERE rs.vault_id = $1 AND rs.state = 'ready' ORDER BY fv.snapshot_id, fv.path",
                 pqxx::params{vaultId})) {
            const auto it = snapshots.find(row["snapshot_id"].as<uint64_t>());
            if (it == snapshots.end()) continue;
            mf::SnapshotMember m;
            if (!row["object_uid"].is_null()) m.uid = uidFromUuid(row["object_uid"]);
            m.path_at_capture = row["path"].as<std::string>();
            if (const auto kv = optNum<uint32_t>(row["key_version"]); kv && *kv > 0) m.key_version = kv;
            m.provider_version_id = optText(row["upstream_version_id"]);
            if (const auto iv = optText(row["encryption_iv"]); iv && vault::content::isVhf1(*iv))
                m.generation = manifest_query_detail::hexOf(crypto::util::b64_decode(*iv));
            // The bucket holds the member's generation as a provider version of its object, or as the object itself.
            m.restorable_from_bucket = m.provider_version_id.has_value();
            if (!m.restorable_from_bucket && m.uid && m.generation) {
                if (const auto g = objectGenerations.find(*m.uid); g != objectGenerations.end() && g->second == *m.generation)
                    m.restorable_from_bucket = true;
                else if (const auto vs = versionsByUid.find(*m.uid); vs != versionsByUid.end())
                    m.restorable_from_bucket = std::ranges::any_of(vs->second, [&](const mf::FileVersion& v) {
                        return v.generation == m.generation && !v.delete_marker;
                    });
            }
            it->second.members.push_back(std::move(m));
        }
        for (auto& [_, s] : snapshots) c.snapshots.push_back(std::move(s));

        mf::normalize(c);
        return c;
    });
}

}
