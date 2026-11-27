#include "db/query/mirror/Contents.hpp"

#include "db/Transactions.hpp"
#include "ops/Error.hpp"
#include "vault/Content.hpp"

#include <pqxx/pqxx>

#include <algorithm>
#include <cctype>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace vh::db::query::mirror {

namespace {

constexpr const char* kPendingColumns = R"SQL(
    vault_id, object_uid::text AS object_uid, generation, key_version, size_bytes, content_hash, mtime_us, priority,
    state, attempts, last_error, EXTRACT(EPOCH FROM expected_at)::BIGINT AS expected_at,
    EXTRACT(EPOCH FROM last_attempt_at)::BIGINT AS last_attempt_at
)SQL";

std::string selectPending(const std::string& where) {
    return std::string("SELECT ") + kPendingColumns + " FROM mirror_content_pending " + where;
}

Expected expectedFrom(const pqxx::row_ref row) {
    Expected e;
    e.vault_id = row["vault_id"].as<uint32_t>();
    e.object_uid = vh::crypto::id::fromUuid(row["object_uid"].as<std::string>());
    e.generation = row["generation"].as<std::string>();
    e.key_version = row["key_version"].as<uint32_t>();
    e.size_bytes = row["size_bytes"].as<uint64_t>();
    e.content_hash = row["content_hash"].as<std::string>();
    e.mtime_us = row["mtime_us"].as<int64_t>();
    e.priority = row["priority"].as<int16_t>();
    e.state = row["state"].as<std::string>();
    e.attempts = row["attempts"].as<uint32_t>();
    if (!row["last_error"].is_null()) e.last_error = row["last_error"].as<std::string>();
    e.expected_at = static_cast<std::time_t>(row["expected_at"].as<int64_t>());
    if (!row["last_attempt_at"].is_null())
        e.last_attempt_at = static_cast<std::time_t>(row["last_attempt_at"].as<int64_t>());
    return e;
}

bool isHexDigest(const std::string& s) {
    return s.size() == 64 && std::ranges::all_of(s, [](const char c) {
               return std::isdigit(static_cast<unsigned char>(c)) || (c >= 'a' && c <= 'f');
           });
}

// An error recorded on a row stays readable: one line, at most 500 bytes.
std::string boundedReason(std::string reason) {
    std::ranges::replace(reason, '\n', ' ');
    if (reason.size() > 500) reason.resize(500);
    return reason;
}

std::mutex& pendingVaultsMutex() {
    static std::mutex m;
    return m;
}

std::unordered_map<uint32_t, bool>& pendingVaults() {
    static std::unordered_map<uint32_t, bool> known;
    return known;
}

// Whether this server has any pending row at all (every server but a mirror: none, after one query per process).
enum class AnyPending { Unknown, None, Some };

AnyPending& anyPending() {
    static AnyPending state = AnyPending::Unknown;
    return state;
}

void markMayHavePending(const uint32_t vaultId) {
    std::scoped_lock lock(pendingVaultsMutex());
    anyPending() = AnyPending::Some;
    pendingVaults()[vaultId] = true;
}

}

// ---- the sealed lane -------------------------------------------------------------------------------------------------

std::optional<SealedObject> SealedObjects::find(const vh::crypto::id::ObjectUid& vaultUid,
                                                const vh::crypto::id::ObjectUid& objectUid) {
    return Transactions::exec("mirror::SealedObjects::find", [&](pqxx::work& txn) -> std::optional<SealedObject> {
        const auto vault = txn.exec("SELECT v.id, m.peer_id, m.role FROM vault v JOIN mirror_vault m ON m.vault_id = v.id "
                                    "WHERE v.uid = $1::uuid AND v.deleted_at IS NULL",
                                    pqxx::params{vh::crypto::id::toUuid(vaultUid)});
        if (vault.empty()) return std::nullopt;
        SealedObject out;
        out.vault_id = vault[0][0].as<uint32_t>();
        out.peer_id = vault[0][1].as<uint32_t>();
        out.role = vault[0][2].as<std::string>();
        const auto file = txn.exec("SELECT f.fs_entry_id, COALESCE(f.size_bytes, 0), COALESCE(f.encryption_iv, ''), "
                                   "       COALESCE(f.encrypted_with_key_version, 0) "
                                   "FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                                   "WHERE e.vault_id = $1 AND f.object_uid = $2::uuid",
                                   pqxx::params{out.vault_id, vh::crypto::id::toUuid(objectUid)});
        if (file.empty()) return out;
        out.file_id = file[0][0].as<uint32_t>();
        out.size_bytes = file[0][1].as<uint64_t>();
        out.generation = file[0][2].as<std::string>();
        out.key_version = file[0][3].as<uint32_t>();
        return out;
    });
}

std::optional<std::string> SealedObjects::generationOf(const uint32_t fileId) {
    return Transactions::exec("mirror::SealedObjects::generationOf", [&](pqxx::work& txn) -> std::optional<std::string> {
        const auto res = txn.exec("SELECT COALESCE(encryption_iv, '') FROM files WHERE fs_entry_id = $1",
                                  pqxx::params{fileId});
        if (res.empty()) return std::nullopt;
        return res[0][0].as<std::string>();
    });
}

std::optional<uint32_t> SealedObjects::fileIdOf(const uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid) {
    return Transactions::exec("mirror::SealedObjects::fileIdOf", [&](pqxx::work& txn) -> std::optional<uint32_t> {
        const auto res = txn.exec("SELECT f.fs_entry_id FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                                  "WHERE e.vault_id = $1 AND f.object_uid = $2::uuid",
                                  pqxx::params{vaultId, vh::crypto::id::toUuid(objectUid)});
        if (res.empty()) return std::nullopt;
        return res[0][0].as<uint32_t>();
    });
}

// ---- what a mirror is waiting for -------------------------------------------------------------------------------------

namespace {

void mirrorValidateExpected(const Expected& e) {
    try {
        (void)vh::vault::content::formatOf(e.generation);
    } catch (const std::invalid_argument&) {
        throw ops::Invalid("not a generation id");
    }
    if (!isHexDigest(e.content_hash)) throw ops::Invalid("the content hash must be 64 lower-case hex digits");
}

void mirrorUpsertExpected(pqxx::work& txn, const Expected& e) {
    txn.exec("INSERT INTO mirror_content_pending (vault_id, object_uid, generation, key_version, size_bytes, "
             "  content_hash, mtime_us, priority) "
             "VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8) "
             "ON CONFLICT (vault_id, object_uid) DO UPDATE SET "
             "  key_version = EXCLUDED.key_version, size_bytes = EXCLUDED.size_bytes, "
             "  content_hash = EXCLUDED.content_hash, mtime_us = EXCLUDED.mtime_us, priority = EXCLUDED.priority, "
             "  state = CASE WHEN mirror_content_pending.generation = EXCLUDED.generation "
             "               THEN mirror_content_pending.state ELSE 'waiting' END, "
             "  attempts = CASE WHEN mirror_content_pending.generation = EXCLUDED.generation "
             "                  THEN mirror_content_pending.attempts ELSE 0 END, "
             "  last_error = CASE WHEN mirror_content_pending.generation = EXCLUDED.generation "
             "                    THEN mirror_content_pending.last_error END, "
             "  expected_at = CASE WHEN mirror_content_pending.generation = EXCLUDED.generation "
             "                     THEN mirror_content_pending.expected_at ELSE CURRENT_TIMESTAMP END, "
             "  generation = EXCLUDED.generation",
             pqxx::params{e.vault_id, vh::crypto::id::toUuid(e.object_uid), e.generation,
                          static_cast<int64_t>(e.key_version), static_cast<int64_t>(e.size_bytes), e.content_hash,
                          e.mtime_us, e.priority});
}

}

void PendingContents::expect(const Expected& e) {
    mirrorValidateExpected(e);
    Transactions::exec("mirror::PendingContents::expect", [&](pqxx::work& txn) {
        const auto role = txn.exec("SELECT m.role FROM vault v JOIN mirror_vault m ON m.vault_id = v.id "
                                   "WHERE v.id = $1 AND v.deleted_at IS NULL",
                                   pqxx::params{e.vault_id});
        if (role.empty()) throw ops::NotFound("no such mirrored vault");
        if (role[0][0].as<std::string>() != "mirror")
            throw ops::Invalid("this server is not the mirror of the vault: only a mirror waits for contents");
        mirrorUpsertExpected(txn, e);
    });
    markMayHavePending(e.vault_id);
}

void PendingContents::expect(pqxx::work& txn, const Expected& e) {
    mirrorValidateExpected(e);
    mirrorUpsertExpected(txn, e);
    markMayHavePending(e.vault_id);
}

void PendingContents::forget(pqxx::work& txn, const uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid) {
    txn.exec("DELETE FROM mirror_content_pending WHERE vault_id = $1 AND object_uid = $2::uuid",
             pqxx::params{vaultId, vh::crypto::id::toUuid(objectUid)});
}

std::optional<Expected> PendingContents::get(const uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid) {
    return Transactions::exec("mirror::PendingContents::get", [&](pqxx::work& txn) -> std::optional<Expected> {
        const auto res = txn.exec(selectPending("WHERE vault_id = $1 AND object_uid = $2::uuid"),
                                  pqxx::params{vaultId, vh::crypto::id::toUuid(objectUid)});
        if (res.empty()) return std::nullopt;
        return expectedFrom(res.one_row_ref());
    });
}

std::vector<Expected> PendingContents::outstanding(const uint32_t vaultId, const std::size_t limit,
                                                   const bool includeFailed) {
    return Transactions::exec("mirror::PendingContents::outstanding", [&](pqxx::work& txn) {
        std::vector<Expected> out;
        const auto res = txn.exec(
            selectPending("WHERE vault_id = $1 AND (state = 'waiting' OR ($2 AND state = 'failed')) "
                          "ORDER BY state = 'failed', priority DESC, queued LIMIT $3"),
            pqxx::params{vaultId, includeFailed, static_cast<int64_t>(limit)});
        out.reserve(res.size());
        for (const auto row : res) out.push_back(expectedFrom(row));
        return out;
    });
}

std::size_t PendingContents::countOutstanding(const uint32_t vaultId) {
    return Transactions::exec("mirror::PendingContents::countOutstanding", [&](pqxx::work& txn) {
        return txn.exec("SELECT count(*) FROM mirror_content_pending WHERE vault_id = $1 AND state = 'waiting'",
                        pqxx::params{vaultId})
            .one_field_ref()
            .as<std::size_t>();
    });
}

std::optional<Expected> PendingContents::recordFailure(const uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid,
                                                       const std::string& generation, const std::string& reason) {
    return Transactions::exec("mirror::PendingContents::recordFailure", [&](pqxx::work& txn) -> std::optional<Expected> {
        const auto res = txn.exec(
            "UPDATE mirror_content_pending SET attempts = attempts + 1, last_error = $4, "
            "  last_attempt_at = CURRENT_TIMESTAMP, "
            "  state = CASE WHEN attempts + 1 >= $5 THEN 'failed' ELSE state END "
            "WHERE vault_id = $1 AND object_uid = $2::uuid AND generation = $3 AND state = 'waiting' "
            "RETURNING " + std::string(kPendingColumns),
            pqxx::params{vaultId, vh::crypto::id::toUuid(objectUid), generation, boundedReason(reason),
                         static_cast<int64_t>(kMaxAttempts)});
        if (res.empty()) return std::nullopt;
        return expectedFrom(res.one_row_ref());
    });
}

bool PendingContents::retry(const uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid) {
    return Transactions::exec("mirror::PendingContents::retry", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_content_pending SET state = 'waiting', attempts = 0 "
                        "WHERE vault_id = $1 AND object_uid = $2::uuid AND state = 'failed'",
                        pqxx::params{vaultId, vh::crypto::id::toUuid(objectUid)})
                   .affected_rows() > 0;
    });
}

bool PendingContents::dropSuperseded(const uint32_t vaultId, const vh::crypto::id::ObjectUid& objectUid,
                                     const std::string& generation) {
    return Transactions::exec("mirror::PendingContents::dropSuperseded", [&](pqxx::work& txn) {
        return txn.exec("DELETE FROM mirror_content_pending WHERE vault_id = $1 AND object_uid = $2::uuid "
                        "AND generation = $3",
                        pqxx::params{vaultId, vh::crypto::id::toUuid(objectUid), generation})
                   .affected_rows() > 0;
    });
}

std::optional<uint32_t> PendingContents::lockForLink(pqxx::work& txn, const Expected& e) {
    const auto uid = vh::crypto::id::toUuid(e.object_uid);
    const bool plain = e.generation.empty();
    if (txn.exec("SELECT 1 FROM mirror_content_pending WHERE vault_id = $1 AND object_uid = $2::uuid "
                 "AND generation = $3 AND key_version = $4 AND size_bytes = $5 AND content_hash = $6 "
                 "AND state = 'waiting' FOR UPDATE",
                 pqxx::params{e.vault_id, uid, e.generation, static_cast<int64_t>(e.key_version),
                              static_cast<int64_t>(e.size_bytes), e.content_hash})
            .empty())
        return std::nullopt;
    const auto file = txn.exec("SELECT f.fs_entry_id FROM files f JOIN fs_entry fe ON fe.id = f.fs_entry_id "
                               "WHERE fe.vault_id = $1 AND f.object_uid = $2::uuid "
                               "AND COALESCE(f.encryption_iv, '') = $3 AND COALESCE(f.size_bytes, 0) = $4 "
                               "AND f.content_hash = $5 AND ($6 OR f.encrypted_with_key_version = $7) "
                               "FOR SHARE OF f",
                               pqxx::params{e.vault_id, uid, e.generation, static_cast<int64_t>(e.size_bytes),
                                            e.content_hash, plain, static_cast<int64_t>(e.key_version)});
    if (file.empty()) return std::nullopt;
    return file[0][0].as<uint32_t>();
}

void PendingContents::clear(pqxx::work& txn, const Expected& e) {
    txn.exec("DELETE FROM mirror_content_pending WHERE vault_id = $1 AND object_uid = $2::uuid AND generation = $3",
             pqxx::params{e.vault_id, vh::crypto::id::toUuid(e.object_uid), e.generation});
}

bool PendingContents::mayHavePending(const uint32_t vaultId) {
    {
        std::scoped_lock lock(pendingVaultsMutex());
        if (anyPending() == AnyPending::None) return false;
        if (const auto it = pendingVaults().find(vaultId); it != pendingVaults().end()) return it->second;
    }
    // On the open path: a database that cannot answer means "not known to be pending" now (the open goes on as it
    // would on any server), and the question is asked again next time.
    try {
        const auto [anyRow, here] = Transactions::exec("mirror::PendingContents::mayHavePending", [&](pqxx::work& txn) {
            const bool any = !txn.exec("SELECT 1 FROM mirror_content_pending LIMIT 1").empty();
            const bool vault = any && !txn.exec("SELECT 1 FROM mirror_content_pending WHERE vault_id = $1 LIMIT 1",
                                                pqxx::params{vaultId})
                                           .empty();
            return std::make_pair(any, vault);
        });
        std::scoped_lock lock(pendingVaultsMutex());
        // expect() may have marked it meanwhile.
        if (!anyRow && anyPending() == AnyPending::Unknown) anyPending() = AnyPending::None;
        if (anyRow) anyPending() = AnyPending::Some;
        auto& known = pendingVaults()[vaultId];
        known = known || here;
        return known;
    } catch (const std::exception&) {
        return false;
    }
}

}
