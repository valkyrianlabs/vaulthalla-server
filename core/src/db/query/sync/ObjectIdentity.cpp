#include "db/query/sync/ObjectIdentity.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/u8.hpp"
#include "db/query/fs/File.hpp"
#include "fs/model/File.hpp"

namespace vh::db::query::sync {

std::shared_ptr<vh::fs::model::File> ObjectIdentity::fileByUid(const uint32_t vaultId,
                                                               const crypto::id::ObjectUid& uid) {
    const auto id = Transactions::read("ObjectIdentity::fileByUid", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec("SELECT f.fs_entry_id FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                                  "WHERE e.vault_id = $1 AND f.object_uid = $2::uuid",
                                  pqxx::params{vaultId, crypto::id::toUuid(uid)});
        return res.empty() ? std::optional<uint32_t>{} : std::make_optional(res.one_field_ref().as<uint32_t>());
    });
    if (!id) return nullptr;
    auto file = fs::File::getFileById(*id);
    if (file && file->object_uid != uid) return nullptr;   // replaced between the two reads
    return file;
}

std::optional<crypto::id::ObjectUid> ObjectIdentity::uidAtPath(const uint32_t vaultId,
                                                               const std::filesystem::path& path) {
    const auto text = encoding::to_utf8_string(path.lexically_normal().u8string());
    return Transactions::read("ObjectIdentity::uidAtPath", [&](pqxx::transaction_base& txn) {
        auto res = txn.exec("SELECT f.object_uid FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                            "WHERE e.vault_id = $1 AND e.path = $2",
                            pqxx::params{vaultId, text});
        if (res.empty())
            res = txn.exec("SELECT object_uid FROM files_trashed WHERE vault_id = $1 AND path = $2 "
                           "AND deleted_at IS NULL AND object_uid IS NOT NULL ORDER BY trashed_at DESC, id DESC LIMIT 1",
                           pqxx::params{vaultId, text});
        if (res.empty()) return std::optional<crypto::id::ObjectUid>{};
        return std::make_optional(crypto::id::fromUuid(res[0][0].as<std::string>()));
    });
}

std::optional<std::filesystem::path> ObjectIdentity::pathOfUid(const uint32_t vaultId,
                                                              const crypto::id::ObjectUid& uid) {
    return Transactions::read("ObjectIdentity::pathOfUid", [&](pqxx::transaction_base& txn) {
        const auto uuid = crypto::id::toUuid(uid);
        auto res = txn.exec("SELECT e.path FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                            "WHERE e.vault_id = $1 AND f.object_uid = $2::uuid",
                            pqxx::params{vaultId, uuid});
        if (res.empty())
            res = txn.exec("SELECT path FROM files_trashed WHERE vault_id = $1 AND object_uid = $2::uuid "
                           "AND deleted_at IS NULL ORDER BY trashed_at DESC, id DESC LIMIT 1",
                           pqxx::params{vaultId, uuid});
        // History the bucket layout migration (#373) re-sealed for a path no file row names any more: its old key.
        if (res.empty())
            res = txn.exec("SELECT '/' || legacy_key FROM vault_layout_migration_item WHERE vault_id = $1 "
                           "AND object_uid = $2::uuid AND kind IN ('version', 'marker') "
                           "ORDER BY legacy_last_modified DESC NULLS LAST, id DESC LIMIT 1",
                           pqxx::params{vaultId, uuid});
        if (res.empty()) return std::optional<std::filesystem::path>{};
        return std::make_optional(std::filesystem::path(res[0][0].as<std::string>()));
    });
}

std::set<crypto::id::ObjectUid> ObjectIdentity::trashedUids(const uint32_t vaultId) {
    return Transactions::read("ObjectIdentity::trashedUids", [&](pqxx::transaction_base& txn) {
        std::set<crypto::id::ObjectUid> out;
        for (const auto row : txn.exec("SELECT object_uid FROM files_trashed WHERE vault_id = $1 "
                                       "AND deleted_at IS NULL AND object_uid IS NOT NULL",
                                       pqxx::params{vaultId}))
            out.insert(crypto::id::fromUuid(row[0].as<std::string>()));
        return out;
    });
}

bool ObjectIdentity::known(const uint32_t vaultId, const crypto::id::ObjectUid& uid) {
    return Transactions::read("ObjectIdentity::known", [&](pqxx::transaction_base& txn) {
        return txn.exec("SELECT EXISTS (SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                        "               WHERE e.vault_id = $1 AND f.object_uid = $2::uuid) "
                        "    OR EXISTS (SELECT 1 FROM files_trashed WHERE vault_id = $1 AND object_uid = $2::uuid "
                        "               AND deleted_at IS NULL)",
                        pqxx::params{vaultId, crypto::id::toUuid(uid)})
            .one_field_ref()
            .as<bool>();
    });
}

}
