#include "db/query/upload/Resumable.hpp"

#include "db/Transactions.hpp"

#include <pqxx/pqxx>

#include <map>

namespace vh::db::query::upload {

namespace {

template <class T>
std::optional<T> nullableField(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return f.as<T>();
}

[[nodiscard]] int64_t signedBytes(const uint64_t v) { return static_cast<int64_t>(v); }

SessionRow sessionFromRow(const pqxx::row_ref row) {
    SessionRow s;
    s.id = row["id"].as<std::string>();
    s.mode = row["mode"].as<std::string>();
    s.user_id = nullableField<uint32_t>(row["user_id"]);
    s.share_session_id = nullableField<std::string>(row["share_session_id"]);
    s.vault_id = row["vault_id"].as<uint32_t>();
    s.state = row["state"].as<std::string>();
    s.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    s.last_activity_at = static_cast<std::time_t>(row["last_activity_at"].as<int64_t>());
    return s;
}

FileRow fileFromRow(const pqxx::row_ref row) {
    FileRow f;
    f.upload_id = row["upload_id"].as<std::string>();
    f.file_id = row["file_id"].as<std::string>();
    f.ordinal = row["ordinal"].as<uint32_t>();
    f.path = row["path"].as<std::string>();
    f.display_path = row["display_path"].as<std::string>();
    f.size_bytes = static_cast<uint64_t>(row["size_bytes"].as<int64_t>());
    f.mime_type = nullableField<std::string>(row["mime_type"]);
    f.precondition = row["precondition"].as<std::string>();
    f.expected_source_id = nullableField<std::string>(row["expected_source_id"]);
    f.encryption_iv = row["encryption_iv"].as<std::string>();
    f.key_version = row["key_version"].as<uint32_t>();
    f.state = row["state"].as<std::string>();
    f.sealed_bytes = static_cast<uint64_t>(row["sealed_bytes"].as<int64_t>());
    f.error_code = nullableField<std::string>(row["error_code"]);
    f.error_message = nullableField<std::string>(row["error_message"]);
    f.error_etag = nullableField<std::string>(row["error_etag"]);
    f.entry_id = nullableField<uint32_t>(row["entry_id"]);
    f.share_upload_id = nullableField<std::string>(row["share_upload_id"]);
    f.share_parent_path = nullableField<std::string>(row["share_parent_path"]);
    return f;
}

}

void Resumable::create(const SessionRow& s, const std::vector<FileRow>& files) {
    Transactions::exec("upload::Resumable::create", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO upload_session (id, mode, user_id, share_session_id, vault_id, state, created_at, "
                 "last_activity_at) VALUES ($1, $2, $3, $4::uuid, $5, $6, to_timestamp($7), to_timestamp($8))",
                 pqxx::params{s.id, s.mode, s.user_id, s.share_session_id, s.vault_id, s.state,
                              static_cast<int64_t>(s.created_at), static_cast<int64_t>(s.last_activity_at)});
        for (const auto& f : files)
            txn.exec("INSERT INTO upload_session_file (upload_id, file_id, ordinal, path, display_path, size_bytes, "
                     "mime_type, precondition, expected_source_id, encryption_iv, key_version, state, sealed_bytes, "
                     "share_upload_id, share_parent_path) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, "
                     "$13, $14::uuid, $15)",
                     pqxx::params{f.upload_id, f.file_id, f.ordinal, f.path, f.display_path, signedBytes(f.size_bytes),
                                  f.mime_type, f.precondition, f.expected_source_id, f.encryption_iv, f.key_version,
                                  f.state, signedBytes(f.sealed_bytes), f.share_upload_id, f.share_parent_path});
    });
}

void Resumable::insertPart(const PartRow& p, const std::time_t now) {
    Transactions::exec("upload::Resumable::insertPart", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO upload_session_part (upload_id, file_id, offset_bytes, length_bytes, encryption_iv) "
                 "VALUES ($1, $2, $3, $4, $5)",
                 pqxx::params{p.upload_id, p.file_id, signedBytes(p.offset), signedBytes(p.length), p.encryption_iv});
        txn.exec("UPDATE upload_session SET last_activity_at = to_timestamp($2) WHERE id = $1",
                 pqxx::params{p.upload_id, static_cast<int64_t>(now)});
    });
}

void Resumable::deletePart(const std::string& uploadId, const std::string& fileId, const uint64_t offset) {
    Transactions::exec("upload::Resumable::deletePart", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM upload_session_part WHERE upload_id = $1 AND file_id = $2 AND offset_bytes = $3",
                 pqxx::params{uploadId, fileId, signedBytes(offset)});
    });
}

void Resumable::deleteParts(const std::string& uploadId, const std::string& fileId) {
    Transactions::exec("upload::Resumable::deleteParts", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM upload_session_part WHERE upload_id = $1 AND file_id = $2",
                 pqxx::params{uploadId, fileId});
    });
}

void Resumable::setSealed(const std::string& uploadId, const std::string& fileId, const uint64_t sealedBytes) {
    Transactions::exec("upload::Resumable::setSealed", [&](pqxx::work& txn) {
        txn.exec("UPDATE upload_session_file SET sealed_bytes = $3 WHERE upload_id = $1 AND file_id = $2",
                 pqxx::params{uploadId, fileId, signedBytes(sealedBytes)});
    });
}

// A file's state only moves forward (receiving < sealing < committing < committed | failed): a late write from a
// slower thread never takes it back (a "sealing" landing after "committing" would make a restart re-seal a file
// whose sealed bytes are already linked into the vault).
void Resumable::setFileState(const std::string& uploadId, const std::string& fileId, const std::string& state) {
    Transactions::exec("upload::Resumable::setFileState", [&](pqxx::work& txn) {
        txn.exec("UPDATE upload_session_file SET state = $3 WHERE upload_id = $1 AND file_id = $2 AND "
                 "array_position(ARRAY['receiving', 'sealing', 'committing', 'committed'], state) < "
                 "array_position(ARRAY['receiving', 'sealing', 'committing', 'committed'], $3::text)",
                 pqxx::params{uploadId, fileId, state});
    });
}

void Resumable::markCommitted(const std::string& uploadId, const std::string& fileId, const uint32_t entryId) {
    Transactions::exec("upload::Resumable::markCommitted", [&](pqxx::work& txn) {
        txn.exec("UPDATE upload_session_file SET state = 'committed', entry_id = $3, sealed_bytes = size_bytes "
                 "WHERE upload_id = $1 AND file_id = $2 AND state <> 'failed'",
                 pqxx::params{uploadId, fileId, entryId});
    });
}

void Resumable::markFailed(const std::string& uploadId, const std::string& fileId, const std::string& code,
                           const std::string& message, const std::optional<std::string>& etag) {
    Transactions::exec("upload::Resumable::markFailed", [&](pqxx::work& txn) {
        txn.exec("UPDATE upload_session_file SET state = 'failed', error_code = $3, error_message = $4, "
                 "error_etag = $5 WHERE upload_id = $1 AND file_id = $2 AND state NOT IN ('committed', 'failed')",
                 pqxx::params{uploadId, fileId, code, message, etag});
    });
}

void Resumable::setSessionState(const std::string& uploadId, const std::string& state) {
    Transactions::exec("upload::Resumable::setSessionState", [&](pqxx::work& txn) {
        txn.exec("UPDATE upload_session SET state = $2 WHERE id = $1", pqxx::params{uploadId, state});
    });
}

void Resumable::remove(const std::string& uploadId) {
    Transactions::exec("upload::Resumable::remove", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM upload_session WHERE id = $1", pqxx::params{uploadId});
    });
}

std::vector<LoadedSession> Resumable::loadAll() {
    return Transactions::exec("upload::Resumable::loadAll", [&](pqxx::work& txn) {
        std::vector<LoadedSession> out;
        std::map<std::string, std::size_t> index;
        for (const auto row : txn.exec(
                 "SELECT id, mode, user_id, share_session_id::text AS share_session_id, vault_id, state, "
                 "EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, "
                 "EXTRACT(EPOCH FROM last_activity_at)::BIGINT AS last_activity_at FROM upload_session ORDER BY id")) {
            index[row["id"].as<std::string>()] = out.size();
            out.push_back({.session = sessionFromRow(row), .files = {}, .parts = {}});
        }
        for (const auto row : txn.exec(
                 "SELECT upload_id, file_id, ordinal, path, display_path, size_bytes, mime_type, precondition, "
                 "expected_source_id, encryption_iv, key_version, state, sealed_bytes, error_code, error_message, "
                 "error_etag, entry_id, share_upload_id::text AS share_upload_id, share_parent_path "
                 "FROM upload_session_file ORDER BY upload_id, ordinal")) {
            if (const auto it = index.find(row["upload_id"].as<std::string>()); it != index.end())
                out[it->second].files.push_back(fileFromRow(row));
        }
        for (const auto row : txn.exec(
                 "SELECT upload_id, file_id, offset_bytes, length_bytes, encryption_iv FROM upload_session_part "
                 "ORDER BY upload_id, file_id, offset_bytes")) {
            const auto it = index.find(row["upload_id"].as<std::string>());
            if (it == index.end()) continue;
            out[it->second].parts.push_back({
                .upload_id = row["upload_id"].as<std::string>(),
                .file_id = row["file_id"].as<std::string>(),
                .offset = static_cast<uint64_t>(row["offset_bytes"].as<int64_t>()),
                .length = static_cast<uint64_t>(row["length_bytes"].as<int64_t>()),
                .encryption_iv = row["encryption_iv"].as<std::string>()});
        }
        return out;
    });
}

bool Resumable::exists(const std::string& uploadId) {
    return Transactions::read("upload::Resumable::exists", [&](pqxx::transaction_base& txn) {
        return !txn.exec("SELECT 1 FROM upload_session WHERE id = $1", pqxx::params{uploadId}).empty();
    });
}

std::vector<std::string> Resumable::expired(const std::time_t now, const int64_t idleSeconds,
                                            const int64_t maxAgeSeconds) {
    return Transactions::read("upload::Resumable::expired", [&](pqxx::transaction_base& txn) {
        std::vector<std::string> out;
        for (const auto row : txn.exec(
                 "SELECT id FROM upload_session WHERE last_activity_at < to_timestamp($1) - make_interval(secs => $2) "
                 "OR created_at < to_timestamp($1) - make_interval(secs => $3)",
                 pqxx::params{static_cast<int64_t>(now), static_cast<double>(idleSeconds),
                              static_cast<double>(maxAgeSeconds)}))
            out.push_back(row["id"].as<std::string>());
        return out;
    });
}

}
