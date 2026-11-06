#pragma once

#include "Entry.hpp"
#include "db/Fwd.hpp"
#include "crypto/id/ObjectUid.hpp"

namespace vh::fs::model {
    struct File final : Entry {
        std::string encryption_iv;
        std::optional<std::string> mime_type, content_hash;
        std::optional<std::string> remote_storage_class, remote_etag, remote_restore_status;
        std::optional<std::string> remote_version_id, remote_sequencer;
        std::optional<bool> remote_encrypted;
        unsigned int encrypted_with_key_version{};
        // files.object_uid (spec 01 §4.1): the file's identity in the bucket under opaque_v1. Drawn by
        // db::query::fs::File::upsertFile when the row is created; rename, move, overwrite and key rotation keep it. A
        // copy is a new file: clear it before storing the copy's row. Empty on a file not yet stored, or loaded by a
        // query that doesn't select it.
        std::optional<vh::crypto::id::ObjectUid> object_uid;

        File() = default;

        File(pqxx::row_ref row, const pqxx::result &parentRows);

        File(const std::string &s3_key, uint64_t size, const std::optional<std::time_t> &updated = {});

        [[nodiscard]] bool isDirectory() const override { return false; }

        [[nodiscard]] bool operator==(const File &other) const;

        [[nodiscard]] bool requiresArchiveRestoreForBodyGet() const;
    };

    void to_json(nlohmann::json &j, const File &f);

    void from_json(const nlohmann::json &j, File &f);

    void to_json(nlohmann::json &j, const std::vector<std::shared_ptr<File> > &files);

    std::vector<std::shared_ptr<File> > files_from_pq_res(const pqxx::result &res);

    std::vector<std::shared_ptr<File> > filesFromS3XML(const std::u8string &xml);

    std::unordered_map<std::u8string, std::shared_ptr<File> > groupEntriesByPath(
        const std::vector<std::shared_ptr<File> > &entries);
}
