#pragma once

#include "Entry.hpp"
#include "db/Fwd.hpp"
#include "crypto/id/ObjectUid.hpp"
#include <optional>
#include <vector>

namespace vh::fs::model {
    struct Directory final : Entry {
        unsigned int file_count{0};
        unsigned int subdirectory_count{0};
        // directories.uid (migration 158): the folder's permanent id, the same on every server and in the manifest.
        // Drawn by db::query::fs::Directory::upsertDirectory when the row is created and kept after. Empty on a
        // folder not yet stored.
        std::optional<vh::crypto::id::ObjectUid> uid;

        Directory() = default;

        Directory(pqxx::row_ref row, const pqxx::result &parentRows);

        [[nodiscard]] bool isDirectory() const override { return true; }
    };

    void to_json(nlohmann::json &j, const Directory &d);

    void from_json(const nlohmann::json &j, Directory &d);

    // Parent chains read in `txn` (see files_from_pq_res).
    std::vector<std::shared_ptr<Directory> > directories_from_pq_res(const pqxx::result &res, pqxx::transaction_base &txn);
}
