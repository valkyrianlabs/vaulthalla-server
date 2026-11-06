#pragma once

#include <filesystem>
#include <optional>
#include <vector>
#include <boost/uuid/uuid.hpp>
#include "crypto/id/ObjectUid.hpp"
#include "db/Fwd.hpp"

namespace vh::fs::model::file {

struct Trashed {
    unsigned int id{}, vault_id{};
    std::string base32_alias{};
    std::filesystem::path path{}, backing_path{};
    std::time_t trashed_at{}, trashed_by{};
    std::optional<std::time_t> deleted_at{};
    uint64_t size_bytes{};
    // files_trashed.object_uid: the file's uid, kept while it is in the trash (its o/<uid> object under opaque_v1).
    std::optional<crypto::id::ObjectUid> object_uid{};

    Trashed() = default;
    explicit Trashed(pqxx::row_ref row);
};
}
