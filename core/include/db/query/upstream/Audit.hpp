#pragma once

#include "storage/upstream/model/Audit.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// upstream_audit: append-only record of control-plane mutations and refusals.
namespace vh::db::query::upstream {

using AuditModel = storage::upstream::model::AuditRecord;

class Audit {
public:
    // Returns the new row id. `record.at` and `record.id` are ignored (the database stamps them); detail_json must
    // be a JSON object.
    static int64_t append(const AuditModel& record);
    // Best effort: a failed audit write is logged, never thrown (callers must not lose the mutation over it).
    static void appendNoThrow(const AuditModel& record) noexcept;
    // Newest first, optionally for one bucket name.
    [[nodiscard]] static std::vector<AuditModel> list(const std::optional<std::string>& bucket, unsigned int limit = 100);
};

}
