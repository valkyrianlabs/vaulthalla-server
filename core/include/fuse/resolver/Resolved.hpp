#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <vector>
#include "fs/Fwd.hpp"
#include "fs/Inode.hpp"
#include "identities/Fwd.hpp"
#include "storage/Fwd.hpp"

namespace vh {

    namespace fuse::resolver {
        enum class Status {
            Ok,
            MissingFuseContext,
            MissingIno,
            MissingChildName,
            MissingParentPath,
            MissingUser,
            MissingEntry,
            MissingParentIno,
            MissingParentEntry,
            MissingPath,
            MissingEngine,
            InvalidChildPath,
            AccessDenied,
            InvalidRequest,
            InternalError
        };

        struct Resolved {
            Status status {Status::Ok};
            int errnum {0};

            std::shared_ptr<identities::User> user{};
            std::shared_ptr<identities::Group> group{};  // the caller's gid, when a group maps it (new entries' group_gid)
            std::shared_ptr<fs::model::Entry> entry{};
            std::shared_ptr<fs::model::Entry> parentEntry{};
            std::optional<std::filesystem::path> path{};
            std::optional<vh::fs::Inode> ino{};
            std::shared_ptr<storage::Engine> engine{};
            std::optional<std::vector<std::shared_ptr<fs::model::Entry>>> dir{};

            [[nodiscard]] bool ok() const {
                return status == Status::Ok;
            }

            void setStatus(const Status& status, const int errnum) {
                this->status = status;
                this->errnum = errnum;
            }
        };
    }
}
