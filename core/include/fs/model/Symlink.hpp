#pragma once

#include "Entry.hpp"
#include "db/Fwd.hpp"

namespace vh::fs::model {
    struct Symlink final : Entry {
        std::string target;

        Symlink() = default;

        Symlink(pqxx::row_ref row, const pqxx::result &parentRows);

        [[nodiscard]] bool isDirectory() const override { return false; }

        [[nodiscard]] bool isSymlink() const override { return true; }
    };

    void to_json(nlohmann::json &j, const Symlink &s);

    void from_json(const nlohmann::json &j, Symlink &s);

    void to_json(nlohmann::json &j, const std::vector<std::shared_ptr<Symlink> > &symlinks);

    // Parent chains read in `txn` (see files_from_pq_res).
    std::vector<std::shared_ptr<Symlink> > symlinks_from_pq_res(const pqxx::result &res, pqxx::transaction_base &txn);
}
