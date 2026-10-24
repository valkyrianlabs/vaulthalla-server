#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <ctime>
#include <optional>
#include <unordered_map>
#include <nlohmann/json_fwd.hpp>
#include <vector>
#include <memory>
#include <boost/uuid/uuid.hpp>
#include "fs/Fwd.hpp"
#include "db/Fwd.hpp"

namespace vh::fs::model {

    struct Entry {
        uint32_t id{};
        std::string name{}, base32_alias{};
        uintmax_t size_bytes{0};
        std::optional<int32_t> parent_id{}, owner_uid{}, group_gid{}, vault_id{}, created_by{}, last_modified_by{};
        std::optional<ino_t> inode{};
        std::optional<mode_t> mode{};
        std::filesystem::path path{}, fuse_path{}, backing_path{};
        bool is_hidden{}, is_system{};
        std::time_t created_at{}, updated_at{};

        Entry() = default;

        virtual ~Entry() = default;

        explicit Entry(const std::string &s3_key);

        Entry(pqxx::row_ref row, const pqxx::result &parentRows);

        [[nodiscard]] bool operator==(const Entry &other) const;

        [[nodiscard]] virtual bool isDirectory() const = 0;

        [[nodiscard]] virtual bool isSymlink() const { return false; }

        void setPath(const std::filesystem::path &path) { this->path = path; }

        void print() const;
    };

    // Opaque version of an entry's metadata ("m<id>-<hex16>"), sent as `metadata_version`: a stable hash of what a
    // sync client shows for the entry itself, i.e. vault, parent folder, name, mode, owner, group and updated_at. It
    // changes on rename, move, mode change and any updated_at change (content writes included) and is the same again
    // only for the same metadata. Not a counter: computed from the fields the reply carries, so it never disagrees
    // with them (no migration, no write path to keep in step). A parent's rename or move does not change it.
    [[nodiscard]] std::string metadataVersion(const Entry &entry);

    void to_json(nlohmann::json &j, const Entry &entry);

    void from_json(const nlohmann::json &j, Entry &entry);

    void to_json(nlohmann::json &j, const std::vector<std::shared_ptr<Entry> > &entries);

    std::vector<std::shared_ptr<Entry> > merge_entries(const std::vector<std::shared_ptr<File> > &files,
                                                       const std::vector<std::shared_ptr<Directory> > &directories);

    std::vector<std::shared_ptr<Entry> > merge_entries(const std::vector<std::shared_ptr<File> > &files,
                                                       const std::vector<std::shared_ptr<Symlink> > &symlinks,
                                                       const std::vector<std::shared_ptr<Directory> > &directories);

    std::vector<std::shared_ptr<Entry> > fromS3XML(const std::u8string &xml);

    std::unordered_map<std::u8string, std::shared_ptr<Entry> > groupEntriesByPath(
        const std::vector<std::shared_ptr<Entry> > &entries);
}
