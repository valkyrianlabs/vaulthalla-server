#include "fs/model/File.hpp"
#include "preview/Plan.hpp"
#include "log/Registry.hpp"
#include "db/query/fs/Entry.hpp"
#include "sync/model/RemoteManifest.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/result>
#include <regex>
#include <pugixml.hpp>
#include <algorithm>
#include <cctype>

using namespace vh::fs::model;

File::File(pqxx::row_ref row, const pqxx::result& parentRows)
    : Entry(row, parentRows),
      encryption_iv(row.at("encryption_iv").as<std::string>()),
      mime_type(row.at("mime_type").as<std::optional<std::string>>()),
      content_hash(row.at("content_hash").as<std::optional<std::string>>()),
      encrypted_with_key_version(row.at("encrypted_with_key_version").as<unsigned int>()) {}

File::File(const std::string& s3_key, const uint64_t size, const std::optional<std::time_t>& updated)
    : Entry(s3_key) {
    size_bytes = size;
    if (updated) updated_at = *updated;
}

bool File::operator==(const File& other) const {
    return static_cast<const Entry&>(*this) == static_cast<const Entry&>(other) &&
           encryption_iv == other.encryption_iv &&
           mime_type == other.mime_type &&
           content_hash == other.content_hash &&
           encrypted_with_key_version == other.encrypted_with_key_version;
}

bool File::requiresArchiveRestoreForBodyGet() const {
    if (!remote_storage_class) return false;

    std::string storageClass = *remote_storage_class;
    std::ranges::transform(storageClass, storageClass.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });

    if (storageClass == "GLACIER" || storageClass == "DEEP_ARCHIVE") return true;

    if (storageClass == "INTELLIGENT_TIERING" && remote_restore_status && !remote_restore_status->empty())
        return true;

    return false;
}

void vh::fs::model::to_json(nlohmann::json& j, const File& f) {
    to_json(j, static_cast<const Entry&>(f));
    j["type"] = "file"; // Helpful for client

    if (f.mime_type) j["mime_type"] = f.mime_type.value();
    else j["mime_type"] = nullptr;

    // Server-authoritative consumption plan: the console renders this instead of re-deriving it from MIME.
    j["preview"] = preview::classify(f);
}

void vh::fs::model::from_json(const nlohmann::json& j, File& f) {
    from_json(j, static_cast<Entry&>(f));

    if (j.contains("mime_type")) f.mime_type = j.at("mime_type").get<std::string>();
    else f.mime_type = std::nullopt;
}

void vh::fs::model::to_json(nlohmann::json& j, const std::vector<std::shared_ptr<File>>& files) {
    j = nlohmann::json::array();
    for (const auto& file : files) j.push_back(*file);
}

std::vector<std::shared_ptr<File>> vh::fs::model::files_from_pq_res(const pqxx::result& res) {
    std::vector<std::shared_ptr<File>> files;
    for (const auto& row : res) {
        if (const auto parentId = row["parent_id"].as<std::optional<unsigned int>>()) {
            const auto parentChain = db::query::fs::Entry::collectParentChain(*parentId);
            files.push_back(std::make_shared<File>(row, parentChain));
        } else files.push_back(std::make_shared<File>(row, pqxx::result{}));
    }
    return files;
}

std::vector<std::shared_ptr<File>> vh::fs::model::filesFromS3XML(const std::u8string& xml) {
    std::vector<std::shared_ptr<File>> files;

    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_string(reinterpret_cast<const char*>(xml.c_str()));

    if (!result) {
        log::Registry::types()->error("[File] [filesFromS3XML] Failed to parse XML: {}", result.description());
        return {};
    }

    // Controller::listObjects concatenates one ListBucketResult per ListObjectsV2 page: read every page, not just
    // the first (a bucket over 1000 objects used to index only its first page, #246).
    if (!doc.child("ListBucketResult")) {
        log::Registry::types()->error("[File] [filesFromS3XML] No ListBucketResult node found in XML");
        return {};
    }

    for (pugi::xml_node root : doc.children("ListBucketResult")) {
        for (pugi::xml_node content : root.children("Contents")) {
            auto keyNode = content.child("Key");
            auto sizeNode = content.child("Size");
            auto modifiedNode = content.child("LastModified");

            if (!keyNode || !sizeNode || !modifiedNode) {
                log::Registry::types()->warn("[File] [filesFromS3XML] Skipping entry due to missing child elements");
                continue;
            }

            const std::u8string key = reinterpret_cast<const char8_t*>(keyNode.text().get());
            if (vh::sync::model::remote_manifest::isVaulthallaManifestKey(
                    std::string(reinterpret_cast<const char*>(key.c_str()))))
                continue;

            const std::string lastMod = modifiedNode.text().get();
            const uint64_t size = std::stoull(sizeNode.text().get());

            std::tm tm{};
            std::istringstream ss(lastMod);
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
            std::time_t ts = ss.fail() ? std::time(nullptr) : timegm(&tm);

            auto file = std::make_shared<File>(std::string(reinterpret_cast<const char*>(key.c_str())), size, ts);
            if (const auto storageClassNode = content.child("StorageClass"))
                file->remote_storage_class = storageClassNode.text().get();
            if (const auto eTagNode = content.child("ETag"))
                file->remote_etag = eTagNode.text().get();
            if (const auto restoreStatusNode = content.child("RestoreStatus")) {
                std::ostringstream restore;
                restoreStatusNode.print(restore, "", pugi::format_raw);
                file->remote_restore_status = restore.str();
            }
            files.push_back(file);
        }
    }

    return files;
}

std::unordered_map<std::u8string, std::shared_ptr<File>> vh::fs::model::groupEntriesByPath(const std::vector<std::shared_ptr<File>>& entries) {
    std::unordered_map<std::u8string, std::shared_ptr<File>> grouped;

    for (const auto& file : entries) {
        if (grouped.contains(file->path.u8string())) {
            log::Registry::types()->warn("[File] [groupEntriesByPath] Duplicate entry found for path: {}", file->path.string());
            continue;
        }
        grouped[file->path.u8string()] = file;
    }

    return grouped;
}
