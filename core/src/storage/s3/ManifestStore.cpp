#include "storage/s3/ManifestStore.hpp"

#include "storage/s3/Controller.hpp"

#include <pugixml.hpp>

#include <cstdio>
#include <ctime>

namespace vh::storage::s3 {

namespace manifest_store_detail {

// "2026-11-05T12:00:00.000Z" (ListObjectsV2 LastModified).
std::optional<std::time_t> parseListTime(const std::string& value) {
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    if (std::sscanf(value.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6) return std::nullopt;
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
    return timegm(&tm);
}

}

ManifestStore::ManifestStore(std::shared_ptr<Controller> s3, const vl::vaultfmt::manifest::WriteCapability mode)
    : s3_(std::move(s3)), mode_(mode) {
    if (!s3_) throw std::invalid_argument("storage::s3::ManifestStore needs a controller");
}

std::optional<vl::vaultfmt::manifest::StoredObject> ManifestStore::get(const std::string& key,
                                                               const std::optional<std::string>& versionId) {
    vl::vaultfmt::manifest::StoredObject out;
    GetObjectOptions options;
    options.version_id = versionId;
    options.max_body_bytes = vl::vaultfmt::manifest::kMaxManifestObjectBytes;
    try {
        const auto result = s3_->streamObject(key, options, [&](const std::span<const uint8_t> chunk) {
            out.bytes.insert(out.bytes.end(), chunk.begin(), chunk.end());
        });
        out.etag = result.etag;
        out.version_id = versionId;
    } catch (const ObjectNotFound&) {
        return std::nullopt;
    }
    return out;
}

std::optional<std::vector<uint8_t>> ManifestStore::getRange(const std::string& key, const uint64_t offset,
                                                            const uint64_t length) {
    if (length == 0) return std::vector<uint8_t>{};
    std::vector<uint8_t> out;
    GetObjectOptions options;
    options.range = std::make_pair(offset, offset + length - 1);
    options.max_body_bytes = length;
    try {
        (void)s3_->streamObject(key, options, [&](const std::span<const uint8_t> chunk) {
            out.insert(out.end(), chunk.begin(), chunk.end());
        });
    } catch (const ObjectNotFound&) {
        return std::nullopt;
    }
    return out;
}

std::optional<std::string> ManifestStore::headEtag(const std::string& key) {
    const auto head = s3_->getHeadObject(key);
    if (!head) return std::nullopt;
    for (const auto& [name, value] : *head)
        if (name.size() == 4 && (name[0] == 'E' || name[0] == 'e') && (name[1] == 'T' || name[1] == 't') &&
            (name[2] == 'a' || name[2] == 'A') && (name[3] == 'g' || name[3] == 'G'))
            return value;
    return std::string{};
}

std::string ManifestStore::put(const std::string& key, const std::vector<uint8_t>& bytes,
                         const std::optional<std::string>& ifMatch, const std::optional<std::string>& ifNoneMatch) {
    try {
        s3_->uploadBufferWithMetadataConditional(key, bytes, RequestOptions{}, ifMatch, ifNoneMatch);
    } catch (const ConditionalRequestFailed& e) {
        throw vl::vaultfmt::manifest::PreconditionFailed(e.what());
    } catch (const PreconditionsUnsupported& e) {
        throw vl::vaultfmt::manifest::ConditionsUnsupported(e.what());
    }
    return Controller::lastPutOutcome().etag;
}

vl::vaultfmt::manifest::PutResult ManifestStore::put(const std::string& key, const std::vector<uint8_t>& bytes) {
    try {
        s3_->uploadBufferWithMetadataConditional(key, bytes, RequestOptions{}, std::nullopt, std::nullopt);
    } catch (const RequestBudgetExceeded&) {
        throw;  // refused before anything was sent
    } catch (const upstream::BucketProtected&) {
        throw;
    } catch (const std::runtime_error& e) {
        // A transport failure or a non-2xx answer: the provider may have applied the PUT all the same.
        throw vl::vaultfmt::manifest::PutOutcomeUnknown(e.what());
    }
    const auto outcome = Controller::lastPutOutcome();
    return {outcome.etag, outcome.version_id};
}

void ManifestStore::removeVersion(const std::string& key, const std::string& versionId) {
    s3_->deleteObjectVersion(key, versionId);
}

std::string ManifestStore::putIfAbsent(const std::string& key, const std::vector<uint8_t>& bytes) {
    return put(key, bytes, std::nullopt, std::string("*"));
}

std::string ManifestStore::putIfMatch(const std::string& key, const std::vector<uint8_t>& bytes,
                                      const std::string& etag) {
    return put(key, bytes, etag, std::nullopt);
}

std::vector<vl::vaultfmt::manifest::ListedObject> ManifestStore::list(const std::string& prefix) {
    const auto xml = s3_->listObjects(prefix);
    pugi::xml_document doc;
    if (!doc.load_buffer(xml.data(), xml.size()))
        throw std::runtime_error("manifest: the bucket listing of " + prefix + " is not XML");
    std::vector<vl::vaultfmt::manifest::ListedObject> out;
    for (const auto page : doc.children("ListBucketResult")) {
        for (const auto contents : page.children("Contents")) {
            vl::vaultfmt::manifest::ListedObject o;
            o.key = contents.child_value("Key");
            if (!o.key.starts_with(prefix)) continue;
            o.size = std::strtoull(contents.child_value("Size"), nullptr, 10);
            o.last_modified = manifest_store_detail::parseListTime(contents.child_value("LastModified"));
            if (const std::string etag = contents.child_value("ETag"); !etag.empty()) o.etag = etag;
            out.push_back(std::move(o));
        }
    }
    return out;
}

std::vector<vl::vaultfmt::manifest::StoredVersion> ManifestStore::versions(const std::string& key) {
    return versionsSince(key, std::nullopt);
}

std::vector<vl::vaultfmt::manifest::StoredVersion> ManifestStore::versionsSince(const std::string& key,
                                                                        const std::optional<std::string>& stopAt) {
    std::vector<vl::vaultfmt::manifest::StoredVersion> out;
    std::string keyMarker, versionMarker;
    for (;;) {
        const auto page = s3_->listObjectVersionsPage(key, keyMarker, versionMarker);
        bool reached = false;
        for (const auto& v : page.versions) {
            if (v.key != key || reached) continue;
            out.push_back({v.key, v.version_id, v.size, v.last_modified, v.delete_marker, v.etag, v.is_latest});
            reached = stopAt && v.version_id == *stopAt;
        }
        if (reached || !page.truncated) break;
        keyMarker = page.next_key_marker;
        versionMarker = page.next_version_id_marker;
        if (keyMarker > key) break;  // past every version of this key
    }
    return out;
}

std::vector<vl::vaultfmt::manifest::StoredVersion> ManifestStore::versionsUnder(const std::string& prefix) {
    std::vector<vl::vaultfmt::manifest::StoredVersion> out;
    std::string keyMarker, versionMarker;
    for (;;) {
        const auto page = s3_->listObjectVersionsPage(prefix, keyMarker, versionMarker);
        for (const auto& v : page.versions) {
            if (!v.key.starts_with(prefix)) continue;
            out.push_back({v.key, v.version_id, v.size, v.last_modified, v.delete_marker, v.etag, v.is_latest});
        }
        if (!page.truncated) break;
        keyMarker = page.next_key_marker;
        versionMarker = page.next_version_id_marker;
    }
    return out;
}

void ManifestStore::remove(const std::string& key) { s3_->deleteObject(key); }

}
