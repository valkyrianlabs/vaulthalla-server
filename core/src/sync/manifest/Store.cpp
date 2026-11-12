#include "sync/manifest/Store.hpp"

#include "storage/s3/Controller.hpp"

#include <algorithm>
#include <pugixml.hpp>

#include <cstdio>
#include <ctime>

namespace vh::sync::manifest {

namespace store_detail {

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

PutResult ObjectStore::put(const std::string& key, const std::vector<uint8_t>&) {
    throw std::logic_error("this store can't write " + key + " without a precondition");
}

std::vector<StoredVersion> ObjectStore::versionsSince(const std::string& key, const std::optional<std::string>& stopAt) {
    auto all = versions(key);
    if (!stopAt) return all;
    const auto it = std::ranges::find_if(all, [&](const StoredVersion& v) { return v.version_id == *stopAt; });
    if (it != all.end()) all.erase(std::next(it), all.end());
    return all;
}

std::vector<StoredVersion> ObjectStore::versionsUnder(const std::string& prefix) {
    throw std::logic_error("this store can't list the versions under " + prefix);
}

void ObjectStore::removeVersion(const std::string& key, const std::string& versionId) {
    throw std::logic_error("this store can't delete version " + versionId + " of " + key);
}

std::string ObjectStore::putOnce(const std::string& key, const std::vector<uint8_t>& bytes) {
    if (storage::s3::sendsPreconditions(mode())) return putIfAbsent(key, bytes);
    return put(key, bytes).etag;
}

S3Store::S3Store(std::shared_ptr<storage::s3::Controller> s3, const storage::s3::WriteCapability mode)
    : s3_(std::move(s3)), mode_(mode) {
    if (!s3_) throw std::invalid_argument("manifest::S3Store needs a controller");
}

std::optional<StoredObject> S3Store::get(const std::string& key, const std::optional<std::string>& versionId) {
    StoredObject out;
    storage::s3::GetObjectOptions options;
    options.version_id = versionId;
    options.max_body_bytes = kMaxManifestObjectBytes;
    try {
        const auto result = s3_->streamObject(key, options, [&](const std::span<const uint8_t> chunk) {
            out.bytes.insert(out.bytes.end(), chunk.begin(), chunk.end());
        });
        out.etag = result.etag;
        out.version_id = versionId;
    } catch (const storage::s3::ObjectNotFound&) {
        return std::nullopt;
    }
    return out;
}

std::optional<std::vector<uint8_t>> S3Store::getRange(const std::string& key, const uint64_t offset,
                                                      const uint64_t length) {
    if (length == 0) return std::vector<uint8_t>{};
    std::vector<uint8_t> out;
    storage::s3::GetObjectOptions options;
    options.range = std::make_pair(offset, offset + length - 1);
    options.max_body_bytes = length;
    try {
        (void)s3_->streamObject(key, options, [&](const std::span<const uint8_t> chunk) {
            out.insert(out.end(), chunk.begin(), chunk.end());
        });
    } catch (const storage::s3::ObjectNotFound&) {
        return std::nullopt;
    }
    return out;
}

std::optional<std::string> S3Store::headEtag(const std::string& key) {
    const auto head = s3_->getHeadObject(key);
    if (!head) return std::nullopt;
    for (const auto& [name, value] : *head)
        if (name.size() == 4 && (name[0] == 'E' || name[0] == 'e') && (name[1] == 'T' || name[1] == 't') &&
            (name[2] == 'a' || name[2] == 'A') && (name[3] == 'g' || name[3] == 'G'))
            return value;
    return std::string{};
}

std::string S3Store::put(const std::string& key, const std::vector<uint8_t>& bytes,
                         const std::optional<std::string>& ifMatch, const std::optional<std::string>& ifNoneMatch) {
    try {
        s3_->uploadBufferWithMetadataConditional(key, bytes, storage::s3::RequestOptions{}, ifMatch, ifNoneMatch);
    } catch (const storage::s3::ConditionalRequestFailed& e) {
        throw PreconditionFailed(e.what());
    } catch (const storage::s3::PreconditionsUnsupported& e) {
        throw ConditionsUnsupported(e.what());
    }
    return storage::s3::Controller::lastPutOutcome().etag;
}

PutResult S3Store::put(const std::string& key, const std::vector<uint8_t>& bytes) {
    try {
        s3_->uploadBufferWithMetadataConditional(key, bytes, storage::s3::RequestOptions{}, std::nullopt, std::nullopt);
    } catch (const storage::s3::RequestBudgetExceeded&) {
        throw;  // refused before anything was sent
    } catch (const storage::upstream::BucketProtected&) {
        throw;
    } catch (const std::runtime_error& e) {
        // A transport failure or a non-2xx answer: the provider may have applied the PUT all the same.
        throw PutOutcomeUnknown(e.what());
    }
    const auto outcome = storage::s3::Controller::lastPutOutcome();
    return {outcome.etag, outcome.version_id};
}

void S3Store::removeVersion(const std::string& key, const std::string& versionId) {
    s3_->deleteObjectVersion(key, versionId);
}

std::string S3Store::putIfAbsent(const std::string& key, const std::vector<uint8_t>& bytes) {
    return put(key, bytes, std::nullopt, std::string("*"));
}

std::string S3Store::putIfMatch(const std::string& key, const std::vector<uint8_t>& bytes, const std::string& etag) {
    return put(key, bytes, etag, std::nullopt);
}

std::vector<ListedObject> S3Store::list(const std::string& prefix) {
    const auto xml = s3_->listObjects(prefix);
    pugi::xml_document doc;
    if (!doc.load_buffer(xml.data(), xml.size()))
        throw std::runtime_error("manifest: the bucket listing of " + prefix + " is not XML");
    std::vector<ListedObject> out;
    for (const auto page : doc.children("ListBucketResult")) {
        for (const auto contents : page.children("Contents")) {
            ListedObject o;
            o.key = contents.child_value("Key");
            if (!o.key.starts_with(prefix)) continue;
            o.size = std::strtoull(contents.child_value("Size"), nullptr, 10);
            o.last_modified = store_detail::parseListTime(contents.child_value("LastModified"));
            if (const std::string etag = contents.child_value("ETag"); !etag.empty()) o.etag = etag;
            out.push_back(std::move(o));
        }
    }
    return out;
}

std::vector<StoredVersion> S3Store::versions(const std::string& key) { return versionsSince(key, std::nullopt); }

std::vector<StoredVersion> S3Store::versionsSince(const std::string& key, const std::optional<std::string>& stopAt) {
    std::vector<StoredVersion> out;
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

std::vector<StoredVersion> S3Store::versionsUnder(const std::string& prefix) {
    std::vector<StoredVersion> out;
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

void S3Store::remove(const std::string& key) { s3_->deleteObject(key); }

}
