#include "sync/manifest/Store.hpp"

#include <algorithm>

namespace vh::sync::manifest {

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
    if (sendsPreconditions(mode())) return putIfAbsent(key, bytes);
    return put(key, bytes).etag;
}

}
