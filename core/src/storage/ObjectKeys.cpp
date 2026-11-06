#include "storage/ObjectKeys.hpp"

#include <algorithm>

namespace vh::storage::object_keys {

namespace object_keys_detail {

std::string_view withoutLeadingSlash(std::string_view key) {
    while (key.starts_with('/')) key.remove_prefix(1);
    return key;
}

bool isUidText(const std::string_view text) { return crypto::id::fromBase32(text).has_value(); }

}

std::string contentKey(const crypto::id::ObjectUid& uid) {
    return std::string(kContentPrefix) + crypto::id::toBase32(uid);
}

std::optional<crypto::id::ObjectUid> uidOfContentKey(std::string_view key) {
    key = object_keys_detail::withoutLeadingSlash(key);
    if (!key.starts_with(kContentPrefix)) return std::nullopt;
    return crypto::id::fromBase32(key.substr(kContentPrefix.size()));
}

bool isMetadataKey(std::string_view key) {
    if (!key.starts_with(kMetadataPrefix)) return false;
    const auto rest = key.substr(kMetadataPrefix.size());
    if (rest == "layout.json" || rest == "root") return true;
    for (const std::string_view sub : {std::string_view("seg/"), std::string_view("key/")})
        if (rest.starts_with(sub)) return object_keys_detail::isUidText(rest.substr(sub.size()));
    return false;
}

KeyClass classify(const std::string_view key) {
    if (uidOfContentKey(key) && !key.starts_with('/')) return KeyClass::Content;
    if (isMetadataKey(key)) return KeyClass::Metadata;
    return KeyClass::Foreign;
}

bool isAllowedKey(const std::string_view key) { return classify(key) != KeyClass::Foreign; }

bool isAllowedListPrefix(const std::string_view prefix) {
    if (prefix.empty() || prefix == kContentPrefix || prefix == kMetadataPrefix) return true;
    if (prefix == ".vaulthalla/seg/" || prefix == ".vaulthalla/key/") return true;
    return isAllowedKey(prefix);
}

std::string importedPathOf(const std::string_view foreignKey) {
    return std::string(kImportedRoot) + "/" + std::string(object_keys_detail::withoutLeadingSlash(foreignKey));
}

uint64_t partSizeFor(const uint64_t objectSize) {
    const uint64_t needed = objectSize / kMaxParts + (objectSize % kMaxParts ? 1 : 0);
    const uint64_t aligned = (needed + kPartAlignment - 1) / kPartAlignment * kPartAlignment;
    return std::max(kMinPartSize, aligned);
}

uint64_t partCountFor(const uint64_t objectSize, const uint64_t partSize) {
    if (objectSize == 0 || partSize == 0) return 0;
    return objectSize / partSize + (objectSize % partSize ? 1 : 0);
}

}
