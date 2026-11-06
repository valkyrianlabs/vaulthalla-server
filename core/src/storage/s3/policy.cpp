// The opaque_v1 request rules (design/encryption/01-provider-blind-storage.md §4.3), enforced in one place for every
// request a Controller sends while Controller::setOpaqueLayout(true): see Controller::enforceRequestPolicy.

#include "storage/s3/Controller.hpp"
#include "storage/ObjectKeys.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <array>
#include <cctype>

namespace vh::storage::s3 {

namespace policy_detail {

thread_local bool foreignReadAllowed = false;

std::string lowered(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string_view opName(const RequestOp op) {
    switch (op) {
    case RequestOp::Put: return "PUT";
    case RequestOp::Get: return "GET";
    case RequestOp::Head: return "HEAD";
    case RequestOp::Delete: return "DELETE";
    case RequestOp::List: return "LIST";
    case RequestOp::ListVersions: return "LIST versions";
    case RequestOp::HeadVersion: return "HEAD version";
    case RequestOp::Copy: return "COPY";
    case RequestOp::MetadataRewrite: return "metadata rewrite";
    }
    return "request";
}

// Headers that would tell the provider something about the content (§4.3 rule 2); x-amz-meta-* are rule 1.
constexpr std::array<std::string_view, 7> kForbiddenHeaders{
    "content-disposition", "content-encoding", "content-language", "cache-control",
    "expires", "x-amz-tagging", "x-amz-website-redirect-location"};

[[noreturn]] void refuse(const RequestOp op, const std::string& why) {
    throw OpaqueRequestRefused(fmt::format("opaque_v1 refuses this {}: {}", opName(op), why));
}

}

ScopedForeignObjectRead::ScopedForeignObjectRead() noexcept : previous_(policy_detail::foreignReadAllowed) {
    policy_detail::foreignReadAllowed = true;
}

ScopedForeignObjectRead::~ScopedForeignObjectRead() { policy_detail::foreignReadAllowed = previous_; }

bool ScopedForeignObjectRead::active() noexcept { return policy_detail::foreignReadAllowed; }

void Controller::enforceRequestPolicy(const RequestOp op, std::string_view key, const RequestOptions* options,
                                      const std::string_view secondKey) const {
    if (!opaqueLayout()) return;
    namespace keys = object_keys;
    while (key.starts_with('/')) key.remove_prefix(1);

    if (op == RequestOp::MetadataRewrite)
        policy_detail::refuse(op, "objects carry no metadata to rewrite");

    if (op == RequestOp::List || op == RequestOp::ListVersions) {
        // Never a key name in a query string: the prefixes are o/ or .vaulthalla/… (or nothing).
        if (!keys::isAllowedListPrefix(key)) policy_detail::refuse(op, "the listing prefix is not o/ or .vaulthalla/");
    } else if (!keys::isAllowedKey(key)) {
        const bool read = op == RequestOp::Get || op == RequestOp::Head;
        if (!(read && ScopedForeignObjectRead::active()))
            policy_detail::refuse(op, "the key is neither o/<uid> nor a .vaulthalla/ object");
    }

    if (op == RequestOp::Copy) {
        auto dest = secondKey;
        while (dest.starts_with('/')) dest.remove_prefix(1);
        if (dest != key) policy_detail::refuse(op, "a copy goes onto its own key only (provider-version restore)");
    }

    if (!options) return;
    if (!options->metadata.empty()) policy_detail::refuse(op, "x-amz-meta-* is never sent");
    for (const auto& [name, value] : options->system_headers) {
        const auto lower = policy_detail::lowered(name);
        if (lower.starts_with("x-amz-meta-")) policy_detail::refuse(op, "x-amz-meta-* is never sent");
        if (std::ranges::find(policy_detail::kForbiddenHeaders, lower) != policy_detail::kForbiddenHeaders.end())
            policy_detail::refuse(op, "header " + lower + " is never sent");
        if (lower == "content-type" && policy_detail::lowered(value) != "application/octet-stream")
            policy_detail::refuse(op, "Content-Type is application/octet-stream only");
        if (lower == "x-amz-metadata-directive" && policy_detail::lowered(value) != "copy")
            policy_detail::refuse(op, "metadata is never replaced");
    }
}

}
