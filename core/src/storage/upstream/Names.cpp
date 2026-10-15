#include "storage/upstream/Names.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <regex>
#include <stdexcept>
#include <string_view>

namespace vh::storage::upstream {

bool validBucketName(const std::string& name, std::string& why) {
    if (name.size() < 3 || name.size() > 63) {
        why = "a bucket name has 3 to 63 characters";
        return false;
    }
    if (!std::ranges::all_of(name, [](const unsigned char c) { return std::islower(c) || std::isdigit(c) || c == '-' || c == '.'; })) {
        why = "a bucket name uses only lower-case letters, digits, '-' and '.'";
        return false;
    }
    const auto alnum = [](const unsigned char c) { return std::islower(c) || std::isdigit(c); };
    if (!alnum(static_cast<unsigned char>(name.front())) || !alnum(static_cast<unsigned char>(name.back()))) {
        why = "a bucket name starts and ends with a letter or digit";
        return false;
    }
    if (name.find("..") != std::string::npos) {
        why = "a bucket name has no two adjacent periods";
        return false;
    }
    static const std::regex ipLike(R"(^\d{1,3}(\.\d{1,3}){3}$)");
    if (std::regex_match(name, ipLike)) {
        why = "a bucket name can't look like an IP address";
        return false;
    }
    for (const auto* prefix : {"xn--", "sthree-", "amzn-s3-demo-"})
        if (name.starts_with(prefix)) {
            why = std::string("a bucket name can't start with '") + prefix + "'";
            return false;
        }
    for (const auto* suffix : {"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"})
        if (name.ends_with(suffix)) {
            why = std::string("a bucket name can't end with '") + suffix + "'";
            return false;
        }
    return true;
}

void requireValidBucketName(const std::string& name) {
    std::string why;
    if (!validBucketName(name, why)) throw std::invalid_argument("invalid bucket name '" + name + "': " + why);
}

bool validAwsRegion(const std::string& region) {
    // <partition-ish prefix>-<direction>-<n>: us-east-2, eu-central-1, ap-southeast-4, me-central-1, us-gov-west-1,
    // cn-northwest-1, eusc-de-east-1. Lower-case letters and digits only, so nothing can leave the host label.
    static const std::regex re(R"(^[a-z]{2,4}(-[a-z]+){1,2}-[0-9]{1,2}$)");
    return region.size() <= 32 && std::regex_match(region, re);
}

bool validR2LocationHint(const std::string& hint) {
    static constexpr std::array<std::string_view, 7> kHints{"auto", "wnam", "enam", "weur", "eeur", "apac", "oc"};
    return std::ranges::find(kHints, std::string_view(hint)) != kHints.end();
}

std::string encodePathSegment(const std::string& segment) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(segment.size() * 3);
    for (const unsigned char c : segment) {
        if (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0F]);
        }
    }
    return out;
}

}
