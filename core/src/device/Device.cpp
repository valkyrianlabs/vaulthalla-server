#include "device/Device.hpp"

#include <nlohmann/json.hpp>

namespace vh::device {

namespace {
nlohmann::json optTime(const std::optional<std::time_t>& t) {
    return t ? nlohmann::json(static_cast<int64_t>(*t)) : nlohmann::json(nullptr);
}
}

void to_json(nlohmann::json& j, const Device& d) {
    j = {
        {"id", d.id},
        {"device_id", d.spki_sha256},
        {"user_id", d.user_id},
        {"user_name", d.user_name},
        {"name", d.name},
        {"platform", d.platform},
        {"app_version", d.app_version},
        {"previous_device_id", d.previous_spki_sha256 ? nlohmann::json(*d.previous_spki_sha256) : nlohmann::json(nullptr)},
        {"approved_by", d.approved_by ? nlohmann::json(*d.approved_by) : nlohmann::json(nullptr)},
        {"created_at", static_cast<int64_t>(d.created_at)},
        {"last_seen_at", optTime(d.last_seen_at)},
        {"last_ip", d.last_ip ? nlohmann::json(*d.last_ip) : nlohmann::json(nullptr)},
        {"revoked_at", optTime(d.revoked_at)},
        {"revoked", d.revoked()},
    };
}

std::optional<std::string> normalizeDeviceName(const std::string& name) {
    std::size_t begin = 0, end = name.size();
    while (begin < end && (name[begin] == ' ' || name[begin] == '\t')) ++begin;
    while (end > begin && (name[end - 1] == ' ' || name[end - 1] == '\t')) --end;
    const auto trimmed = name.substr(begin, end - begin);
    if (trimmed.empty()) return std::nullopt;

    // Count code points and refuse control characters and malformed UTF-8 (the name is shown in consoles and logs).
    std::size_t codePoints = 0;
    for (std::size_t i = 0; i < trimmed.size();) {
        const auto c = static_cast<unsigned char>(trimmed[i]);
        std::size_t len = 0;
        if (c < 0x80) {
            if (c < 0x20 || c == 0x7f) return std::nullopt;
            len = 1;
        } else if ((c & 0xe0) == 0xc0 && c >= 0xc2) len = 2;
        else if ((c & 0xf0) == 0xe0) len = 3;
        else if ((c & 0xf8) == 0xf0 && c <= 0xf4) len = 4;
        else return std::nullopt;
        if (i + len > trimmed.size()) return std::nullopt;
        for (std::size_t k = 1; k < len; ++k)
            if ((static_cast<unsigned char>(trimmed[i + k]) & 0xc0) != 0x80) return std::nullopt;
        // C1 controls (U+0080..U+009F) are two bytes: 0xc2 0x80..0x9f.
        if (len == 2 && c == 0xc2 && static_cast<unsigned char>(trimmed[i + 1]) < 0xa0) return std::nullopt;
        i += len;
        ++codePoints;
    }
    if (codePoints > 64) return std::nullopt;
    return trimmed;
}

}
