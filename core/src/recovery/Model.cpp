#include "recovery/Model.hpp"

#include <charconv>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace vh::recovery {

namespace {

// Strict decimal: digits only, no sign, no leading zero, within [min, max].
uint64_t parseRecoveryDecimal(const std::string_view digits, const uint64_t min, const uint64_t max,
                              const std::string& what) {
    if (digits.empty() || digits.size() > 20 || (digits.size() > 1 && digits.front() == '0'))
        throw std::invalid_argument("invalid " + what);
    for (const char c : digits)
        if (c < '0' || c > '9') throw std::invalid_argument("invalid " + what);
    uint64_t value = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
    if (ec != std::errc() || end != digits.data() + digits.size() || value < min || value > max)
        throw std::invalid_argument("invalid " + what);
    return value;
}

}

std::string to_string(const Mode m) {
    switch (m) {
    case Mode::Off: return "off";
    case Mode::LocalSnapshots: return "local_snapshots";
    case Mode::ProviderVersioning: return "provider_versioning";
    }
    return "off";
}

Mode modeFromString(const std::string& s) {
    if (s == "off") return Mode::Off;
    if (s == "local_snapshots" || s == "local-snapshots") return Mode::LocalSnapshots;
    if (s == "provider_versioning" || s == "provider-versioning") return Mode::ProviderVersioning;
    throw std::invalid_argument("unknown recovery mode '" + s + "' (off | local_snapshots | provider_versioning)");
}

std::string to_string(const Backend b) {
    switch (b) {
    case Backend::LocalSnapshot: return "local_snapshot";
    case Backend::LocalVersion: return "local_version";
    case Backend::ProviderVersion: return "provider_version";
    }
    return "local_snapshot";
}

std::string to_string(const PointKind k) { return k == PointKind::Directory ? "directory" : "file"; }

std::string RecoveryId::str() const {
    switch (type) {
    case Type::Snapshot: return "snap-" + std::to_string(id);
    case Type::LocalGeneration: return "lv-" + std::to_string(id);
    case Type::ProviderVersion: return "pv-" + std::to_string(id);
    }
    return "snap-" + std::to_string(id);
}

RecoveryId RecoveryId::parse(const std::string& s) {
    static constexpr struct {
        std::string_view prefix;
        Type type;
    } kPrefixes[] = {{"snap-", Type::Snapshot}, {"lv-", Type::LocalGeneration}, {"pv-", Type::ProviderVersion}};
    // Ids are BIGSERIAL values: 1 .. 2^63-1.
    constexpr auto kMax = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    for (const auto& [prefix, type] : kPrefixes) {
        if (!s.starts_with(prefix)) continue;
        return {.type = type, .id = parseRecoveryDecimal(std::string_view(s).substr(prefix.size()), 1, kMax,
                                                         "recovery id '" + s + "' (snap-<n> | lv-<n> | pv-<n>)")};
    }
    throw std::invalid_argument("invalid recovery id '" + s + "' (snap-<n> | lv-<n> | pv-<n>)");
}

std::string to_string(const ItemAction a) {
    switch (a) {
    case ItemAction::Create: return "create";
    case ItemAction::Overwrite: return "overwrite";
    case ItemAction::Skip: return "skip";
    case ItemAction::Conflict: return "conflict";
    case ItemAction::Remove: return "remove";
    case ItemAction::Unavailable: return "unavailable";
    }
    return "unavailable";
}

std::string ProviderRetention::str() const { return indefinite ? "indefinite" : std::to_string(days) + "d"; }

ProviderRetention ProviderRetention::parse(const std::string& s) {
    if (s == "indefinite") return {.indefinite = true, .days = 0};
    std::string_view digits(s);
    if (digits.ends_with('d')) digits.remove_suffix(1);
    return {.indefinite = false,
            .days = static_cast<unsigned int>(parseRecoveryDecimal(
                digits, 1, 36500, "retention '" + s + "' (1..36500 days, e.g. 30d, or indefinite)"))};
}

}
