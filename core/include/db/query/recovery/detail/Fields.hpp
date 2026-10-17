#pragma once

#include <pqxx/field>
#include <pqxx/row>

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Field helpers shared by the db::query::recovery implementations (not an API). Rows are row_ref views: copy out.
namespace vh::db::query::recovery::detail {

template <typename T>
[[nodiscard]] std::optional<T> opt(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return f.as<T>();
}

[[nodiscard]] inline std::optional<std::time_t> optTime(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return static_cast<std::time_t>(f.as<int64_t>());
}

[[nodiscard]] inline std::time_t timeOr0(const pqxx::field_ref f) {
    return f.is_null() ? 0 : static_cast<std::time_t>(f.as<int64_t>());
}

[[nodiscard]] inline uint64_t u64(const pqxx::field_ref f) {
    if (f.is_null()) return 0;
    const auto v = f.as<int64_t>();
    return v < 0 ? 0 : static_cast<uint64_t>(v);
}

[[nodiscard]] inline std::optional<uint64_t> optU64(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return u64(f);
}

[[nodiscard]] inline std::optional<int64_t> optI64(const std::optional<uint64_t>& v) {
    if (!v) return std::nullopt;
    return static_cast<int64_t>(*v);
}

[[nodiscard]] inline std::optional<double> optEpoch(const std::optional<std::time_t>& t) {
    if (!t) return std::nullopt;
    return static_cast<double>(*t);
}

// A Postgres bigint[] literal ("{1,2,3}"): integers only, nothing to escape.
[[nodiscard]] inline std::string idArray(const std::vector<int64_t>& ids) {
    std::string out = "{";
    for (const auto id : ids) out += (out.size() > 1 ? "," : "") + std::to_string(id);
    return out + "}";
}

[[nodiscard]] inline unsigned int clampLimit(const unsigned int limit, const unsigned int max = 10000) {
    return limit == 0 ? 1 : (limit > max ? max : limit);
}

// A LIKE pattern matching everything strictly under directory `path` ("/a" → "/a/%", "/" → "/%"), with LIKE's
// metacharacters in the path escaped (ESCAPE '\').
[[nodiscard]] inline std::string likeUnder(const std::string& path) {
    std::string base = path;
    while (base.size() > 1 && base.back() == '/') base.pop_back();
    if (base == "/") base.clear();
    std::string out;
    out.reserve(base.size() + 4);
    for (const char c : base) {
        if (c == '\\' || c == '%' || c == '_') out += '\\';
        out += c;
    }
    return out + "/%";
}

}
