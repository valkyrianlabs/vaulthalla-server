#pragma once

#include <array>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

// The Vaulthalla Cloud link row (migration 134): at most one, pending or linked.
namespace vh::db::query::cloud {

struct LinkRow {
    std::string endpoint;
    std::string status;  // pending | linked
    std::array<uint8_t, 32> public_key{};
    std::string name;
    std::optional<std::string> request_id;
    std::optional<std::time_t> request_expires_at;
    std::optional<std::string> installation_id;
    std::optional<int64_t> account_id;
    std::string requested_by;
    std::time_t requested_at = 0;
    std::optional<std::time_t> linked_at;
};

struct Link {
    [[nodiscard]] static std::optional<LinkRow> get();
    // A new pending row, replacing a pending one (never a linked one: returns false then).
    static bool putPending(const LinkRow& row);
    // pending → linked, for the request it names. False when it isn't that pending request any more.
    static bool markLinked(const std::string& requestId, const std::string& installationId, int64_t accountId);
    static void clear();
};

}
